use crate::anon_xfr::address_folding_ed25519::{
    create_address_folding_ed25519, prepare_verifier_input_ed25519, verify_address_folding_ed25519,
};
use crate::anon_xfr::address_folding_secp256k1::{
    create_address_folding_secp256k1, prepare_verifier_input_secp256k1,
    verify_address_folding_secp256k1,
};
use crate::anon_xfr::{
    abar_to_ar::build_abar_to_ar_cs,
    commit, nullify,
    structs::{AnonAssetRecord, Commitment, Nullifier, OpenAnonAssetRecord, PayerWitness},
    AXfrAddressFoldingInstance, AXfrAddressFoldingWitness, AXfrPlonkPf,
};
use crate::errors::{NoahError, Result};
use crate::keys::{KeyPair, PublicKey, SecretKey};
use crate::parameters::params::ProverParams;
use crate::parameters::params::VerifierParams;
use crate::xfr::{
    asset_record::{
        build_open_asset_record, AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
    },
    structs::{AssetRecordTemplate, BlindAssetRecord},
};
use digest::{consts::U64, Digest};
use merlin::Transcript;
use noah_algebra::{bls12_381::BLSScalar, prelude::*, ristretto::PedersenCommitmentRistretto};
use noah_crypto::anemoi_jive::AnemoiVLHTrace;
use noah_plonk::plonk::{prover::prover_with_lagrange, verifier::verifier};

/// The domain separator for anonymous-to-transparent, for the Plonk proof.
const OWNERSHIP_PLONK_PROOF_TRANSCRIPT: &[u8] = b"Ownership Plonk Proof";

/// The domain separator for anonymous-to-transparent, for address folding.
const OWNERSHIP_FOLDING_PROOF_TRANSCRIPT: &[u8] = b"Ownership Folding Proof";

/// The anonymous-to-transparent note.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnershipNote {
    /// The body part of ABAR to AR.
    pub body: OwnershipBody,
    /// The Plonk proof (assuming non-malleability).
    pub proof: AXfrPlonkPf,
    /// The address folding instance.
    pub folding_instance: AXfrAddressFoldingInstance,
}

/// The anonymous-to-transparent note without proof.
#[derive(Clone, Debug)]
pub struct OwnershipPreNote {
    /// The body part of ABAR to AR.
    pub body: OwnershipBody,
    /// Witness.
    pub witness: PayerWitness,
    /// The trace of the input commitment.
    pub input_commitment_trace: AnemoiVLHTrace<BLSScalar, 2, 12>,
    /// The trace of the nullifier.
    pub nullifier_trace: AnemoiVLHTrace<BLSScalar, 2, 12>,
    /// Input key pair.
    pub input_keypair: KeyPair,
}

/// The anonymous-to-transparent body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnershipBody {
    /// the commitment
    pub commitment: Commitment,
    /// input ABAR being spent.
    pub input: Nullifier,
    /// The new AR to be created.
    pub output: BlindAssetRecord,
    /// The Merkle root hash.
    pub merkle_root: BLSScalar,
    /// The Merkle root version.
    pub merkle_root_version: u64,
}

/// Generate an anonymous-to-transparent pre-note.
pub fn init_ownership_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    oabar: &OpenAnonAssetRecord,
    abar_keypair: &KeyPair,
    ar_pub_key: &PublicKey,
) -> Result<OwnershipPreNote> {
    if oabar.mt_leaf_info.is_none() || abar_keypair.get_pk() != oabar.pub_key {
        return Err(NoahError::ParameterError);
    }

    let oar_amount = oabar.amount;
    let oar_type = oabar.asset_type;

    let pc_gens = PedersenCommitmentRistretto::default();
    let art = AssetRecordTemplate::with_no_asset_tracing(
        oar_amount,
        oar_type,
        NonConfidentialAmount_NonConfidentialAssetType,
        ar_pub_key.clone(),
    );
    let (oar, _, _) = build_open_asset_record(prng, &pc_gens, &art, vec![]);

    let mt_leaf_info = oabar.mt_leaf_info.as_ref().unwrap();
    let (this_nullifier, this_nullifier_trace) = nullify(
        &abar_keypair,
        oabar.amount,
        oabar.asset_type.as_scalar(),
        mt_leaf_info.uid,
    )?;

    let (_, this_commitment_trace) = commit(
        &abar_keypair.get_pk(),
        oabar.blind,
        oabar.amount,
        oabar.asset_type.as_scalar(),
    )
    .unwrap();

    let payers_secret = PayerWitness {
        secret_key: abar_keypair.get_sk(),
        uid: mt_leaf_info.uid,
        amount: oabar.amount,
        asset_type: oabar.asset_type.as_scalar(),
        path: mt_leaf_info.path.clone(),
        blind: oabar.blind,
    };

    let mt_info_temp = oabar.mt_leaf_info.as_ref().unwrap();

    let body = OwnershipBody {
        commitment: AnonAssetRecord::from_oabar(&oabar).commitment,
        input: this_nullifier,
        output: oar.blind_asset_record.clone(),
        merkle_root: mt_info_temp.root,
        merkle_root_version: mt_info_temp.root_version,
    };

    Ok(OwnershipPreNote {
        body,
        witness: payers_secret,
        input_commitment_trace: this_commitment_trace,
        nullifier_trace: this_nullifier_trace,
        input_keypair: abar_keypair.clone(),
    })
}

/// Finalize an anonymous-to-transparent note.
pub fn finish_ownership_note<R: CryptoRng + RngCore, D: Digest<OutputSize = U64> + Default>(
    prng: &mut R,
    params: &ProverParams,
    pre_note: OwnershipPreNote,
    hash: D,
) -> Result<OwnershipNote> {
    let OwnershipPreNote {
        body,
        witness,
        input_commitment_trace,
        nullifier_trace,
        input_keypair,
    } = pre_note;

    let mut transcript = Transcript::new(OWNERSHIP_FOLDING_PROOF_TRANSCRIPT);

    let (folding_instance, folding_witness) = match input_keypair.get_sk_ref() {
        SecretKey::Secp256k1(_) => {
            let (folding_instance, folding_witness) =
                create_address_folding_secp256k1(prng, hash, &mut transcript, &input_keypair)?;
            (
                AXfrAddressFoldingInstance::Secp256k1(folding_instance),
                AXfrAddressFoldingWitness::Secp256k1(folding_witness),
            )
        }
        SecretKey::Ed25519(_) => {
            let (folding_instance, folding_witness) =
                create_address_folding_ed25519(prng, hash, &mut transcript, &input_keypair)?;
            (
                AXfrAddressFoldingInstance::Ed25519(folding_instance),
                AXfrAddressFoldingWitness::Ed25519(folding_witness),
            )
        }
    };

    let proof = prove_ownership(
        prng,
        params,
        &witness,
        &nullifier_trace,
        &input_commitment_trace,
        &folding_witness,
    )?;

    Ok(OwnershipNote {
        body,
        proof,
        folding_instance,
    })
}

/// Verify the anonymous-to-transparent note.
pub fn verify_ownership_note<D: Digest<OutputSize = U64> + Default>(
    params: &VerifierParams,
    note: &OwnershipNote,
    merkle_root: &BLSScalar,
    hash: D,
) -> Result<()> {
    // require the output amount & asset type are non-confidential
    if note.body.output.amount.is_confidential() || note.body.output.asset_type.is_confidential() {
        return Err(NoahError::ParameterError);
    }

    let mut transcript = Transcript::new(OWNERSHIP_FOLDING_PROOF_TRANSCRIPT);

    let address_folding_public_input = match &note.folding_instance {
        AXfrAddressFoldingInstance::Secp256k1(a) => {
            let (beta, lambda) = verify_address_folding_secp256k1(hash, &mut transcript, a)?;
            prepare_verifier_input_secp256k1(&a, &beta, &lambda)
        }
        AXfrAddressFoldingInstance::Ed25519(a) => {
            let (beta, lambda) = verify_address_folding_ed25519(hash, &mut transcript, a)?;
            prepare_verifier_input_ed25519(&a, &beta, &lambda)
        }
    };

    let payer_amount = note.body.output.amount.get_amount().unwrap();
    let payer_asset_type = note.body.output.asset_type.get_asset_type().unwrap();

    if *merkle_root != note.body.merkle_root {
        return Err(NoahError::AXfrVerificationError);
    }

    let mut transcript = Transcript::new(OWNERSHIP_PLONK_PROOF_TRANSCRIPT);
    let mut online_inputs = vec![];
    online_inputs.push(note.body.commitment);
    online_inputs.push(note.body.input.clone());
    online_inputs.push(merkle_root.clone());
    online_inputs.push(BLSScalar::from(payer_amount));
    online_inputs.push(payer_asset_type.as_scalar());
    online_inputs.extend_from_slice(&address_folding_public_input);

    Ok(verifier(
        &mut transcript,
        &params.shrunk_vk,
        &params.shrunk_cs,
        &params.verifier_params,
        &online_inputs,
        &note.proof,
    )?)
}

fn prove_ownership<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    payers_witness: &PayerWitness,
    nullifier_trace: &AnemoiVLHTrace<BLSScalar, 2, 12>,
    input_commitment_trace: &AnemoiVLHTrace<BLSScalar, 2, 12>,
    folding_witness: &AXfrAddressFoldingWitness,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(OWNERSHIP_PLONK_PROOF_TRANSCRIPT);

    let (mut cs, _) = build_abar_to_ar_cs(
        payers_witness,
        nullifier_trace,
        input_commitment_trace,
        &folding_witness,
        true,
    );
    let witness = cs.get_and_clear_witness();

    Ok(prover_with_lagrange(
        rng,
        &mut transcript,
        &params.pcs,
        params.lagrange_pcs.as_ref(),
        &params.cs,
        &params.prover_params,
        &witness,
    )?)
}
