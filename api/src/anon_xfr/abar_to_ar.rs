use crate::anon_xfr::address_folding::{
    create_address_folding, prepare_verifier_input, prove_address_folding_in_cs,
    verify_address_folding, AXfrAddressFoldingWitness,
};
use crate::anon_xfr::{
    abar_to_abar::add_payers_witnesses,
    address_folding::AXfrAddressFoldingInstance,
    commit_in_cs, compute_merkle_root_variables,
    keys::AXfrKeyPair,
    nullify, nullify_in_cs,
    structs::{AccElemVars, Nullifier, OpenAnonAssetRecord, PayerWitness},
    AXfrPlonkPf, TurboPlonkCS, ANON_XFR_BP_GENS_LEN,
};
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::{
    asset_record::{
        build_open_asset_record, AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
    },
    sig::XfrPublicKey,
    structs::{AssetRecordTemplate, BlindAssetRecord, OwnerMemo},
};
use digest::{consts::U64, Digest};
use merlin::Transcript;
use noah_algebra::{bls12_381::BLSScalar, prelude::*};
use noah_crypto::basic::pedersen_comm::PedersenCommitmentRistretto;
use noah_plonk::plonk::{
    constraint_system::{TurboCS, VarIndex},
    prover::prover_with_lagrange,
    verifier::verifier,
};
#[cfg(feature = "parallel")]
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

/// The domain separator for anonymous-to-transparent, for the Plonk proof.
const ABAR_TO_AR_PLONK_PROOF_TRANSCRIPT: &[u8] = b"ABAR to AR Plonk Proof";

/// The domain separator for anonymous-to-transparent, for address folding.
const ABAR_TO_AR_FOLDING_PROOF_TRANSCRIPT: &[u8] = b"ABAR to AR Folding Proof";

/// The anonymous-to-transparent note.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToArNote {
    /// The body part of ABAR to AR.
    pub body: AbarToArBody,
    /// The Plonk proof (assuming non-malleability).
    pub proof: AXfrPlonkPf,
    /// The address folding instance.
    pub folding_instance: AXfrAddressFoldingInstance,
}

/// The anonymous-to-transparent note without proof.
#[derive(Clone, Debug)]
pub struct AbarToArPreNote {
    /// The body part of ABAR to AR.
    pub body: AbarToArBody,
    /// Witness.
    pub witness: PayerWitness,
    /// Input key pair.
    pub input_keypair: AXfrKeyPair,
}

/// The anonymous-to-transparent body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToArBody {
    /// input ABAR being spent.
    pub input: Nullifier,
    /// The new AR to be created.
    pub output: BlindAssetRecord,
    /// The Merkle root hash.
    pub merkle_root: BLSScalar,
    /// The Merkle root version.
    pub merkle_root_version: u64,
    /// The owner memo.
    pub memo: Option<OwnerMemo>,
}

/// Generate an anonymous-to-transparent pre-note.
pub fn init_abar_to_ar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    oabar: &OpenAnonAssetRecord,
    abar_keypair: &AXfrKeyPair,
    ar_pub_key: &XfrPublicKey,
) -> Result<AbarToArPreNote> {
    if oabar.mt_leaf_info.is_none() || abar_keypair.get_public_key() != oabar.pub_key {
        return Err(eg!(NoahError::ParameterError));
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
    let (oar, _, owner_memo) = build_open_asset_record(prng, &pc_gens, &art, vec![]);

    let mt_leaf_info = oabar.mt_leaf_info.as_ref().unwrap();
    let this_nullifier = nullify(
        &abar_keypair,
        oabar.amount,
        &oabar.asset_type,
        mt_leaf_info.uid,
    )?;

    let payers_secret = PayerWitness {
        secret_key: abar_keypair.get_secret_key(),
        uid: mt_leaf_info.uid,
        amount: oabar.amount,
        asset_type: oabar.asset_type.as_scalar(),
        path: mt_leaf_info.path.clone(),
        blind: oabar.blind,
    };

    let mt_info_temp = oabar.mt_leaf_info.as_ref().unwrap();

    let body = AbarToArBody {
        input: this_nullifier,
        output: oar.blind_asset_record.clone(),
        merkle_root: mt_info_temp.root,
        merkle_root_version: mt_info_temp.root_version,
        memo: owner_memo,
    };

    Ok(AbarToArPreNote {
        body,
        witness: payers_secret,
        input_keypair: abar_keypair.clone(),
    })
}

/// Finalize an anonymous-to-transparent note.
pub fn finish_abar_to_ar_note<R: CryptoRng + RngCore, D: Digest<OutputSize = U64> + Default>(
    prng: &mut R,
    params: &ProverParams,
    pre_note: AbarToArPreNote,
    hash: D,
) -> Result<AbarToArNote> {
    let AbarToArPreNote {
        body,
        witness,
        input_keypair,
    } = pre_note;

    let mut transcript = Transcript::new(ABAR_TO_AR_FOLDING_PROOF_TRANSCRIPT);
    let (folding_instance, folding_witness) = create_address_folding(
        prng,
        hash,
        &mut transcript,
        ANON_XFR_BP_GENS_LEN,
        &input_keypair,
    )?;

    let proof = prove_abar_to_ar(prng, params, witness, &folding_witness).c(d!())?;

    Ok(AbarToArNote {
        body,
        proof,
        folding_instance,
    })
}

/// Verify the anonymous-to-transparent note.
pub fn verify_abar_to_ar_note<D: Digest<OutputSize = U64> + Default>(
    params: &VerifierParams,
    note: &AbarToArNote,
    merkle_root: &BLSScalar,
    hash: D,
) -> Result<()> {
    // require the output amount & asset type are non-confidential
    if note.body.output.amount.is_confidential() || note.body.output.asset_type.is_confidential() {
        return Err(eg!(NoahError::ParameterError));
    }

    let mut transcript = Transcript::new(ABAR_TO_AR_FOLDING_PROOF_TRANSCRIPT);
    let (beta, lambda) = verify_address_folding(
        hash,
        &mut transcript,
        ANON_XFR_BP_GENS_LEN,
        &note.folding_instance,
    )?;

    let address_folding_public_input =
        prepare_verifier_input(&note.folding_instance, &beta, &lambda);

    let payer_amount = note.body.output.amount.get_amount().unwrap();
    let payer_asset_type = note.body.output.asset_type.get_asset_type().unwrap();

    if *merkle_root != note.body.merkle_root {
        return Err(eg!(NoahError::AXfrVerificationError));
    }

    let mut transcript = Transcript::new(ABAR_TO_AR_PLONK_PROOF_TRANSCRIPT);
    let mut online_inputs = vec![];
    online_inputs.push(note.body.input.clone());
    online_inputs.push(merkle_root.clone());
    online_inputs.push(BLSScalar::from(payer_amount));
    online_inputs.push(payer_asset_type.as_scalar());
    online_inputs.extend_from_slice(&address_folding_public_input);

    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        &note.proof,
    )
    .c(d!(NoahError::AXfrVerificationError))
}

/// Batch verify the anonymous-to-transparent notes.
/// Note: this function assumes that the correctness of the Merkle roots has been checked outside.
#[cfg(feature = "parallel")]
pub fn batch_verify_abar_to_ar_note<D: Digest<OutputSize = U64> + Default + Sync + Send>(
    params: &VerifierParams,
    notes: &[&AbarToArNote],
    merkle_roots: &[&BLSScalar],
    hashes: Vec<D>,
) -> Result<()> {
    // require the output amount & asset type are non-confidential
    if notes.par_iter().any(|note| {
        note.body.output.amount.is_confidential() || note.body.output.asset_type.is_confidential()
    }) {
        return Err(eg!(NoahError::ParameterError));
    }

    if merkle_roots
        .par_iter()
        .zip(notes)
        .any(|(x, y)| **x != y.body.merkle_root)
    {
        return Err(eg!(NoahError::AXfrVerificationError));
    }

    let is_ok = notes
        .par_iter()
        .zip(merkle_roots)
        .zip(hashes)
        .map(|((note, merkle_root), hash)| {
            let mut transcript = Transcript::new(ABAR_TO_AR_FOLDING_PROOF_TRANSCRIPT);
            let (beta, lambda) = verify_address_folding(
                hash,
                &mut transcript,
                ANON_XFR_BP_GENS_LEN,
                &note.folding_instance,
            )?;

            let address_folding_public_input =
                prepare_verifier_input(&note.folding_instance, &beta, &lambda);

            let payer_amount = note.body.output.amount.get_amount().unwrap();
            let payer_asset_type = note.body.output.asset_type.get_asset_type().unwrap();

            let mut transcript = Transcript::new(ABAR_TO_AR_PLONK_PROOF_TRANSCRIPT);
            let mut online_inputs = vec![];
            online_inputs.push(note.body.input.clone());
            online_inputs.push(*merkle_root.clone());
            online_inputs.push(BLSScalar::from(payer_amount));
            online_inputs.push(payer_asset_type.as_scalar());
            online_inputs.extend_from_slice(&address_folding_public_input);

            verifier(
                &mut transcript,
                &params.pcs,
                &params.cs,
                &params.verifier_params,
                &online_inputs,
                &note.proof,
            )
        })
        .all(|x| x.is_ok());

    if is_ok {
        Ok(())
    } else {
        Err(eg!(NoahError::AXfrVerificationError))
    }
}
fn prove_abar_to_ar<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    payers_witness: PayerWitness,
    folding_witness: &AXfrAddressFoldingWitness,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(ABAR_TO_AR_PLONK_PROOF_TRANSCRIPT);

    let (mut cs, _) = build_abar_to_ar_cs(payers_witness, &folding_witness);
    let witness = cs.get_and_clear_witness();

    prover_with_lagrange(
        rng,
        &mut transcript,
        &params.pcs,
        params.lagrange_pcs.as_ref(),
        &params.cs,
        &params.prover_params,
        &witness,
    )
    .c(d!(NoahError::AXfrProofError))
}

/// Construct the anonymous-to-transparent constraint system.
pub fn build_abar_to_ar_cs(
    payers_witness: PayerWitness,
    folding_witness: &AXfrAddressFoldingWitness,
) -> (TurboPlonkCS, usize) {
    let mut cs = TurboCS::new();
    let payers_witnesses_vars = add_payers_witnesses(&mut cs, &[payers_witness]);
    let payers_witness_vars = &payers_witnesses_vars[0];

    let keypair = folding_witness.keypair.clone();
    let public_key_scalars = keypair.get_public_key().get_public_key_scalars().unwrap();
    let secret_key_scalars = keypair.get_secret_key().get_secret_key_scalars().unwrap();

    let public_key_scalars_vars = [
        cs.new_variable(public_key_scalars[0]),
        cs.new_variable(public_key_scalars[1]),
        cs.new_variable(public_key_scalars[2]),
    ];
    let secret_key_scalars_vars = [
        cs.new_variable(secret_key_scalars[0]),
        cs.new_variable(secret_key_scalars[1]),
    ];

    let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::one());
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let zero_var = cs.zero_var();
    let mut root_var: Option<VarIndex> = None;

    // commitments
    let com_abar_in_var = commit_in_cs(
        &mut cs,
        payers_witness_vars.blind,
        payers_witness_vars.amount,
        payers_witness_vars.asset_type,
        &public_key_scalars_vars,
    );

    // prove pre-image of the nullifier
    // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`
    let uid_amount = cs.linear_combine(
        &[
            payers_witness_vars.uid,
            payers_witness_vars.amount,
            zero_var,
            zero_var,
        ],
        pow_2_64,
        one,
        zero,
        zero,
    );
    let nullifier_var = nullify_in_cs(
        &mut cs,
        &secret_key_scalars_vars,
        uid_amount,
        payers_witness_vars.asset_type,
        &public_key_scalars_vars,
    );

    // Merkle path authentication
    let acc_elem = AccElemVars {
        uid: payers_witness_vars.uid,
        commitment: com_abar_in_var,
    };
    let tmp_root_var = compute_merkle_root_variables(&mut cs, acc_elem, &payers_witness_vars.path);

    if let Some(root) = root_var {
        cs.equal(root, tmp_root_var);
    } else {
        root_var = Some(tmp_root_var);
    }

    // prepare public inputs variables
    cs.prepare_pi_variable(nullifier_var);
    cs.prepare_pi_variable(root_var.unwrap()); // safe unwrap

    cs.prepare_pi_variable(payers_witness_vars.amount);
    cs.prepare_pi_variable(payers_witness_vars.asset_type);

    prove_address_folding_in_cs(
        &mut cs,
        &public_key_scalars_vars,
        &secret_key_scalars_vars,
        &folding_witness,
    )
    .unwrap();

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}
