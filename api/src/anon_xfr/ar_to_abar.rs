use crate::anon_xfr::{
    commit_in_cs,
    keys::AXfrPubKey,
    structs::{
        AnonAssetRecord, AxfrOwnerMemo, OpenAnonAssetRecordBuilder, PayeeWitness, PayeeWitnessVars,
    },
    AXfrPlonkPf, TurboPlonkCS,
};
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::{
    sig::{XfrKeyPair, XfrSignature},
    structs::{BlindAssetRecord, OpenAssetRecord},
};
use merlin::Transcript;
use zei_algebra::{bls12_381::BLSScalar, errors::ZeiError, prelude::*};
use zei_plonk::plonk::{
    constraint_system::TurboCS, prover::prover_with_lagrange, verifier::verifier,
};

/// The domain separator for transparent-to-anonymous, for the Plonk proof.
const AR_TO_ABAR_PLONK_PROOF_TRANSCRIPT: &[u8] = b"AR to ABAR Plonk Proof";

/// The transparent-to-anonymous note.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ArToAbarNote {
    /// The transparent-to-anonymous body.
    pub body: ArToAbarBody,
    /// Signature of the sender.
    pub signature: XfrSignature,
}

/// The transparent-to-anonymous body.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ArToAbarBody {
    /// The input transparent asset note, requiring both amounts and asset types to be transparent.
    pub input: BlindAssetRecord,
    /// The output anonymous asset record.
    pub output: AnonAssetRecord,
    /// The proof that the output matches the input.
    pub proof: AXfrPlonkPf,
    /// memo to hold the blinding factor of commitment
    pub memo: AxfrOwnerMemo,
}

/// Generate a transparent-to-anonymous note.
pub fn gen_ar_to_abar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    record: &OpenAssetRecord,
    bar_keypair: &XfrKeyPair,
    abar_pubkey: &AXfrPubKey,
) -> Result<ArToAbarNote> {
    // generate body
    let body = gen_ar_to_abar_body(prng, params, record, &abar_pubkey).c(d!())?;

    let msg = bincode::serialize(&body)
        .map_err(|_| ZeiError::SerializationError)
        .c(d!())?;
    let signature = bar_keypair.sign(&msg);

    let note = ArToAbarNote { body, signature };
    Ok(note)
}

/// Verify a transparent-to-anonymous note.
pub fn verify_ar_to_abar_note(params: &VerifierParams, note: &ArToAbarNote) -> Result<()> {
    let msg = bincode::serialize(&note.body).c(d!(ZeiError::SerializationError))?;
    note.body
        .input
        .public_key
        .verify(&msg, &note.signature)
        .c(d!())?;

    verify_ar_to_abar_body(params, &note.body).c(d!())
}

/// Generate the transparent-to-anonymous body.
pub fn gen_ar_to_abar_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    obar: &OpenAssetRecord,
    abar_pubkey: &AXfrPubKey,
) -> Result<ArToAbarBody> {
    let oabar_amount = obar.amount;

    // 1. Construct ABAR.
    let oabar = OpenAnonAssetRecordBuilder::new()
        .amount(oabar_amount)
        .asset_type(obar.asset_type)
        .pub_key(abar_pubkey)
        .finalize(prng)
        .c(d!())?
        .build()
        .c(d!())?;

    let payee_witness = PayeeWitness {
        amount: oabar.get_amount(),
        blind: oabar.blind.clone(),
        asset_type: oabar.asset_type.as_scalar(),
        public_key: abar_pubkey.clone(),
    };

    let mut transcript = Transcript::new(AR_TO_ABAR_PLONK_PROOF_TRANSCRIPT);
    let (mut cs, _) = build_ar_to_abar_cs(payee_witness);
    let witness = cs.get_and_clear_witness();

    let proof = prover_with_lagrange(
        prng,
        &mut transcript,
        &params.pcs,
        params.lagrange_pcs.as_ref(),
        &params.cs,
        &params.prover_params,
        &witness,
    )
    .c(d!(ZeiError::AXfrProofError))?;

    let body = ArToAbarBody {
        input: obar.blind_asset_record.clone(),
        output: AnonAssetRecord::from_oabar(&oabar),
        proof,
        memo: oabar.owner_memo.unwrap(),
    };
    Ok(body)
}

/// Verify the transparent-to-anonymous body.
pub fn verify_ar_to_abar_body(params: &VerifierParams, body: &ArToAbarBody) -> Result<()> {
    if body.input.amount.is_confidential() || body.input.asset_type.is_confidential() {
        return Err(eg!(ZeiError::ParameterError));
    }

    let amount = body.input.amount.get_amount().unwrap();
    let asset_type = body.input.asset_type.get_asset_type().unwrap();

    let mut transcript = Transcript::new(AR_TO_ABAR_PLONK_PROOF_TRANSCRIPT);
    let mut online_inputs: Vec<BLSScalar> = vec![];
    online_inputs.push(BLSScalar::from(amount));
    online_inputs.push(asset_type.as_scalar());
    online_inputs.push(body.output.commitment);

    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        &body.proof,
    )
    .c(d!(ZeiError::AXfrVerificationError))
}

/// Construct the transparent-to-anonymous constraint system.
pub fn build_ar_to_abar_cs(payee_data: PayeeWitness) -> (TurboPlonkCS, usize) {
    let mut cs = TurboCS::new();

    let ar_amount_var = cs.new_variable(BLSScalar::from(payee_data.amount));
    cs.prepare_pi_variable(ar_amount_var);
    let ar_asset_var = cs.new_variable(payee_data.asset_type);
    cs.prepare_pi_variable(ar_asset_var);

    let blind = cs.new_variable(payee_data.blind);

    let public_key_scalars = payee_data.public_key.get_public_key_scalars().unwrap();
    let public_key_scalars_vars = [
        cs.new_variable(public_key_scalars[0]),
        cs.new_variable(public_key_scalars[1]),
        cs.new_variable(public_key_scalars[2]),
    ];

    let payee = PayeeWitnessVars {
        amount: ar_amount_var,
        blind,
        asset_type: ar_asset_var,
        public_key_scalars: public_key_scalars_vars.clone(),
    };

    // commitment
    let com_abar_out_var = commit_in_cs(
        &mut cs,
        payee.blind,
        payee.amount,
        payee.asset_type,
        &public_key_scalars_vars,
    );

    // prepare the public input for the output commitment
    cs.prepare_pi_variable(com_abar_out_var);

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::xfr::{
        asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType},
        sig::XfrPublicKey,
        structs::{AssetRecordTemplate, AssetType, BlindAssetRecord, OwnerMemo},
    };
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use zei_crypto::basic::pedersen_comm::PedersenCommitmentRistretto;

    fn build_ar(
        pubkey: &XfrPublicKey,
        prng: &mut ChaChaRng,
        pc_gens: &PedersenCommitmentRistretto,
        amt: u64,
        asset_type: AssetType,
        ar_type: AssetRecordType,
    ) -> (BlindAssetRecord, Option<OwnerMemo>) {
        let ar = AssetRecordTemplate::with_no_asset_tracing(amt, asset_type, ar_type, *pubkey);
        let (bar, _, memo) = build_blind_asset_record(prng, &pc_gens, &ar, vec![]);
        (bar, memo)
    }

    #[test]
    fn test_ar_to_abar() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenCommitmentRistretto::default();

        let bar_keypair = XfrKeyPair::generate(&mut prng);
        let abar_keypair = AXfrKeyPair::generate(&mut prng);

        let params = ProverParams::ar_to_abar_params().unwrap();

        let (bar_conf, memo) = build_ar(
            &bar_keypair.pub_key,
            &mut prng,
            &pc_gens,
            10u64,
            AssetType::from_identical_byte(1u8),
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        );
        let obar = open_blind_asset_record(&bar_conf, &memo, &bar_keypair).unwrap();

        let note = gen_ar_to_abar_note(
            &mut prng,
            &params,
            &obar,
            &bar_keypair,
            &abar_keypair.get_public_key(),
        )
        .unwrap();

        let node_params = VerifierParams::ar_to_abar_params().unwrap();
        assert!(verify_ar_to_abar_note(&node_params, &note,).is_ok());
    }
}
