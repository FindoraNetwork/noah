use crate::anon_xfr::{
    commit, commit_in_cs,
    structs::{
        AnonAssetRecord, AxfrOwnerMemo, OpenAnonAssetRecordBuilder, PayeeWitness, PayeeWitnessVars,
    },
    AXfrPlonkPf, TurboPlonkCS,
};
use crate::keys::{KeyPair, PublicKey, PublicKeyInner, Signature};
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::structs::{BlindAssetRecord, OpenAssetRecord};
use merlin::Transcript;
use noah_algebra::{bls12_381::BLSScalar, errors::NoahError, prelude::*};
use noah_crypto::basic::anemoi_jive::{AnemoiJive381, AnemoiVLHTrace};
use noah_plonk::plonk::{
    constraint_system::TurboCS, prover::prover_with_lagrange, verifier::verifier,
};
#[cfg(feature = "parallel")]
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

/// The domain separator for transparent-to-anonymous, for the Plonk proof.
const AR_TO_ABAR_PLONK_PROOF_TRANSCRIPT: &[u8] = b"AR to ABAR Plonk Proof";

/// The transparent-to-anonymous note.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ArToAbarNote {
    /// The transparent-to-anonymous body.
    pub body: ArToAbarBody,
    /// Signature of the sender.
    pub signature: Signature,
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
    bar_keypair: &KeyPair,
    abar_pubkey: &PublicKey,
) -> Result<ArToAbarNote> {
    // generate body
    let body = gen_ar_to_abar_body(prng, params, record, &abar_pubkey).c(d!())?;

    let msg = bincode::serialize(&body)
        .map_err(|_| NoahError::SerializationError)
        .c(d!())?;
    let signature = bar_keypair.sign(&msg)?;

    let note = ArToAbarNote { body, signature };
    Ok(note)
}

/// Verify a transparent-to-anonymous note.
pub fn verify_ar_to_abar_note(params: &VerifierParams, note: &ArToAbarNote) -> Result<()> {
    let msg = bincode::serialize(&note.body).c(d!(NoahError::SerializationError))?;
    note.body
        .input
        .public_key
        .verify(&msg, &note.signature)
        .c(d!())?;

    verify_ar_to_abar_body(params, &note.body).c(d!())
}

/// Batch verify the transparent-to-anonymous notes.
#[cfg(feature = "parallel")]
pub fn batch_verify_ar_to_abar_note(
    params: &VerifierParams,
    notes: &[&ArToAbarNote],
) -> Result<()> {
    let is_ok = notes
        .par_iter()
        .map(|note| {
            let msg = bincode::serialize(&note.body).c(d!(NoahError::SerializationError))?;
            note.body
                .input
                .public_key
                .verify(&msg, &note.signature)
                .c(d!())?;

            verify_ar_to_abar_body(params, &note.body).c(d!())
        })
        .all(|x| x.is_ok());

    if is_ok {
        Ok(())
    } else {
        Err(eg!())
    }
}

/// Generate the transparent-to-anonymous body.
pub fn gen_ar_to_abar_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    obar: &OpenAssetRecord,
    abar_pubkey: &PublicKey,
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

    let (_, output_trace) = commit(
        &abar_pubkey,
        oabar.blind,
        oabar.amount,
        oabar.asset_type.as_scalar(),
    )
        .unwrap();

    let mut transcript = Transcript::new(AR_TO_ABAR_PLONK_PROOF_TRANSCRIPT);
    let (mut cs, _) = build_ar_to_abar_cs(payee_witness, &output_trace);
    let witness = cs.get_and_clear_witness();

    let (cs, prover_params) = params.cs_params(None);

    let proof = prover_with_lagrange(
        prng,
        &mut transcript,
        &params.pcs,
        params.lagrange_pcs.as_ref(),
        cs,
        prover_params,
        &witness,
    )
        .c(d!(NoahError::AXfrProofError))?;

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
        return Err(eg!(NoahError::ParameterError));
    }

    let amount = body.input.amount.get_amount().unwrap();
    let asset_type = body.input.asset_type.get_asset_type().unwrap();

    let mut transcript = Transcript::new(AR_TO_ABAR_PLONK_PROOF_TRANSCRIPT);
    let mut online_inputs: Vec<BLSScalar> = vec![];
    online_inputs.push(BLSScalar::from(amount));
    online_inputs.push(asset_type.as_scalar());
    online_inputs.push(body.output.commitment);

    let (cs, verifier_params) = params.cs_params(None);

    verifier(
        &mut transcript,
        &params.pcs,
        &cs,
        verifier_params,
        &online_inputs,
        &body.proof,
    )
        .c(d!(NoahError::AXfrVerificationError))
}

/// Construct the transparent-to-anonymous constraint system.
pub fn build_ar_to_abar_cs(
    payee_data: PayeeWitness,
    output_trace: &AnemoiVLHTrace<BLSScalar, 2, 12>,
) -> (TurboPlonkCS, usize) {
    let mut cs = TurboCS::new();
    cs.load_anemoi_jive_parameters::<AnemoiJive381>();

    let ar_amount_var = cs.new_variable(BLSScalar::from(payee_data.amount));
    cs.prepare_pi_variable(ar_amount_var);
    let ar_asset_var = cs.new_variable(payee_data.asset_type);
    cs.prepare_pi_variable(ar_asset_var);

    let blind = cs.new_variable(payee_data.blind);

    let public_key_scalars = payee_data.public_key.to_bls_scalars().unwrap();
    let public_key_scalars_vars = [
        cs.new_variable(public_key_scalars[0]),
        cs.new_variable(public_key_scalars[1]),
        cs.new_variable(public_key_scalars[2]),
    ];

    let public_key_type = match payee_data.public_key.0 {
        PublicKeyInner::Ed25519(_) => cs.new_variable(BLSScalar::one()),
        PublicKeyInner::Secp256k1(_) => cs.new_variable(BLSScalar::zero()),
        PublicKeyInner::EthAddress(_) => unimplemented!(),
    };
    cs.insert_boolean_gate(public_key_type);

    let payee = PayeeWitnessVars {
        amount: ar_amount_var,
        blind,
        asset_type: ar_asset_var,
        public_key_type,
        public_key_scalars: public_key_scalars_vars.clone(),
    };

    // commitment
    let com_abar_out_var = commit_in_cs(
        &mut cs,
        payee.blind,
        payee.amount,
        payee.asset_type,
        public_key_type,
        &public_key_scalars_vars,
        &output_trace,
    );

    // prepare the public input for the output commitment
    cs.prepare_pi_variable(com_abar_out_var);

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}
