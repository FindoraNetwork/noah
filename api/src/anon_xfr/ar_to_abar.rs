use crate::anon_xfr::{
    circuits::{commit, PayeeSecret, PayeeSecretVars, TurboPlonkCS, AMOUNT_LEN},
    keys::AXfrPubKey,
    proofs::AXfrPlonkPf,
    structs::{
        AnonBlindAssetRecord, Commitment, OpenAnonBlindAssetRecord, OpenAnonBlindAssetRecordBuilder,
    },
};
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::{
    sig::{XfrKeyPair, XfrPublicKey, XfrSignature},
    structs::{AssetType, BlindAssetRecord, OpenAssetRecord, OwnerMemo},
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use zei_algebra::{bls12_381::BLSScalar, errors::ZeiError};
use zei_crypto::basic::hybrid_encryption::XPublicKey;
use zei_plonk::plonk::{
    constraint_system::TurboConstraintSystem, prover::prover_with_lagrange, verifier::verifier,
};

const AR_TO_ABAR_TRANSCRIPT: &[u8] = b"AR To ABAR proof";
pub const TWO_POW_32: u64 = 1 << 32;

#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ArToAbarBody {
    pub input: BlindAssetRecord,
    pub output: AnonBlindAssetRecord,
    pub proof: AXfrPlonkPf,
    pub memo: OwnerMemo,
}

#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ArToAbarNote {
    pub body: ArToAbarBody,
    pub signature: XfrSignature,
}

/// Generate BlindAssetRecord To AnonymousBlindAssetRecord conversion note: body + spending input signature
/// Returns conversion note and output AnonymousBlindAssetRecord opening keys
pub fn gen_ar_to_abar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    record: &OpenAssetRecord,
    bar_keypair: &XfrKeyPair,
    abar_pubkey: &AXfrPubKey,
    enc_key: &XPublicKey,
) -> Result<ArToAbarNote> {
    let body = gen_ar_to_abar_body(prng, params, record, &abar_pubkey, enc_key).c(d!())?;
    let msg = bincode::serialize(&body)
        .map_err(|_| ZeiError::SerializationError)
        .c(d!())?;
    let signature = bar_keypair.sign(&msg);
    let note = ArToAbarNote { body, signature };
    Ok(note)
}

pub fn verify_ar_to_abar_note(
    params: &VerifierParams,
    note: ArToAbarNote,
    bar_pub_key: &XfrPublicKey,
) -> Result<()> {
    // verify signature
    let msg = bincode::serialize(&note.body).c(d!(ZeiError::SerializationError))?;
    bar_pub_key.verify(&msg, &note.signature).c(d!())?;

    // verify body
    verify_ar_to_abar_body(params, note.body).c(d!())
}

/// Generate AR To Abar conversion note body
/// Returns note Body and ABAR opening keys
pub fn gen_ar_to_abar_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    record: &OpenAssetRecord,
    abar_pubkey: &AXfrPubKey,
    enc_key: &XPublicKey,
) -> Result<ArToAbarBody> {
    let (open_abar, proof) = ar_to_abar(prng, params, record, abar_pubkey, enc_key).c(d!())?;
    let body = ArToAbarBody {
        input: record.blind_asset_record.clone(),
        output: AnonBlindAssetRecord::from_oabar(&open_abar),
        proof,
        memo: open_abar.owner_memo.unwrap(),
    };
    Ok(body)
}

pub fn verify_ar_to_abar_body(params: &VerifierParams, body: ArToAbarBody) -> Result<()> {
    // check amount & asset type are non-confidential
    if body.input.amount.is_confidential() || body.input.asset_type.is_confidential() {
        return Err(eg!(ZeiError::ParameterError));
    }

    let amount = body.input.amount.get_amount().unwrap();
    let asset_type = body.input.asset_type.get_asset_type().unwrap();

    verify_ar_to_abar(
        params,
        amount,
        asset_type,
        body.output.commitment,
        &body.proof,
    )
    .c(d!("ArToAbar Body verification failed"))
}

pub(crate) fn ar_to_abar<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    obar: &OpenAssetRecord,
    abar_pubkey: &AXfrPubKey,
    enc_key: &XPublicKey,
) -> Result<(OpenAnonBlindAssetRecord, AXfrPlonkPf)> {
    let oabar_amount = obar.amount;

    // 1. Construct ABAR.
    let oabar = OpenAnonBlindAssetRecordBuilder::new()
        .amount(oabar_amount)
        .asset_type(obar.asset_type)
        .pub_key(*abar_pubkey)
        .finalize(prng, &enc_key)
        .c(d!())?
        .build()
        .c(d!())?;

    let payee_secret = PayeeSecret {
        amount: oabar.get_amount(),
        blind: oabar.blind.clone(),
        asset_type: oabar.asset_type.as_scalar(),
        pubkey_x: oabar.pub_key.0.point_ref().get_x(),
    };

    let proof = prove_ar_to_abar(prng, params, payee_secret).c(d!())?;
    Ok((oabar, proof))
}

///
///     Generate proof for ArToAbar body
///
fn prove_ar_to_abar<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    payee_secret: PayeeSecret,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(AR_TO_ABAR_TRANSCRIPT);
    let (mut cs, _) = build_ar_to_abar_cs(payee_secret);
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
    .c(d!(ZeiError::AXfrProofError))
}

fn verify_ar_to_abar(
    params: &VerifierParams,
    payer_amount: u64,
    payer_asset_type: AssetType,
    commitment: Commitment,
    proof: &AXfrPlonkPf,
) -> Result<()> {
    let mut transcript = Transcript::new(AR_TO_ABAR_TRANSCRIPT);
    let mut online_inputs: Vec<BLSScalar> = vec![];
    online_inputs.push(BLSScalar::from(payer_amount));
    online_inputs.push(payer_asset_type.as_scalar());
    online_inputs.push(commitment);

    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        proof,
    )
    .c(d!(ZeiError::ZKProofVerificationError))
}

///
///        Constraint System for abar_to_bar
///
pub fn build_ar_to_abar_cs(payee_data: PayeeSecret) -> (TurboPlonkCS, usize) {
    let mut cs = TurboConstraintSystem::new();

    let ar_amount_var = cs.new_variable(BLSScalar::from(payee_data.amount));
    cs.prepare_io_variable(ar_amount_var);
    let ar_asset_var = cs.new_variable(payee_data.asset_type);
    cs.prepare_io_variable(ar_asset_var);

    let amount = cs.new_variable(BLSScalar::from(payee_data.amount));
    let blind = cs.new_variable(payee_data.blind);
    let asset_type = cs.new_variable(payee_data.asset_type);
    let pubkey_x = cs.new_variable(payee_data.pubkey_x);
    let payee = PayeeSecretVars {
        amount,
        blind,
        asset_type,
        pubkey_x,
    };
    // commitment
    let com_abar_out_var = commit(
        &mut cs,
        payee.blind,
        payee.amount,
        payee.asset_type,
        payee.pubkey_x,
    );

    // Range check `amount`
    // Note we don't need to range-check payers' `amount`, because those amounts are bound
    // to payers' accumulated abars, whose underlying amounts have already been range-checked
    // in the transactions that created the payers' abars.
    cs.range_check(payee.amount, AMOUNT_LEN);

    // prepare the public input for the output commitment
    cs.prepare_io_variable(com_abar_out_var);

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}
