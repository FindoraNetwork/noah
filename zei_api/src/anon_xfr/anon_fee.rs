use crate::anon_xfr::circuits::{
    AMultiXfrPubInputs, AMultiXfrWitness, PayeeSecret, PayerSecret,
};
use crate::anon_xfr::proofs::{prove_xfr, verify_xfr};
use crate::anon_xfr::{
    check_asset_amount, check_roots,
    keys::{AXfrKeyPair, AXfrPubKey, AXfrSignature},
    nullifier,
    structs::{AXfrProof, AnonBlindAssetRecord, Nullifier, OpenAnonBlindAssetRecord},
};
use crate::setup::{NodeParams, UserParams};
use crate::xfr::structs::OwnerMemo;
use algebra::bls12_381::BLSScalar;
use algebra::groups::Scalar;
use algebra::jubjub::JubjubScalar;
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use std::borrow::Borrow;
use utils::errors::ZeiError;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AnonFeeNote {
    pub body: AnonFeeBody,
    pub signature: AXfrSignature,
}

impl AnonFeeNote {
    pub fn generate_note_from_body(
        body: AnonFeeBody,
        keypair: AXfrKeyPair,
    ) -> Result<AnonFeeNote> {
        let msg: Vec<u8> = bincode::serialize(&body)
            .map_err(|_| ZeiError::SerializationError)
            .c(d!())?;

        Ok(AnonFeeNote {
            body,
            signature: keypair.sign(msg.as_slice()),
        })
    }

    pub fn verify_signatures(&self) -> Result<()> {
        let msg: Vec<u8> = bincode::serialize(&self.body)
            .map_err(|_| ZeiError::SerializationError)
            .c(d!())?;

        self.body
            .input
            .1
            .verify(msg.as_slice(), &self.signature)
            .c(d!("AXfrNote signature verification failed"))?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AnonFeeBody {
    pub input: (Nullifier, AXfrPubKey),
    pub output: AnonBlindAssetRecord,
    pub proof: AXfrProof,
    pub owner_memo: OwnerMemo,
}

/// Build an anonymous fee structure AnonFeeBody. It also returns randomized signature keys to sign the transfer,
/// * `rng` - pseudo-random generator.
/// * `params` - User parameters
/// * `input` - Open source asset records
/// * `output` - Description of output asset records.
#[allow(unused_variables)]
pub fn gen_anon_fee_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    input: &OpenAnonBlindAssetRecord,
    output: &OpenAnonBlindAssetRecord,
    input_keypair: &AXfrKeyPair,
) -> Result<(AnonFeeBody, AXfrKeyPair)> {
    if input.pub_key.ne(input_keypair.pub_key().borrow()) {
        return Err(eg!(ZeiError::ParameterError));
    }
    check_asset_amount(vec![input.clone()].as_slice(), vec![output.clone()].as_slice()).c(d!())?;
    check_roots(vec![input.clone()].as_slice()).c(d!())?;

    let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();
    let rand_input_keypair = input_keypair.randomize(&input.key_rand_factor);
    let diversifier = JubjubScalar::random(prng);
    let nullifier_and_signing_key = (
        nullifier(
            &rand_input_keypair,
            input.amount,
            &input.asset_type,
            mt_leaf_info.uid,
        ),
        rand_input_keypair.pub_key().randomize(&diversifier),
    );

    let payers_secret = PayerSecret {
        sec_key: rand_input_keypair.get_secret_scalar(),
        diversifier,
        uid: mt_leaf_info.uid,
        amount: input.amount,
        asset_type: input.asset_type.as_scalar(),
        path: mt_leaf_info.path.clone(),
        blind: input.blind,
    };
    let payees_secrets = PayeeSecret {
        amount: output.amount,
        blind: output.blind,
        asset_type: output.asset_type.as_scalar(),
    };

    let secret_inputs = AMultiXfrWitness {
        payers_secrets: vec![payers_secret],
        payees_secrets: vec![payees_secrets],
    };
    let proof = prove_xfr(prng, params, secret_inputs).c(d!())?;

    Ok((
        AnonFeeBody {
            input: nullifier_and_signing_key,
            output: AnonBlindAssetRecord::from_oabar(output),
            proof: AXfrProof {
                snark_proof: proof,
                merkle_root: mt_leaf_info.root,
                merkle_root_version: mt_leaf_info.root_version,
            },
            owner_memo: output
                .owner_memo
                .clone()
                .c(d!(ZeiError::ParameterError))
                .c(d!())?,
        },
        rand_input_keypair.randomize(&diversifier),
    ))
}

/// Verifies an anonymous transfer structure AXfrBody.
/// * `params` - Verifier parameters
/// * `body` - Transfer structure to verify
/// * `accumulator` - candidate state of the accumulator. It must match body.proof.merkle_root, otherwise it returns ZeiError::AXfrVerification Error.
#[allow(unused_variables)]
pub fn verify_anon_xfr_body(
    params: &NodeParams,
    body: &AnonFeeBody,
    merkle_root: &BLSScalar,
) -> Result<()> {
    if *merkle_root != body.proof.merkle_root {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }

    let pub_inputs = AMultiXfrPubInputs {
        payers_inputs: vec![body.input.clone()],
        payees_commitments: vec![body.output.amount_type_commitment],
        merkle_root: *merkle_root,
    };

    verify_xfr(params, &pub_inputs, &body.proof.snark_proof)
        .c(d!(ZeiError::AXfrVerificationError))
}
