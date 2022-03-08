use rand_core::{CryptoRng, RngCore};
use crate::anon_xfr::{
    keys::{
        AXfrPubKey, AXfrKeyPair, AXfrSignature
    },
    structs::{AnonBlindAssetRecord, AXfrProof,OpenAnonBlindAssetRecord, Nullifier}
};
use ruc::*;
use algebra::bls12_381::BLSScalar;
use utils::errors::ZeiError;
use crate::setup::{NodeParams, UserParams};
use crate::xfr::structs::OwnerMemo;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AnonFeeNote {
    pub body: AnonFeeBody,
    pub signature: AXfrSignature,
}

impl AnonFeeNote {
    pub fn generate_note_from_body(body: AnonFeeBody, keypair: AXfrKeyPair) -> Result<AnonFeeNote> {
        let msg: Vec<u8> = bincode::serialize(&body)
            .map_err(|_| ZeiError::SerializationError)
            .c(d!())?;

        Ok(AnonFeeNote {
            body,
            signature: keypair.sign(msg.as_slice())
        })
    }

    pub fn verify_signatures(&self) -> Result<()> {
        let msg: Vec<u8> = bincode::serialize(&self.body)
            .map_err(|_| ZeiError::SerializationError)
            .c(d!())?;

        self.body.input.1.verify(msg.as_slice(), &self.signature).c(d!("AXfrNote signature verification failed"))?;

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
    input_keypairs: &[AXfrKeyPair],
) -> Result<(AnonFeeBody, AXfrKeyPair)> {



    Err(eg!(""))
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

    Ok(())
}