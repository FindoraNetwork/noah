// BLS Signatures
use algebra::bls12_381::BLSPairingEngine;
use crypto::basics::signatures::{AggSignature, Signature};
use rand_core::{CryptoRng, RngCore};
use ruc::*;

pub type BlsSecretKey = crypto::basics::signatures::bls::BlsSecretKey<BLSPairingEngine>;
pub type BlsPublicKey = crypto::basics::signatures::bls::BlsPublicKey<BLSPairingEngine>;
pub type BlsSignature = crypto::basics::signatures::bls::BlsSignature<BLSPairingEngine>;

/// bls key generation function
pub fn bls_gen_keys<R: CryptoRng + RngCore>(prng: &mut R) -> (BlsSecretKey, BlsPublicKey) {
    crypto::basics::signatures::bls::bls_gen_keys::<_, BLSPairingEngine>(prng)
}

/// bls signature function
pub fn bls_sign<B: AsRef<[u8]>>(signing_key: &BlsSecretKey, message: &B) -> BlsSignature {
    crypto::basics::signatures::bls::bls_sign::<BLSPairingEngine, B>(signing_key, message)
}

/// bls verification function
pub fn bls_verify<B: AsRef<[u8]>>(
    ver_key: &BlsPublicKey,
    message: &B,
    signature: &BlsSignature,
) -> Result<()> {
    crypto::basics::signatures::bls::bls_verify::<BLSPairingEngine, B>(ver_key, message, signature)
        .c(d!())
}

/// aggregate signature (for a single common message)
pub fn bls_aggregate(ver_keys: &[&BlsPublicKey], signatures: &[&BlsSignature]) -> BlsSignature {
    crypto::basics::signatures::bls::bls_aggregate::<BLSPairingEngine>(ver_keys, signatures)
}

/// Verification of an aggregated signature for a common message
pub fn bls_verify_aggregated<B: AsRef<[u8]>>(
    ver_keys: &[&BlsPublicKey],
    message: &B,
    agg_signature: &BlsSignature,
) -> Result<()> {
    crypto::basics::signatures::bls::bls_verify_aggregated::<BLSPairingEngine, B>(
        ver_keys,
        message,
        agg_signature,
    )
    .c(d!())
}

/// Batch verification of many signatures
pub fn bls_batch_verify<B: AsRef<[u8]>>(
    ver_keys: &[BlsPublicKey],
    messages: &[B],
    signatures: &[BlsSignature],
) -> Result<()> {
    crypto::basics::signatures::bls::bls_batch_verify::<BLSPairingEngine, B>(
        ver_keys, messages, signatures,
    )
    .c(d!())
}

/// signature aggregation for (possibly) different messages
pub fn bls_add_signatures(signatures: &[BlsSignature]) -> BlsSignature {
    crypto::basics::signatures::bls::bls_add_signatures::<BLSPairingEngine>(signatures)
}

/// verification of an aggregated signatures for different messages
pub fn bls_batch_verify_added_signatures<B: AsRef<[u8]>>(
    ver_keys: &[BlsPublicKey],
    messages: &[B],
    signature: &BlsSignature,
) -> Result<()> {
    crypto::basics::signatures::bls::bls_batch_verify_added_signatures::<BLSPairingEngine, B>(
        ver_keys, messages, signature,
    )
    .c(d!())
}

pub struct Bls;

impl Signature for Bls {
    type PublicKey = BlsPublicKey;
    type SecretKey = BlsSecretKey;
    type Signature = BlsSignature;
    fn gen_keys<R: CryptoRng + RngCore>(prng: &mut R) -> (BlsSecretKey, BlsPublicKey) {
        bls_gen_keys(prng)
    }
    fn sign<B: AsRef<[u8]>>(sk: &Self::SecretKey, msg: &B) -> Self::Signature {
        bls_sign(sk, msg)
    }
    fn verify<B: AsRef<[u8]>>(pk: &Self::PublicKey, sig: &Self::Signature, msg: &B) -> Result<()> {
        bls_verify(pk, msg, sig).c(d!())
    }
}

impl AggSignature for Bls {
    type AggSignature = BlsSignature;
    fn aggregate<B: AsRef<[u8]>>(
        pks: &[&Self::PublicKey],
        sigs: &[&Self::Signature],
    ) -> Self::AggSignature {
        bls_aggregate(pks, sigs)
    }
    fn verify_aggregate<B: AsRef<[u8]>>(
        pks: &[&Self::PublicKey],
        agg_sig: &Self::AggSignature,
        msg: &B,
    ) -> Result<()> {
        bls_verify_aggregated(pks, msg, agg_sig).c(d!())
    }
}
