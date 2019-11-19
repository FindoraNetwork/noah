// BLS Signatures
use crate::algebra::bls12_381::BLSGt;
use crate::errors::ZeiError;
use rand::{CryptoRng, Rng};

pub type BlsSecretKey = crate::basic_crypto::signatures::bls::BlsSecretKey<BLSGt>;
pub type BlsPublicKey = crate::basic_crypto::signatures::bls::BlsPublicKey<BLSGt>;
pub type BlsSignature = crate::basic_crypto::signatures::bls::BlsSignature<BLSGt>;

/// bls key generation function
pub fn bls_gen_keys<R: CryptoRng + Rng>(prng: &mut R) -> (BlsSecretKey, BlsPublicKey) {
  crate::basic_crypto::signatures::bls::bls_gen_keys::<_, BLSGt>(prng)
}

/// bls signature function
pub fn bls_sign(signing_key: &BlsSecretKey, message: &[u8]) -> BlsSignature {
  crate::basic_crypto::signatures::bls::bls_sign::<BLSGt>(signing_key, message)
}

/// bls verification function
pub fn bls_verify(ver_key: &BlsPublicKey,
                  message: &[u8],
                  signature: &BlsSignature)
                  -> Result<(), ZeiError> {
  crate::basic_crypto::signatures::bls::bls_verify::<BLSGt>(ver_key, message, signature)
}

/// aggregate signature (for a single common message)
pub fn bls_aggregate(ver_keys: &[BlsPublicKey], signatures: &[BlsSignature]) -> BlsSignature {
  crate::basic_crypto::signatures::bls::bls_aggregate::<BLSGt>(ver_keys, signatures)
}

/// Verification of an aggregated signature for a common message
pub fn bls_verify_aggregated(ver_keys: &[BlsPublicKey],
                             message: &[u8],
                             agg_signature: &BlsSignature)
                             -> Result<(), ZeiError> {
  crate::basic_crypto::signatures::bls::bls_verify_aggregated::<BLSGt>(ver_keys, message, agg_signature)
}

/// Batch verification of many signatures
pub fn bls_batch_verify(ver_keys: &[BlsPublicKey],
                        messages: &[&[u8]],
                        signatures: &[BlsSignature])
                        -> Result<(), ZeiError> {
  crate::basic_crypto::signatures::bls::bls_batch_verify::<BLSGt>(ver_keys, messages, signatures)
}

/// signature aggregation for (possibly) different messages
pub fn bls_add_signatures(signatures: &[BlsSignature]) -> BlsSignature {
  crate::basic_crypto::signatures::bls::bls_add_signatures::<BLSGt>(signatures)
}

/// verification of an aggregated signatures for different messages
pub fn bls_batch_verify_added_signatures(ver_keys: &[BlsPublicKey],
                                         messages: &[&[u8]],
                                         signature: &BlsSignature)
                                         -> Result<(), ZeiError> {
  crate::basic_crypto::signatures::bls::bls_batch_verify_added_signatures::<BLSGt>(ver_keys, messages,
                                                                              signature)
}
