use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;

pub mod bls;
pub mod pointcheval_sanders;
pub mod schnorr;

pub trait Signature {
  type PublicKey;
  type SecretKey;
  type Signature;
  fn gen_keys<R: CryptoRng + RngCore>(prng: &mut R) -> (Self::SecretKey, Self::PublicKey);
  fn sign<B: AsRef<[u8]>>(sk: &Self::SecretKey, msg: &B) -> Self::Signature;
  fn verify<B: AsRef<[u8]>>(pk: &Self::PublicKey,
                            sig: &Self::Signature,
                            msg: &B)
                            -> Result<(), ZeiError>;
}

pub trait AggSignature: Signature {
  type AggSignature;
  fn aggregate<B: AsRef<[u8]>>(pks: &[&Self::PublicKey],
                               sigs: &[&Self::Signature])
                               -> Self::AggSignature;
  fn verify_aggregate<B: AsRef<[u8]>>(pks: &[&Self::PublicKey],
                                      agg_sig: &Self::AggSignature,
                                      msg: &B)
                                      -> Result<(), ZeiError>;
}
