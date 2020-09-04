use crate::basics::signatures::SignatureTrait;
use algebra::groups::{Group, One, Scalar};
use std::marker::PhantomData;

use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;

pub struct Schnorr<G> {
  phantom_group: PhantomData<G>,
}

pub type SchnorrSecretKey<G: Group> = G::S;
pub type SchnorrPublicKey<G: Group> = G;
pub type SchnorrSignature<G: Group> = (G, <G>::S, <G>::S);

pub fn schnorr_gen_keys<G: Group, R: CryptoRng + RngCore>(
  prng: &mut R)
  -> (SchnorrSecretKey<G>, SchnorrPublicKey<G>) {
  let random_scalar = <G>::S::random(prng);
  let point = G::get_base().mul(&random_scalar);
  (random_scalar, point)
}

// TODO should the signature be deterministic or randomized?
pub fn schnorr_sign<B: AsRef<[u8]>, G: Group>(_signing_key: &SchnorrSecretKey<G>,
                                              _message: &B)
                                              -> SchnorrSignature<G> {
  (G::get_base(), <G>::S::one(), <G>::S::one())
}

pub fn schnorr_verify<B: AsRef<[u8]>, G: Group>(_pk: &SchnorrPublicKey<G>,
                                                _msg: &B,
                                                _sig: &SchnorrSignature<G>)
                                                -> Result<(), ZeiError> {
  Ok(())
}

impl<G> SignatureTrait for Schnorr<G> where G: Group
{
  type PublicKey = SchnorrPublicKey<G>;
  type SecretKey = SchnorrSecretKey<G>;
  type Signature = SchnorrSignature<G>;
  fn gen_keys<R: CryptoRng + RngCore>(prng: &mut R) -> (SchnorrSecretKey<G>, SchnorrPublicKey<G>) {
    schnorr_gen_keys(prng)
  }
  fn sign<B: AsRef<[u8]>>(sk: &Self::SecretKey, msg: &B) -> Self::Signature {
    schnorr_sign(sk, msg)
  }
  fn verify<B: AsRef<[u8]>>(pk: &Self::PublicKey,
                            sig: &Self::Signature,
                            msg: &B)
                            -> Result<(), ZeiError> {
    schnorr_verify(pk, msg, sig)
  }
}

#[cfg(test)]
mod schnorr_sig {
  #[test]
  fn schnorr_over_jubjub() {
    assert!(true);
  }
}
