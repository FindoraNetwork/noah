use algebra::groups::{Group, Scalar, ScalarArithmetic};

use rand_chacha::rand_core::SeedableRng;
use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;

pub type SchnorrSecretKey<G: Group> = G::S;
pub type SchnorrPublicKey<G: Group> = G;
pub type SchnorrSignature<G: Group> = (G, <G>::S, <G>::S);

pub fn schnorr_gen_keys<R: CryptoRng + RngCore, G: Group>(
  prng: &mut R)
  -> (SchnorrSecretKey<G>, SchnorrPublicKey<G>) {
  // Private key
  let alpha = G::S::random(prng);

  // Public key
  let base = G::get_base();
  let u = base.mul(&alpha);

  (alpha, u)
}

pub fn schnorr_sign<B: AsRef<[u8]>, G: Group>(signing_key: &SchnorrSecretKey<G>,
                                              _message: &B)
                                              -> SchnorrSignature<G> {
  // TODO should the signature be deterministic or randomized?
  let seed = [0_u8; 32];
  let mut rng = rand_chacha::ChaChaRng::from_seed(seed);

  // Verifier challenge
  // TODO use merlin?
  let c = G::S::random(&mut rng);

  // TODO hash message inside commitment
  // Prover commitment
  let base = G::get_base();
  let alpha_t = G::S::random(&mut rng);
  let u_t = base.mul(&alpha_t);

  // Prover response
  let alpha_z = alpha_t.add(&c.mul(&signing_key));

  (u_t, c, alpha_z)
}

pub fn schnorr_verify<B: AsRef<[u8]>, G: Group>(pk: &SchnorrPublicKey<G>,
                                                msg: &B,
                                                sig: &SchnorrSignature<G>)
                                                -> Result<(), ZeiError> {
  let alpha_z = sig.2.clone();
  let u_t = sig.0.clone();
  let c = sig.1.clone();

  // TODO recompute the challenge !

  let base = G::get_base();
  let left = base.mul(&alpha_z);
  let right = u_t.add(&pk.mul(&c));

  if left == right {
    Ok(())
  } else {
    Err(ZeiError::ArgumentVerificationError)
  }
}

#[cfg(test)]
mod schnorr_sig {
  use crate::basics::signatures::schnorr::{schnorr_gen_keys, schnorr_sign, schnorr_verify};
  use algebra::groups::{Group, One};
  use algebra::jubjub::{JubjubGroup, JubjubScalar};
  use rand_chacha::rand_core::SeedableRng;
  use rand_chacha::ChaCha20Rng;

  #[test]
  fn check_schnorr() {
    let seed = [0_u8; 32];
    let mut prng = rand_chacha::ChaChaRng::from_seed(seed);

    let (private_key, public_key) = schnorr_gen_keys::<ChaCha20Rng, JubjubGroup>(&mut prng);

    let message = String::from("message");

    let sig = schnorr_sign::<String, JubjubGroup>(&private_key, &message);

    let res = schnorr_verify::<String, JubjubGroup>(&public_key, &message, &sig);
    assert!(res.is_ok());

    let wrong_sig = (JubjubGroup::get_base(), JubjubScalar::one(), JubjubScalar::one());
    let res = schnorr_verify::<String, JubjubGroup>(&public_key, &message, &wrong_sig);
    assert!(res.is_err());
  }

  #[test]
  fn schnorr_over_jubjub() {
    check_schnorr();
  }
}
