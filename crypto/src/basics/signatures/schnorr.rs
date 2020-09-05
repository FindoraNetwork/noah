use algebra::groups::{Group, Scalar, ScalarArithmetic};
use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;

use digest::Digest;
use sha2::Sha512;

pub struct SchnorrSecretKey<G: Group>(G::S);
pub struct SchnorrPublicKey<G: Group>(G);
pub struct SchnorrSignature<G: Group>((G::S, G::S));

// TODO serialization ?
pub fn schnorr_gen_keys<R: CryptoRng + RngCore, G: Group>(
  prng: &mut R)
  -> (SchnorrSecretKey<G>, SchnorrPublicKey<G>) {
  // Private key
  let alpha = G::S::random(prng);

  // Public key
  let base = G::get_base();
  let u = base.mul(&alpha);

  (SchnorrSecretKey(alpha), SchnorrPublicKey(u))
}

fn hash_commitment_and_message<G: Group, B: AsRef<[u8]>>(commitment: G, message: &B) -> G::S {
  // TODO make hash function a parameter
  let mut hasher = Sha512::new();
  hasher.input(message);
  hasher.input(commitment.to_compressed_bytes());
  G::S::from_hash(hasher)
}

#[allow(clippy::many_single_char_names)]
pub fn schnorr_sign<R: CryptoRng + RngCore, B: AsRef<[u8]>, G: Group>(prng: &mut R,
                                                                      signing_key: &SchnorrSecretKey<G>,
                                                                      message: &B)
                                                                      -> SchnorrSignature<G> {
  let g = G::get_base();
  let u = G::S::random(prng);
  let a = g.mul(&u);

  let c: G::S = hash_commitment_and_message::<G, B>(a, message);
  let r: G::S = u.add(&c.mul(&signing_key.0));

  // TODO use ::zeroize::Zeroize::zeroize(&mut u); How to test this?
  SchnorrSignature((c, r))
}

pub fn schnorr_verify<B: AsRef<[u8]>, G: Group>(pk: &SchnorrPublicKey<G>,
                                                msg: &B,
                                                sig: &SchnorrSignature<G>)
                                                -> Result<(), ZeiError> {
  let g = G::get_base();
  let (c, r) = sig.0;

  let point = g.mul(&r).add(&pk.0.mul(&c.neg()));

  let c_computed = hash_commitment_and_message(point, msg);

  if c == c_computed {
    Ok(())
  } else {
    Err(ZeiError::ArgumentVerificationError)
  }
}

#[cfg(test)]
mod schnorr_sig {

  use crate::basics::signatures::schnorr::{
    schnorr_gen_keys, schnorr_sign, schnorr_verify, SchnorrPublicKey, SchnorrSecretKey,
    SchnorrSignature,
  };
  use algebra::groups::{Group, GroupArithmetic, One};
  use algebra::jubjub::JubjubGroup;
  use rand_chacha::rand_core::SeedableRng;
  use rand_chacha::ChaCha20Rng;

  fn check_schnorr<G: Group>() {
    let seed = [0_u8; 32];
    let mut prng = rand_chacha::ChaChaRng::from_seed(seed);

    let (private_key, public_key): (SchnorrSecretKey<G>, SchnorrPublicKey<G>) =
      schnorr_gen_keys::<ChaCha20Rng, G>(&mut prng);

    let message = String::from("message");

    let sig = schnorr_sign::<ChaCha20Rng, String, G>(&mut prng, &private_key, &message);

    let res = schnorr_verify::<String, G>(&public_key, &message, &sig);
    assert!(res.is_ok());

    let wrong_sig =
      SchnorrSignature((<G as GroupArithmetic>::S::one(), <G as GroupArithmetic>::S::one()));
    let res = schnorr_verify::<String, G>(&public_key, &message, &wrong_sig);
    assert!(res.is_err());

    let wrong_message = String::from("wrong_message");
    let res = schnorr_verify::<String, G>(&public_key, &wrong_message, &sig);
    assert!(res.is_err());
  }

  #[test]
  fn schnorr_over_jubjub() {
    check_schnorr::<JubjubGroup>();
  }
}
