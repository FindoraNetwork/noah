use algebra::groups::{Group, Scalar, ScalarArithmetic};
use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;

use digest::Digest;
use sha2::Sha512;

pub struct SchnorrSecretKey<G: Group>(G::S);
pub struct SchnorrPublicKey<G: Group>(G);
pub struct SchnorrKeyPair<G: Group>(SchnorrSecretKey<G>, SchnorrPublicKey<G>);
pub struct SchnorrSignature<G: Group>((G, G::S));

// TODO from_bytes, to_bytes

// TODO use merlin?

pub fn schnorr_gen_keys<R: CryptoRng + RngCore, G: Group>(prng: &mut R) -> SchnorrKeyPair<G> {
  // Private key
  let alpha = G::S::random(prng);

  // Public key
  let base = G::get_base();
  let u = base.mul(&alpha);

  SchnorrKeyPair(SchnorrSecretKey(alpha), SchnorrPublicKey(u))
}

fn hash_commitment_and_message<G: Group, B: AsRef<[u8]>>(public_key: &SchnorrPublicKey<G>,
                                                         commitment: &G,
                                                         message: &B)
                                                         -> G::S {
  // TODO make hash function a parameter ?
  let mut hasher = Sha512::new();
  hasher.input(public_key.0.to_compressed_bytes());
  hasher.input(commitment.to_compressed_bytes());
  hasher.input(message);
  G::S::from_hash(hasher)
}

#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
pub fn schnorr_sign<R: CryptoRng + RngCore, B: AsRef<[u8]>, G: Group>(prng: &mut R,
                                                                      signing_key: &SchnorrKeyPair<G>,
                                                                      message: &B)
                                                                      -> SchnorrSignature<G> {
  let g = G::get_base();
  let r = G::S::random(prng);
  let R = g.mul(&r);

  let public_key = &signing_key.1;
  let c: G::S = hash_commitment_and_message::<G, B>(&public_key, &R, message);
  let private_key = &(signing_key.0).0;
  let s: G::S = r.add(&c.mul(private_key));

  // TODO use ::zeroize::Zeroize::zeroize(&mut u); How to test this?
  SchnorrSignature((R, s))
}

#[allow(non_snake_case)]
pub fn schnorr_verify<B: AsRef<[u8]>, G: Group>(pk: &SchnorrPublicKey<G>,
                                                msg: &B,
                                                sig: &SchnorrSignature<G>)
                                                -> Result<(), ZeiError> {
  let g = G::get_base();
  let (R, s) = &sig.0;

  let c = hash_commitment_and_message(&pk, &R, msg);
  let left = R.add(&pk.0.mul(&c));
  let right = g.mul(&s);

  if left == right {
    Ok(())
  } else {
    Err(ZeiError::ArgumentVerificationError)
  }
}

#[cfg(test)]
mod schnorr_sig {

  use crate::basics::signatures::schnorr::{
    schnorr_gen_keys, schnorr_sign, schnorr_verify, SchnorrKeyPair, SchnorrSignature,
  };
  use algebra::groups::{Group, GroupArithmetic, One};
  use algebra::jubjub::JubjubGroup;
  use algebra::ristretto::RistrettoPoint;
  use rand_chacha::rand_core::SeedableRng;
  use rand_chacha::ChaCha20Rng;

  fn check_schnorr<G: Group>() {
    let seed = [0_u8; 32];
    let mut prng = rand_chacha::ChaChaRng::from_seed(seed);

    let key_pair: SchnorrKeyPair<G> = schnorr_gen_keys::<ChaCha20Rng, G>(&mut prng);

    let message = String::from("message");

    let sig = schnorr_sign::<ChaCha20Rng, String, G>(&mut prng, &key_pair, &message);

    let public_key = key_pair.1;
    let res = schnorr_verify::<String, G>(&public_key, &message, &sig);
    assert!(res.is_ok());

    let wrong_sig =
      SchnorrSignature((<G as Group>::get_identity(), <G as GroupArithmetic>::S::one()));
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

  #[test]
  fn schnorr_over_ristretto() {
    check_schnorr::<RistrettoPoint>();
  }
}
