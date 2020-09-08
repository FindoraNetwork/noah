use algebra::groups::{Group, Scalar, ScalarArithmetic};
use digest::Digest;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::Sha512;
use utils::errors::ZeiError;

// TODO use ::zeroize::Zeroize where needed

pub type SchnorrNonce = [u8; 32];

pub struct SchnorrSecretKey<G: Group> {
  pub(crate) key: G::S,
  pub(crate) nonce: SchnorrNonce,
}

impl<G: Group> SchnorrSecretKey<G> {
  pub fn new(key: G::S, nonce: SchnorrNonce) -> SchnorrSecretKey<G> {
    SchnorrSecretKey { key, nonce }
  }
}

pub struct SchnorrPublicKey<G: Group>(G);
pub struct SchnorrKeyPair<G: Group>(SchnorrSecretKey<G>, SchnorrPublicKey<G>);
pub struct SchnorrSignature<G: Group>((G, G::S));

// TODO document

// TODO from_bytes, to_bytes

// TODO use merlin?

pub fn schnorr_gen_keys<R: CryptoRng + RngCore, G: Group>(prng: &mut R) -> SchnorrKeyPair<G> {
  // Private key
  let alpha = G::S::random(prng);
  // Secret nonce:
  let mut nonce = [0u8; 32];
  prng.fill_bytes(&mut nonce);

  // Public key
  let base = G::get_base();
  let u = base.mul(&alpha);

  SchnorrKeyPair(SchnorrSecretKey::new(alpha, nonce), SchnorrPublicKey(u))
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

//TODO check this below

/// Deterministic computation of a scalar based on the secret nonce of the private key.
/// This is to avoid attacks due to bad implementation of prng involving the generation
/// of the commitment in the signature.
/// See RFC 6979 https://www.hjp.at/doc/rfc/rfc6979.html
fn deterministic_scalar_gen<G: Group, R: CryptoRng + RngCore + SeedableRng<Seed = SchnorrNonce>>(
  secret_key: &SchnorrSecretKey<G>)
  -> G::S {
  let mut scalar_bytes = [0u8; 32];
  let mut seed = [0u8; 32];
  seed.copy_from_slice(&secret_key.nonce[..]);
  let mut prng = R::from_seed(seed);
  prng.fill_bytes(&mut scalar_bytes);

  G::S::from_bytes_safe(&scalar_bytes)
}

#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
pub fn schnorr_sign<R: CryptoRng + RngCore + SeedableRng<Seed = SchnorrNonce>,
                    B: AsRef<[u8]>,
                    G: Group>(
  signing_key: &SchnorrKeyPair<G>,
  message: &B)
  -> SchnorrSignature<G> {
  let g = G::get_base();
  let r = deterministic_scalar_gen::<G, R>(&signing_key.0);
  let R = g.mul(&r);

  let public_key = &signing_key.1;
  let c: G::S = hash_commitment_and_message::<G, B>(&public_key, &R, message);
  let private_key = &(signing_key.0).key;
  let s: G::S = r.add(&c.mul(private_key));

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
  use rand_chacha::rand_core::SeedableRng;
  use rand_chacha::ChaCha20Rng;

  fn check_schnorr<G: Group>() {
    let seed = [0_u8; 32];
    let mut prng = rand_chacha::ChaChaRng::from_seed(seed);

    let key_pair: SchnorrKeyPair<G> = schnorr_gen_keys::<ChaCha20Rng, G>(&mut prng);

    let message = String::from("message");

    let sig = schnorr_sign::<ChaCha20Rng, String, G>(&key_pair, &message);

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
}
