//! # Schnorr signature implementation
//!
//! This file implements a Schnorr (multi)-signature scheme.
//! Currently this scheme is deterministic and the multi-signature is implemented in a naive way:
//! a multi-signature is the list of simple Schnorr signatures.
//! In the future we might implement a more sophisticated scheme that produces short multi-signatures
//! See MuSig => https://eprint.iacr.org/2018/068.pdf and  MuSig-DN => https://eprint.iacr.org/2020/1057
//!
//! At a high level the scheme works as follows:
//! * `key_gen()` => sample a random scalar `x` and compute `X=g^x` where `g` is some group generator. Return return the key pair `(x,X)`
//! * `sign(m,sk)` => sample a random scalar `r` and compute `R=g^r`. Compute scalars `c=H(X,R,m)` and `s=r+cx`. Return `(R,s)`
//! * `verify(m,pk,sig)` => parse `sig` as `(R,s)`. Compute `c=H(X,R,m)`. Check that `R.X^c == g^s`.

use algebra::groups::{Group, Scalar, ScalarArithmetic};
use digest::Digest;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;
use utils::errors::ZeiError;

// TODO use ::zeroize::Zeroize where needed

const SCALAR_SIZE: usize = 32;

/// A random value part of the secret key, which purpose is to make the Schnorr signature computation
/// deterministic.
pub type SchnorrNonce = [u8; SCALAR_SIZE];

pub struct SchnorrSecretKey<G: Group> {
  pub(crate) key: G::S,
  pub(crate) nonce: SchnorrNonce,
}

impl<G: Group> SchnorrSecretKey<G> {
  pub fn new(key: G::S, nonce: SchnorrNonce) -> SchnorrSecretKey<G> {
    SchnorrSecretKey { key, nonce }
  }
}

#[derive(Clone)]
pub struct SchnorrPublicKey<G: Group>(G);

impl<G: Group> SchnorrPublicKey<G> {
  pub fn to_bytes(&self) -> Vec<u8> {
    self.0.to_compressed_bytes()
  }
}

pub struct SchnorrKeyPair<G: Group>(SchnorrSecretKey<G>, SchnorrPublicKey<G>);

#[derive(Clone)]
#[allow(non_snake_case)]
/// A Schnorr signature is composed by some group element R and some scalar s
pub struct SchnorrSignature<G: Group> {
  R: G,
  s: G::S,
}

/// In this naive implementation a multi signature is a list
/// of  "simple" signatures.
pub struct SchnorrMultiSignature<G: Group>(Vec<SchnorrSignature<G>>);

/// Generates a key pair for the Schnorr signature scheme
/// * `prng` - pseudo-random generator
/// * `returns` - a key pair
pub fn schnorr_gen_keys<R: CryptoRng + RngCore, G: Group>(prng: &mut R) -> SchnorrKeyPair<G> {
  // Private key
  let alpha = G::S::random(prng);
  // Secret nonce:
  let mut nonce = [0u8; SCALAR_SIZE];
  prng.fill_bytes(&mut nonce);

  // Public key
  let base = G::get_base();
  let u = base.mul(&alpha);

  SchnorrKeyPair(SchnorrSecretKey::new(alpha, nonce), SchnorrPublicKey(u))
}

/// The challenge is computed from the transcript
fn compute_challenge<G: Group>(t: &mut Transcript) -> G::S {
  let mut c_bytes = [0_u8; SCALAR_SIZE];
  t.challenge_bytes(b"c", &mut c_bytes);
  G::S::from_bytes_safe(&c_bytes)
}

/// Deterministic computation of a scalar based on the secret nonce of the private key.
/// This is to avoid attacks due to bad implementation of prng involving the generation
/// of the commitment in the signature.
/// Inspired from https://github.com/w3f/schnorrkel/blob/cfdbe9ae865a4d3ffa2566d896d4dbedf5107028/src/sign.rs#L179
/// Note that the transcript is not involved here as the verifier has no access to the
/// secret nonce.
/// * `message` - message to be signed. Needed to make the scalar unique
/// * `key_pair` - Schnorr key pair. In the Schnorrkel library the "signing context" contains the message as well as the public key.
fn deterministic_scalar_gen<G: Group>(message: &[u8], key_pair: &SchnorrKeyPair<G>) -> G::S {
  let mut hasher = Sha512::new();

  let pk = &key_pair.1; // TODO is this needed? It seems that hashing the message with the secret nonce is enough
  let secret_nonce = &key_pair.0.nonce;

  hasher.input(message);
  hasher.input(pk.to_bytes());
  hasher.input(secret_nonce);
  G::S::from_hash(hasher)
}

#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
/// Computes a signature given a key pair and a message
/// * `signing_key` - key pair. Having both public and private key makes the signature computation more efficient
/// * `message` - sequence of bytes to be signed
/// * `returns` - a Schnorr signature
pub fn schnorr_sign<B: AsRef<[u8]>, G: Group>(signing_key: &SchnorrKeyPair<G>,
                                              message: &B)
                                              -> SchnorrSignature<G> {
  // TODO handle errors
  let mut transcript = Transcript::new(b"schnorr_sig");

  // Note the message must be part of the transcript before computing other values, in particular the challenge `c`
  transcript.append_message(b"message", message.as_ref());

  let g = G::get_base();
  let r = deterministic_scalar_gen::<G>(message.as_ref(), &signing_key);

  let R = g.mul(&r);
  let public_key = &signing_key.1;

  transcript.append_message(b"public key", &public_key.to_bytes());
  transcript.append_message(b"R", &R.to_compressed_bytes());

  let c: G::S = compute_challenge::<G>(&mut transcript);

  let private_key = &(signing_key.0).key;
  let s: G::S = r.add(&c.mul(private_key));

  SchnorrSignature { R, s }
}

/// Computes a signature with key pairs sk_1, sk_2,...,sk_n on a message m
/// * `signing_keys` - list of key pairs
/// * `message` - message to be signed
pub fn schnorr_multisig_sign<B: AsRef<[u8]>, G: Group>(signing_keys: &[SchnorrKeyPair<G>],
                                                       message: &B)
                                                       -> SchnorrMultiSignature<G> {
  // TODO handle errors?
  let mut signatures = vec![];

  for signing_key in signing_keys {
    let sig = schnorr_sign::<B, G>(&signing_key, &message);
    signatures.push(sig);
  }
  SchnorrMultiSignature(signatures)
}

/// Verifies a Schnorr signature given a message, a public key
/// * `pk` -  public key
/// * `msg` - message
/// * `sig` - signature
/// * `returns` - Nothing if the verification succeeds, an error otherwise
#[allow(non_snake_case)]
pub fn schnorr_verify<B: AsRef<[u8]>, G: Group>(pk: &SchnorrPublicKey<G>,
                                                msg: &B,
                                                sig: &SchnorrSignature<G>)
                                                -> Result<(), ZeiError> {
  let mut transcript = Transcript::new(b"schnorr_sig");
  transcript.append_message(b"message", msg.as_ref());

  let g = G::get_base();

  transcript.append_message(b"public key", &pk.clone().to_bytes());
  transcript.append_message(b"R", &sig.R.to_compressed_bytes());

  // TODO check scalar see https://github.com/w3f/schnorrkel/blob/cfdbe9ae865a4d3ffa2566d896d4dbedf5107028/src/sign.rs#L66
  let c = compute_challenge::<G>(&mut transcript);

  let left = sig.R.add(&pk.0.mul(&c));
  let right = g.mul(&sig.s);

  if left == right {
    Ok(())
  } else {
    Err(ZeiError::ArgumentVerificationError)
  }
}

/// Verifies a multi-signature given a list of public keys and a message
/// * `public_keys` - list of public keys. Note that the order of the public keys must correspond to the order of the signing keys used to produce the multi-signature
/// * `msg` - message
/// * `msig` - multi signature
/// * `returns` - Nothing if the verification succeeds, an error otherwise
pub fn schnorr_multisig_verify<B: AsRef<[u8]>, G: Group>(public_keys: &[SchnorrPublicKey<G>],
                                                         msg: &B,
                                                         msig: &SchnorrMultiSignature<G>)
                                                         -> Result<(), ZeiError> {
  for (pk, sig) in public_keys.iter().zip(msig.0.clone()) {
    schnorr_verify(&pk, msg, &sig)?;
  }

  Ok(())
}

#[cfg(test)]
mod schnorr_sigs {

  mod schnorr_simple_sig {

    use crate::basics::signatures::schnorr::{
      schnorr_gen_keys, schnorr_sign, schnorr_verify, SchnorrKeyPair, SchnorrSignature, SCALAR_SIZE,
    };
    use algebra::groups::{Group, GroupArithmetic, One};
    use algebra::jubjub::JubjubGroup;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn check_schnorr<G: Group>() {
      let seed = [0_u8; SCALAR_SIZE];
      let mut prng = rand_chacha::ChaChaRng::from_seed(seed);

      let key_pair: SchnorrKeyPair<G> = schnorr_gen_keys::<ChaCha20Rng, G>(&mut prng);

      let message = String::from("message");

      let sig = schnorr_sign::<String, G>(&key_pair, &message);

      let public_key = key_pair.1;
      let res = schnorr_verify::<String, G>(&public_key, &message, &sig);
      assert!(res.is_ok());

      let wrong_sig = SchnorrSignature { R: <G as Group>::get_identity(),
                                         s: <G as GroupArithmetic>::S::one() };
      let res = schnorr_verify::<String, G>(&public_key, &message, &wrong_sig);
      assert!(res.is_err());

      let wrong_message = String::from("wrong_message");
      let res = schnorr_verify::<String, G>(&public_key, &wrong_message, &sig);
      assert!(res.is_err());
    }

    #[test]
    fn schnorr_sig_over_jubjub() {
      check_schnorr::<JubjubGroup>();
    }
  }

  #[cfg(test)]
  mod schnorr_multisig {

    use crate::basics::signatures::schnorr::{
      schnorr_gen_keys, schnorr_multisig_sign, schnorr_multisig_verify, SchnorrKeyPair,
      SchnorrMultiSignature, SchnorrSignature, SCALAR_SIZE,
    };
    use algebra::groups::{Group, GroupArithmetic, One};

    use algebra::jubjub::JubjubGroup;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn check_schnorr_multisig<G: Group>() {
      let seed = [0_u8; SCALAR_SIZE];
      let mut prng = rand_chacha::ChaChaRng::from_seed(seed);

      const NUMBER_OF_KEYS: usize = 3;
      let mut key_pairs = vec![];
      let mut public_keys = vec![];
      for _i in 0..NUMBER_OF_KEYS {
        let key_pair: SchnorrKeyPair<G> = schnorr_gen_keys::<ChaCha20Rng, G>(&mut prng);
        let public_key = key_pair.1.clone();
        key_pairs.push(key_pair);
        public_keys.push(public_key);
      }

      let message = String::from("message");

      let msig = schnorr_multisig_sign::<String, G>(&key_pairs, &message);

      let res = schnorr_multisig_verify::<String, G>(&public_keys, &message, &msig);
      assert!(res.is_ok());

      let wrong_msig: SchnorrMultiSignature<G> = SchnorrMultiSignature(vec![
                                SchnorrSignature{ R: <G as Group>::get_identity(),
                                                  s: <G as GroupArithmetic>::S::one()};
                                3
                              ]);
      let res = schnorr_multisig_verify::<String, G>(&public_keys, &message, &wrong_msig);
      assert!(res.is_err());

      let wrong_message = String::from("wrong_message");
      let res = schnorr_multisig_verify::<String, G>(&public_keys, &wrong_message, &msig);
      assert!(res.is_err());
    }

    #[test]
    fn schnorr_multi_sig_over_jubjub() {
      check_schnorr_multisig::<JubjubGroup>();
    }
  }
}
