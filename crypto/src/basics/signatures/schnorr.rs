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
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use utils::errors::ZeiError;
use utils::serialization::ZeiFromToBytes;

const SCALAR_SIZE: usize = 32;

/// A random value part of the secret key, which purpose is to make the Schnorr signature computation
/// deterministic.
pub type SchnorrNonce = [u8; SCALAR_SIZE];

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrSecretKey<S> {
  pub(crate) key: S,
  pub(crate) nonce: SchnorrNonce,
}

impl<S: Scalar> SchnorrSecretKey<S> {
  pub fn new(key: S, nonce: SchnorrNonce) -> SchnorrSecretKey<S> {
    SchnorrSecretKey { key, nonce }
  }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrPublicKey<G>(G);

impl<G: Group> ZeiFromToBytes for SchnorrPublicKey<G> {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.0.to_compressed_bytes()
  }
  fn zei_from_bytes(bytes: &[u8]) -> Result<SchnorrPublicKey<G>, ZeiError> {
    let group_element = G::from_compressed_bytes(bytes);

    match group_element {
      Ok(g) => Ok(SchnorrPublicKey(g)),
      _ => Err(ZeiError::ParameterError),
    }
  }
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrKeyPair<G, S> {
  sec_key: SchnorrSecretKey<S>,
  pub_key: SchnorrPublicKey<G>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(non_snake_case)]
/// A Schnorr signature is composed by some group element R and some scalar s
pub struct SchnorrSignature<G: Group> {
  R: G,
  s: G::S,
}

/// Transcript functions
pub trait SchnorrTranscript {
  fn update_transcript_with_sig_info<B: AsRef<[u8]>, G: Group>(&mut self,
                                                               msg: &B,
                                                               pk: &SchnorrPublicKey<G>,
                                                               commitment: &G);

  fn compute_challenge<S: Scalar>(&mut self) -> S;
}

impl SchnorrTranscript for Transcript {
  fn update_transcript_with_sig_info<B: AsRef<[u8]>, G: Group>(&mut self,
                                                               msg: &B,
                                                               pk: &SchnorrPublicKey<G>,
                                                               commitment: &G) {
    self.append_message(b"message", msg.as_ref());
    self.append_message(b"public key", &pk.clone().zei_to_bytes());
    self.append_message(b"R", &commitment.to_compressed_bytes());
  }

  /// The challenge is computed from the transcript
  fn compute_challenge<S: Scalar>(&mut self) -> S {
    let mut c_bytes = [0_u8; SCALAR_SIZE];
    self.challenge_bytes(b"c", &mut c_bytes);
    let mut prg = ChaChaRng::from_seed(c_bytes);
    Scalar::random(&mut prg)
  }
}

#[allow(non_snake_case)]
impl<G: Group> ZeiFromToBytes for SchnorrSignature<G> {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v1 = self.R.to_compressed_bytes();
    let mut v2 = self.s.to_bytes();
    v1.append(&mut v2);
    v1
  }

  fn zei_from_bytes(bytes_repr: &[u8]) -> Result<SchnorrSignature<G>, ZeiError> {
    let R = G::from_compressed_bytes(&bytes_repr[..G::COMPRESSED_LEN]);
    if R.is_err() {
      return Err(ZeiError::ParameterError);
    }
    let R = R.unwrap(); // safe unwrap()
    let s = G::S::from_bytes(&bytes_repr[G::COMPRESSED_LEN..]);
    match s {
      Ok(s) => Ok(SchnorrSignature { R, s }),
      _ => Err(ZeiError::DeserializationError),
    }
  }
}

/// In this naive implementation a multi signature is a list
/// of  "simple" signatures.
pub struct SchnorrMultiSignature<G: Group>(Vec<SchnorrSignature<G>>);

/// Generates a key pair for the Schnorr signature scheme
/// * `prng` - pseudo-random generator
/// * `returns` - a key pair
pub fn schnorr_gen_keys<R: CryptoRng + RngCore, G: Group>(prng: &mut R) -> SchnorrKeyPair<G, G::S> {
  // Private key
  let alpha = G::S::random(prng);
  // Secret nonce:
  let mut nonce = [0u8; SCALAR_SIZE];
  prng.fill_bytes(&mut nonce);

  // Public key
  let base = G::get_base();
  let u = base.mul(&alpha);

  SchnorrKeyPair { sec_key: SchnorrSecretKey::new(alpha, nonce),
                   pub_key: SchnorrPublicKey(u) }
}

/// Deterministic computation of a scalar based on the secret nonce of the private key.
/// This is to avoid attacks due to bad implementation of prng involving the generation
/// of the commitment in the signature.
/// The scalar is computed as PRF(nonce,message) where PRF is the CRHF Sha512 following the
/// high level idea of RFC 6979 (https://tools.ietf.org/html/rfc6979#section-3.2)
/// Note that the transcript is not involved here as the verifier has no access to the
/// secret nonce.
/// * `message` - message to be signed. Needed to make the scalar unique
/// * `nonce` - nonce from the Schnorr secret key.
fn deterministic_scalar_gen<G: Group>(message: &[u8], nonce: &SchnorrNonce) -> G::S {
  let mut hasher = Sha512::new();

  hasher.input(message);
  hasher.input(nonce);

  G::S::from_hash(hasher)
}

#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
/// Computes a signature given a key pair and a message.
/// * `signing_key` - key pair. Having both public and private key makes the signature computation more efficient
/// * `message` - sequence of bytes to be signed
/// * `returns` - a Schnorr signature
pub fn schnorr_sign<B: AsRef<[u8]>, G: Group>(signing_key: &SchnorrKeyPair<G, G::S>,
                                              msg: &B)
                                              -> SchnorrSignature<G> {
  let mut transcript = Transcript::new(b"schnorr_sig");

  let g = G::get_base();
  let r = deterministic_scalar_gen::<G>(msg.as_ref(), &signing_key.sec_key.nonce);

  let R = g.mul(&r);
  let pk = &signing_key.pub_key;

  transcript.update_transcript_with_sig_info::<B, G>(msg, &pk, &R);

  let c = transcript.compute_challenge::<G::S>();

  let private_key = &(signing_key.sec_key).key;
  let s: G::S = r.add(&c.mul(private_key));

  SchnorrSignature { R, s }
}

/// Computes a signature with key pairs sk_1, sk_2,...,sk_n on a message m
/// * `signing_keys` - list of key pairs
/// * `message` - message to be signed
pub fn schnorr_multisig_sign<B: AsRef<[u8]>, G: Group>(signing_keys: &[SchnorrKeyPair<G,
                                                                        G::S>],
                                                       message: &B)
                                                       -> SchnorrMultiSignature<G> {
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

  let g = G::get_base();

  transcript.update_transcript_with_sig_info(msg, pk, &sig.R);

  let c = transcript.compute_challenge::<G::S>();

  let left = sig.R.add(&pk.0.mul(&c));
  let right = g.mul(&sig.s);

  if left == right {
    Ok(())
  } else {
    Err(ZeiError::ArgumentVerificationError)
  }
}

/// Verifies a multi-signature given a list of public keys and a message
/// * `public_keys` - list of public keys. Note that the order of the public keys must correspond
/// to the order of the signing keys used to produce the multi-signature
/// * `msg` - message
/// * `msig` - multi signature
/// * `returns` - Nothing if the verification succeeds, an error otherwise
pub fn schnorr_multisig_verify<B: AsRef<[u8]>, G: Group>(public_keys: &[SchnorrPublicKey<G>],
                                                         msg: &B,
                                                         msig: &SchnorrMultiSignature<G>)
                                                         -> Result<(), ZeiError> {
  if public_keys.len() != msig.0.len() || public_keys.is_empty() {
    return Err(ZeiError::ParameterError);
  }

  for (pk, sig) in public_keys.iter().zip(msig.0.clone()) {
    schnorr_verify(&pk, msg, &sig)?;
  }

  Ok(())
}

#[cfg(test)]
mod schnorr_sigs {

  mod schnorr_simple_sig {

    use crate::basics::signatures::schnorr::{
      schnorr_gen_keys, schnorr_sign, schnorr_verify, SchnorrKeyPair, SchnorrPublicKey,
      SchnorrSignature, SCALAR_SIZE,
    };
    use algebra::groups::{Group, GroupArithmetic, One};
    use algebra::jubjub::JubjubGroup;
    use algebra::ristretto::RistrettoPoint;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use utils::serialization::ZeiFromToBytes;

    fn check_schnorr<G: Group>() {
      let seed = [0_u8; SCALAR_SIZE];
      let mut prng = rand_chacha::ChaChaRng::from_seed(seed);

      let key_pair: SchnorrKeyPair<G, G::S> = schnorr_gen_keys::<ChaCha20Rng, G>(&mut prng);

      let message = String::from("message");

      let sig = schnorr_sign::<String, G>(&key_pair, &message);

      let public_key = key_pair.pub_key;
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

    #[test]
    fn schnorr_sig_over_ristretto() {
      check_schnorr::<RistrettoPoint>();
    }

    fn check_from_to_bytes<G: Group>() {
      let seed = [0_u8; SCALAR_SIZE];
      let mut prng = rand_chacha::ChaChaRng::from_seed(seed);
      let key_pair: SchnorrKeyPair<G, G::S> = schnorr_gen_keys::<ChaCha20Rng, G>(&mut prng);
      let message = String::from("message");
      let sig = schnorr_sign::<String, G>(&key_pair, &message);
      let public_key = key_pair.pub_key;

      // Public key
      let public_key_bytes = public_key.zei_to_bytes();
      let public_key_from_bytes = SchnorrPublicKey::zei_from_bytes(&public_key_bytes).unwrap();
      assert_eq!(public_key, public_key_from_bytes);

      // Signature
      let signature_bytes = sig.zei_to_bytes();
      let signature_from_bytes = SchnorrSignature::zei_from_bytes(&signature_bytes).unwrap();
      assert_eq!(sig, signature_from_bytes);
    }

    #[test]
    pub fn schnorr_from_to_bytes() {
      check_from_to_bytes::<JubjubGroup>();
    }

    #[test]
    pub fn ristretto_from_to_bytes() {
      check_from_to_bytes::<RistrettoPoint>();
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
    use algebra::ristretto::RistrettoPoint;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use utils::errors::ZeiError;

    fn check_schnorr_multisig<G: Group>() {
      let seed = [0_u8; SCALAR_SIZE];
      let mut prng = rand_chacha::ChaChaRng::from_seed(seed);

      const NUMBER_OF_KEYS: usize = 3;
      let mut key_pairs = vec![];
      let mut public_keys = vec![];
      for _ in 0..NUMBER_OF_KEYS {
        let key_pair: SchnorrKeyPair<G, G::S> = schnorr_gen_keys::<ChaCha20Rng, G>(&mut prng);
        let public_key = key_pair.pub_key.clone();
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
      assert_eq!(res, Err(ZeiError::ArgumentVerificationError));

      let too_short_multi_sig = SchnorrMultiSignature(msig.0.clone()[0..2].to_vec());
      let res = schnorr_multisig_verify::<String, G>(&public_keys, &message, &too_short_multi_sig);
      assert_eq!(res, Err(ZeiError::ParameterError));

      let empty_msig = SchnorrMultiSignature(vec![]);
      let empty_public_keys = vec![];
      let res = schnorr_multisig_verify::<String, G>(&empty_public_keys, &message, &empty_msig);
      assert_eq!(res, Err(ZeiError::ParameterError));
    }

    #[test]
    fn schnorr_multi_sig_over_jubjub() {
      check_schnorr_multisig::<JubjubGroup>();
    }

    #[test]
    fn schnorr_multi_sig_over_ristretto() {
      check_schnorr_multisig::<RistrettoPoint>();
    }
  }
}
