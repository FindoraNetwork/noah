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

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretKey<S>(S);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey<G>(G);

impl<G: Group> ZeiFromToBytes for PublicKey<G> {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.0.to_compressed_bytes()
  }
  fn zei_from_bytes(bytes: &[u8]) -> Result<PublicKey<G>, ZeiError> {
    let group_element = G::from_compressed_bytes(bytes);

    match group_element {
      Ok(g) => Ok(PublicKey(g)),
      _ => Err(ZeiError::ParameterError),
    }
  }
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyPair<G, S> {
  sec_key: SecretKey<S>,
  pub_key: PublicKey<G>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(non_snake_case)]
/// A Schnorr signature is composed by some group element R and some scalar s
pub struct Signature<G: Group> {
  R: G,
  s: G::S,
}

/// Transcript functions
pub trait SchnorrTranscript {
  fn update_transcript_with_sig_info<B: AsRef<[u8]>, G: Group>(&mut self,
                                                               msg: &B,
                                                               pk: &PublicKey<G>,
                                                               commitment: &G);

  fn compute_challenge<S: Scalar>(&mut self) -> S;
}

impl SchnorrTranscript for Transcript {
  fn update_transcript_with_sig_info<B: AsRef<[u8]>, G: Group>(&mut self,
                                                               msg: &B,
                                                               pk: &PublicKey<G>,
                                                               commitment: &G) {
    self.append_message(b"message", msg.as_ref());
    self.append_message(b"public key", &pk.zei_to_bytes());
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
impl<G: Group> ZeiFromToBytes for Signature<G> {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v1 = self.R.to_compressed_bytes();
    let mut v2 = self.s.to_bytes();
    v1.append(&mut v2);
    v1
  }

  fn zei_from_bytes(bytes_repr: &[u8]) -> Result<Signature<G>, ZeiError> {
    let R = G::from_compressed_bytes(&bytes_repr[..G::COMPRESSED_LEN]);
    if R.is_err() {
      return Err(ZeiError::ParameterError);
    }
    let R = R.unwrap(); // safe unwrap()
    let s = G::S::from_bytes(&bytes_repr[G::COMPRESSED_LEN..]);
    match s {
      Ok(s) => Ok(Signature { R, s }),
      _ => Err(ZeiError::DeserializationError),
    }
  }
}

/// In this naive implementation a multi signature is a list
/// of  "simple" signatures.
pub struct MultiSignature<G: Group>(Vec<Signature<G>>);

/// Generates a key pair for the Schnorr signature scheme
/// * `prng` - pseudo-random generator
/// * `returns` - a key pair
pub fn gen_keys<R: CryptoRng + RngCore, G: Group>(prng: &mut R) -> KeyPair<G, G::S> {
  // Private key
  let alpha = G::S::random(prng);

  // Public key
  let base = G::get_base();
  let u = base.mul(&alpha);

  KeyPair { sec_key: SecretKey(alpha),
            pub_key: PublicKey(u) }
}

/// Deterministic computation of a scalar based on the secret key and the message.
/// This is to avoid attacks due to bad implementation of prng involving the generation
/// of the commitment in the signature.
/// The scalar is computed as PRF(algorith_desc, nonce,message) where PRF is the CRHF Sha512 following the
/// high level idea of RFC 6979 (https://tools.ietf.org/html/rfc6979#section-3.2) and
/// algorith_desc is a constant string describing the algorithm involved.
/// This is to avoid attacks where the same private key is used with different
/// algorithms (ECDSA and Schnorr) for example.
/// Note that the transcript is not involved here as the verifier has no access to the
/// secret key.
/// * `message` - message to be signed. Needed to make the scalar unique
/// * `secret_key` - Schnorr secret key.
/// * `returns` - pseudo-random scalar
#[allow(non_snake_case)]
fn deterministic_scalar_gen<G: Group>(message: &[u8], secret_key: &SecretKey<G::S>) -> G::S {
  let mut hasher = Sha512::new();

  let ALGORITHM_DESC = b"ZeiSchnorrAlgorithm";

  hasher.input(ALGORITHM_DESC);
  hasher.input(message);
  hasher.input(&secret_key.0.to_bytes());

  G::S::from_hash(hasher)
}

#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
/// Computes a signature given a key pair and a message.
/// * `signing_key` - key pair. Having both public and private key makes the signature computation more efficient
/// * `message` - sequence of bytes to be signed
/// * `returns` - a Schnorr signature
pub fn sign<B: AsRef<[u8]>, G: Group>(signing_key: &KeyPair<G, G::S>, msg: &B) -> Signature<G> {
  let mut transcript = Transcript::new(b"schnorr_sig");

  let g = G::get_base();

  let r = deterministic_scalar_gen::<G>(msg.as_ref(), &signing_key.sec_key);

  let R = g.mul(&r);
  let pk = &signing_key.pub_key;

  transcript.update_transcript_with_sig_info::<B, G>(msg, &pk, &R);

  let c = transcript.compute_challenge::<G::S>();

  let private_key = &(signing_key.sec_key);
  let s: G::S = r.add(&c.mul(&private_key.0));

  Signature { R, s }
}

/// Computes a signature with key pairs sk_1, sk_2,...,sk_n on a message m
/// * `signing_keys` - list of key pairs
/// * `message` - message to be signed
pub fn multisig_sign<B: AsRef<[u8]>, G: Group>(signing_keys: &[KeyPair<G, G::S>],
                                               message: &B)
                                               -> MultiSignature<G> {
  let mut signatures = vec![];

  for signing_key in signing_keys {
    let sig = sign::<B, G>(&signing_key, &message);
    signatures.push(sig);
  }
  MultiSignature(signatures)
}

/// Verifies a Schnorr signature given a message, a public key
/// * `pk` -  public key
/// * `msg` - message
/// * `sig` - signature
/// * `returns` - Nothing if the verification succeeds, an error otherwise
#[allow(non_snake_case)]
pub fn verify<B: AsRef<[u8]>, G: Group>(pk: &PublicKey<G>,
                                        msg: &B,
                                        sig: &Signature<G>)
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
pub fn multisig_verify<B: AsRef<[u8]>, G: Group>(public_keys: &[PublicKey<G>],
                                                 msg: &B,
                                                 msig: &MultiSignature<G>)
                                                 -> Result<(), ZeiError> {
  if public_keys.len() != msig.0.len() || public_keys.is_empty() {
    return Err(ZeiError::ParameterError);
  }

  for (pk, sig) in public_keys.iter().zip(msig.0.clone()) {
    verify(&pk, msg, &sig)?;
  }

  Ok(())
}

#[cfg(test)]
mod schnorr_sigs {

  mod schnorr_simple_sig {

    use crate::basics::signatures::schnorr::{
      gen_keys, sign, verify, KeyPair, PublicKey, Signature, SCALAR_SIZE,
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

      let key_pair: KeyPair<G, G::S> = gen_keys::<ChaCha20Rng, G>(&mut prng);

      let message = String::from("message");

      let sig = sign::<String, G>(&key_pair, &message);

      let public_key = key_pair.pub_key;
      let res = verify::<String, G>(&public_key, &message, &sig);
      assert!(res.is_ok());

      let wrong_sig = Signature { R: <G as Group>::get_identity(),
                                  s: <G as GroupArithmetic>::S::one() };
      let res = verify::<String, G>(&public_key, &message, &wrong_sig);
      assert!(res.is_err());

      let wrong_message = String::from("wrong_message");
      let res = verify::<String, G>(&public_key, &wrong_message, &sig);
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
      let key_pair: KeyPair<G, G::S> = gen_keys::<ChaCha20Rng, G>(&mut prng);
      let message = String::from("message");
      let sig = sign::<String, G>(&key_pair, &message);
      let public_key = key_pair.pub_key;

      // Public key
      let public_key_bytes = public_key.zei_to_bytes();
      let public_key_from_bytes = PublicKey::zei_from_bytes(&public_key_bytes).unwrap();
      assert_eq!(public_key, public_key_from_bytes);

      // Signature
      let signature_bytes = sig.zei_to_bytes();
      let signature_from_bytes = Signature::zei_from_bytes(&signature_bytes).unwrap();
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
      gen_keys, multisig_sign, multisig_verify, KeyPair, MultiSignature, Signature, SCALAR_SIZE,
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
        let key_pair: KeyPair<G, G::S> = gen_keys::<ChaCha20Rng, G>(&mut prng);
        let public_key = key_pair.pub_key.clone();
        key_pairs.push(key_pair);
        public_keys.push(public_key);
      }

      let message = String::from("message");

      let msig = multisig_sign::<String, G>(&key_pairs, &message);

      let res = multisig_verify::<String, G>(&public_keys, &message, &msig);
      assert!(res.is_ok());

      let wrong_msig: MultiSignature<G> =
        MultiSignature(vec![
                         Signature { R: <G as Group>::get_identity(),
                                     s: <G as GroupArithmetic>::S::one() };
                         3
                       ]);
      let res = multisig_verify::<String, G>(&public_keys, &message, &wrong_msig);
      assert!(res.is_err());

      let wrong_message = String::from("wrong_message");
      let res = multisig_verify::<String, G>(&public_keys, &wrong_message, &msig);
      assert_eq!(res, Err(ZeiError::ArgumentVerificationError));

      let too_short_multi_sig = MultiSignature(msig.0.clone()[0..2].to_vec());
      let res = multisig_verify::<String, G>(&public_keys, &message, &too_short_multi_sig);
      assert_eq!(res, Err(ZeiError::ParameterError));

      let empty_msig = MultiSignature(vec![]);
      let empty_public_keys = vec![];
      let res = multisig_verify::<String, G>(&empty_public_keys, &message, &empty_msig);
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
