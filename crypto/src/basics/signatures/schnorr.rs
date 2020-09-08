use algebra::groups::{Group, Scalar, ScalarArithmetic};
use digest::Digest;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;
use utils::errors::ZeiError;

// TODO use ::zeroize::Zeroize where needed
// TODO remove magic number 32

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

#[derive(Clone)]
pub struct SchnorrPublicKey<G: Group>(G);

impl<G: Group> SchnorrPublicKey<G> {
  pub fn to_bytes(&self) -> Vec<u8> {
    self.0.to_compressed_bytes()
  }
}

pub struct SchnorrKeyPair<G: Group>(SchnorrSecretKey<G>, SchnorrPublicKey<G>);

#[derive(Clone)]
pub struct SchnorrSignature<G: Group>((G, G::S));

pub struct SchnorrMultiSignature<G: Group>(Vec<SchnorrSignature<G>>);

// TODO document

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

fn compute_challenge<G: Group>(t: &mut Transcript) -> G::S {
  const CHALLENGE_BYTES_LEN: usize = 32;
  let mut c_bytes = [0_u8; CHALLENGE_BYTES_LEN];
  t.challenge_bytes(b"c", &mut c_bytes);
  G::S::from_bytes_safe(&c_bytes)
}

//TODO check this below
/// Deterministic computation of a scalar based on the secret nonce of the private key.
/// This is to avoid attacks due to bad implementation of prng involving the generation
/// of the commitment in the signature.
/// See RFC 6979 https://www.hjp.at/doc/rfc/rfc6979.html
fn deterministic_scalar_gen<G: Group>(message: &[u8], secret_key: &SchnorrSecretKey<G>) -> G::S {
  // The seed is computed from the hash of the message and the secret nonce
  let mut hasher = Sha512::new();
  hasher.input(message);
  hasher.input(&secret_key.nonce);
  G::S::from_hash(hasher)
}

#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
pub fn schnorr_sign<B: AsRef<[u8]>, G: Group>(signing_key: &SchnorrKeyPair<G>,
                                              message: &B)
                                              -> SchnorrSignature<G> {
  // TODO handle errors
  let mut transcript = Transcript::new(b"schnorr_sig");

  // Note the message must be part of the transcript before computing other values, in particular the challenge `c`
  transcript.append_message(b"message", message.as_ref());

  let g = G::get_base();
  let r = deterministic_scalar_gen::<G>(message.as_ref(), &signing_key.0);

  let R = g.mul(&r);
  let public_key = &signing_key.1;

  transcript.append_message(b"public key", &public_key.to_bytes());
  transcript.append_message(b"R", &R.to_compressed_bytes());

  let c: G::S = compute_challenge::<G>(&mut transcript);

  let private_key = &(signing_key.0).key;
  let s: G::S = r.add(&c.mul(private_key));

  SchnorrSignature((R, s))
}

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

// TODO multisig => start with naive (but not insecure) implementation

#[allow(non_snake_case)]
pub fn schnorr_verify<B: AsRef<[u8]>, G: Group>(pk: &SchnorrPublicKey<G>,
                                                msg: &B,
                                                sig: &SchnorrSignature<G>)
                                                -> Result<(), ZeiError> {
  let mut transcript = Transcript::new(b"schnorr_sig");
  transcript.append_message(b"message", msg.as_ref());

  let g = G::get_base();
  let (R, s) = &sig.0;

  transcript.append_message(b"public key", &pk.clone().to_bytes());
  transcript.append_message(b"R", &R.to_compressed_bytes());

  // TODO check scalar see https://github.com/w3f/schnorrkel/blob/cfdbe9ae865a4d3ffa2566d896d4dbedf5107028/src/sign.rs#L66
  let c = compute_challenge::<G>(&mut transcript);

  let left = R.add(&pk.0.mul(&c));
  let right = g.mul(&s);

  if left == right {
    Ok(())
  } else {
    Err(ZeiError::ArgumentVerificationError)
  }
}

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

      let sig = schnorr_sign::<String, G>(&key_pair, &message);

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
    fn schnorr_sig_over_jubjub() {
      check_schnorr::<JubjubGroup>();
    }
  }

  #[cfg(test)]
  mod schnorr_multisig {

    use crate::basics::signatures::schnorr::{
      schnorr_gen_keys, schnorr_multisig_sign, schnorr_multisig_verify, SchnorrKeyPair,
      SchnorrMultiSignature, SchnorrSignature,
    };
    use algebra::groups::{Group, GroupArithmetic, One};

    use algebra::jubjub::JubjubGroup;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn check_schnorr_multisig<G: Group>() {
      let seed = [0_u8; 32];
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

      let wrong_msig: SchnorrMultiSignature<G> =
        SchnorrMultiSignature(vec![
                                SchnorrSignature((<G as Group>::get_identity(),
                                                  <G as GroupArithmetic>::S::one()));
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
