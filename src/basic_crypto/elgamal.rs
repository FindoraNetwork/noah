use crate::algebra::groups::{Group, Scalar};
use crate::errors::ZeiError;
use crate::serialization::ZeiFromToBytes;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand_core::{CryptoRng, RngCore};
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalEncKey<G>(pub G); //PK = sk*G

impl<G: Clone> ElGamalEncKey<G> {
  pub fn get_point(&self) -> G {
    self.0.clone()
  }
  pub fn get_point_ref(&self) -> &G {
    &self.0
  }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalDecKey<S>(pub(crate) S); //sk

pub fn elgamal_key_gen<R: CryptoRng + RngCore, S: Scalar, G: Group<S>>(
  prng: &mut R,
  base: &G)
  -> (ElGamalDecKey<S>, ElGamalEncKey<G>) {
  let secret_key = ElGamalDecKey(S::random_scalar(prng));
  let public_key = ElGamalEncKey(base.mul(&secret_key.0));
  (secret_key, public_key)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalCiphertext<G> {
  pub(crate) e1: G, //r*G
  pub(crate) e2: G, //m*G + r*PK
}

impl Hash for ElGamalEncKey<RistrettoPoint> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.0.to_compressed_bytes().as_slice().hash(state);
  }
}

impl ZeiFromToBytes for ElGamalCiphertext<RistrettoPoint> {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(self.e1.to_compressed_bytes().as_slice());
    v.extend_from_slice(self.e2.to_compressed_bytes().as_slice());
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> Self {
    ElGamalCiphertext{
            e1: RistrettoPoint::from_compressed_bytes(&bytes[0..RistrettoPoint::COMPRESSED_LEN]).unwrap(),
            e2: RistrettoPoint::from_compressed_bytes(&bytes[RistrettoPoint::COMPRESSED_LEN..]).unwrap(),
        }
  }
}

/// I return an ElGamal ciphertext pair as (r*G, m*g + r*PK), where G is a curve base point
pub fn elgamal_encrypt<S: Scalar, G: Group<S>>(base: &G,
                                               m: &S,
                                               r: &S,
                                               pub_key: &ElGamalEncKey<G>)
                                               -> ElGamalCiphertext<G> {
  let e1 = base.mul(r);
  let e2 = base.mul(m).add(&(pub_key.0).mul(r));

  ElGamalCiphertext::<G> { e1, e2 }
}

/// I verify that ctext encrypts m (ctext.e2 - ctext.e1 * sk = m* G)
pub fn elgamal_verify<S: Scalar, G: Group<S>>(base: &G,
                                              m: &S,
                                              ctext: &ElGamalCiphertext<G>,
                                              sec_key: &ElGamalDecKey<S>)
                                              -> Result<(), ZeiError> {
  if base.mul(m).add(&ctext.e1.mul(&sec_key.0)) == ctext.e2 {
    Ok(())
  } else {
    Err(ZeiError::ElGamalVerificationError)
  }
}

/// ElGamal decryption: Return group element
pub fn elgamal_decrypt_elem<S: Scalar, G: Group<S>>(ctext: &ElGamalCiphertext<G>,
                                                    sec_key: &ElGamalDecKey<S>)
                                                    -> G {
  ctext.e2.sub(&ctext.e1.mul(&sec_key.0))
}

/// I decrypt en ElGamal ciphertext on the exponent via brute force
/// Return ZeiError::ElGamalDecryptionError if value is not in the range [0..2^32-1]
pub fn elgamal_decrypt<S: Scalar, G: Group<S>>(base: &G,
                                               ctext: &ElGamalCiphertext<G>,
                                               sec_key: &ElGamalDecKey<S>)
                                               -> Result<u64, ZeiError> {
  elgamal_decrypt_hinted::<S, G>(base, ctext, sec_key, 0, (u32::max_value() as u64) + 1)
}

/// I decrypt en ElGamal ciphertext on the exponent via brute force
/// Return ZeiError::ElGamalDecryptionError if value is not in the range [0..2^32-1]
pub fn elgamal_decrypt_as_scalar<S: Scalar, G: Group<S>>(base: &G,
                                                         ctext: &ElGamalCiphertext<G>,
                                                         sec_key: &ElGamalDecKey<S>)
                                                         -> Result<S, ZeiError> {
  Ok(S::from_u64(elgamal_decrypt(base, ctext, sec_key)?))
}

/// I decrypt en ElGamal ciphertext on the exponent via brute force in the range [lower_bound..upper_bound]
/// Return ZeiError::ElGamalDecryptionError if value is not in the range.
pub fn elgamal_decrypt_hinted<S: Scalar, G: Group<S>>(base: &G,
                                                      ctext: &ElGamalCiphertext<G>,
                                                      sec_key: &ElGamalDecKey<S>,
                                                      lower_bound: u64,
                                                      upper_bound: u64)
                                                      -> Result<u64, ZeiError> {
  let encoded = elgamal_decrypt_elem(ctext, sec_key);
  brute_force::<S, G>(base, &encoded, lower_bound, upper_bound)
}

fn brute_force<S: Scalar, G: Group<S>>(base: &G,
                                       encoded: &G,
                                       lower_bound: u64,
                                       upper_bound: u64)
                                       -> Result<u64, ZeiError> {
  let mut b = base.mul(&S::from_u64(lower_bound));
  for i in lower_bound..upper_bound {
    if b == *encoded {
      return Ok(i);
    }
    b = b.add(base);
  }
  Err(ZeiError::ElGamalDecryptionError)
}

pub mod elgamal_test {
  use crate::algebra::groups::{Group, Scalar};
  use crate::basic_crypto::elgamal::{ElGamalCiphertext, ElGamalDecKey, ElGamalEncKey};
  use crate::errors::ZeiError;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
  use rmp_serde::Deserializer;
  use serde::de::Deserialize;
  use serde::ser::Serialize;

  pub fn verification<S: Scalar, G: Group<S>>() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let base = G::get_base();

    let (secret_key, public_key) = super::elgamal_key_gen::<_, S, G>(&mut prng, &base);

    let m = S::from_u32(100u32);
    let r = S::random_scalar(&mut prng);
    let ctext = super::elgamal_encrypt::<S, G>(&base, &m, &r, &public_key);
    assert_eq!(Ok(()),
               super::elgamal_verify::<S, G>(&base, &m, &ctext, &secret_key));

    let wrong_m = S::from_u32(99u32);
    let err = super::elgamal_verify(&base, &wrong_m, &ctext, &secret_key).err()
                                                                         .unwrap();
    assert_eq!(ZeiError::ElGamalVerificationError, err);
  }

  pub fn decryption<S: Scalar, G: Group<S>>() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let base = G::get_base();

    let (secret_key, public_key) = super::elgamal_key_gen::<_, S, G>(&mut prng, &base);

    let mu32 = 100u32;
    let m = S::from_u32(mu32);
    let r = S::random_scalar(&mut prng);
    let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
    assert_eq!(Ok(()),
               super::elgamal_verify(&base, &m, &ctext, &secret_key));

    assert_eq!(m,
               super::elgamal_decrypt_as_scalar(&base, &ctext, &secret_key).unwrap());
    assert_eq!(mu32,
               super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 200).unwrap() as u32);

    let err = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 50).err()
                                                                              .unwrap();
    assert_eq!(ZeiError::ElGamalDecryptionError, err);

    let err = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300).err()
                                                                                 .unwrap();
    assert_eq!(ZeiError::ElGamalDecryptionError, err);

    let m = S::from_u64(u64::max_value());
    let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
    assert_eq!(Ok(()),
               super::elgamal_verify(&base, &m, &ctext, &secret_key));

    let err = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300).err()
                                                                                 .unwrap();
    assert_eq!(ZeiError::ElGamalDecryptionError, err);
  }

  pub fn to_json<S: Scalar, G: Group<S>>() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let base = G::get_base();

    let (secret_key, public_key) = super::elgamal_key_gen::<_, S, G>(&mut prng, &base);

    //keys serialization
    let json_str = serde_json::to_string(&secret_key).unwrap();
    let sk_de: ElGamalDecKey<S> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(secret_key, sk_de);

    let json_str = serde_json::to_string(&public_key).unwrap();
    let pk_de: ElGamalEncKey<G> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(public_key, pk_de);

    //ciphertext serialization
    let m = S::from_u32(100u32);
    let r = S::random_scalar(&mut prng);

    let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
    let json_str = serde_json::to_string(&ctext).unwrap();
    let ctext_de: ElGamalCiphertext<G> = serde_json::from_str(&json_str).unwrap();

    assert_eq!(ctext, ctext_de);
  }

  pub fn to_message_pack<S: Scalar, G: Group<S>>() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let base = G::get_base();

    let (secret_key, public_key) = super::elgamal_key_gen::<_, S, G>(&mut prng, &base);

    //keys serialization
    let mut vec = vec![];
    secret_key.serialize(&mut rmp_serde::Serializer::new(&mut vec))
              .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let sk_de: ElGamalDecKey<S> = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(secret_key, sk_de);

    //public key serialization
    let mut vec = vec![];
    public_key.serialize(&mut rmp_serde::Serializer::new(&mut vec))
              .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let pk_de: ElGamalEncKey<G> = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(public_key, pk_de);

    //ciphertext serialization
    let m = S::from_u32(100u32);
    let r = S::random_scalar(&mut prng);

    let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);

    let mut vec = vec![];
    ctext.serialize(&mut rmp_serde::Serializer::new(&mut vec))
         .unwrap();

    let mut de = Deserializer::new(&vec[..]);
    let ctext_de: ElGamalCiphertext<G> = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(ctext, ctext_de);
  }
}
