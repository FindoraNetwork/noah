use crate::algebra::groups::{Group, Scalar};
use crate::algebra::ristretto::RistPoint;
use crate::errors::ZeiError;
use crate::serialization::ZeiFromToBytes;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::{CryptoRng, Rng};
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalPublicKey<G>(pub G); //PK = sk*G

impl<G: Clone> ElGamalPublicKey<G> {
  pub fn get_point(&self) -> G {
    self.0.clone()
  }
  pub fn get_point_ref(&self) -> &G {
    &self.0
  }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalSecretKey<S>(pub(crate) S); //sk

pub fn elgamal_generate_secret_key<R: CryptoRng + Rng, S: Scalar>(prng: &mut R)
                                                                  -> ElGamalSecretKey<S> {
  ElGamalSecretKey(S::random_scalar(prng))
}

pub fn elgamal_derive_public_key< G: Group>(base: &G,
                                                         sec_key: &ElGamalSecretKey<G::ScalarField>)
                                                         -> ElGamalPublicKey<G> {
  ElGamalPublicKey(base.mul(&sec_key.0))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalCiphertext<G> {
  pub(crate) e1: G, //r*G
  pub(crate) e2: G, //m*G + r*PK
}

impl Hash for ElGamalPublicKey<RistPoint> {
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
pub fn elgamal_encrypt<G: Group>(base: &G,
                                               m: &G::ScalarField,
                                               r: &G::ScalarField,
                                               pub_key: &ElGamalPublicKey<G>)
                                               -> ElGamalCiphertext<G> {
  let e1 = base.mul(r);
  let e2 = base.mul(m).add(&(pub_key.0).mul(r));

  ElGamalCiphertext::<G> { e1, e2 }
}

/// I verify that ctext encrypts m (ctext.e2 - ctext.e1 * sk = m* G)
pub fn elgamal_verify<G: Group>(base: &G,
                                              m: &G::ScalarField,
                                              ctext: &ElGamalCiphertext<G>,
                                              sec_key: &ElGamalSecretKey<G::ScalarField>)
                                              -> Result<(), ZeiError> {
  match base.mul(m).add(&ctext.e1.mul(&sec_key.0)) == ctext.e2 {
    true => Ok(()),
    false => Err(ZeiError::ElGamalVerificationError),
  }
}

/// I decrypt en el gamal ciphertext via brute force
/// Return ZeiError::ElGamalDecryptionError if value is not in the range [0..2^32-1]
pub fn elgamal_decrypt<G: Group>(base: &G,
                                               ctext: &ElGamalCiphertext<G>,
                                               sec_key: &ElGamalSecretKey<G::ScalarField>)
                                               -> Result<G::ScalarField, ZeiError> {
  elgamal_decrypt_hinted::<G>(base, ctext, sec_key, 0, u32::max_value())
}

/// I decrypt en el gamal ciphertext via brute force in the range [lower_bound..upper_bound]
/// Return ZeiError::ElGamalDecryptionError if value is not in the range.
pub fn elgamal_decrypt_hinted<G: Group>(base: &G,
                                                      ctext: &ElGamalCiphertext<G>,
                                                      sec_key: &ElGamalSecretKey<G::ScalarField>,
                                                      lower_bound: u32,
                                                      upper_bound: u32)
                                                      -> Result<G::ScalarField, ZeiError> {
  let encoded = &ctext.e2.sub(&ctext.e1.mul(&sec_key.0));

  brute_force::<G>(base, &encoded, lower_bound, upper_bound)
}

fn brute_force<G: Group>(base: &G,
                                       encoded: &G,
                                       lower_bound: u32,
                                       upper_bound: u32)
                                       -> Result<G::ScalarField, ZeiError> {
  let mut b = base.mul(&G::ScalarField::from_u32(lower_bound));
  for i in lower_bound..upper_bound {
    //let s = G::ScalarType::from_u32(i);
    if b == *encoded {
      return Ok(G::ScalarField::from_u32(i));
    }
    b = b.add(base);
  }
  Err(ZeiError::ElGamalDecryptionError)
}

pub mod elgamal_test {
  use crate::algebra::groups::{Group, Scalar};
  use crate::basic_crypto::elgamal::{ElGamalCiphertext, ElGamalPublicKey, ElGamalSecretKey};
  use crate::errors::ZeiError;
  use rand::SeedableRng;
  use rand_chacha::ChaChaRng;
  use rmp_serde::Deserializer;
  use serde::de::Deserialize;
  use serde::ser::Serialize;

  pub fn verification<G: Group>() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let base = G::get_base();

    let secret_key = super::elgamal_generate_secret_key::<_, G::ScalarField>(&mut prng);
    let public_key = super::elgamal_derive_public_key(&base, &secret_key);

    let m = G::ScalarField::from_u32(100u32);
    let r = G::ScalarField::random_scalar(&mut prng);
    let ctext = super::elgamal_encrypt::<G>(&base, &m, &r, &public_key);
    assert_eq!(Ok(()),
               super::elgamal_verify::<G>(&base, &m, &ctext, &secret_key));

    let wrong_m = G::ScalarField::from_u32(99u32);
    let err = super::elgamal_verify(&base, &wrong_m, &ctext, &secret_key).err()
                                                                         .unwrap();
    assert_eq!(ZeiError::ElGamalVerificationError, err);
  }

  pub fn decryption<G: Group>() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let base = G::get_base();

    let secret_key = super::elgamal_generate_secret_key::<_, G::ScalarField>(&mut prng);
    let public_key = super::elgamal_derive_public_key(&base, &secret_key);

    let m = G::ScalarField::from_u32(100u32);
    let r = G::ScalarField::random_scalar(&mut prng);
    let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
    assert_eq!(Ok(()),
               super::elgamal_verify(&base, &m, &ctext, &secret_key));

    assert_eq!(m,
               super::elgamal_decrypt(&base, &ctext, &secret_key).unwrap());
    assert_eq!(m,
               super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 200).unwrap());

    let err = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 50).err()
                                                                              .unwrap();
    assert_eq!(ZeiError::ElGamalDecryptionError, err);

    let err = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300).err()
                                                                                 .unwrap();
    assert_eq!(ZeiError::ElGamalDecryptionError, err);

    let m = G::ScalarField::from_u64(u64::max_value());
    let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
    assert_eq!(Ok(()),
               super::elgamal_verify(&base, &m, &ctext, &secret_key));

    let err = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300).err()
                                                                                 .unwrap();
    assert_eq!(ZeiError::ElGamalDecryptionError, err);
  }

  pub fn to_json<G:Group>() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let base = G::get_base();

    let secret_key = super::elgamal_generate_secret_key::<_, G::ScalarField>(&mut prng);
    let public_key = super::elgamal_derive_public_key(&base, &secret_key);

    //keys serialization
    let json_str = serde_json::to_string(&secret_key).unwrap();
    let sk_de: ElGamalSecretKey<G::ScalarField> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(secret_key, sk_de);

    let json_str = serde_json::to_string(&public_key).unwrap();
    let pk_de: ElGamalPublicKey<G> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(public_key, pk_de);

    //ciphertext serialization
    let m = G::ScalarField::from_u32(100u32);
    let r = G::ScalarField::random_scalar(&mut prng);

    let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
    let json_str = serde_json::to_string(&ctext).unwrap();
    let ctext_de: ElGamalCiphertext<G> = serde_json::from_str(&json_str).unwrap();

    assert_eq!(ctext, ctext_de);
  }

  pub fn to_message_pack<G: Group>() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let base = G::get_base();

    let secret_key = super::elgamal_generate_secret_key::<_, G::ScalarField>(&mut prng);
    let public_key = super::elgamal_derive_public_key(&base, &secret_key);

    //keys serialization
    let mut vec = vec![];
    secret_key.serialize(&mut rmp_serde::Serializer::new(&mut vec))
              .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let sk_de: ElGamalSecretKey<G::ScalarField> = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(secret_key, sk_de);

    //public key serialization
    let mut vec = vec![];
    public_key.serialize(&mut rmp_serde::Serializer::new(&mut vec))
              .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let pk_de: ElGamalPublicKey<G> = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(public_key, pk_de);

    //ciphertext serialization
    let m = G::ScalarField::from_u32(100u32);
    let r = G::ScalarField::random_scalar(&mut prng);

    let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);

    let mut vec = vec![];
    ctext.serialize(&mut rmp_serde::Serializer::new(&mut vec))
         .unwrap();

    let mut de = Deserializer::new(&vec[..]);
    let ctext_de: ElGamalCiphertext<G> = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(ctext, ctext_de);
  }
}
