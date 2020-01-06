use crate::crypto::chaum_pedersen::ChaumPedersenProof;
use crate::crypto::chaum_pedersen::ChaumPedersenProofX;
use crate::xfr::sig::{XfrPublicKey, XfrSecretKey, XfrSignature};
use bulletproofs::RangeProof;
use bulletproofs::r1cs::R1CSProof;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{PublicKey, SecretKey};
use serde::de::{SeqAccess, Visitor};
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

impl Serialize for XfrPublicKey {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
  {
    if serializer.is_human_readable() {
      serializer.serialize_str(&base64::encode(&self.as_bytes()))
    } else {
      serializer.serialize_bytes(self.as_bytes())
    }
  }
}

impl<'de> Deserialize<'de> for XfrPublicKey {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de>
  {
    struct XfrPublicKeyVisitor;

    impl<'de> Visitor<'de> for XfrPublicKeyVisitor {
      type Value = XfrPublicKey;

      fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        formatter.write_str("an array of 32 bytes")
      }

      fn visit_bytes<E>(self, v: &[u8]) -> Result<XfrPublicKey, E>
        where E: serde::de::Error
      {
        if v.len() == 32 {
          let mut bytes = [0u8; 32];
          bytes.copy_from_slice(v);

          static ERRMSG: &str = "Bad public key encoding";

          let pk = match PublicKey::from_bytes(&bytes[..]) {
            Ok(pk) => pk,
            Err(_) => {
              return Err(serde::de::Error::invalid_value(serde::de::Unexpected::Bytes(v),
                                                         &ERRMSG));
            }
          };
          Ok(XfrPublicKey(pk))
        } else {
          Err(serde::de::Error::invalid_length(v.len(), &self))
        }
      }
      fn visit_str<E>(self, s: &str) -> Result<XfrPublicKey, E>
        where E: serde::de::Error
      {
        self.visit_bytes(&base64::decode(s).map_err(serde::de::Error::custom)?)
      }
    }
    if deserializer.is_human_readable() {
      deserializer.deserialize_str(XfrPublicKeyVisitor)
    } else {
      deserializer.deserialize_bytes(XfrPublicKeyVisitor)
    }
  }
}

impl Serialize for XfrSecretKey {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
  {
    if serializer.is_human_readable() {
      serializer.serialize_str(&base64::encode(&self.zei_to_bytes()))
    } else {
      serializer.serialize_bytes(self.zei_to_bytes().as_slice())
    }
  }
}

impl<'de> Deserialize<'de> for XfrSecretKey {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de>
  {
    struct XfrSecretKeyVisitor;

    impl<'de> Visitor<'de> for XfrSecretKeyVisitor {
      type Value = XfrSecretKey;

      fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        formatter.write_str("an array of 32 bytes")
      }

      fn visit_bytes<E>(self, v: &[u8]) -> Result<XfrSecretKey, E>
        where E: serde::de::Error
      {
        if v.len() == 32 {
          let mut bytes = [0u8; 32];
          bytes.copy_from_slice(v);

          static ERRMSG: &str = "Bad secret key encoding";

          let sk = match SecretKey::from_bytes(&bytes[..]) {
            Ok(sk) => sk,
            Err(_) => {
              return Err(serde::de::Error::invalid_value(serde::de::Unexpected::Bytes(v),
                                                         &ERRMSG));
            }
          };
          Ok(XfrSecretKey(sk))
        } else {
          Err(serde::de::Error::invalid_length(v.len(), &self))
        }
      }
      fn visit_str<E>(self, s: &str) -> Result<XfrSecretKey, E>
        where E: serde::de::Error
      {
        self.visit_bytes(&base64::decode(s).map_err(serde::de::Error::custom)?)
      }
    }
    if deserializer.is_human_readable() {
      deserializer.deserialize_str(XfrSecretKeyVisitor)
    } else {
      deserializer.deserialize_bytes(XfrSecretKeyVisitor)
    }
  }
}

/// Helper trait to serialize zei and foreign objects that implement from/to bytes/bits
pub trait ZeiFromToBytes {
  fn zei_to_bytes(&self) -> Vec<u8>;
  fn zei_from_bytes(bytes: &[u8]) -> Self;
}

impl ZeiFromToBytes for Scalar {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&self.to_bytes()[..]);
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> Scalar {
    let mut bits = [0u8; 32];
    bits.copy_from_slice(bytes);
    Scalar::from_bits(bits)
  }
}

impl ZeiFromToBytes for RistrettoPoint {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.compress().zei_to_bytes()
  }
  fn zei_from_bytes(bytes: &[u8]) -> RistrettoPoint {
    let compressed = CompressedRistretto::from_slice(bytes);
    compressed.decompress().unwrap() //TODO handle error
  }
}

impl ZeiFromToBytes for CompressedRistretto {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&self.to_bytes()[..]);
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> CompressedRistretto {
    CompressedRistretto::from_slice(bytes)
  }
}

impl ZeiFromToBytes for RangeProof {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&self.to_bytes()[..]);
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> RangeProof {
    RangeProof::from_bytes(bytes).unwrap()
  }
}

impl ZeiFromToBytes for R1CSProof {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }
  fn zei_from_bytes(bytes: &[u8]) -> R1CSProof {
    R1CSProof::from_bytes(bytes).unwrap()
  }
}

impl ZeiFromToBytes for CompressedEdwardsY {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&self.to_bytes()[..]);
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> CompressedEdwardsY {
    CompressedEdwardsY::from_slice(bytes)
  }
}

impl ZeiFromToBytes for (CompressedRistretto, CompressedRistretto) {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&self.0.to_bytes()[..]);
    v.extend_from_slice(&self.1.to_bytes()[..]);
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> (CompressedRistretto, CompressedRistretto) {
    let a = CompressedRistretto::from_slice(&bytes[..32]);
    let b = CompressedRistretto::from_slice(&bytes[32..]);
    (a, b)
  }
}

impl ZeiFromToBytes for ChaumPedersenProof {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&self.c3.zei_to_bytes());
    v.extend_from_slice(&self.c4.zei_to_bytes());
    v.extend_from_slice(&self.z1.zei_to_bytes());
    v.extend_from_slice(&self.z2.zei_to_bytes());
    v.extend_from_slice(&self.z3.zei_to_bytes());
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> ChaumPedersenProof {
    ChaumPedersenProof { c3: RistrettoPoint::zei_from_bytes(&bytes[0..32]),
                         c4: RistrettoPoint::zei_from_bytes(&bytes[32..64]),
                         z1: Scalar::zei_from_bytes(&bytes[64..96]),
                         z2: Scalar::zei_from_bytes(&bytes[96..128]),
                         z3: Scalar::zei_from_bytes(&bytes[128..160]) }
  }
}

impl ZeiFromToBytes for ChaumPedersenProofX {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&self.c1_eq_c2.zei_to_bytes());
    if self.zero.is_some() {
      v.extend_from_slice(&self.zero.as_ref().unwrap().zei_to_bytes());
    }
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> ChaumPedersenProofX {
    let c1_eq_c2 = ChaumPedersenProof::zei_from_bytes(&bytes[0..32 * 5]);
    let zero = if bytes.len() > 32 * 5 {
      Some(ChaumPedersenProof::zei_from_bytes(&bytes[32 * 5..]))
    } else {
      None
    };
    ChaumPedersenProofX { c1_eq_c2, zero }
  }
}

impl ZeiFromToBytes for XfrSignature {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let bytes = self.0.to_bytes();
    let mut vec = vec![];
    vec.extend_from_slice(&bytes[..]);
    vec
  }

  fn zei_from_bytes(bytes: &[u8]) -> Self {
    XfrSignature(ed25519_dalek::Signature::from_bytes(bytes).unwrap())
  }
}

impl Serialize for XfrSignature {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
  {
    if serializer.is_human_readable() {
      serializer.serialize_str(&base64::encode(self.zei_to_bytes().as_slice()))
    } else {
      serializer.serialize_bytes(self.zei_to_bytes().as_slice())
    }
  }
}

impl<'de> Deserialize<'de> for XfrSignature {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de>
  {
    struct XfrSignatureVisitor;

    impl<'de> Visitor<'de> for XfrSignatureVisitor {
      type Value = XfrSignature;

      fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        formatter.write_str("a encoded Signature")
      }

      fn visit_bytes<E>(self, v: &[u8]) -> Result<XfrSignature, E>
        where E: serde::de::Error
      {
        Ok(XfrSignature::zei_from_bytes(v))
      }

      fn visit_seq<V>(self, mut seq: V) -> Result<XfrSignature, V::Error>
        where V: SeqAccess<'de>
      {
        let mut vec: Vec<u8> = vec![];
        while let Some(x) = seq.next_element().unwrap() {
          vec.push(x);
        }
        Ok(XfrSignature::zei_from_bytes(vec.as_slice()))
      }
      fn visit_str<E>(self, s: &str) -> Result<XfrSignature, E>
        where E: serde::de::Error
      {
        self.visit_bytes(&base64::decode(s).map_err(serde::de::Error::custom)?)
      }
    }

    //let v = deserializer.deserialize_bytes(zei_obj_serde::BytesVisitor).unwrap();
    //Ok(XfrSignature::zei_from_bytes(v.as_slice()))
    if deserializer.is_human_readable() {
      deserializer.deserialize_str(XfrSignatureVisitor)
    } else {
      deserializer.deserialize_bytes(XfrSignatureVisitor)
    }
  }
}

pub mod zei_obj_serde {
  use crate::serialization::ZeiFromToBytes;
  use serde::de::SeqAccess;
  use serde::de::Visitor;
  use serde::Deserializer;
  use serde::Serializer;

  pub struct BytesVisitor;

  impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
      formatter.write_str("a valid ZeiFromTo Object")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Vec<u8>, V::Error>
      where V: SeqAccess<'de>
    {
      let mut vec: Vec<u8> = vec![];
      while let Some(x) = seq.next_element().unwrap() {
        vec.push(x);
      }
      Ok(vec)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Vec<u8>, E> {
      let mut vec: Vec<u8> = vec![];
      vec.extend_from_slice(v);
      Ok(vec)
    }

    fn visit_str<E>(self, v: &str) -> Result<Vec<u8>, E>
      where E: serde::de::Error
    {
      base64::decode(v).map_err(serde::de::Error::custom)
    }
  }

  pub fn serialize<S, T>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer,
          T: ZeiFromToBytes
  {
    let bytes = obj.zei_to_bytes();
    if serializer.is_human_readable() {
      serializer.serialize_str(&base64::encode(&bytes))
    } else {
      serializer.serialize_bytes(&bytes[..])
    }
  }

  pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where D: Deserializer<'de>,
          T: ZeiFromToBytes
  {
    if deserializer.is_human_readable() {
      let bytes = deserializer.deserialize_str(BytesVisitor)?;
      Ok(T::zei_from_bytes(bytes.as_slice()))
    } else {
      let v = deserializer.deserialize_bytes(BytesVisitor)?;
      Ok(T::zei_from_bytes(v.as_slice()))
    }
  }
}

pub mod option_bytes {
  use crate::serialization::ZeiFromToBytes;
  use serde::{self, Deserialize, Deserializer, Serializer};

  pub fn serialize<S, T>(object: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer,
          T: ZeiFromToBytes
  {
    if object.is_none() {
      serializer.serialize_none()
    } else {
      let bytes = object.as_ref().unwrap().zei_to_bytes();
      //let encoded = hex::encode(&bytes[..]);
      if serializer.is_human_readable() {
        serializer.serialize_str(&base64::encode(bytes.as_slice()))
      } else {
        serializer.serialize_bytes(bytes.as_slice())
      }
    }
  }

  pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
    where D: Deserializer<'de>,
          T: ZeiFromToBytes
  {
    let vec: Option<Vec<u8>> = Option::deserialize(deserializer)?;

    if let Some(value) = vec {
      Ok(Some(T::zei_from_bytes(value.as_slice())))
    } else {
      Ok(None)
    }
  }
}

#[cfg(test)]
mod test {
  use crate::algebra::ristretto::{RistPoint, RistScalar};
  use crate::basic_crypto::elgamal::elgamal_keygen;
  use crate::serialization::ZeiFromToBytes;
  use crate::xfr::sig::{XfrKeyPair, XfrPublicKey, XfrSecretKey, XfrSignature};
  use crate::xfr::structs::EGPubKey;
  use bulletproofs::PedersenGens;

  use rand_core::SeedableRng;
  use rand_chacha::ChaChaRng;
  use rmp_serde::{Deserializer, Serializer};
  use serde::de::Deserialize;
  use serde::ser::Serialize;

  #[test]
  fn public_key_message_pack_serialization() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let keypair = XfrKeyPair::generate(&mut prng);
    let pk = keypair.get_pk_ref();

    let mut pk_mp_vec = vec![];
    assert_eq!(true,
               pk.serialize(&mut Serializer::new(&mut pk_mp_vec)).is_ok());
    let mut de = Deserializer::new(&pk_mp_vec[..]);
    let pk2: XfrPublicKey = Deserialize::deserialize(&mut de).unwrap();

    assert_eq!(pk, &pk2);
  }

  #[test]
  fn signature_message_pack_serialization() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let keypair = XfrKeyPair::generate(&mut prng);
    let message = [10u8; 55];

    let signature = keypair.sign(&message);

    let mut vec = vec![];
    assert_eq!(true,
               signature.serialize(&mut Serializer::new(&mut vec)).is_ok());

    let mut de = Deserializer::new(&vec[..]);
    let signature2 = XfrSignature::deserialize(&mut de).unwrap();

    assert_eq!(signature, signature2);
  }

  #[derive(Serialize, Deserialize, Default)]
  struct StructWithPubKey {
    key: XfrPublicKey,
  }

  #[derive(Serialize, Deserialize, Default)]
  struct StructWithSecKey {
    key: XfrSecretKey,
  }

  #[test]
  fn serialize_and_deserialize_as_json() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let keypair = XfrKeyPair::generate(&mut prng);
    let pk = keypair.get_pk_ref();
    let test_struct = StructWithPubKey { key: pk.clone() };
    let as_json = if let Ok(res) = serde_json::to_string(&test_struct) {
      res
    } else {
      println!("Failed to serialize XfrPublicKey to JSON");
      assert!(false);
      "{}".to_string()
    };
    if let Ok(restored) = serde_json::from_str::<StructWithPubKey>(&as_json) {
      assert_eq!(test_struct.key, restored.key);
    } else {
      println!("Failed to deserialize XfrPublicKey from JSON");
      assert!(false);
    }

    let sk = keypair.get_sk_ref();
    let test_struct = StructWithSecKey { key: sk.clone() };
    let as_json = if let Ok(res) = serde_json::to_string(&test_struct) {
      res
    } else {
      println!("Failed to serialize XfrSecretKey to JSON");
      assert!(false);
      "{}".to_string()
    };
    if let Ok(restored) = serde_json::from_str::<StructWithSecKey>(&as_json) {
      assert_eq!(test_struct.key.zei_to_bytes(), restored.key.zei_to_bytes());
    } else {
      println!("Failed to deserialize XfrSecretKey from JSON");
      assert!(false);
    }
  }

  #[test]
  fn serialize_and_deserialize_elgamal() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();
    let (_sk, xfr_pub_key) =
      elgamal_keygen::<_, RistScalar, RistPoint>(&mut prng, &RistPoint(pc_gens.B));
    let serialized = if let Ok(res) = serde_json::to_string(&xfr_pub_key) {
      res
    } else {
      println!("Failed to serialize Elgamal public key");
      assert!(false);
      "{}".to_string()
    };
    if let Ok(restored) = serde_json::from_str::<EGPubKey>(&serialized) {
      assert_eq!(xfr_pub_key, restored);
    } else {
      println!("Failed to deserialize XfrPublicKey from JSON");
      assert!(false);
    }
  }
}
