use crate::errors::ZeiError;
use crate::utils::{b64dec, b64enc};
use crate::xfr::sig::{XfrPublicKey, XfrSecretKey, XfrSignature};
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::RangeProof;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek_new::ed25519::signature::Signature;
use ed25519_dalek_new::{PublicKey, SecretKey};
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
      serializer.serialize_str(&b64enc(&self.as_bytes()))
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
        self.visit_bytes(&b64dec(s).map_err(serde::de::Error::custom)?)
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
      serializer.serialize_str(&b64enc(&self.zei_to_bytes()))
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
        self.visit_bytes(&b64dec(s).map_err(serde::de::Error::custom)?)
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
pub trait ZeiFromToBytes: Sized {
  fn zei_to_bytes(&self) -> Vec<u8>;
  fn zei_from_bytes(bytes: &[u8]) -> Result<Self, ZeiError>;
}

impl ZeiFromToBytes for Scalar {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&self.to_bytes()[..]);
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> Result<Scalar, ZeiError> {
    let mut bits = [0u8; 32];
    bits.copy_from_slice(bytes);
    Ok(Scalar::from_bits(bits))
  }
}

impl ZeiFromToBytes for RistrettoPoint {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.compress().zei_to_bytes()
  }
  fn zei_from_bytes(bytes: &[u8]) -> Result<RistrettoPoint, ZeiError> {
    let compressed = CompressedRistretto::from_slice(bytes);
    match compressed.decompress() {
      Some(x) => Ok(x),
      None => Err(ZeiError::DecompressElementError),
    }
  }
}

impl ZeiFromToBytes for CompressedRistretto {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&self.to_bytes()[..]);
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> Result<CompressedRistretto, ZeiError> {
    Ok(CompressedRistretto::from_slice(bytes))
  }
}

impl ZeiFromToBytes for RangeProof {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&self.to_bytes()[..]);
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> Result<RangeProof, ZeiError> {
    RangeProof::from_bytes(bytes).map_err(|_| ZeiError::DeserializationError) // TODO import error message
  }
}

impl ZeiFromToBytes for R1CSProof {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }
  fn zei_from_bytes(bytes: &[u8]) -> Result<R1CSProof, ZeiError> {
    R1CSProof::from_bytes(bytes).map_err(|_| ZeiError::DeserializationError) // TODO import error message
  }
}

impl ZeiFromToBytes for CompressedEdwardsY {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(&self.to_bytes()[..]);
    v
  }
  fn zei_from_bytes(bytes: &[u8]) -> Result<CompressedEdwardsY, ZeiError> {
    Ok(CompressedEdwardsY::from_slice(bytes))
  }
}

impl ZeiFromToBytes for XfrSignature {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let bytes = self.0.to_bytes();
    let mut vec = vec![];
    vec.extend_from_slice(&bytes[..]);
    vec
  }

  fn zei_from_bytes(bytes: &[u8]) -> Result<Self, ZeiError> {
    match ed25519_dalek_new::Signature::from_bytes(bytes) {
      Ok(e) => Ok(XfrSignature(e)),
      Err(_) => Err(ZeiError::DeserializationError),
    }
  }
}

impl Serialize for XfrSignature {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
  {
    if serializer.is_human_readable() {
      serializer.serialize_str(&b64enc(self.zei_to_bytes().as_slice()))
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
        XfrSignature::zei_from_bytes(v).map_err(serde::de::Error::custom)
      }

      fn visit_seq<V>(self, mut seq: V) -> Result<XfrSignature, V::Error>
        where V: SeqAccess<'de>
      {
        let mut vec: Vec<u8> = vec![];
        while let Some(x) = seq.next_element().map_err(serde::de::Error::custom)? {
          vec.push(x);
        }
        XfrSignature::zei_from_bytes(vec.as_slice()).map_err(serde::de::Error::custom)
      }
      fn visit_str<E>(self, s: &str) -> Result<XfrSignature, E>
        where E: serde::de::Error
      {
        self.visit_bytes(&b64dec(s).map_err(serde::de::Error::custom)?)
      }
    }

    if deserializer.is_human_readable() {
      deserializer.deserialize_str(XfrSignatureVisitor)
    } else {
      deserializer.deserialize_bytes(XfrSignatureVisitor)
    }
  }
}

pub mod zei_obj_serde {
  use crate::serialization::ZeiFromToBytes;
  use crate::utils::{b64dec, b64enc};
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
      while let Some(x) = seq.next_element().map_err(serde::de::Error::custom)? {
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
      b64dec(v).map_err(serde::de::Error::custom)
    }
  }

  pub fn serialize<S, T>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer,
          T: ZeiFromToBytes
  {
    let bytes = obj.zei_to_bytes();
    if serializer.is_human_readable() {
      serializer.serialize_str(&b64enc(&bytes))
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
      T::zei_from_bytes(bytes.as_slice()).map_err(serde::de::Error::custom)
    } else {
      let v = deserializer.deserialize_bytes(BytesVisitor)?;
      T::zei_from_bytes(v.as_slice()).map_err(serde::de::Error::custom)
    }
  }
}

/*
// XXX keep this for future reference
// use with #[serde(with = "serialization::option_bytes")]
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
        serializer.serialize_str(&b64enc(bytes.as_slice()))
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
*/

#[cfg(test)]
mod test {
  use crate::basic_crypto::elgamal::elgamal_key_gen;
  use crate::serialization::ZeiFromToBytes;
  use crate::xfr::sig::{XfrKeyPair, XfrPublicKey, XfrSecretKey, XfrSignature};
  use bulletproofs::PedersenGens;

  use crate::xfr::asset_tracer::RecordDataEncKey;
  use curve25519_dalek::ristretto::RistrettoPoint;
  use curve25519_dalek::scalar::Scalar;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
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

  #[derive(Serialize, Deserialize)]
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
    let (_sk, xfr_pub_key) = elgamal_key_gen::<_, Scalar, RistrettoPoint>(&mut prng, &pc_gens.B);
    let serialized = if let Ok(res) = serde_json::to_string(&xfr_pub_key) {
      res
    } else {
      println!("Failed to serialize Elgamal public key");
      assert!(false);
      "{}".to_string()
    };
    if let Ok(restored) = serde_json::from_str::<RecordDataEncKey>(&serialized) {
      assert_eq!(xfr_pub_key, restored);
    } else {
      println!("Failed to deserialize XfrPublicKey from JSON");
      assert!(false);
    }
  }
}
