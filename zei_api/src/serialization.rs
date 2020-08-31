use crate::xfr::sig::{XfrPublicKey, XfrSecretKey, XfrSignature};
use ed25519_dalek::{PublicKey, SecretKey};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utils::errors::ZeiError;
use utils::serialization::ZeiFromToBytes;
use utils::{b64dec, b64enc};

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

/*
impl Serialize for XPublicKey {
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

impl<'de> Deserialize<'de> for XPublicKey {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de>
  {
    struct XPublicKeyVisitor;

    impl<'de> Visitor<'de> for XPublicKeyVisitor {
      type Value = XPublicKey;

      fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        formatter.write_str("a encoded XPublicKey")
      }

      fn visit_bytes<E>(self, v: &[u8]) -> Result<XPublicKey, E>
        where E: serde::de::Error
      {
        XPublicKey::zei_from_bytes(v).map_err(serde::de::Error::custom)
      }

      fn visit_seq<V>(self, mut seq: V) -> Result<XPublicKey, V::Error>
        where V: SeqAccess<'de>
      {
        let mut vec: Vec<u8> = vec![];
        while let Some(x) = seq.next_element().map_err(serde::de::Error::custom)? {
          vec.push(x);
        }
        XPublicKey::zei_from_bytes(vec.as_slice()).map_err(serde::de::Error::custom)
      }
      fn visit_str<E>(self, s: &str) -> Result<XPublicKey, E>
        where E: serde::de::Error
      {
        self.visit_bytes(&b64dec(s).map_err(serde::de::Error::custom)?)
      }
    }

    if deserializer.is_human_readable() {
      deserializer.deserialize_str(XPublicKeyVisitor)
    } else {
      deserializer.deserialize_bytes(XPublicKeyVisitor)
    }
  }
}
*/

impl ZeiFromToBytes for XfrSignature {
  fn zei_to_bytes(&self) -> Vec<u8> {
    let bytes = self.0.to_bytes();
    let mut vec = vec![];
    vec.extend_from_slice(&bytes[..]);
    vec
  }

  fn zei_from_bytes(bytes: &[u8]) -> Result<Self, ZeiError> {
    match ed25519_dalek::Signature::from_bytes(bytes) {
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
  use algebra::ristretto::RistrettoPoint;
  use crate::serialization::ZeiFromToBytes;
  use crate::xfr::asset_tracer::RecordDataEncKey;
  use crate::xfr::sig::{XfrKeyPair, XfrPublicKey, XfrSecretKey, XfrSignature};
  use crypto::basics::elgamal::elgamal_key_gen;
  use crypto::basics::hybrid_encryption::{XPublicKey, XSecretKey};
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
  use rmp_serde::{Deserializer, Serializer};
  use serde::de::Deserialize;
  use serde::ser::Serialize;
  use crypto::ristretto_pedersen::RistrettoPedersenGens;

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
  fn x25519_public_key_message_pack_serialization() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let sk = XSecretKey::new(&mut prng);
    let pk = XPublicKey::from(&sk);

    let mut pk_mp_vec = vec![];
    assert_eq!(true,
               pk.serialize(&mut Serializer::new(&mut pk_mp_vec)).is_ok());
    let mut de = Deserializer::new(&pk_mp_vec[..]);
    let pk2: XPublicKey = Deserialize::deserialize(&mut de).unwrap();

    assert_eq!(&pk, &pk2);
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
    let pc_gens = RistrettoPedersenGens::default();
    let (_sk, xfr_pub_key) = elgamal_key_gen::<_, RistrettoPoint>(&mut prng, &pc_gens.B);
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
