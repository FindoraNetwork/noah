//use crate::anon_xfr::structs::{AXfrPubKey, AXfrSecKey};
use crate::xfr::sig::{XfrPublicKey, XfrSecretKey, XfrSignature};
use crate::xfr::structs::{AssetType, ASSET_TYPE_LENGTH};
//use algebra::jubjub::{JubjubGroup, JubjubScalar};
use ed25519_dalek::ed25519::signature::Signature;
use ed25519_dalek::{PublicKey, SecretKey};
use serde::Serializer;
use utils::errors::ZeiError;
use utils::serialization::ZeiFromToBytes;

/*
impl ZeiFromToBytes for AXfrPubKey {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.0.zei_to_bytes()
  }

  fn zei_from_bytes(bytes: &[u8]) -> Result<Self, ZeiError> {
    let point = JubjubGroup::zei_from_bytes(bytes)?;
    Ok(AXfrPubKey(point))
  }
}

serialize_deserialize!(AXfrPubKey);

impl ZeiFromToBytes for AXfrSecKey {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.0.zei_to_bytes()
  }

  fn zei_from_bytes(bytes: &[u8]) -> Result<Self, ZeiError> {
    let scalar = JubjubScalar::zei_from_bytes(bytes)?;
    Ok(AXfrSecKey(scalar))
  }
}

serialize_deserialize!(AXfrSecKey);
*/

impl ZeiFromToBytes for AssetType {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.0.to_vec()
  }

  fn zei_from_bytes(bytes: &[u8]) -> Result<Self, ZeiError> {
    if bytes.len() != ASSET_TYPE_LENGTH {
      Err(ZeiError::DeserializationError)
    } else {
      let mut array = [0u8; ASSET_TYPE_LENGTH];
      array.copy_from_slice(bytes);
      Ok(AssetType(array))
    }
  }
}

serialize_deserialize!(AssetType);

impl ZeiFromToBytes for XfrPublicKey {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.0.as_bytes().to_vec()
  }

  fn zei_from_bytes(bytes: &[u8]) -> Result<Self, ZeiError> {
    let pk = PublicKey::from_bytes(bytes).map_err(|_| ZeiError::DeserializationError)?;
    Ok(XfrPublicKey(pk))
  }
}
serialize_deserialize!(XfrPublicKey);

impl ZeiFromToBytes for XfrSecretKey {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.0.as_bytes().to_vec()
  }

  fn zei_from_bytes(bytes: &[u8]) -> Result<Self, ZeiError> {
    Ok(XfrSecretKey(SecretKey::from_bytes(bytes).map_err(|_| ZeiError::DeserializationError)?))
  }
}

serialize_deserialize!(XfrSecretKey);

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

serialize_deserialize!(XfrSignature);

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
  use crate::anon_xfr::structs::{AXfrPubKey, AXfrSecKey};
  use crate::serialization::ZeiFromToBytes;
  use crate::xfr::asset_tracer::RecordDataEncKey;
  use crate::xfr::sig::{XfrKeyPair, XfrPublicKey, XfrSecretKey, XfrSignature};
  use algebra::groups::{Group, GroupArithmetic, Scalar};
  use algebra::jubjub::{JubjubGroup, JubjubScalar};
  use algebra::ristretto::RistrettoPoint;
  use crypto::basics::elgamal::elgamal_key_gen;
  use crypto::basics::hybrid_encryption::{XPublicKey, XSecretKey};
  use crypto::ristretto_pedersen::RistrettoPedersenGens;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
  use rmp_serde::{Deserializer, Serializer};
  use serde::de::Deserialize;
  use serde::ser::Serialize;

  // TODO: More serialization tests for `AXfrPubKey` and `AXfrSecKey`
  #[test]
  fn anon_xfr_pub_key_serialization() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let sk = AXfrSecKey(JubjubScalar::random(&mut prng));
    let pk = AXfrPubKey(JubjubGroup::get_base().mul(&sk.0));

    let mut pk_mp_vec = vec![];
    assert_eq!(true,
               pk.serialize(&mut Serializer::new(&mut pk_mp_vec)).is_ok());
    let mut de = Deserializer::new(&pk_mp_vec[..]);
    let pk2: AXfrPubKey = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(pk, pk2);
  }

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
