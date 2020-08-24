use crate::errors::AlgebraError;
use crate::groups::GroupArithmetic;
use crate::groups::{Group, Scalar};
use digest::generic_array::typenum::U64;
use digest::Digest;
use jubjub::{AffinePoint, ExtendedPoint, Fq, Fr};
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryInto;
use utils::{b64dec, b64enc};

const GENERATOR: AffinePoint =
  AffinePoint::from_raw_unchecked(Fq::from_raw([0xe4b3_d35d_f1a7_adfe,
                                                0xcaf5_5d1b_29bf_81af,
                                                0x8b0f_03dd_d60a_8187,
                                                0x62ed_cbb8_bf37_87c8]),
                                  Fq::from_raw([0xb, 0x0, 0x0, 0x0]));

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct JubjubScalar(pub(crate) Fr);
#[derive(Clone, PartialEq, Debug)]
pub struct JubjubGroup(pub(crate) ExtendedPoint);

impl Scalar for JubjubScalar {
  // scalar generation
  fn random_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> JubjubScalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    JubjubScalar(Fr::from_bytes_wide(&bytes))
  }

  fn from_u32(value: u32) -> JubjubScalar {
    Self::from_u64(value as u64)
  }

  fn from_u64(value: u64) -> JubjubScalar {
    JubjubScalar(Fr::from(value))
  }

  fn from_hash<D>(hash: D) -> JubjubScalar
    where D: Digest<OutputSize = U64> + Default
  {
    let result = hash.result();
    let mut seed = [0u8; 32];
    for i in 0..32 {
      seed[i] = result[i];
    }
    let mut prng = ChaChaRng::from_seed(seed);
    let mut bytes = [0u8; 64];
    prng.fill_bytes(&mut bytes);
    JubjubScalar(Fr::from_bytes_wide(&bytes))
  }

  // scalar arithmetic
  fn add(&self, b: &JubjubScalar) -> JubjubScalar {
    JubjubScalar(self.0 + b.0)
  }

  fn mul(&self, b: &JubjubScalar) -> JubjubScalar {
    JubjubScalar(self.0 * b.0)
  }

  fn sub(&self, b: &JubjubScalar) -> JubjubScalar {
    JubjubScalar(self.0 - b.0)
  }

  fn inv(&self) -> Result<JubjubScalar, AlgebraError> {
    let inv = (self.0).invert();
    if inv.is_some().into() {
      Ok(JubjubScalar(inv.unwrap())) // safe unwrap
    } else {
      Err(AlgebraError::GroupInversionError)
    }
  }

  fn get_little_endian_u64(&self) -> Vec<u64> {
    panic!("get_little_endian_u64 not implemented for JubjubScalar")
  }

  //scalar serialization
  fn to_bytes(&self) -> Vec<u8> {
    (self.0).to_bytes().to_vec()
  }

  fn from_bytes(bytes: &[u8]) -> Result<JubjubScalar, AlgebraError> {
    let res = Fr::from_bytes(&bytes[..32].try_into()
                                         .map_err(|_| AlgebraError::DeserializationError)?);
    if res.is_some().into() {
      Ok(JubjubScalar(res.unwrap()))
    } else {
      Err(AlgebraError::DeserializationError)
    }
  }
}

impl Serialize for JubjubScalar {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
  {
    if serializer.is_human_readable() {
      serializer.serialize_str(&b64enc(self.to_bytes().as_slice()))
    } else {
      serializer.serialize_bytes(self.to_bytes().as_slice())
    }
  }
}

impl<'de> Deserialize<'de> for JubjubScalar {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de>
  {
    struct ScalarVisitor;

    impl<'de> Visitor<'de> for ScalarVisitor {
      type Value = JubjubScalar;

      fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        formatter.write_str("an encoded Jubjub scalar")
      }

      fn visit_bytes<E>(self, v: &[u8]) -> Result<JubjubScalar, E>
        where E: serde::de::Error
      {
        JubjubScalar::from_bytes(v).map_err(serde::de::Error::custom)
      }

      fn visit_seq<V>(self, mut seq: V) -> Result<JubjubScalar, V::Error>
        where V: SeqAccess<'de>
      {
        let mut vec: Vec<u8> = vec![];
        while let Some(x) = seq.next_element().map_err(serde::de::Error::custom)? {
          vec.push(x);
        }
        JubjubScalar::from_bytes(vec.as_slice()).map_err(serde::de::Error::custom)
      }
      fn visit_str<E>(self, s: &str) -> Result<JubjubScalar, E>
        where E: serde::de::Error
      {
        self.visit_bytes(&b64dec(s).map_err(serde::de::Error::custom)?)
      }
    }
    if deserializer.is_human_readable() {
      deserializer.deserialize_str(ScalarVisitor)
    } else {
      deserializer.deserialize_bytes(ScalarVisitor)
    }
  }
}

impl Eq for JubjubGroup {}

impl Group<JubjubScalar> for JubjubGroup {
  const COMPRESSED_LEN: usize = 32;
  const SCALAR_BYTES_LEN: usize = 32;

  fn get_identity() -> JubjubGroup {
    JubjubGroup(ExtendedPoint::identity())
  }

  fn get_base() -> JubjubGroup {
    JubjubGroup(ExtendedPoint::from(GENERATOR))
  }

  // compression/serialization helpers
  fn to_compressed_bytes(&self) -> Vec<u8> {
    AffinePoint::from(&self.0).to_bytes().to_vec()
  }

  fn from_compressed_bytes(bytes: &[u8]) -> Result<JubjubGroup, AlgebraError> {
    let affine = AffinePoint::from_bytes(bytes[..Self::COMPRESSED_LEN].try_into().map_err(|_| AlgebraError::DecompressElementError)?);
    if affine.is_some().into() {
      Ok(JubjubGroup(ExtendedPoint::from(affine.unwrap()))) // safe unwrap
    } else {
      Err(AlgebraError::DecompressElementError)
    }
  }

  fn from_hash<D>(_hash: D) -> JubjubGroup
    where D: Digest<OutputSize = U64> + Default
  {
    panic!("from_hash not implemented for JubjubGroup")
  }
}

impl GroupArithmetic<JubjubScalar> for JubjubGroup {
  //arithmetic
  fn mul(&self, scalar: &JubjubScalar) -> JubjubGroup {
    JubjubGroup(self.0 * scalar.0)
  }
  fn add(&self, other: &Self) -> JubjubGroup {
    JubjubGroup(self.0 + other.0)
  }
  fn sub(&self, other: &Self) -> JubjubGroup {
    JubjubGroup(self.0 - other.0)
  }
}

impl Serialize for JubjubGroup {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
  {
    if serializer.is_human_readable() {
      serializer.serialize_str(&b64enc(self.to_compressed_bytes().as_slice()))
    } else {
      serializer.serialize_bytes(self.to_compressed_bytes().as_slice())
    }
  }
}

impl<'de> Deserialize<'de> for JubjubGroup {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de>
  {
    struct G1Visitor;

    impl<'de> Visitor<'de> for G1Visitor {
      type Value = JubjubGroup;

      fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        formatter.write_str("an encoded ElGamal ciphertext or Schnorr signature")
      }

      fn visit_bytes<E>(self, v: &[u8]) -> Result<JubjubGroup, E>
        where E: serde::de::Error
      {
        JubjubGroup::from_compressed_bytes(v).map_err(serde::de::Error::custom)
      }

      fn visit_seq<V>(self, mut seq: V) -> Result<JubjubGroup, V::Error>
        where V: SeqAccess<'de>
      {
        let mut vec: Vec<u8> = vec![];
        while let Some(x) = seq.next_element()? {
          vec.push(x);
        }
        JubjubGroup::from_compressed_bytes(vec.as_slice()).map_err(serde::de::Error::custom)
      }
      fn visit_str<E>(self, s: &str) -> Result<JubjubGroup, E>
        where E: serde::de::Error
      {
        self.visit_bytes(&b64dec(s).map_err(serde::de::Error::custom)?)
      }
    }
    if deserializer.is_human_readable() {
      deserializer.deserialize_str(G1Visitor)
    } else {
      deserializer.deserialize_bytes(G1Visitor)
    }
  }
}

// TODO: Add tests for Schnorr signatures
#[cfg(test)]
mod jubjub_groups_test {
  use crate::algebra::groups::group_tests::{test_scalar_operations, test_scalar_serialization};
  use crate::algebra::groups::Scalar;
  use crate::algebra::jubjub::JubjubScalar;

  #[test]
  fn test_scalar_ops() {
    test_scalar_operations::<super::JubjubScalar>();
  }

  #[test]
  fn scalar_deser() {
    test_scalar_serialization::<super::JubjubScalar>();
  }

  #[test]
  fn scalar_from_to_bytes() {
    let small_value = JubjubScalar::from_u32(165747);
    let small_value_bytes = small_value.to_bytes();
    let expected_small_value_bytes: [u8; 32] = [115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(small_value_bytes, expected_small_value_bytes);

    let small_value_from_bytes = JubjubScalar::from_bytes(&small_value_bytes).unwrap();
    assert_eq!(small_value_from_bytes, small_value);
  }
}

#[cfg(test)]
mod elgamal_over_jubjub_groups {
  use crate::basic_crypto::elgamal::elgamal_test;

  #[test]
  fn verification_jubjub_group() {
    elgamal_test::verification::<super::JubjubScalar, super::JubjubGroup>();
  }

  #[test]
  fn decryption_jubjub_group() {
    elgamal_test::decryption::<super::JubjubScalar, super::JubjubGroup>();
  }

  #[test]
  fn to_json_jubjub_group() {
    elgamal_test::to_json::<super::JubjubScalar, super::JubjubGroup>();
  }

  #[test]
  fn to_message_pack_jubjub_group() {
    elgamal_test::to_message_pack::<super::JubjubScalar, super::JubjubGroup>();
  }
}
