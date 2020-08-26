use crate::errors::AlgebraError;
use crate::groups::GroupArithmetic;
use crate::groups::{Group, Scalar};
use digest::generic_array::typenum::U64;
use digest::Digest;
use jubjub::{AffinePoint, ExtendedPoint, Fq, Fr};
use rand_core::{CryptoRng, RngCore};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryInto;
use utils::{b64dec, b64enc, compute_prng_from_hash};


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
  fn random<R: CryptoRng + RngCore>(rng: &mut R) -> JubjubScalar {
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
    let mut prng = compute_prng_from_hash(hash);
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

impl Eq for JubjubGroup {}

impl Group for JubjubGroup {
  const COMPRESSED_LEN: usize = 32;

  fn get_identity() -> JubjubGroup {
    JubjubGroup(ExtendedPoint::identity())
  }

  fn get_base() -> JubjubGroup {
    JubjubGroup(ExtendedPoint::from(GENERATOR))
  }

  fn to_compressed_bytes(&self) -> Vec<u8> {
    AffinePoint::from(&self.0).to_bytes().to_vec()
  }

  fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, AlgebraError> {
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

impl GroupArithmetic for JubjubGroup {
  type S = JubjubScalar;
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

// TODO: Add tests for Schnorr signatures
#[cfg(test)]
mod jubjub_groups_test {
  use crate::groups::group_tests::{test_scalar_operations, test_scalar_serialization};
  use crate::groups::Scalar;
  use crate::jubjub::JubjubScalar;

  #[test]
  fn test_scalar_ops() {
    test_scalar_operations::<JubjubScalar>();
  }

  #[test]
  fn scalar_deser() {
    test_scalar_serialization::<JubjubScalar>();
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
