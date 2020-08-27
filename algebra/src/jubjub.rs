use crate::errors::AlgebraError;
use crate::groups::GroupArithmetic;
use crate::groups::{Group, Scalar};
use digest::generic_array::typenum::U64;
use digest::Digest;
use ff::Field;
use group::Group as _;
use jubjub::{AffinePoint, ExtendedPoint, Fr};
use rand_core::{CryptoRng, RngCore};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryInto;

const GENERATOR: AffinePoint =
  AffinePoint::from_raw_unchecked(Fq::from_raw([0xe4b3_d35d_f1a7_adfe,
                                                0xcaf5_5d1b_29bf_81af,
                                                0x8b0f_03dd_d60a_8187,
                                                0x62ed_cbb8_bf37_87c8]),
                                  Fq::from_raw([0xb, 0x0, 0x0, 0x0]));

use utils::{b64dec, b64enc, compute_prng_from_hash, u8_littleendian_slice_to_u64};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct JubjubScalar(pub(crate) Fr);
#[derive(Clone, PartialEq, Debug)]
pub struct JubjubGroup(pub(crate) ExtendedPoint);

impl Scalar for JubjubScalar {
  // scalar generation
  fn random_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> JubjubScalar {
    JubjubScalar(Fr::random(rng))
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
    Self::random_scalar(&mut prng)
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
    let a = self.0.to_bytes();
    let a1 = u8_littleendian_slice_to_u64(&a[0..8]);
    let a2 = u8_littleendian_slice_to_u64(&a[8..16]);
    let a3 = u8_littleendian_slice_to_u64(&a[16..24]);
    let a4 = u8_littleendian_slice_to_u64(&a[24..]);
    vec![a1, a2, a3, a4]
  }

  //scalar serialization
  fn to_bytes(&self) -> Vec<u8> {
    (self.0).to_bytes().to_vec()
  }

  fn from_bytes(bytes: &[u8]) -> Result<JubjubScalar, AlgebraError> {
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    let scalar = Fr::from_bytes(&array);
    if bool::from(scalar.is_none()) {
      return Err(AlgebraError::SerializationError);
    }
    Ok(JubjubScalar(scalar.unwrap()))
  }
}

impl Eq for JubjubGroup {}

impl Group for JubjubGroup {
  const COMPRESSED_LEN: usize = 32;

  fn get_identity() -> JubjubGroup {
    JubjubGroup(ExtendedPoint::identity())
  }

  fn get_base() -> JubjubGroup {
    JubjubGroup(ExtendedPoint::generator())
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

  fn from_hash<D>(hash: D) -> JubjubGroup
    where D: Digest<OutputSize = U64> + Default
  {
    let mut prng = compute_prng_from_hash(hash);
    JubjubGroup(ExtendedPoint::random(&mut prng))
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

#[cfg(test)]
mod jubjub_groups_test {
  use crate::groups::group_tests::{test_scalar_operations, test_scalar_serialization};
  use crate::groups::{Group, GroupArithmetic, Scalar};
  use crate::jubjub::{JubjubGroup, JubjubScalar};
  use rand_core::SeedableRng;

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

  #[test]
  // TODO: Add tests for Schnorr signatures

  fn schnorr_signature() {
    // PRNG
    let seed = [0_u8; 32];
    let mut _rng = rand_chacha::ChaChaRng::from_seed(seed);

    // Private key
    // let alpha = JubjubScalar::random_scalar(&mut rng);
    let alpha = JubjubScalar::from_u64(1_64);

    // Public key
    let base = JubjubGroup::get_base();
    let u = base.mul(&alpha);

    // Verifier challenge
    // let c = JubjubScalar::random_scalar(&mut rng);  // TODO compute from message (signature)
    let c = JubjubScalar::from_u64(3_64);

    // Prover commitment
    //let alpha_t = JubjubScalar::random_scalar(&mut rng);
    let alpha_t = JubjubScalar::from_u64(2_64);
    let u_t = base.mul(&alpha_t);

    // Prover response
    let alpha_z = alpha_t.add(&c.mul(&alpha));

    // Proof verification
    let left = base.mul(&alpha_z);
    let right = u_t.add(&u.mul(&c));

    assert_eq!(left, right);
  }
}
