use crate::bls12_381::BLSScalar;
use crate::errors::AlgebraError;
use crate::groups::GroupArithmetic;
use crate::groups::{Group, One, Scalar, ScalarArithmetic, Zero};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use digest::generic_array::typenum::U64;
use digest::Digest;
use ff::Field;
use group::Group as _;
use jubjub::{AffinePoint, ExtendedPoint, Fr};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore};
use std::convert::TryInto;
use utils::{derive_prng_from_hash, u8_le_slice_to_u64};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct JubjubScalar(pub(crate) Fr);
#[derive(Clone, PartialEq, Debug)]
pub struct JubjubGroup(pub(crate) ExtendedPoint);

pub const JUBJUB_SCALAR_LEN: usize = 32;

impl One for JubjubScalar {
  fn one() -> JubjubScalar {
    JubjubScalar(Fr::one())
  }
}

impl Zero for JubjubScalar {
  fn zero() -> JubjubScalar {
    JubjubScalar(Fr::zero())
  }

  fn is_zero(&self) -> bool {
    self.0.eq(&Fr::zero())
  }
}

impl ScalarArithmetic for JubjubScalar {
  fn add(&self, b: &JubjubScalar) -> JubjubScalar {
    JubjubScalar(self.0.add(&b.0))
  }

  fn add_assign(&mut self, b: &JubjubScalar) {
    (self.0).add_assign(&b.0);
  }

  fn mul(&self, b: &JubjubScalar) -> JubjubScalar {
    JubjubScalar(self.0.mul(&b.0))
  }

  fn mul_assign(&mut self, b: &JubjubScalar) {
    (self.0).mul_assign(&b.0);
  }

  fn sub(&self, b: &JubjubScalar) -> JubjubScalar {
    JubjubScalar(self.0.sub(&b.0))
  }

  fn sub_assign(&mut self, b: &JubjubScalar) {
    (self.0).sub_assign(&b.0);
  }

  fn inv(&self) -> Result<JubjubScalar, AlgebraError> {
    let a = self.0.invert();
    if bool::from(a.is_none()) {
      return Err(AlgebraError::GroupInversionError);
    }
    Ok(JubjubScalar(a.unwrap()))
  }
}

impl Scalar for JubjubScalar {
  // scalar generation
  fn random<R: CryptoRng + RngCore>(rng: &mut R) -> JubjubScalar {
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
    let mut prng = derive_prng_from_hash::<D, ChaCha20Rng>(hash);
    Self::random(&mut prng)
  }

  fn multiplicative_generator() -> Self {
    Self::from_u64(6)
  }

  // scalar field size
  fn get_field_size_lsf_bytes() -> Vec<u8> {
    [183, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204, 147, 32, 104, 166, 0, 59, 52, 1, 1,
     59, 103, 6, 169, 175, 51, 101, 234, 180, 125, 14].to_vec()
  }

  fn get_little_endian_u64(&self) -> Vec<u64> {
    let a = self.0.to_bytes();
    let a1 = u8_le_slice_to_u64(&a[0..8]);
    let a2 = u8_le_slice_to_u64(&a[8..16]);
    let a3 = u8_le_slice_to_u64(&a[16..24]);
    let a4 = u8_le_slice_to_u64(&a[24..]);
    vec![a1, a2, a3, a4]
  }

  fn bytes_len() -> usize {
    JUBJUB_SCALAR_LEN
  }
  //scalar serialization
  fn to_bytes(&self) -> Vec<u8> {
    (self.0).to_bytes().to_vec()
  }

  fn from_bytes(bytes: &[u8]) -> Result<JubjubScalar, AlgebraError> {
    if bytes.len() != JUBJUB_SCALAR_LEN {
      return Err(AlgebraError::ParameterError);
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    let scalar = Fr::from_bytes(&array);
    if bool::from(scalar.is_none()) {
      return Err(AlgebraError::SerializationError);
    }
    Ok(JubjubScalar(scalar.unwrap()))
  }

  fn from_le_bytes(bytes: &[u8]) -> Result<JubjubScalar, AlgebraError> {
    Self::from_bytes(bytes)
  }
}

impl Eq for JubjubGroup {}

impl JubjubGroup {
  pub fn mul_by_cofactor(&self) -> JubjubGroup {
    JubjubGroup(self.0.mul_by_cofactor())
  }
}

impl Group for JubjubGroup {
  const COMPRESSED_LEN: usize = 32;

  fn get_identity() -> JubjubGroup {
    JubjubGroup(ExtendedPoint::identity())
  }

  fn get_base() -> JubjubGroup {
    JubjubGroup(ExtendedPoint::generator().mul_by_cofactor())
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
    let mut prng = derive_prng_from_hash::<D, ChaCha20Rng>(hash);
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
  fn double(&self) -> JubjubGroup {
    JubjubGroup(self.0.double())
  }
}

impl JubjubGroup {
  /// Get the x-coordinate of the Jubjub affine point.
  pub fn get_x(&self) -> BLSScalar {
    let affine_point = AffinePoint::from(&self.0);
    BLSScalar::new(affine_point.get_u())
  }
  /// Get the y-coordinate of the Jubjub affine point.
  pub fn get_y(&self) -> BLSScalar {
    let affine_point = AffinePoint::from(&self.0);
    BLSScalar::new(affine_point.get_v())
  }
}

#[cfg(test)]
mod jubjub_groups_test {
  use crate::groups::group_tests::{test_scalar_operations, test_scalar_serialization};
  use crate::groups::{Group, GroupArithmetic, Scalar, ScalarArithmetic};
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
  fn schnorr_identification_protocol() {
    // PRNG
    let seed = [0_u8; 32];
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);

    // Private key
    let alpha = JubjubScalar::random(&mut rng);

    // Public key
    let base = JubjubGroup::get_base();
    let u = base.mul(&alpha);

    // Verifier challenge
    let c = JubjubScalar::random(&mut rng);

    // Prover commitment
    let alpha_t = JubjubScalar::random(&mut rng);
    let u_t = base.mul(&alpha_t);

    // Prover response
    let alpha_z = alpha_t.add(&c.mul(&alpha));

    // Proof verification
    let left = base.mul(&alpha_z);
    let right = u_t.add(&u.mul(&c));

    assert_eq!(left, right);
  }
}
