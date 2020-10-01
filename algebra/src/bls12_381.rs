use crate::errors::AlgebraError;
use crate::groups::GroupArithmetic;
use crate::groups::{Group, One, Scalar as ZeiScalar, ScalarArithmetic, Zero};
use crate::jubjub::JubjubScalar;
use crate::pairing::Pairing;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use digest::generic_array::typenum::U64;
use digest::Digest;
use ff::{Field, PrimeField};
use group::Group as _;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore};

use std::str::FromStr;
use utils::{derive_prng_from_hash, u8_le_slice_to_u64};

pub type Bls12381field = Scalar;

pub const BLS_SCALAR_LEN: usize = 32;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct BLSScalar(Bls12381field);
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BLSG1(pub(crate) G1Projective);
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BLSG2(pub(crate) G2Projective);
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BLSGt(pub(crate) Gt);

impl FromStr for BLSScalar {
  type Err = AlgebraError;

  fn from_str(string: &str) -> Result<BLSScalar, AlgebraError> {
    Ok(BLSScalar(Scalar::from_str(string).ok_or(AlgebraError::DeserializationError)?))
  }
}

impl From<&JubjubScalar> for BLSScalar {
  fn from(scalar: &JubjubScalar) -> Self {
    let bytes = scalar.to_bytes();
    BLSScalar::from_bytes(&bytes).unwrap()
  }
}

impl BLSScalar {
  pub fn new(elem: Scalar) -> Self {
    Self(elem)
  }

  pub fn get_scalar(&self) -> Scalar {
    self.0
  }
}

impl One for BLSScalar {
  fn one() -> BLSScalar {
    BLSScalar(Scalar::one())
  }
}

impl Zero for BLSScalar {
  fn zero() -> BLSScalar {
    BLSScalar(Scalar::zero())
  }

  fn is_zero(&self) -> bool {
    self.0.is_zero()
  }
}

impl ScalarArithmetic for BLSScalar {
  fn add(&self, b: &BLSScalar) -> BLSScalar {
    BLSScalar(self.0.add(&b.0))
  }

  fn add_assign(&mut self, b: &BLSScalar) {
    (self.0).add_assign(&b.0);
  }

  fn mul(&self, b: &BLSScalar) -> BLSScalar {
    BLSScalar(self.0.mul(&b.0))
  }

  fn mul_assign(&mut self, b: &BLSScalar) {
    (self.0).mul_assign(&b.0);
  }

  fn sub(&self, b: &BLSScalar) -> BLSScalar {
    BLSScalar(self.0.sub(&b.0))
  }

  fn sub_assign(&mut self, b: &BLSScalar) {
    (self.0).sub_assign(&b.0);
  }

  fn inv(&self) -> Result<BLSScalar, AlgebraError> {
    let a = self.0.invert();
    if bool::from(a.is_none()) {
      return Err(AlgebraError::GroupInversionError);
    }
    Ok(BLSScalar(a.unwrap()))
  }

  fn neg(&self) -> Self {
    Self(self.0.neg())
  }

  fn pow(&self, exponent: &[u64]) -> Self {
    let len = exponent.len();
    let mut array = [0u64; 4];
    array[..len].copy_from_slice(&exponent[..]);
    Self(self.0.pow(&array))
  }
}

impl ZeiScalar for BLSScalar {
  // scalar generation
  fn random<R: CryptoRng + RngCore>(rng: &mut R) -> BLSScalar {
    BLSScalar(Scalar::random(rng))
  }

  fn from_u32(value: u32) -> BLSScalar {
    Self::from_u64(value as u64)
  }

  fn from_u64(value: u64) -> BLSScalar {
    BLSScalar(bls12_381::Scalar::from(value))
  }

  fn from_hash<D>(hash: D) -> BLSScalar
    where D: Digest<OutputSize = U64> + Default
  {
    let mut prng = derive_prng_from_hash::<D, ChaCha20Rng>(hash);
    Self::random(&mut prng)
  }

  fn multiplicative_generator() -> Self {
    BLSScalar(Scalar::multiplicative_generator())
  }
  // scalar field size
  fn get_field_size_lsf_bytes() -> Vec<u8> {
    [0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd,
     0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7,
     0xed, 0x73].to_vec()
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
    BLS_SCALAR_LEN
  }
  //scalar serialization
  fn to_bytes(&self) -> Vec<u8> {
    self.0.to_bytes().to_vec()
  }

  fn from_bytes(bytes: &[u8]) -> Result<BLSScalar, AlgebraError> {
    if bytes.len() != BLS_SCALAR_LEN {
      return Err(AlgebraError::ParameterError);
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    let scalar = bls12_381::Scalar::from_bytes(&array);
    if bool::from(scalar.is_none()) {
      return Err(AlgebraError::SerializationError);
    }
    Ok(BLSScalar(scalar.unwrap()))
  }

  fn from_le_bytes(bytes: &[u8]) -> Result<BLSScalar, AlgebraError> {
    if bytes.len() > Self::bytes_len() {
      return Err(AlgebraError::DeserializationError);
    }
    let mut array = vec![0u8; Self::bytes_len()];
    array[0..bytes.len()].copy_from_slice(bytes);
    Self::from_bytes(&array)
  }
}

impl Group for BLSG1 {
  const COMPRESSED_LEN: usize = 48;

  fn get_identity() -> BLSG1 {
    BLSG1(bls12_381::G1Projective::identity())
  }
  fn get_base() -> BLSG1 {
    BLSG1(bls12_381::G1Projective::generator())
  }

  /// Pick a random base/generator inside BLSG1
  /// Note that BLSG1 is of prime order q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
  /// and thus any scalar sampled at random (except 0 which only happens with very low probability) will be coprime with q.
  fn get_random_base<R: CryptoRng + RngCore>(prng: &mut R) -> BLSG1 {
    Self::get_base().mul(&BLSScalar::random(prng))
  }

  // compression/serialization helpers
  fn to_compressed_bytes(&self) -> Vec<u8> {
    let affine = G1Affine::from(&self.0);
    affine.to_compressed().to_vec()
  }
  fn from_compressed_bytes(bytes: &[u8]) -> Result<BLSG1, AlgebraError> {
    let mut array = [0u8; Self::COMPRESSED_LEN];
    array.copy_from_slice(bytes);
    let affine = bls12_381::G1Affine::from_compressed(&array);
    if bool::from(affine.is_none()) {
      return Err(AlgebraError::DeserializationError);
    }
    let projective = G1Projective::from(affine.unwrap());
    Ok(BLSG1(projective))
  }

  fn from_hash<D>(hash: D) -> BLSG1
    where D: Digest<OutputSize = U64> + Default
  {
    let mut prng = derive_prng_from_hash::<D, ChaCha20Rng>(hash);
    BLSG1(bls12_381::G1Projective::random(&mut prng))
  }
}

impl GroupArithmetic for BLSG1 {
  type S = BLSScalar;
  //arithmetic
  fn mul(&self, other: &BLSScalar) -> BLSG1 {
    BLSG1(self.0.mul(&other.0))
  }
  fn add(&self, other: &Self) -> BLSG1 {
    BLSG1(self.0.add(&other.0))
  }
  fn sub(&self, other: &Self) -> BLSG1 {
    BLSG1(self.0.sub(&other.0))
  }
  fn double(&self) -> BLSG1 {
    BLSG1(self.0.double())
  }
}

impl Group for BLSG2 {
  const COMPRESSED_LEN: usize = 96;

  fn get_identity() -> BLSG2 {
    BLSG2(G2Projective::identity())
  }
  fn get_base() -> BLSG2 {
    BLSG2(G2Projective::generator())
  }

  /// Pick a random base/generator inside BLSG2
  /// Note that BLSG2 is of prime order q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
  /// and thus any scalar sampled at random (except 0 which only happens with very low probability) will be coprime with q.
  fn get_random_base<R: CryptoRng + RngCore>(prng: &mut R) -> BLSG2 {
    Self::get_base().mul(&BLSScalar::random(prng))
  }

  fn to_compressed_bytes(&self) -> Vec<u8> {
    let affine = G2Affine::from(&self.0);
    affine.to_compressed().to_vec()
  }

  fn from_compressed_bytes(bytes: &[u8]) -> Result<BLSG2, AlgebraError> {
    let mut array = [0u8; Self::COMPRESSED_LEN];
    array.copy_from_slice(bytes);
    let affine = bls12_381::G2Affine::from_compressed(&array);
    if bool::from(affine.is_none()) {
      return Err(AlgebraError::DeserializationError);
    }
    let projective = G2Projective::from(affine.unwrap());
    Ok(BLSG2(projective))
  }
  fn from_hash<D>(hash: D) -> BLSG2
    where D: Digest<OutputSize = U64> + Default
  {
    let mut prng = derive_prng_from_hash::<D, ChaCha20Rng>(hash);
    BLSG2(G2Projective::random(&mut prng))
  }
}

impl GroupArithmetic for BLSG2 {
  type S = BLSScalar;
  //arithmetic
  fn mul(&self, other: &BLSScalar) -> BLSG2 {
    BLSG2(self.0.mul(&other.0))
  }
  fn add(&self, other: &Self) -> BLSG2 {
    BLSG2(self.0.add(&other.0))
  }
  fn sub(&self, other: &Self) -> BLSG2 {
    BLSG2(self.0.sub(&other.0))
  }
  fn double(&self) -> BLSG2 {
    BLSG2(self.0.double())
  }
}

pub struct Bls12381;

impl Pairing for Bls12381 {
  type ScalarField = BLSScalar;
  type G1 = BLSG1;
  type G2 = BLSG2;
  type Gt = BLSGt;

  fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt {
    BLSGt(pairing(&G1Affine::from(a.0), &G2Affine::from(b.0)))
  }
}

impl GroupArithmetic for BLSGt {
  type S = BLSScalar;
  fn mul(&self, scalar: &BLSScalar) -> Self {
    let r = self.0.mul(scalar.0);
    BLSGt(r)
  }
  fn add(&self, other: &Self) -> Self {
    let r = self.0.add(other.0);
    BLSGt(r)
  }
  fn sub(&self, other: &Self) -> Self {
    BLSGt(self.0.sub(&other.0))
  }
  fn double(&self) -> BLSGt {
    BLSGt(self.0.double())
  }
}

impl Group for BLSGt {
  const COMPRESSED_LEN: usize = 576;

  fn get_identity() -> BLSGt {
    BLSGt(Gt::identity())
  }

  fn get_base() -> Self {
    BLSGt(Gt::generator())
  }

  // TODO: Implement
  fn to_compressed_bytes(&self) -> Vec<u8> {
    unimplemented!()
  }

  // TODO: Implement
  fn from_compressed_bytes(_bytes: &[u8]) -> Result<Self, AlgebraError> {
    unimplemented!()
  }

  fn from_hash<D>(hash: D) -> Self
    where D: Digest<OutputSize = U64> + Default
  {
    let mut prng = derive_prng_from_hash::<D, ChaCha20Rng>(hash);
    BLSGt(Gt::random(&mut prng))
  }
}

#[cfg(test)]
mod bls12_381_groups_test {
  use crate::bls12_381::{BLSGt, BLSScalar, Bls12381, BLSG1, BLSG2};
  use crate::groups::group_tests::{test_scalar_operations, test_scalar_serialization};
  use crate::groups::{Group, Scalar};
  use crate::pairing::Pairing;

  #[test]
  fn test_scalar_ops() {
    test_scalar_operations::<super::BLSScalar>();
  }

  #[test]
  fn scalar_deser() {
    test_scalar_serialization::<super::BLSScalar>();
  }

  #[test]
  fn scalar_from_to_bytes() {
    let small_value = BLSScalar::from_u32(165747);
    let small_value_bytes = small_value.to_bytes();
    let expected_small_value_bytes: [u8; 32] = [115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(small_value_bytes, expected_small_value_bytes);

    let small_value_from_bytes = BLSScalar::from_bytes(&small_value_bytes).unwrap();
    assert_eq!(small_value_from_bytes, small_value);
  }

  #[test]
  fn hard_coded_group_elements() {
    // BLSGt
    let base_bls_gt = BLSGt::get_base();
    let expected_base = Bls12381::pairing(&BLSG1::get_base(), &BLSG2::get_base());
    assert_eq!(base_bls_gt, expected_base);
  }
}
