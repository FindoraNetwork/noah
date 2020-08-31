use crate::errors::AlgebraError;
use crate::groups::GroupArithmetic;
use crate::groups::{Group, Scalar as ZeiScalar};
use crate::pairing::Pairing;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use digest::generic_array::typenum::U64;
use digest::Digest;
use ff::{Field, PrimeField};
use group::Group as _;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use std::ops::{Add, Mul, Sub};
use utils::{u8_littleendian_slice_to_u64};
use std::str::FromStr;

pub type Bls12381field = Scalar;

#[derive(Clone, PartialEq, Eq, Debug)]
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
impl BLSScalar {
  pub fn get_scalar(&self) -> Scalar {
    self.0
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
    let result = hash.result();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result[0..32]);
    let mut prng = rand_chacha::ChaChaRng::from_seed(seed);
    Self::random(&mut prng)
  }

  // scalar arithmetic
  fn add(&self, b: &BLSScalar) -> BLSScalar {
    BLSScalar(self.0.add(&b.0))
  }
  fn mul(&self, b: &BLSScalar) -> BLSScalar {
    BLSScalar(self.0.mul(&b.0))
  }

  fn sub(&self, b: &BLSScalar) -> BLSScalar {
    BLSScalar(self.0.sub(&b.0))
  }

  fn inv(&self) -> Result<BLSScalar, AlgebraError> {
    let a = self.0.invert();
    if bool::from(a.is_none()) {
      return Err(AlgebraError::GroupInversionError);
    }
    Ok(BLSScalar(a.unwrap()))
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
    self.0.to_bytes().to_vec()
  }

  fn from_bytes(bytes: &[u8]) -> Result<BLSScalar, AlgebraError> {
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    let scalar = bls12_381::Scalar::from_bytes(&array);
    if bool::from(scalar.is_none()) {
      return Err(AlgebraError::SerializationError);
    }
    Ok(BLSScalar(scalar.unwrap()))
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
    let result = hash.result();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result[0..32]);
    let mut prng = rand_chacha::ChaChaRng::from_seed(seed);
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
}

impl Group for BLSG2 {
  const COMPRESSED_LEN: usize = 96; // TODO

  fn get_identity() -> BLSG2 {
    BLSG2(G2Projective::identity())
  }
  fn get_base() -> BLSG2 {
    BLSG2(G2Projective::generator())
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
    let result = hash.result();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result[0..32]);
    let mut prng = rand_chacha::ChaChaRng::from_seed(seed);
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
}

impl Group for BLSGt {
  const COMPRESSED_LEN: usize = 576;

  fn get_identity() -> BLSGt {
    BLSGt(Gt::identity())
  }

  fn get_base() -> Self {
    BLSGt(Gt::generator())
  }

  fn to_compressed_bytes(&self) -> Vec<u8> {
    unimplemented!()
  }

  fn from_compressed_bytes(_bytes: &[u8]) -> Result<Self, AlgebraError> {
    unimplemented!()
  }

  fn from_hash<D>(hash: D) -> Self
    where D: Digest<OutputSize = U64> + Default
  {
    let result = hash.result();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result[0..32]);
    let mut prng = rand_chacha::ChaChaRng::from_seed(seed);
    BLSGt(Gt::random(&mut prng))
  }
}

#[cfg(test)]
mod bls12_381_groups_test {
  use crate::bls12_381::BLSScalar;
  use crate::groups::group_tests::{test_scalar_operations, test_scalar_serialization};
  use crate::groups::Scalar;

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
}
