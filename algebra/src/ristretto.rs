use crate::errors::AlgebraError;
use crate::groups::Scalar as ZeiScalar;
use crate::groups::{Group, GroupArithmetic};
use byteorder::ByteOrder;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto as CR, RistrettoPoint as RPoint};
use curve25519_dalek::traits::Identity;
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RistrettoScalar(pub Scalar);

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CompressedRistretto(pub CR);

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RistrettoPoint(pub RPoint);

impl From<u128> for RistrettoScalar {
  fn from(x: u128) -> Self {
    RistrettoScalar(curve25519_dalek::scalar::Scalar::from(x))
  }
}

impl ZeiScalar for RistrettoScalar {
  fn random<R: CryptoRng + RngCore>(rng: &mut R) -> RistrettoScalar {
    RistrettoScalar(curve25519_dalek::scalar::Scalar::random(rng))
  }

  fn from_u32(x: u32) -> RistrettoScalar {
    RistrettoScalar(Scalar::from(x))
  }

  fn from_u64(x: u64) -> RistrettoScalar {
    RistrettoScalar(Scalar::from(x))
  }

  fn from_hash<D>(hash: D) -> RistrettoScalar
    where D: Digest<OutputSize = U64> + Default
  {
    RistrettoScalar(Scalar::from_hash(hash))
  }

  fn add(&self, b: &RistrettoScalar) -> RistrettoScalar {
    RistrettoScalar(self.0 + b.0)
  }

  fn mul(&self, b: &RistrettoScalar) -> RistrettoScalar {
    RistrettoScalar(self.0 * b.0)
  }

  fn sub(&self, b: &RistrettoScalar) -> RistrettoScalar {
    RistrettoScalar(self.0 - b.0)
  }

  fn inv(&self) -> Result<RistrettoScalar, AlgebraError> {
    Ok(RistrettoScalar(self.0.invert()))
  }

  fn get_little_endian_u64(&self) -> Vec<u64> {
    let mut r = vec![0u64; 4];
    byteorder::LittleEndian::read_u64_into(self.0.as_bytes(), &mut r[0..4]);
    r
  }

  fn to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(self.0.as_bytes());
    v
  }

  fn from_bytes(bytes: &[u8]) -> Result<RistrettoScalar, AlgebraError> {
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    Ok(RistrettoScalar(Scalar::from_bits(array)))
  }
}

impl RistrettoPoint {
  pub fn compress(&self) -> CompressedRistretto {
    CompressedRistretto(self.0.compress())
  }
}

impl CompressedRistretto {
  pub fn decompress(&self) -> Option<RistrettoPoint> {
    self.0.decompress().map(|x| RistrettoPoint(x))
  }
  pub fn identity() -> CompressedRistretto {
    CompressedRistretto(CR::identity())
  }
}

impl Group for RistrettoPoint {
  const COMPRESSED_LEN: usize = 32;

  fn get_identity() -> RistrettoPoint {
    RistrettoPoint(RPoint::identity())
  }

  fn get_base() -> RistrettoPoint {
    RistrettoPoint(RISTRETTO_BASEPOINT_POINT)
  }

  fn to_compressed_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(self.0.compress().as_bytes());
    v
  }

  fn from_compressed_bytes(bytes: &[u8]) -> Result<RistrettoPoint, AlgebraError> {
    Ok(RistrettoPoint(CR::from_slice(bytes).decompress()
      .ok_or(AlgebraError::DecompressElementError)?))
  }

  fn from_hash<D>(hash: D) -> RistrettoPoint
    where D: Digest<OutputSize = U64> + Default
  {
    RistrettoPoint(RPoint::from_hash(hash))
  }
}

impl GroupArithmetic for RistrettoPoint {
  type S = RistrettoScalar;
  fn mul(&self, scalar: &RistrettoScalar) -> Self {
    RistrettoPoint(self.0 * scalar.0)
  }

  fn add(&self, other: &RistrettoPoint) -> RistrettoPoint {
    RistrettoPoint(self.0 + other.0)
  }

  fn sub(&self, other: &RistrettoPoint) -> RistrettoPoint {
    RistrettoPoint(self.0 - other.0)
  }
}

#[cfg(test)]
mod ristretto_group_test {
  use crate::groups::group_tests::{test_scalar_operations, test_scalar_serialization};

  #[test]
  fn scalar_ops() {
    test_scalar_operations::<super::RistrettoScalar>();
  }
  #[test]
  fn scalar_serialization() {
    test_scalar_serialization::<super::RistrettoScalar>();
  }
  #[test]
  fn scalar_to_radix() {
    crate::groups::group_tests::test_to_radix::<super::RistrettoScalar>();
  }
}
