use crate::groups::Scalar as ZeiScalar;
use crate::groups::{Group, GroupArithmetic};
use crate::errors::AlgebraError;
use byteorder::ByteOrder;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};

impl ZeiScalar for Scalar {
  fn random_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Scalar {
    Scalar::random(rng)
  }

  fn from_u32(x: u32) -> Scalar {
    Scalar::from(x)
  }

  fn from_u64(x: u64) -> Scalar {
    Scalar::from(x)
  }

  fn from_hash<D>(hash: D) -> Scalar
    where D: Digest<OutputSize = U64> + Default
  {
    Scalar::from_hash(hash)
  }

  fn add(&self, b: &Scalar) -> Scalar {
    self + b
  }

  fn mul(&self, b: &Scalar) -> Scalar {
    self * b
  }

  fn sub(&self, b: &Scalar) -> Scalar {
    self - b
  }

  fn inv(&self) -> Result<Scalar, AlgebraError> {
    Ok(self.invert())
  }

  fn get_little_endian_u64(&self) -> Vec<u64> {
    let mut r = vec![0u64; 4];
    byteorder::LittleEndian::read_u64_into(self.as_bytes(), &mut r[0..4]);
    r
  }

  fn to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(self.as_bytes());
    v
  }

  fn from_bytes(bytes: &[u8]) -> Result<Scalar, AlgebraError> {
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    Ok(Scalar::from_bits(array))
  }
}
impl Group for RistrettoPoint {
  const COMPRESSED_LEN: usize = 32;
  const SCALAR_BYTES_LEN: usize = 32;

  fn get_identity() -> RistrettoPoint {
    RistrettoPoint::identity()
  }

  fn get_base() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
  }

  fn to_compressed_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(self.compress().as_bytes());
    v
  }

  fn from_compressed_bytes(bytes: &[u8]) -> Result<RistrettoPoint, AlgebraError> {
    Ok(CompressedRistretto::from_slice(bytes).decompress()
                                             .ok_or(AlgebraError::DecompressElementError)?)
  }

  fn from_hash<D>(hash: D) -> RistrettoPoint
    where D: Digest<OutputSize = U64> + Default
  {
    RistrettoPoint::from_hash(hash)
  }
}

impl GroupArithmetic for RistrettoPoint {
  type S = Scalar;
  fn mul(&self, scalar: &Scalar) -> Self {
    self * scalar
  }

  fn add(&self, other: &RistrettoPoint) -> RistrettoPoint {
    self + other
  }

  fn sub(&self, other: &RistrettoPoint) -> RistrettoPoint {
    self - other
  }
}

#[cfg(test)]
mod ristretto_group_test {
  use crate::groups::group_tests::{test_scalar_operations, test_scalar_serialization};

  #[test]
  fn scalar_ops() {
    test_scalar_operations::<super::Scalar>();
  }
  #[test]
  fn scalar_serialization() {
    test_scalar_serialization::<super::Scalar>();
  }
  #[test]
  fn scalar_to_radix() {
    crate::groups::group_tests::test_to_radix::<super::Scalar>();
  }
}
