use crate::algebra::groups::Group;
use crate::algebra::groups::Scalar as ZeiScalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand::{CryptoRng, Rng};

impl ZeiScalar for Scalar {
  fn random_scalar<R: CryptoRng + Rng>(rng: &mut R) -> Scalar {
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

  fn to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(self.as_bytes());
    v
  }

  fn from_bytes(bytes: &[u8]) -> Scalar {
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    Scalar::from_bits(array)
  }
}
impl Group<Scalar> for RistrettoPoint {
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

  fn from_compressed_bytes(bytes: &[u8]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes).decompress()
  }

  fn from_hash<D>(hash: D) -> RistrettoPoint
    where D: Digest<OutputSize = U64> + Default
  {
    RistrettoPoint::from_hash(hash)
  }

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
  use crate::algebra::groups::group_tests::{test_scalar_operations, test_scalar_serialization};
  #[test]
  fn scalar_ops() {
    test_scalar_operations::<super::Scalar>();
  }
  #[test]
  fn scalar_serialization() {
    test_scalar_serialization::<super::Scalar>();
  }
}

#[cfg(test)]
mod elgamal_over_ristretto_tests {
  use crate::basic_crypto::elgamal::elgamal_test;
  use curve25519_dalek::ristretto::RistrettoPoint;
  use curve25519_dalek::scalar::Scalar;

  #[test]
  fn verification() {
    elgamal_test::verification::<Scalar, RistrettoPoint>();
  }

  #[test]
  fn decrypt() {
    elgamal_test::decryption::<Scalar, RistrettoPoint>();
  }

  /*
      #[test]
      fn to_json(){
          elgamal_test::to_json::<Scalar, RistrettoPoint>();
      }
  */

  #[test]
  fn to_message_pack() {
    elgamal_test::to_message_pack::<Scalar, RistrettoPoint>();
  }
}
