use crate::algebra::groups::Group;
use crate::algebra::groups::Scalar as ZeiScalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul, VartimeMultiscalarMul};
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

  fn sub(&self, b: &Scalar) -> Scalar{
    self - b
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

  fn multi_exp(scalars: &[Scalar], points:&[Self]) -> Self{
    RistrettoPoint::multiscalar_mul(scalars, points)
  }
  fn vartime_multi_exp(scalars: &[Scalar], points:&[Self]) -> Self{
    RistrettoPoint::vartime_multiscalar_mul(scalars,points)
  }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RistScalar(pub Scalar);

impl RistScalar {
  pub fn get_scalar(&self) -> Scalar {
    self.0
  }
}

impl ZeiScalar for RistScalar {
  fn random_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> RistScalar {
    RistScalar(Scalar::random(rng))
  }

  fn from_u32(x: u32) -> RistScalar {
    RistScalar(Scalar::from(x))
  }

  fn from_u64(x: u64) -> RistScalar {
    RistScalar(Scalar::from(x))
  }

  fn from_hash<D>(hash: D) -> RistScalar
    where D: Digest<OutputSize = U64> + Default
  {
    RistScalar(Scalar::from_hash(hash))
  }

  fn add(&self, b: &RistScalar) -> RistScalar {
    RistScalar(self.0 + b.0)
  }

  fn mul(&self, b: &RistScalar) -> RistScalar {
    RistScalar(self.0 * b.0)
  }

  fn sub(&self, b: &RistScalar) -> RistScalar{
    RistScalar(self.0 - b.0)
  }

  fn to_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(self.0.as_bytes());
    v
  }

  fn from_bytes(bytes: &[u8]) -> RistScalar {
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    RistScalar(Scalar::from_bits(array))
  }
}

impl Serialize for RistScalar {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
  {
    if serializer.is_human_readable() {
      serializer.serialize_str(&base64::encode(self.to_bytes().as_slice()))
    } else {
      serializer.serialize_bytes(self.to_bytes().as_slice())
    }
  }
}

impl<'de> Deserialize<'de> for RistScalar {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de>
  {
    struct RistScalarVisitor;

    impl<'de> Visitor<'de> for RistScalarVisitor {
      type Value = RistScalar;

      fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        formatter.write_str("a encoded Ristretto Scalar")
      }

      fn visit_bytes<E>(self, v: &[u8]) -> Result<RistScalar, E>
        where E: serde::de::Error
      {
        Ok(RistScalar::from_bytes(v))
      }

      fn visit_seq<V>(self, mut seq: V) -> Result<RistScalar, V::Error>
        where V: SeqAccess<'de>
      {
        let mut vec: Vec<u8> = vec![];
        while let Some(x) = seq.next_element().unwrap() {
          vec.push(x);
        }
        Ok(RistScalar::from_bytes(vec.as_slice()))
      }
      fn visit_str<E>(self, s: &str) -> Result<RistScalar, E>
        where E: serde::de::Error
      {
        self.visit_bytes(&base64::decode(s).map_err(serde::de::Error::custom)?)
      }
    }
    if deserializer.is_human_readable() {
      deserializer.deserialize_str(RistScalarVisitor)
    } else {
      deserializer.deserialize_bytes(RistScalarVisitor)
    }
  }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RistPoint(pub RistrettoPoint);

impl RistPoint {
  pub fn get_ristretto_point(&self) -> RistrettoPoint {
    self.0
  }
}

impl Group<RistScalar> for RistPoint {
  const COMPRESSED_LEN: usize = 32;
  const SCALAR_BYTES_LEN: usize = 32;

  fn get_identity() -> RistPoint {
    RistPoint(RistrettoPoint::identity())
  }

  fn get_base() -> RistPoint {
    RistPoint(RISTRETTO_BASEPOINT_POINT)
  }

  fn from_hash<D>(hash: D) -> Self
    where D: Digest<OutputSize = U64> + Default
  {
    RistPoint(RistrettoPoint::from_hash(hash))
  }

  fn to_compressed_bytes(&self) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(self.0.compress().as_bytes());
    v
  }

  fn from_compressed_bytes(bytes: &[u8]) -> Option<RistPoint> {
    match CompressedRistretto::from_slice(bytes).decompress() {
      None => None,
      Some(x) => Some(RistPoint(x)),
    }
  }

  fn mul(&self, scalar: &RistScalar) -> Self {
    RistPoint(self.0 * scalar.0)
  }

  fn add(&self, other: &RistPoint) -> RistPoint {
    RistPoint(self.0 + other.0)
  }

  fn sub(&self, other: &RistPoint) -> RistPoint {
    RistPoint(self.0 - other.0)
  }

  fn multi_exp(scalars: &[RistScalar], points:&[Self]) -> Self{
    let s: Vec<Scalar> = scalars.iter().map(|x| x.0).collect();
    let p: Vec<RistrettoPoint> = points.iter().map(|x| x.0).collect();
    RistPoint(RistrettoPoint::multiscalar_mul(s, p))
  }
  fn vartime_multi_exp(scalars: &[RistScalar], points:&[Self]) -> Self{
    let s: Vec<Scalar> = scalars.iter().map(|x| x.0).collect();
    let p: Vec<RistrettoPoint> = points.iter().map(|x| x.0).collect();
    RistPoint(RistrettoPoint::vartime_multiscalar_mul(s,p))
  }
}

impl Serialize for RistPoint {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
  {
    if serializer.is_human_readable() {
      serializer.serialize_str(&base64::encode(self.to_compressed_bytes().as_slice()))
    } else {
      serializer.serialize_bytes(self.to_compressed_bytes().as_slice())
    }
  }
}

impl<'de> Deserialize<'de> for RistPoint {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de>
  {
    struct RistPointVisitor;

    impl<'de> Visitor<'de> for RistPointVisitor {
      type Value = RistPoint;

      fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        formatter.write_str("a encoded Ristretto Point")
      }

      fn visit_bytes<E>(self, v: &[u8]) -> Result<RistPoint, E>
        where E: serde::de::Error
      {
        Ok(RistPoint::from_compressed_bytes(v).unwrap())
      }

      fn visit_seq<V>(self, mut seq: V) -> Result<RistPoint, V::Error>
        where V: SeqAccess<'de>
      {
        let mut vec: Vec<u8> = vec![];
        while let Some(x) = seq.next_element().unwrap() {
          vec.push(x);
        }
        Ok(RistPoint::from_compressed_bytes(vec.as_slice()).unwrap())
      }
      fn visit_str<E>(self, s: &str) -> Result<RistPoint, E>
        where E: serde::de::Error
      {
        self.visit_bytes(&base64::decode(s).map_err(serde::de::Error::custom)?)
      }
    }
    if deserializer.is_human_readable() {
      deserializer.deserialize_str(RistPointVisitor)
    } else {
      deserializer.deserialize_bytes(RistPointVisitor)
    }
  }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CompRist(pub CompressedRistretto);

impl CompRist {
  pub fn decompress_to_ristretto(&self) -> Option<RistrettoPoint> {
    self.0.decompress()
  }
  pub fn get_compressed_ristretto(&self) -> CompressedRistretto {
    self.0
  }
}

impl Default for CompRist {
  fn default() -> CompRist {
    CompRist(CompressedRistretto::default())
  }
}

impl Serialize for CompRist {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
  {
    if serializer.is_human_readable() {
      serializer.serialize_str(&base64::encode(self.0.as_bytes()))
    } else {
      serializer.serialize_bytes(self.0.as_bytes())
    }
  }
}

impl<'de> Deserialize<'de> for CompRist {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de>
  {
    struct RistPointVisitor;

    impl<'de> Visitor<'de> for RistPointVisitor {
      type Value = CompRist;

      fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        formatter.write_str("a encoded Ristretto Point")
      }

      fn visit_bytes<E>(self, v: &[u8]) -> Result<CompRist, E>
        where E: serde::de::Error
      {
        Ok(CompRist(CompressedRistretto::from_slice(v)))
      }

      fn visit_seq<V>(self, mut seq: V) -> Result<CompRist, V::Error>
        where V: SeqAccess<'de>
      {
        let mut vec: Vec<u8> = vec![];
        while let Some(x) = seq.next_element().unwrap() {
          vec.push(x);
        }
        Ok(CompRist(CompressedRistretto::from_slice(vec.as_slice())))
      }
      fn visit_str<E>(self, s: &str) -> Result<CompRist, E>
        where E: serde::de::Error
      {
        self.visit_bytes(&base64::decode(s).map_err(serde::de::Error::custom)?)
      }
    }
    if deserializer.is_human_readable() {
      deserializer.deserialize_str(RistPointVisitor)
    } else {
      deserializer.deserialize_bytes(RistPointVisitor)
    }
  }
}

#[cfg(test)]
mod ristretto_group_test {
  use crate::algebra::groups::group_tests::{test_scalar_operations, test_scalar_serialization};
  #[test]
  fn scalar_ops() {
    test_scalar_operations::<super::Scalar>();
    test_scalar_operations::<super::RistScalar>();
  }
  #[test]
  fn scalar_serialization() {
    test_scalar_serialization::<super::Scalar>();
    test_scalar_serialization::<super::RistScalar>();
  }
}

#[cfg(test)]
mod elgamal_over_ristretto_tests {
  use super::{RistPoint, RistScalar};
  use crate::basic_crypto::elgamal::elgamal_test;
  use curve25519_dalek::ristretto::RistrettoPoint;
  use curve25519_dalek::scalar::Scalar;

  #[test]
  fn verification() {
    elgamal_test::verification::<Scalar, RistrettoPoint>();
    elgamal_test::verification::<RistScalar, RistPoint>();
  }

  #[test]
  fn decrypt() {
    elgamal_test::decryption::<Scalar, RistrettoPoint>();
    elgamal_test::decryption::<RistScalar, RistPoint>();
  }

  #[test]
  fn to_json() {
    elgamal_test::to_json::<RistScalar, RistPoint>();
  }

  #[test]
  fn to_message_pack() {
    elgamal_test::to_message_pack::<Scalar, RistrettoPoint>();
    elgamal_test::to_message_pack::<RistScalar, RistPoint>();
  }
}
