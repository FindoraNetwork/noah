use crate::errors::AlgebraError;
use crate::groups::{Group, GroupArithmetic};
use crate::groups::{One, Scalar as ZeiScalar, ScalarArithmetic, Zero};
use byteorder::ByteOrder;
use core::ops::{AddAssign, MulAssign, SubAssign};
use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::edwards::{CompressedEdwardsY as CEY, EdwardsPoint};
use curve25519_dalek::ristretto::{CompressedRistretto as CR, RistrettoPoint as RPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use ruc::*;

pub const RISTRETTO_SCALAR_LEN: usize = 32;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RistrettoScalar(pub Scalar);

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CompressedRistretto(pub CR);

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CompressedEdwardsY(pub curve25519_dalek::edwards::CompressedEdwardsY);

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RistrettoPoint(pub RPoint);

impl From<u128> for RistrettoScalar {
    fn from(x: u128) -> Self {
        RistrettoScalar(curve25519_dalek::scalar::Scalar::from(x))
    }
}

impl One for RistrettoScalar {
    fn one() -> RistrettoScalar {
        RistrettoScalar(Scalar::one())
    }
}

impl Zero for RistrettoScalar {
    fn zero() -> RistrettoScalar {
        RistrettoScalar(Scalar::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.eq(&Scalar::zero())
    }
}

impl ScalarArithmetic for RistrettoScalar {
    fn add(&self, b: &RistrettoScalar) -> RistrettoScalar {
        RistrettoScalar(self.0 + b.0)
    }

    fn add_assign(&mut self, b: &RistrettoScalar) {
        (self.0).add_assign(&b.0);
    }

    fn mul(&self, b: &RistrettoScalar) -> RistrettoScalar {
        RistrettoScalar(self.0 * b.0)
    }

    fn mul_assign(&mut self, b: &RistrettoScalar) {
        (self.0).mul_assign(&b.0);
    }

    fn sub(&self, b: &RistrettoScalar) -> RistrettoScalar {
        RistrettoScalar(self.0 - b.0)
    }

    fn sub_assign(&mut self, b: &RistrettoScalar) {
        (self.0).sub_assign(&b.0);
    }

    fn inv(&self) -> Result<RistrettoScalar> {
        Ok(RistrettoScalar(self.0.invert()))
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
    where
        D: Digest<OutputSize = U64> + Default,
    {
        RistrettoScalar(Scalar::from_hash(hash))
    }

    // TODO: Implement
    fn multiplicative_generator() -> Self {
        unimplemented!();
    }

    // scalar field size: 2**252 + 27742317777372353535851937790883648493
    fn get_field_size_lsf_bytes() -> Vec<u8> {
        [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
            0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ]
        .to_vec()
    }

    fn get_little_endian_u64(&self) -> Vec<u64> {
        let mut r = vec![0u64; 4];
        byteorder::LittleEndian::read_u64_into(self.0.as_bytes(), &mut r[0..4]);
        r
    }

    fn bytes_len() -> usize {
        RISTRETTO_SCALAR_LEN
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(self.0.as_bytes());
        v
    }

    fn from_bytes(bytes: &[u8]) -> Result<RistrettoScalar> {
        if bytes.len() != RISTRETTO_SCALAR_LEN {
            return Err(eg!(AlgebraError::ParameterError));
        }
        let mut array = [0u8; RISTRETTO_SCALAR_LEN];
        array.copy_from_slice(bytes);
        Ok(RistrettoScalar(Scalar::from_bits(array)))
    }

    fn from_le_bytes(bytes: &[u8]) -> Result<RistrettoScalar> {
        if bytes.len() > Self::bytes_len() {
            return Err(eg!(AlgebraError::DeserializationError));
        }
        let mut array = vec![0u8; Self::bytes_len()];
        array[0..bytes.len()].copy_from_slice(bytes);
        Self::from_bytes(&array)
    }
}

impl RistrettoScalar {
    /// returns a tuple of (r, g^r)
    /// where r is a random `RistrettoScalar`, and g is the `ED25519_BASEPOINT_POINT`
    pub fn random_scalar_with_compressed_edwards<R: CryptoRng + RngCore>(
        prng: &mut R,
    ) -> (Self, CompressedEdwardsY) {
        let r = RistrettoScalar::random(prng);
        let r_mul_edwards_base = CompressedEdwardsY::scalar_mul_basepoint(&r);
        (r, r_mul_edwards_base)
    }
}

impl RistrettoPoint {
    pub fn compress(&self) -> CompressedRistretto {
        CompressedRistretto(self.0.compress())
    }
}

impl CompressedRistretto {
    pub fn decompress(&self) -> Option<RistrettoPoint> {
        self.0.decompress().map(RistrettoPoint)
    }
    pub fn identity() -> CompressedRistretto {
        CompressedRistretto(CR::identity())
    }
}

impl CompressedEdwardsY {
    /// builds a `CompressedEdwardsY` from slice of bytes
    pub fn from_slice(bytes: &[u8]) -> Self {
        CompressedEdwardsY(CEY::from_slice(bytes))
    }

    pub fn decompress(&self) -> Option<EdwardsPoint> {
        self.0.decompress()
    }

    /// returns compressed edwards point of (`ED25519_BASEPOINT_POINT` ^ s)
    pub fn scalar_mul_basepoint(s: &RistrettoScalar) -> Self {
        CompressedEdwardsY((s.0 * ED25519_BASEPOINT_POINT).compress())
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

    fn from_compressed_bytes(bytes: &[u8]) -> Result<RistrettoPoint> {
        Ok(RistrettoPoint(
            CR::from_slice(bytes)
                .decompress()
                .ok_or(eg!(AlgebraError::DecompressElementError))?,
        ))
    }

    fn from_hash<D>(hash: D) -> RistrettoPoint
    where
        D: Digest<OutputSize = U64> + Default,
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

    fn double(&self) -> RistrettoPoint {
        RistrettoPoint(self.0 + self.0)
    }
}

#[cfg(test)]
mod ristretto_group_test {
    use crate::groups::group_tests::{
        test_scalar_operations, test_scalar_serialization,
    };

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
