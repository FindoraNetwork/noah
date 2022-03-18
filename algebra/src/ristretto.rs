use crate::{
    errors::AlgebraError,
    groups::{Group, GroupArithmetic},
    groups::{One, Scalar as ZeiScalar, ScalarArithmetic, Zero},
};
use ark_std::{
    ops::{AddAssign, MulAssign, SubAssign},
    rand::{CryptoRng, RngCore},
};
use byteorder::ByteOrder;
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT},
    edwards::{CompressedEdwardsY as CEY, EdwardsPoint},
    ristretto::{CompressedRistretto as CR, RistrettoPoint as RPoint},
    scalar::Scalar,
    traits::Identity,
};
use digest::{generic_array::typenum::U64, Digest};
use ruc::*;

/// The number of bytes for a scalar value over BLS12-381
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
    #[inline]
    fn from(x: u128) -> Self {
        Self(Scalar::from(x))
    }
}

impl One for RistrettoScalar {
    #[inline]
    fn one() -> Self {
        Self(Scalar::one())
    }
}

impl Zero for RistrettoScalar {
    #[inline]
    fn zero() -> Self {
        Self(Scalar::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.eq(&Scalar::zero())
    }
}

impl ScalarArithmetic for RistrettoScalar {
    #[inline]
    fn add(&self, b: &Self) -> Self {
        Self(self.0 + b.0)
    }

    #[inline]
    fn add_assign(&mut self, b: &Self) {
        (self.0).add_assign(&b.0);
    }

    #[inline]
    fn mul(&self, b: &Self) -> Self {
        Self(self.0 * b.0)
    }

    #[inline]
    fn mul_assign(&mut self, b: &Self) {
        (self.0).mul_assign(&b.0);
    }

    #[inline]
    fn sub(&self, b: &Self) -> Self {
        Self(self.0 - b.0)
    }

    #[inline]
    fn sub_assign(&mut self, b: &Self) {
        (self.0).sub_assign(&b.0);
    }

    #[inline]
    fn inv(&self) -> Result<Self> {
        Ok(Self(self.0.invert()))
    }
}

impl ZeiScalar for RistrettoScalar {
    #[inline]
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(Scalar::random(rng))
    }

    #[inline]
    fn from_u32(x: u32) -> Self {
        Self(Scalar::from(x))
    }

    #[inline]
    fn from_u64(x: u64) -> Self {
        Self(Scalar::from(x))
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        Self(Scalar::from_hash(hash))
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self(Scalar::from(2u8))
    }

    #[inline]
    // Ristretto scalar field size: 2**252 + 27742317777372353535851937790883648493
    fn get_field_size_lsf_bytes() -> Vec<u8> {
        [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
            0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ]
        .to_vec()
    }

    #[inline]
    fn get_little_endian_u64(&self) -> Vec<u64> {
        let mut r = vec![0u64; 4];
        byteorder::LittleEndian::read_u64_into(self.0.as_bytes(), &mut r[0..4]);
        r
    }

    #[inline]
    fn bytes_len() -> usize {
        RISTRETTO_SCALAR_LEN
    }

    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(self.0.as_bytes());
        v
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RISTRETTO_SCALAR_LEN {
            return Err(eg!(AlgebraError::ParameterError));
        }
        let mut array = [0u8; RISTRETTO_SCALAR_LEN];
        array.copy_from_slice(bytes);
        Ok(Self(Scalar::from_bits(array)))
    }

    #[inline]
    fn from_le_bytes(bytes: &[u8]) -> Result<Self> {
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
    #[inline]
    pub fn random_scalar_with_compressed_edwards<R: CryptoRng + RngCore>(
        prng: &mut R,
    ) -> (Self, CompressedEdwardsY) {
        let r = Self::random(prng);
        let r_mul_edwards_base = CompressedEdwardsY::scalar_mul_basepoint(&r);
        (r, r_mul_edwards_base)
    }
}

impl RistrettoPoint {
    #[inline]
    pub fn compress(&self) -> CompressedRistretto {
        CompressedRistretto(self.0.compress())
    }
}

impl CompressedRistretto {
    #[inline]
    pub fn decompress(&self) -> Option<RistrettoPoint> {
        self.0.decompress().map(RistrettoPoint)
    }
    #[inline]
    pub fn identity() -> Self {
        Self(CR::identity())
    }
}

impl CompressedEdwardsY {
    /// builds a `CompressedEdwardsY` from slice of bytes
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(CEY::from_slice(bytes))
    }

    #[inline]
    pub fn decompress(&self) -> Option<EdwardsPoint> {
        self.0.decompress()
    }

    /// returns compressed edwards point of (`ED25519_BASEPOINT_POINT` ^ s)
    #[inline]
    pub fn scalar_mul_basepoint(s: &RistrettoScalar) -> Self {
        Self((s.0 * ED25519_BASEPOINT_POINT).compress())
    }
}

impl Group for RistrettoPoint {
    const COMPRESSED_LEN: usize = 32;

    #[inline]
    fn get_identity() -> Self {
        Self(RPoint::identity())
    }

    #[inline]
    fn get_base() -> Self {
        Self(RISTRETTO_BASEPOINT_POINT)
    }

    #[inline]
    fn get_random_base<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(RISTRETTO_BASEPOINT_POINT * Scalar::random(rng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(self.0.compress().as_bytes());
        v
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            CR::from_slice(bytes)
                .decompress()
                .ok_or(eg!(AlgebraError::DecompressElementError))?,
        ))
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        Self(RPoint::from_hash(hash))
    }
}

impl GroupArithmetic for RistrettoPoint {
    type S = RistrettoScalar;

    #[inline]
    fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    #[inline]
    fn sub(&self, other: &Self) -> Self {
        Self(self.0 - other.0)
    }

    #[inline]
    fn mul(&self, scalar: &RistrettoScalar) -> Self {
        Self(self.0 * scalar.0)
    }

    #[inline]
    fn double(&self) -> Self {
        Self(self.0 + self.0)
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
