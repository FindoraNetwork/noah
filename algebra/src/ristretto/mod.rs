use crate::fmt::{Debug, Formatter};
use crate::prelude::*;
use crate::traits::PedersenCommitment;
use ark_ff::LegendreSymbol;
use ark_std::{vec, vec::Vec};
use byteorder::ByteOrder;
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT},
    edwards::{CompressedEdwardsY as CEY, EdwardsPoint},
    ristretto::{CompressedRistretto as CR, RistrettoPoint as RPoint},
    traits::Identity,
};
use digest::{generic_array::typenum::U64, Digest};
use num_bigint::BigUint;
use num_traits::Num;

/// The number of bytes for a scalar value over BLS12-381
pub const RISTRETTO_SCALAR_LEN: usize = 32;

/// The wrapped struct for `curve25519_dalek::scalar::Scalar`
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct RistrettoScalar(pub curve25519_dalek::scalar::Scalar);

/// The wrapped struct for `curve25519_dalek::ristretto::CompressedRistretto`
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CompressedRistretto(pub CR);

/// The wrapped struct for `curve25519_dalek::edwards::CompressedEdwardsY`
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CompressedEdwardsY(pub curve25519_dalek::edwards::CompressedEdwardsY);

/// The wrapped struct for `curve25519_dalek::ristretto::RistrettoPoint`
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RistrettoPoint(pub RPoint);

impl Debug for RistrettoScalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> ark_std::fmt::Result {
        <curve25519_dalek::scalar::Scalar as Debug>::fmt(&self.0, f)
    }
}

impl From<u128> for RistrettoScalar {
    #[inline]
    fn from(x: u128) -> Self {
        Self(curve25519_dalek::scalar::Scalar::from(x))
    }
}

impl One for RistrettoScalar {
    #[inline]
    fn one() -> Self {
        Self(curve25519_dalek::scalar::Scalar::one())
    }
}

impl Zero for RistrettoScalar {
    #[inline]
    fn zero() -> Self {
        Self(curve25519_dalek::scalar::Scalar::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.eq(&curve25519_dalek::scalar::Scalar::zero())
    }
}

impl Add for RistrettoScalar {
    type Output = RistrettoScalar;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Mul for RistrettoScalar {
    type Output = RistrettoScalar;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Sum<RistrettoScalar> for RistrettoScalar {
    #[inline]
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a> Add<&'a RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<'a> AddAssign<&'a RistrettoScalar> for RistrettoScalar {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<'a> SubAssign<&'a RistrettoScalar> for RistrettoScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<'a> MulAssign<&'a RistrettoScalar> for RistrettoScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl<'a> Sum<&'a RistrettoScalar> for RistrettoScalar {
    #[inline]
    fn sum<I: Iterator<Item = &'a RistrettoScalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl Neg for RistrettoScalar {
    type Output = RistrettoScalar;

    #[inline]
    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl From<u32> for RistrettoScalar {
    #[inline]
    fn from(value: u32) -> Self {
        Self(curve25519_dalek::scalar::Scalar::from(value))
    }
}

impl From<u64> for RistrettoScalar {
    #[inline]
    fn from(value: u64) -> Self {
        Self(curve25519_dalek::scalar::Scalar::from(value))
    }
}

impl From<RistrettoScalar> for BigUint {
    #[inline]
    fn from(val: RistrettoScalar) -> Self {
        BigUint::from_bytes_le(val.0.as_bytes())
    }
}

impl<'a> From<&'a BigUint> for RistrettoScalar {
    #[inline]
    fn from(x: &BigUint) -> Self {
        let biguint = x % RistrettoScalar::get_field_size_biguint();
        let raw_bytes = biguint.to_bytes_le();
        let n = core::cmp::min(raw_bytes.len(), RISTRETTO_SCALAR_LEN);

        let mut bytes = [0u8; 32];
        bytes[0..n].copy_from_slice(&raw_bytes[0..n]);

        Self(curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
            bytes,
        ))
    }
}

impl Scalar for RistrettoScalar {
    #[inline]
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(curve25519_dalek::scalar::Scalar::random(rng))
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        Self(curve25519_dalek::scalar::Scalar::from_hash(hash))
    }

    #[inline]
    fn capacity() -> usize {
        252
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self(curve25519_dalek::scalar::Scalar::from(2u8))
    }

    #[inline]
    fn get_field_size_biguint() -> BigUint {
        BigUint::from_str_radix(
            "7237005577332262213973186563042994240857116359379907606001950938285454250989",
            10,
        )
        .unwrap()
    }

    #[inline]
    fn get_field_size_le_bytes() -> Vec<u8> {
        // Ristretto scalar field size: 2**252 + 27742317777372353535851937790883648493
        [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
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
        self.0.as_bytes().to_vec()
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::bytes_len() {
            return Err(AlgebraError::DeserializationError);
        }
        let mut array = [0u8; RISTRETTO_SCALAR_LEN];
        array[0..bytes.len()].copy_from_slice(bytes);
        Ok(Self(curve25519_dalek::scalar::Scalar::from_bits(array)))
    }

    #[inline]
    fn inv(&self) -> Result<Self> {
        Ok(Self(self.0.invert()))
    }

    #[inline]
    fn square(&self) -> Self {
        *self * self
    }

    #[inline]
    fn legendre(&self) -> LegendreSymbol {
        let biguint: BigUint = (*self).into();
        crate::ed25519::Ed25519Scalar::from(&biguint).legendre()
    }

    #[inline]
    fn sqrt(&self) -> Option<Self> {
        let biguint: BigUint = (*self).into();

        crate::ed25519::Ed25519Scalar::from(&biguint)
            .sqrt()
            .map(|v| {
                let v: BigUint = v.0.into();
                Self::from(&v)
            })
    }

    #[inline]
    fn double(&self) -> Self {
        *self + self
    }
}

impl RistrettoScalar {
    /// Return a tuple of (r, g^r)
    /// where r is a random `RistrettoScalar`, and g is the `ED25519_BASEPOINT_POINT`
    #[inline]
    pub fn random_scalar_with_compressed_point<R: CryptoRng + RngCore>(
        prng: &mut R,
    ) -> (Self, CompressedEdwardsY) {
        let r = Self::random(prng);
        let r_mul_edwards_base = CompressedEdwardsY::scalar_mul_basepoint(&r);
        (r, r_mul_edwards_base)
    }
}

impl RistrettoPoint {
    /// Compress the point and output `CompressedRistretto`
    #[inline]
    pub fn compress(&self) -> CompressedRistretto {
        CompressedRistretto(self.0.compress())
    }
}

impl CompressedRistretto {
    /// Recover the point from the `CompressedRistretto`
    #[inline]
    pub fn decompress(&self) -> Option<RistrettoPoint> {
        self.0.decompress().map(RistrettoPoint)
    }

    /// Return the `CompressedRistretto` for the identity point
    #[inline]
    pub fn identity() -> Self {
        Self(CR::identity())
    }
}

impl CompressedEdwardsY {
    /// Build a `CompressedEdwardsY` from slice of bytes
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(CEY::from_slice(bytes))
    }

    /// Convert into bytes.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Recover the point from the `CompressedEdwardsY`
    #[inline]
    pub fn decompress(&self) -> Option<EdwardsPoint> {
        self.0.decompress()
    }

    /// Return compressed edwards point of (`ED25519_BASEPOINT_POINT` ^ s)
    #[inline]
    pub fn scalar_mul_basepoint(s: &RistrettoScalar) -> Self {
        Self((s.0 * ED25519_BASEPOINT_POINT).compress())
    }
}

impl Neg for RistrettoPoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Group for RistrettoPoint {
    type ScalarType = RistrettoScalar;
    const COMPRESSED_LEN: usize = 32;
    const UNCOMPRESSED_LEN: usize = 32;

    #[inline]
    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }

    #[inline]
    fn get_identity() -> Self {
        Self(RPoint::identity())
    }

    #[inline]
    fn get_base() -> Self {
        Self(RISTRETTO_BASEPOINT_POINT)
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(RPoint::random(rng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(self.0.compress().as_bytes());
        v
    }

    #[inline]
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(self.0.compress().as_bytes());
        v
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            CR::from_slice(bytes)
                .decompress()
                .ok_or(AlgebraError::DecompressElementError)?,
        ))
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            CR::from_slice(bytes)
                .decompress()
                .ok_or(AlgebraError::DecompressElementError)?,
        ))
    }

    #[inline]
    fn unchecked_size() -> usize {
        RISTRETTO_SCALAR_LEN
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        Self(RPoint::from_hash(hash))
    }
}

impl<'a> Add<&'a RistrettoPoint> for RistrettoPoint {
    type Output = RistrettoPoint;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a RistrettoPoint> for RistrettoPoint {
    type Output = RistrettoPoint;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<'a> Mul<&'a RistrettoScalar> for RistrettoPoint {
    type Output = RistrettoPoint;

    #[inline]
    fn mul(self, rhs: &RistrettoScalar) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<'a> Mul<&'a RistrettoScalar> for CompressedEdwardsY {
    type Output = CompressedEdwardsY;

    #[inline]
    fn mul(self, rhs: &RistrettoScalar) -> Self::Output {
        let p = self.decompress().unwrap().mul(rhs.0);
        CompressedEdwardsY(p.compress())
    }
}

impl<'a> AddAssign<&'a RistrettoPoint> for RistrettoPoint {
    #[inline]
    fn add_assign(&mut self, rhs: &RistrettoPoint) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a RistrettoPoint> for RistrettoPoint {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a RistrettoPoint) {
        self.0.sub_assign(&rhs.0)
    }
}

impl<'a> MulAssign<&'a RistrettoScalar> for RistrettoPoint {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a RistrettoScalar) {
        self.0.mul_assign(rhs.0)
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// The Pedersen commitment implementation for the Ristretto group.
pub struct PedersenCommitmentRistretto {
    /// The generator for the value part.
    pub B: RistrettoPoint,
    /// The generator for the blinding part.
    pub B_blinding: RistrettoPoint,
}

impl Default for PedersenCommitmentRistretto {
    fn default() -> Self {
        let pc_gens = bulletproofs::PedersenGens::default();
        Self {
            B: RistrettoPoint(pc_gens.B),
            B_blinding: RistrettoPoint(pc_gens.B_blinding),
        }
    }
}
impl PedersenCommitment<RistrettoPoint> for PedersenCommitmentRistretto {
    fn generator(&self) -> RistrettoPoint {
        self.B
    }

    fn blinding_generator(&self) -> RistrettoPoint {
        self.B_blinding
    }

    fn commit(&self, value: RistrettoScalar, blinding: RistrettoScalar) -> RistrettoPoint {
        RistrettoPoint(
            curve25519_dalek::ristretto::RistrettoPoint::multiscalar_mul(
                &[value.0, blinding.0],
                &[self.B.0, self.B_blinding.0],
            ),
        )
    }
}

impl From<&PedersenCommitmentRistretto> for bulletproofs::PedersenGens {
    fn from(rp: &PedersenCommitmentRistretto) -> Self {
        bulletproofs::PedersenGens {
            B: rp.B.0,
            B_blinding: rp.B_blinding.0,
        }
    }
}

#[cfg(test)]
mod ristretto_group_test {
    use crate::traits::group_tests::{test_scalar_operations, test_scalar_serialization};

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
        crate::traits::group_tests::test_to_radix::<super::RistrettoScalar>();
    }
}
