use crate::bls12_381::BLS12_381_SCALAR_LEN;
use crate::errors::AlgebraError;
use crate::prelude::{derive_prng_from_hash, *};
use crate::traits::Domain;
use ark_bls12_381::{Fr, FrParameters};
use ark_ff::{BigInteger, BigInteger256, FftField, Field, FpParameters, PrimeField};
use ark_std::{
    fmt::{Debug, Formatter},
    result::Result as StdResult,
    str::FromStr,
};
use digest::{consts::U64, Digest};
use num_bigint::BigUint;
use num_traits::Num;
use wasm_bindgen::prelude::*;

/// The wrapped struct for `ark_bls12_381::Fr`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct BLSFr(pub(crate) Fr);

impl Debug for BLSFr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <BigUint as Debug>::fmt(
            &<BigInteger256 as Into<BigUint>>::into(self.0.into_repr()),
            f,
        )
    }
}

impl FromStr for BLSFr {
    type Err = AlgebraError;

    fn from_str(string: &str) -> StdResult<Self, AlgebraError> {
        let res = Fr::from_str(string);

        if res.is_ok() {
            Ok(Self(res.unwrap()))
        } else {
            Err(AlgebraError::DeserializationError)
        }
    }
}

impl BLSFr {
    /// Create a new scalar element from the arkworks-rs representation.
    pub const fn new(is_positive: bool, limbs: &[u64]) -> Self {
        type Params = <Fr as PrimeField>::Params;
        BLSFr(Fr::const_from_str(
            &limbs,
            is_positive,
            Params::R2,
            Params::MODULUS,
            Params::INV,
        ))
    }
}

impl Into<BigUint> for BLSFr {
    #[inline]
    fn into(self) -> BigUint {
        self.0.into_repr().into()
    }
}

impl<'a> From<&'a BigUint> for BLSFr {
    #[inline]
    fn from(src: &BigUint) -> Self {
        Self(Fr::from(src.clone()))
    }
}

impl One for BLSFr {
    #[inline]
    fn one() -> Self {
        BLSFr(Fr::one())
    }
}

impl Zero for BLSFr {
    #[inline]
    fn zero() -> Self {
        Self(Fr::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Add for BLSFr {
    type Output = BLSFr;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Mul for BLSFr {
    type Output = BLSFr;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Sum<BLSFr> for BLSFr {
    #[inline]
    fn sum<I: Iterator<Item = BLSFr>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a> Add<&'a BLSFr> for BLSFr {
    type Output = BLSFr;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> AddAssign<&'a BLSFr> for BLSFr {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a BLSFr> for BLSFr {
    type Output = BLSFr;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> SubAssign<&'a BLSFr> for BLSFr {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a BLSFr> for BLSFr {
    type Output = BLSFr;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> MulAssign<&'a BLSFr> for BLSFr {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl<'a> Sum<&'a BLSFr> for BLSFr {
    #[inline]
    fn sum<I: Iterator<Item = &'a BLSFr>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl Neg for BLSFr {
    type Output = BLSFr;

    #[inline]
    fn neg(self) -> Self {
        Self(self.0.neg())
    }
}

impl From<u32> for BLSFr {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<u64> for BLSFr {
    #[inline]
    fn from(value: u64) -> Self {
        Self(Fr::from(value))
    }
}

impl Scalar for BLSFr {
    #[inline]
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(Fr::rand(rng))
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        Self::random(&mut prng)
    }

    #[inline]
    fn capacity() -> usize {
        FrParameters::CAPACITY as usize
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self(Fr::multiplicative_generator())
    }

    #[inline]
    fn get_field_size_biguint() -> BigUint {
        BigUint::from_str_radix(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513",
            10,
        )
        .unwrap()
    }

    #[inline]
    fn get_field_size_le_bytes() -> Vec<u8> {
        [
            0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4,
            0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29,
            0x53, 0xa7, 0xed, 0x73,
        ]
        .to_vec()
    }

    #[inline]
    fn get_little_endian_u64(&self) -> Vec<u64> {
        let a = self.0.into_repr().to_bytes_le();
        let a1 = u8_le_slice_to_u64(&a[0..8]);
        let a2 = u8_le_slice_to_u64(&a[8..16]);
        let a3 = u8_le_slice_to_u64(&a[16..24]);
        let a4 = u8_le_slice_to_u64(&a[24..]);
        vec![a1, a2, a3, a4]
    }

    #[inline]
    fn bytes_len() -> usize {
        BLS12_381_SCALAR_LEN
    }

    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::bytes_len() {
            return Err(eg!(AlgebraError::DeserializationError));
        }
        let mut array = vec![0u8; Self::bytes_len()];
        array[0..bytes.len()].copy_from_slice(bytes);
        Ok(Self(Fr::from_le_bytes_mod_order(bytes)))
    }

    #[inline]
    fn inv(&self) -> Result<Self> {
        let a = self.0.inverse();
        if a.is_none() {
            return Err(eg!(AlgebraError::GroupInversionError));
        }
        Ok(Self(a.unwrap()))
    }

    #[inline]
    fn pow(&self, exponent: &[u64]) -> Self {
        let len = exponent.len();
        let mut array = [0u64; 4];
        array[..len].copy_from_slice(exponent);
        Self(self.0.pow(&array))
    }

    fn square(&self) -> Self {
        Self(self.0.square())
    }
}

impl Domain for BLSFr {
    type Field = Fr;

    #[inline]
    fn get_field(&self) -> Self::Field {
        self.0
    }

    #[inline]
    fn from_field(field: Self::Field) -> Self {
        Self(field)
    }
}
