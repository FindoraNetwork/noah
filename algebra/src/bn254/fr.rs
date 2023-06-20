use crate::bn254::BN254_SCALAR_LEN;
use crate::prelude::*;
use crate::traits::Domain;
use ark_bn254::Fr;
use ark_ff::{BigInteger, BigInteger256, FftField, Field, LegendreSymbol, PrimeField};
use ark_std::{
    fmt::{Debug, Formatter},
    result::Result as StdResult,
    str::FromStr,
    vec,
    vec::Vec,
};
use digest::{consts::U64, Digest};
use num_bigint::BigUint;
use num_traits::Num;
use wasm_bindgen::prelude::*;

/// The wrapped struct for `ark_bn254::Fr`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct BN254Scalar(pub(crate) Fr);

impl Debug for BN254Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> ark_std::fmt::Result {
        <BigUint as Debug>::fmt(
            &<BigInteger256 as Into<BigUint>>::into(self.0.into_bigint()),
            f,
        )
    }
}

impl FromStr for BN254Scalar {
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

impl BN254Scalar {
    /// Create a new scalar element from the arkworks-rs representation.
    pub const fn new(is_positive: bool, limbs: &[u64]) -> Self {
        BN254Scalar(Fr::from_sign_and_limbs(is_positive, &limbs))
    }
}

impl Into<BigUint> for BN254Scalar {
    #[inline]
    fn into(self) -> BigUint {
        self.0.into_bigint().into()
    }
}

impl<'a> From<&'a BigUint> for BN254Scalar {
    #[inline]
    fn from(src: &BigUint) -> Self {
        Self(Fr::from(src.clone()))
    }
}

impl One for BN254Scalar {
    #[inline]
    fn one() -> Self {
        BN254Scalar(Fr::one())
    }
}

impl Zero for BN254Scalar {
    #[inline]
    fn zero() -> Self {
        Self(Fr::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Add for BN254Scalar {
    type Output = BN254Scalar;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Mul for BN254Scalar {
    type Output = BN254Scalar;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Sum<BN254Scalar> for BN254Scalar {
    #[inline]
    fn sum<I: Iterator<Item = BN254Scalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a> Add<&'a BN254Scalar> for BN254Scalar {
    type Output = BN254Scalar;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> AddAssign<&'a BN254Scalar> for BN254Scalar {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a BN254Scalar> for BN254Scalar {
    type Output = BN254Scalar;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> SubAssign<&'a BN254Scalar> for BN254Scalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a BN254Scalar> for BN254Scalar {
    type Output = BN254Scalar;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> MulAssign<&'a BN254Scalar> for BN254Scalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl<'a> Sum<&'a BN254Scalar> for BN254Scalar {
    #[inline]
    fn sum<I: Iterator<Item = &'a BN254Scalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl Neg for BN254Scalar {
    type Output = BN254Scalar;

    #[inline]
    fn neg(self) -> Self {
        Self(self.0.neg())
    }
}

impl From<u32> for BN254Scalar {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<u64> for BN254Scalar {
    #[inline]
    fn from(value: u64) -> Self {
        Self(Fr::from(value))
    }
}

impl From<u128> for BN254Scalar {
    #[inline]
    fn from(value: u128) -> Self {
        Self(Fr::from(value))
    }
}

impl Scalar for BN254Scalar {
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
        (Fr::MODULUS_BIT_SIZE - 1) as usize
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self(Fr::GENERATOR)
    }

    #[inline]
    fn get_field_size_biguint() -> BigUint {
        BigUint::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap()
    }

    #[inline]
    fn get_field_size_le_bytes() -> Vec<u8> {
        [
            0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8,
            0x33, 0x28, 0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1,
            0x72, 0x4e, 0x64, 0x30,
        ]
        .to_vec()
    }

    #[inline]
    fn get_little_endian_u64(&self) -> Vec<u64> {
        let a = self.0.into_bigint().to_bytes_le();
        let a1 = u8_le_slice_to_u64(&a[0..8]);
        let a2 = u8_le_slice_to_u64(&a[8..16]);
        let a3 = u8_le_slice_to_u64(&a[16..24]);
        let a4 = u8_le_slice_to_u64(&a[24..]);
        vec![a1, a2, a3, a4]
    }

    #[inline]
    fn bytes_len() -> usize {
        BN254_SCALAR_LEN
    }

    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        self.0.into_bigint().to_bytes_le()
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::bytes_len() {
            return Err(AlgebraError::DeserializationError);
        }
        let mut array = vec![0u8; Self::bytes_len()];
        array[0..bytes.len()].copy_from_slice(bytes);
        Ok(Self(Fr::from_le_bytes_mod_order(bytes)))
    }

    #[inline]
    fn inv(&self) -> Result<Self> {
        let a = self.0.inverse();
        if a.is_none() {
            return Err(AlgebraError::GroupInversionError);
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

    #[inline]
    fn square(&self) -> Self {
        Self(self.0.square())
    }

    #[inline]
    fn legendre(&self) -> LegendreSymbol {
        self.0.legendre()
    }

    #[inline]
    fn sqrt(&self) -> Option<Self> {
        let res = self.0.sqrt();
        if res.is_some() {
            Some(Self(res.unwrap()))
        } else {
            None
        }
    }
}

impl Domain for BN254Scalar {
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
