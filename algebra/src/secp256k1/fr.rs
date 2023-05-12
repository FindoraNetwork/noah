use crate::prelude::*;
use crate::secp256k1::{SECP256K1G1, SECP256K1_SCALAR_LEN};
use ark_ff::{BigInteger, BigInteger256, FftField, Field, PrimeField};
use ark_secp256k1::Fr;
use ark_std::{
    fmt::{Debug, Formatter},
    result::Result as StdResult,
    str::FromStr,
    vec,
    vec::Vec,
};
use digest::consts::U64;
use digest::Digest;
use num_bigint::BigUint;
use num_traits::Num;
use wasm_bindgen::prelude::*;

/// The wrapped struct for `ark_secp256k1::Fr`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct SECP256K1Scalar(pub(crate) Fr);

impl Debug for SECP256K1Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> ark_std::fmt::Result {
        <BigUint as Debug>::fmt(
            &<BigInteger256 as Into<BigUint>>::into(self.0.into_bigint()),
            f,
        )
    }
}

impl SECP256K1Scalar {
    /// Return a tuple of (r, g^r)
    /// where r is a random `Scalar`, and g is the `BASEPOINT_POINT`
    #[inline]
    pub fn random_scalar_with_compressed_point<R: CryptoRng + RngCore>(
        prng: &mut R,
    ) -> (Self, SECP256K1G1) {
        let r = Self::random(prng);
        let p = SECP256K1G1::get_base().mul(&r);
        (r, p)
    }
}

impl FromStr for SECP256K1Scalar {
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

impl One for SECP256K1Scalar {
    #[inline]
    fn one() -> Self {
        SECP256K1Scalar(Fr::one())
    }
}

impl Zero for SECP256K1Scalar {
    #[inline]
    fn zero() -> Self {
        Self(Fr::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Add for SECP256K1Scalar {
    type Output = SECP256K1Scalar;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Mul for SECP256K1Scalar {
    type Output = SECP256K1Scalar;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Sum<SECP256K1Scalar> for SECP256K1Scalar {
    #[inline]
    fn sum<I: Iterator<Item = SECP256K1Scalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a> Add<&'a SECP256K1Scalar> for SECP256K1Scalar {
    type Output = SECP256K1Scalar;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> AddAssign<&'a SECP256K1Scalar> for SECP256K1Scalar {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a SECP256K1Scalar> for SECP256K1Scalar {
    type Output = SECP256K1Scalar;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> SubAssign<&'a SECP256K1Scalar> for SECP256K1Scalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a SECP256K1Scalar> for SECP256K1Scalar {
    type Output = SECP256K1Scalar;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> MulAssign<&'a SECP256K1Scalar> for SECP256K1Scalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl<'a> Sum<&'a SECP256K1Scalar> for SECP256K1Scalar {
    #[inline]
    fn sum<I: Iterator<Item = &'a SECP256K1Scalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl Neg for SECP256K1Scalar {
    type Output = SECP256K1Scalar;

    #[inline]
    fn neg(self) -> Self {
        Self(self.0.neg())
    }
}

impl From<u32> for SECP256K1Scalar {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<u64> for SECP256K1Scalar {
    #[inline]
    fn from(value: u64) -> Self {
        Self(Fr::from(value))
    }
}

impl Into<BigUint> for SECP256K1Scalar {
    #[inline]
    fn into(self) -> BigUint {
        let value: BigUint = self.0.into_bigint().into();
        value
    }
}

impl<'a> From<&'a BigUint> for SECP256K1Scalar {
    #[inline]
    fn from(value: &'a BigUint) -> Self {
        Self(Fr::from(value.clone()))
    }
}

impl Scalar for SECP256K1Scalar {
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
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            10,
        )
        .unwrap()
    }

    #[inline]
    fn get_field_size_le_bytes() -> Vec<u8> {
        [
            0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc,
            0xae, 0xba, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
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
        SECP256K1_SCALAR_LEN
    }

    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        self.0.into_bigint().to_bytes_le()[..SECP256K1_SCALAR_LEN].to_vec()
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
        let mut array = [0u64; 5];
        array[..len].copy_from_slice(exponent);
        Self(self.0.pow(&array))
    }

    #[inline]
    fn square(&self) -> Self {
        Self(self.0.square())
    }
}

impl SECP256K1Scalar {
    /// Get the raw data.
    pub fn get_raw(&self) -> Fr {
        self.0.clone()
    }

    /// From the raw data.
    pub fn from_raw(raw: Fr) -> Self {
        Self(raw)
    }
}
