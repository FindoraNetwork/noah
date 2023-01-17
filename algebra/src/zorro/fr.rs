use crate::errors::AlgebraError;
use crate::prelude::*;
use crate::zorro::{ZorroG1, ZORRO_SCALAR_LEN};
use ark_bulletproofs::curve::zorro::Fr;
use ark_ff::{BigInteger, FftField, Field, PrimeField};
use ark_std::{boxed::Box, format, vec, vec::Vec};
use digest::consts::U64;
use digest::Digest;
use num_bigint::BigUint;
use num_traits::Num;
use wasm_bindgen::prelude::*;

/// The wrapped struct for `ark_bulletproofs::curve::zorro::Fr`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Debug, Hash)]
pub struct ZorroScalar(pub(crate) Fr);

impl One for ZorroScalar {
    #[inline]
    fn one() -> Self {
        Self(Fr::one())
    }
}

impl Zero for ZorroScalar {
    #[inline]
    fn zero() -> Self {
        Self(Fr::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.eq(&Fr::zero())
    }
}

impl Add for ZorroScalar {
    type Output = ZorroScalar;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Mul for ZorroScalar {
    type Output = ZorroScalar;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Sum<ZorroScalar> for ZorroScalar {
    #[inline]
    fn sum<I: Iterator<Item = ZorroScalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a> Add<&'a ZorroScalar> for ZorroScalar {
    type Output = ZorroScalar;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> AddAssign<&'a ZorroScalar> for ZorroScalar {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a ZorroScalar> for ZorroScalar {
    type Output = ZorroScalar;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> MulAssign<&'a ZorroScalar> for ZorroScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a ZorroScalar> for ZorroScalar {
    type Output = ZorroScalar;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> SubAssign<&'a ZorroScalar> for ZorroScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Sum<&'a ZorroScalar> for ZorroScalar {
    #[inline]
    fn sum<I: Iterator<Item = &'a ZorroScalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl Neg for ZorroScalar {
    type Output = ZorroScalar;

    #[inline]
    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl From<u32> for ZorroScalar {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<u64> for ZorroScalar {
    #[inline]
    fn from(value: u64) -> Self {
        Self(Fr::from(value))
    }
}

impl Into<BigUint> for ZorroScalar {
    #[inline]
    fn into(self) -> BigUint {
        self.0.into_bigint().into()
    }
}

impl<'a> From<&'a BigUint> for ZorroScalar {
    #[inline]
    fn from(src: &BigUint) -> Self {
        Self(Fr::from(src.clone()))
    }
}

impl ZorroScalar {
    /// Return a tuple of (r, g^r)
    /// where r is a random `Scalar`, and g is the `BASEPOINT_POINT`
    #[inline]
    pub fn random_scalar_with_compressed_point<R: CryptoRng + RngCore>(
        prng: &mut R,
    ) -> (Self, ZorroG1) {
        let r = Self::random(prng);
        let p = ZorroG1::get_base().mul(&r);
        (r, p)
    }

    /// Get the raw data.
    pub fn get_raw(&self) -> Fr {
        self.0.clone()
    }

    /// From the raw data.
    pub fn from_raw(raw: Fr) -> Self {
        Self(raw)
    }
}

impl Scalar for ZorroScalar {
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
    fn get_field_size_le_bytes() -> Vec<u8> {
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ]
        .to_vec()
    }

    #[inline]
    fn get_field_size_biguint() -> BigUint {
        BigUint::from_str_radix(
            "57896044618658097711785492504343953926634992332820282019728792003956564819949",
            10,
        )
        .unwrap()
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
        ZORRO_SCALAR_LEN
    }

    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        (self.0).into_bigint().to_bytes_le()
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
    fn square(&self) -> Self {
        Self(self.0.square())
    }
}
