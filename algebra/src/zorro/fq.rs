use crate::errors::AlgebraError;
use crate::prelude::*;
use ark_bulletproofs::curve::zorro::Fq;
use ark_ff::{BigInteger, FftField, Field, PrimeField};
use ark_std::{boxed::Box, format, vec, vec::Vec};
use digest::consts::U64;
use digest::Digest;
use num_bigint::BigUint;
use num_traits::Num;
use wasm_bindgen::prelude::*;

/// The wrapped struct for `ark_bulletproofs::curve::zorro::Fq`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Debug, Hash)]
pub struct ZorroFq(pub(crate) Fq);

impl One for ZorroFq {
    #[inline]
    fn one() -> Self {
        Self(Fq::one())
    }
}

impl Zero for ZorroFq {
    #[inline]
    fn zero() -> Self {
        Self(Fq::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.eq(&Fq::zero())
    }
}

impl Add for ZorroFq {
    type Output = ZorroFq;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Mul for ZorroFq {
    type Output = ZorroFq;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Sum<ZorroFq> for ZorroFq {
    #[inline]
    fn sum<I: Iterator<Item = ZorroFq>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a> Add<&'a ZorroFq> for ZorroFq {
    type Output = ZorroFq;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> AddAssign<&'a ZorroFq> for ZorroFq {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a ZorroFq> for ZorroFq {
    type Output = ZorroFq;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> MulAssign<&'a ZorroFq> for ZorroFq {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a ZorroFq> for ZorroFq {
    type Output = ZorroFq;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> SubAssign<&'a ZorroFq> for ZorroFq {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Sum<&'a ZorroFq> for ZorroFq {
    #[inline]
    fn sum<I: Iterator<Item = &'a ZorroFq>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl Neg for ZorroFq {
    type Output = ZorroFq;

    #[inline]
    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl From<u32> for ZorroFq {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<u64> for ZorroFq {
    #[inline]
    fn from(value: u64) -> Self {
        Self(Fq::from(value))
    }
}

impl Into<BigUint> for ZorroFq {
    #[inline]
    fn into(self) -> BigUint {
        self.0.into_bigint().into()
    }
}

impl<'a> From<&'a BigUint> for ZorroFq {
    #[inline]
    fn from(src: &BigUint) -> Self {
        Self(Fq::from(src.clone()))
    }
}

impl Scalar for ZorroFq {
    #[inline]
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(Fq::rand(rng))
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
    fn multiplicative_generator() -> Self {
        Self(Fq::GENERATOR)
    }

    #[inline]
    fn capacity() -> usize {
        (Fq::MODULUS_BIT_SIZE - 1) as usize
    }

    #[inline]
    fn get_field_size_le_bytes() -> Vec<u8> {
        [
            0x21, 0x10, 0x65, 0xd3, 0x23, 0x19, 0x5f, 0x88, 0xed, 0xb, 0x21, 0xa6, 0x6, 0x3, 0xf4,
            0x69, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x80,
        ]
        .to_vec()
    }

    #[inline]
    fn get_field_size_biguint() -> BigUint {
        BigUint::from_str_radix(
            "57896044618658097711785492504343953927116110621106131396339151912985063395361",
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
        let a4 = u8_le_slice_to_u64(&a[24..32]);
        vec![a1, a2, a3, a4]
    }

    #[inline]
    fn bytes_len() -> usize {
        32
    }

    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        (self.0).into_bigint().to_bytes_le()[..32].to_vec()
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::bytes_len() {
            return Err(eg!(AlgebraError::DeserializationError));
        }
        let mut array = vec![0u8; Self::bytes_len()];
        array[0..bytes.len()].copy_from_slice(bytes);

        Ok(Self(Fq::from_le_bytes_mod_order(bytes)))
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
