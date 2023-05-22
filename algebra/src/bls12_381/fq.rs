use crate::prelude::*;
use ark_bls12_381::Fq;
use ark_ff::{BigInteger, BigInteger384, FftField, Field, LegendreSymbol, PrimeField};
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

/// The wrapped struct for `ark_bls12_381::Fq`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct BLSFq(pub(crate) Fq);

impl Debug for BLSFq {
    fn fmt(&self, f: &mut Formatter<'_>) -> ark_std::fmt::Result {
        <BigUint as Debug>::fmt(
            &<BigInteger384 as Into<BigUint>>::into(self.0.into_bigint()),
            f,
        )
    }
}

impl FromStr for BLSFq {
    type Err = AlgebraError;

    fn from_str(string: &str) -> StdResult<Self, AlgebraError> {
        let res = Fq::from_str(string);

        if res.is_ok() {
            Ok(Self(res.unwrap()))
        } else {
            Err(AlgebraError::DeserializationError)
        }
    }
}

impl Into<BigUint> for BLSFq {
    #[inline]
    fn into(self) -> BigUint {
        self.0.into_bigint().into()
    }
}

impl<'a> From<&'a BigUint> for BLSFq {
    #[inline]
    fn from(src: &BigUint) -> Self {
        Self(Fq::from(src.clone()))
    }
}

impl One for BLSFq {
    #[inline]
    fn one() -> Self {
        BLSFq(Fq::one())
    }
}

impl Zero for BLSFq {
    #[inline]
    fn zero() -> Self {
        Self(Fq::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Add for BLSFq {
    type Output = BLSFq;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Mul for BLSFq {
    type Output = BLSFq;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Sum<BLSFq> for BLSFq {
    #[inline]
    fn sum<I: Iterator<Item = BLSFq>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a> Add<&'a BLSFq> for BLSFq {
    type Output = BLSFq;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> AddAssign<&'a BLSFq> for BLSFq {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a BLSFq> for BLSFq {
    type Output = BLSFq;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> SubAssign<&'a BLSFq> for BLSFq {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a BLSFq> for BLSFq {
    type Output = BLSFq;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> MulAssign<&'a BLSFq> for BLSFq {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl<'a> Sum<&'a BLSFq> for BLSFq {
    #[inline]
    fn sum<I: Iterator<Item = &'a BLSFq>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl Neg for BLSFq {
    type Output = BLSFq;

    #[inline]
    fn neg(self) -> Self {
        Self(self.0.neg())
    }
}

impl From<u32> for BLSFq {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<u64> for BLSFq {
    #[inline]
    fn from(value: u64) -> Self {
        Self(Fq::from(value))
    }
}

impl Scalar for BLSFq {
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
    fn capacity() -> usize {
        (Fq::MODULUS_BIT_SIZE - 1) as usize
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self(Fq::GENERATOR)
    }

    #[inline]
    fn get_field_size_biguint() -> BigUint {
        BigUint::from_str_radix(
            "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787",
            10,
        )
            .unwrap()
    }

    #[inline]
    fn get_field_size_le_bytes() -> Vec<u8> {
        [
            0xab, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xb9, 0xff, 0xff, 0x53, 0xb1, 0xfe, 0xff,
            0xab, 0x1e, 0x24, 0xf6, 0xb0, 0xf6, 0xa0, 0xd2, 0x30, 0x67, 0xbf, 0x12, 0x85, 0xf3,
            0x84, 0x4b, 0x77, 0x64, 0xd7, 0xac, 0x4b, 0x43, 0xb6, 0xa7, 0x1b, 0x4b, 0x9a, 0xe6,
            0x7f, 0x39, 0xea, 0x11, 0x01, 0x1a,
        ]
        .to_vec()
    }

    #[inline]
    fn get_little_endian_u64(&self) -> Vec<u64> {
        let a = self.0.into_bigint().to_bytes_le();
        let a1 = u8_le_slice_to_u64(&a[0..8]);
        let a2 = u8_le_slice_to_u64(&a[8..16]);
        let a3 = u8_le_slice_to_u64(&a[16..24]);
        let a4 = u8_le_slice_to_u64(&a[24..32]);
        let a5 = u8_le_slice_to_u64(&a[32..40]);
        let a6 = u8_le_slice_to_u64(&a[40..48]);
        vec![a1, a2, a3, a4, a5, a6]
    }

    #[inline]
    fn bytes_len() -> usize {
        48
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
        Ok(Self(Fq::from_le_bytes_mod_order(bytes)))
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
        let mut array = [0u64; 6];
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
