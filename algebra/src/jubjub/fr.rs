use crate::jubjub::JUBJUB_SCALAR_LEN;
use crate::{hash::Hash, prelude::*};
use ark_ed_on_bls12_381::Fr;
use ark_ff::{BigInteger, FftField, Field, LegendreSymbol, PrimeField};
use ark_std::{vec, vec::Vec};
use digest::{generic_array::typenum::U64, Digest};
use num_bigint::BigUint;
use num_traits::Num;
use wasm_bindgen::prelude::wasm_bindgen;

/// The wrapped struct for `ark_ed_on_bls12_381::Fr`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Debug, Hash)]
pub struct JubjubScalar(pub(crate) Fr);

impl One for JubjubScalar {
    #[inline]
    fn one() -> Self {
        Self(Fr::one())
    }
}

impl Zero for JubjubScalar {
    #[inline]
    fn zero() -> Self {
        Self(Fr::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.eq(&Fr::zero())
    }
}

impl Add for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Mul for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Sum<JubjubScalar> for JubjubScalar {
    #[inline]
    fn sum<I: Iterator<Item = JubjubScalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a> Add<&'a JubjubScalar> for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> AddAssign<&'a JubjubScalar> for JubjubScalar {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a JubjubScalar> for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> MulAssign<&'a JubjubScalar> for JubjubScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a JubjubScalar> for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> SubAssign<&'a JubjubScalar> for JubjubScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Sum<&'a JubjubScalar> for JubjubScalar {
    #[inline]
    fn sum<I: Iterator<Item = &'a JubjubScalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl Neg for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl From<u32> for JubjubScalar {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<u64> for JubjubScalar {
    #[inline]
    fn from(value: u64) -> Self {
        Self(Fr::from(value))
    }
}

impl Into<BigUint> for JubjubScalar {
    #[inline]
    fn into(self) -> BigUint {
        self.0.into_bigint().into()
    }
}

impl<'a> From<&'a BigUint> for JubjubScalar {
    #[inline]
    fn from(src: &BigUint) -> Self {
        Self(Fr::from(src.clone()))
    }
}

impl Scalar for JubjubScalar {
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
            183, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204, 147, 32, 104, 166, 0, 59, 52,
            1, 1, 59, 103, 6, 169, 175, 51, 101, 234, 180, 125, 14,
        ]
        .to_vec()
    }

    #[inline]
    fn get_field_size_biguint() -> BigUint {
        BigUint::from_str_radix(
            "6554484396890773809930967563523245729705921265872317281365359162392183254199",
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
        JUBJUB_SCALAR_LEN
    }

    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        (self.0).into_bigint().to_bytes_le()
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

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.double())
    }
}
