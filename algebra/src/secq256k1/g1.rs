use crate::prelude::*;
use crate::secq256k1::SECQ256K1Scalar;
use ark_bulletproofs::curve::secq256k1::{G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::fmt::{Debug, Formatter};
use wasm_bindgen::prelude::wasm_bindgen;

/// The wrapped struct for `ark_bulletproofs::curve::secq256k1::G1Projective`
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct SECQ256K1G1(pub(crate) G1Projective);

impl Debug for SECQ256K1G1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0.into_affine(), f)
    }
}

impl SECQ256K1G1 {
    /// Get the raw data.
    pub fn get_raw(&self) -> G1Affine {
        self.0.into_affine()
    }

    /// From the raw data.
    pub fn from_raw(raw: G1Affine) -> Self {
        Self(raw.into_projective())
    }
}

impl<'a> Add<&'a SECQ256K1G1> for SECQ256K1G1 {
    type Output = SECQ256K1G1;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> Sub<&'a SECQ256K1G1> for SECQ256K1G1 {
    type Output = SECQ256K1G1;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> Mul<&'a SECQ256K1Scalar> for SECQ256K1G1 {
    type Output = SECQ256K1G1;

    #[inline]
    fn mul(self, rhs: &SECQ256K1Scalar) -> Self::Output {
        Self(self.0.mul(&rhs.0.into_repr()))
    }
}

impl<'a> AddAssign<&'a SECQ256K1G1> for SECQ256K1G1 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a SECQ256K1G1) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a SECQ256K1G1> for SECQ256K1G1 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a SECQ256K1G1) {
        self.0.sub_assign(&rhs.0)
    }
}

impl<'a> MulAssign<&'a SECQ256K1Scalar> for SECQ256K1G1 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a SECQ256K1Scalar) {
        self.0.mul_assign(rhs.0.clone())
    }
}
