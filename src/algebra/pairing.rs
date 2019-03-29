use super::groups::{Group, Scalar};

pub trait Pairing {
    type G1: Group;
    type G2: Group;
    type ScalarType: Scalar;
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self;
    fn scalar_mul(&self, a: &Self::ScalarType) -> Self;
    fn add(&self, other: &Self) -> Self;
}