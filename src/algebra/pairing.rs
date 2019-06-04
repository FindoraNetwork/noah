use super::groups::Group;

pub trait Pairing<S>: PartialEq{
    type G1: Group<S>;
    type G2: Group<S>;
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self;
    fn scalar_mul(&self, a: &S) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn get_identity() -> Self;

    fn g1_mul_scalar(a: &Self::G1, b: &S) -> Self::G1;
    fn g2_mul_scalar(a: &Self::G2, b: &S) -> Self::G2;
}