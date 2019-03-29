use super::groups::Group;

pub trait Pairing {
    type G1: Group;
    type G2: Group;
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self;
}