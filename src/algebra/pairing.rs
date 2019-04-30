use super::groups::{Group, Scalar};
use serde::{Serialize, Deserialize};

pub trait Pairing: PartialEq + Serialize + for<'de> Deserialize<'de>{
    type G1: Group;
    type G2: Group;
    type ScalarType: Scalar;
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self;
    fn scalar_mul(&self, a: &Self::ScalarType) -> Self;
    fn add(&self, other: &Self) -> Self;

    fn g1_mul_scalar(a: &Self::G1, b: &Self::ScalarType) -> Self::G1;
    fn g2_mul_scalar(a: &Self::G2, b: &Self::ScalarType) -> Self::G2;

    // compression/serialization helpers
    fn to_compressed_bytes(&self) -> Vec<u8>;
    fn from_compressed_bytes(bytes: &[u8]) -> Option<Self>;
}