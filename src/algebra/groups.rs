use rand::{Rng, CryptoRng};
use digest::generic_array::typenum::U64;
use digest::Digest;
use std::fmt::Debug;
use serde::{Deserialize, Serialize};


pub trait Scalar: Debug + Sized + PartialEq + Eq + Clone + Serialize + for<'de> Deserialize<'de>{
    // generation
    fn random_scalar<R: CryptoRng + Rng>(rng: &mut R) -> Self;
    fn from_u32(value: u32) -> Self;
    fn from_u64(value: u64) -> Self;
    fn from_hash<D>(hash: D) -> Self
    where D: Digest<OutputSize = U64> + Default;

    //arithmetic
    fn add(&self, b: &Self) -> Self;
    fn mul(&self, b: &Self) -> Self;

    // serialization
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Self;
}


pub trait Group: Debug + Sized + PartialEq + Eq + Clone + Serialize + for<'de> Deserialize<'de>{
    type ScalarType: Scalar;
    const COMPRESSED_LEN: usize;
    const SCALAR_BYTES_LEN: usize;
    fn get_identity() -> Self;
    fn get_base() -> Self;

    // compression/serialization helpers
    fn to_compressed_bytes(&self) -> Vec<u8>;
    fn from_compressed_bytes(bytes: &[u8]) -> Option<Self>;

    //arithmetic
    fn mul(&self, scalar: &Self::ScalarType) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
}


pub mod group_tests {
    use crate::algebra::groups::Scalar;

    pub fn test_scalar_operations<S: Scalar>() {
        let a = S::from_u32(40);
        let b = S::from_u32(60);
        let c = a.add(&b);
        let d = S::from_u32(100);
        assert_eq!(c, d);

        let a = S::from_u32(10);
        let b = S::from_u32(40);
        let c = a.mul(&b);
        let d = S::from_u32(400);
        assert_eq!(c, d);

        let a = S::from_u32(0xFFFFFFFF);
        let b = S::from_u32(1);
        let c = a.add(&b);
        let d = S::from_u64(0x100000000);
        assert_eq!(c, d);
    }

    pub fn test_scalar_serialization<S: Scalar>(){
        let a = S::from_u32(100);
        let bytes = a.to_bytes();
        let b = S::from_bytes(bytes.as_slice());
        assert_eq!(a, b);
    }
}