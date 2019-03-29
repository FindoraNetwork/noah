use rand::{Rng, CryptoRng};
use digest::generic_array::typenum::U64;
use digest::Digest;
use std::fmt::Debug;


pub trait Scalar: Debug + Sized + PartialEq + Eq + Clone {
    // scalar generation
    fn random_scalar<R: CryptoRng + Rng>(rng: &mut R) -> Self;
    fn scalar_from_u32(value: u32) -> Self;
    fn scalar_from_u64(value: u64) -> Self;
    fn scalar_from_hash<D>(hash: D) -> Self
    where D: Digest<OutputSize = U64> + Default;

    // scalar arithmetic
    fn scalar_add(a: &Self, b: &Self) -> Self;
    fn scalar_mul(a: &Self, b: &Self) -> Self;

    //scalar serialization
    fn scalar_to_bytes(a: &Self) -> Vec<u8>;
    fn scalar_from_bytes(bytes: &[u8]) -> Self;
}


pub trait Group: Debug + Sized + PartialEq + Eq + Clone{
    type ScalarType: Scalar;
    const COMPRESSED_LEN: usize;
    const SCALAR_BYTES_LEN: usize;
    fn get_identity() -> Self;
    fn get_base() -> Self;

    // compression/serialization helpers
    fn to_compressed_bytes(&self) -> Vec<u8>;
    fn from_compressed_bytes(bytes: &[u8]) -> Option<Self>;

    //arithmetic
    fn mul_by_scalar(&self, scalar: &Self::ScalarType) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;

/*
    // scalar generation
    fn random_scalar<R: CryptoRng + Rng>(rng: &mut R) -> Self::ScalarType;
    fn scalar_from_u32(value: u32) -> Self::ScalarType;
    fn scalar_from_u64(value: u64) -> Self::ScalarType;
    fn scalar_from_hash<D>(hash: D) -> Self::ScalarType
        where D: Digest<OutputSize = U64> + Default;


    // scalar arithmetic
    fn scalar_add<S: Scalar>(a: &S, b: &S) -> S;
    fn scalar_mul<S: Scalar>(a: &S, b: &S) -> S;

    //scalar serialization
    fn scalar_to_bytes(a: &Self::ScalarType) -> Vec<u8>;
    fn scalar_from_bytes(bytes: &[u8]) -> Self::ScalarType;
*/
}

