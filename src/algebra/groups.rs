use rand::{Rng, CryptoRng};
use digest::generic_array::typenum::U64;
use digest::Digest;

pub trait Group: Sized + PartialEq + Eq + Clone{
    type ScalarType;
    fn get_identity() -> Self;

    // compression/serialization helpers
    fn to_compressed_bytes(&self) -> Vec<u8>;
    fn from_compressed_bytes(bytes: &[u8]) -> Option<Self>;
    fn get_compressed_len() -> usize;

    //arithmetic
    fn mul_by_scalar(&self, scalar: &Self::ScalarType) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;

    // scalar generation
    fn gen_random_scalar<R: CryptoRng + Rng>(rng: &mut R) -> Self::ScalarType;
    fn scalar_from_u32(value: u32) -> Self::ScalarType;
    fn scalar_from_hash<D>(hash: D) -> Self::ScalarType
        where D: Digest<OutputSize = U64> + Default;

    // scalar arithmetic
    fn scalar_add(a: &Self::ScalarType, b: &Self::ScalarType) -> Self::ScalarType;
    fn scalar_mul(a: &Self::ScalarType, b: &Self::ScalarType) -> Self::ScalarType;

    //scalar serialization
    fn scalar_to_bytes(a: &Self::ScalarType) -> Vec<u8>;
}

