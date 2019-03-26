use crate::algebra::groups::{Group};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{ RistrettoPoint, CompressedRistretto};
use curve25519_dalek::traits::Identity;
use rand::{CryptoRng, Rng};
use digest::Digest;
use digest::generic_array::typenum::U64;

impl Group for RistrettoPoint{
    type ScalarType = Scalar;

    fn get_identity() -> RistrettoPoint{
        curve25519_dalek::ristretto::RistrettoPoint::identity()
    }

    fn mul_by_scalar(&self, scalar: &Scalar) -> Self{
        self * scalar
    }

    fn to_compressed_bytes(&self) -> Vec<u8>{
        let mut v = vec![];
        v.extend_from_slice(self.compress().as_bytes());
        v
    }

    fn from_compressed_bytes(bytes: &[u8]) -> Option<RistrettoPoint>{
        CompressedRistretto::from_slice(bytes).decompress()
    }

    fn get_compressed_len() -> usize {
        32
    }

    fn gen_random_scalar<R: CryptoRng + Rng>(rng: &mut R) -> Scalar {
        Scalar::random(rng)
    }

    fn scalar_from_u32(x: u32) -> Scalar{
        Scalar::from(x)
    }

    fn scalar_from_hash<D>(hash: D) -> Scalar
    where D: Digest<OutputSize = U64> + Default,
    {
        Scalar::from_hash(hash)
    }

    fn add(&self, other: &RistrettoPoint) -> RistrettoPoint {
        self + other
    }

    fn sub(&self, other: &RistrettoPoint) -> RistrettoPoint {
        self - other
    }

    fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar{
        a + b
    }
    fn scalar_mul(a: &Scalar, b: &Scalar) -> Scalar{
        a * b
    }

    fn scalar_to_bytes(a: &Scalar) -> Vec<u8>{
        let mut v = vec![];
        v.extend_from_slice(a.as_bytes());
        v
    }
}

