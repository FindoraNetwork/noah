use crate::bn254::{BN254PairingEngine, BN254Scalar, BN254G1, BN254G2};
use crate::prelude::*;
use crate::traits::Pairing;
use ark_bn254::{Bn254, Fq12Config};
use ark_ec::pairing::PairingOutput;
use ark_ff::{BigInteger, Fp12, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{vec::Vec, UniformRand};
use digest::{consts::U64, Digest};
use wasm_bindgen::prelude::*;

/// The wrapped struct for [`Fp12<ark_bn254::Fq12Parameters>`](https://docs.rs/ark-bn254/0.3.0/ark_bn254/fq12/struct.Fq12Parameters.html),
/// which is the pairing result
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq, Debug)]
pub struct BN254Gt(pub(crate) Fp12<Fq12Config>);

impl Neg for BN254Gt {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut v = self.0;
        v.conjugate_in_place();
        Self(v)
    }
}

impl<'a> Add<&'a BN254Gt> for BN254Gt {
    type Output = BN254Gt;

    #[inline]
    fn add(self, rhs: &'a BN254Gt) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> Sub<&'a BN254Gt> for BN254Gt {
    type Output = BN254Gt;

    #[inline]
    fn sub(self, rhs: &'a BN254Gt) -> Self::Output {
        let mut rhs_inverse = rhs.0;
        rhs_inverse.conjugate_in_place();

        Self(self.0.mul(&rhs_inverse))
    }
}

impl<'a> MulAssign<&'a BN254Scalar> for BN254Gt {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a BN254Scalar) {
        *self = self.mul(rhs)
    }
}

impl<'a> Mul<&'a BN254Scalar> for BN254Gt {
    type Output = BN254Gt;

    fn mul(self, rhs: &'a BN254Scalar) -> Self::Output {
        let mut acc = Self::get_identity();

        // This is a simple double-and-add implementation of group element
        // multiplication, moving from most significant to least
        // significant bit of the scalar.
        //
        // We skip the leading bit because it's always unset for Fq
        // elements.
        for bit in rhs
            .0
            .into_bigint()
            .to_bytes_le()
            .iter()
            .rev()
            .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1u8) == 1u8))
            .skip(1)
        {
            acc = acc.double();
            if bit {
                acc = acc.add(&self)
            }
        }

        acc
    }
}

impl<'a> AddAssign<&'a BN254Gt> for BN254Gt {
    #[inline]
    fn add_assign(&mut self, rhs: &'a BN254Gt) {
        self.0.mul_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a BN254Gt> for BN254Gt {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a BN254Gt) {
        let mut rhs_inverse = rhs.0;
        rhs_inverse.conjugate_in_place();

        self.0.mul_assign(&rhs_inverse)
    }
}

impl Group for BN254Gt {
    type ScalarType = BN254Scalar;

    const COMPRESSED_LEN: usize = 384;
    const UNCOMPRESSED_LEN: usize = 384;

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.mul(&self.0))
    }

    #[inline]
    fn get_identity() -> Self {
        Self(Fp12::<Fq12Config>::one())
    }

    #[inline]
    fn get_base() -> Self {
        BN254PairingEngine::pairing(&BN254G1::get_base(), &BN254G2::get_base())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let g: PairingOutput<Bn254> = prng.gen();
        Self(g.0)
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.0.serialize_with_mode(&mut buf, Compress::Yes).unwrap();

        buf
    }

    #[inline]
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.0.serialize_with_mode(&mut buf, Compress::No).unwrap();

        buf
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        let res = Fp12::<Fq12Config>::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes)
            .map_err(|_| AlgebraError::DeserializationError)?;

        Ok(Self(res))
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let res = Fp12::<Fq12Config>::deserialize_with_mode(bytes, Compress::No, Validate::No)
            .map_err(|_| AlgebraError::DeserializationError)?;

        Ok(Self(res))
    }

    #[inline]
    fn unchecked_size() -> usize {
        let g = Self::get_base().0;
        g.serialized_size(Compress::No)
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        Self(Fp12::<Fq12Config>::rand(&mut prng))
    }
}
