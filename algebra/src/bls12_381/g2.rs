use crate::bls12_381::BLSFr;
use crate::errors::AlgebraError;
use crate::prelude::{derive_prng_from_hash, *};
use ark_bls12_381::{G2Affine, G2Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt::{Debug, Display, Formatter};
use digest::{consts::U64, Digest};
use wasm_bindgen::prelude::*;

/// The wrapped struct for `ark_bls12_381::G2Projective`
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct BLSG2(pub(crate) G2Projective);

impl Debug for BLSG2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <G2Affine as Display>::fmt(&self.0.into_affine(), f)
    }
}

impl Group for BLSG2 {
    type ScalarType = BLSFr;
    const COMPRESSED_LEN: usize = 96;

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.double())
    }

    #[inline]
    fn get_identity() -> Self {
        Self(G2Projective::zero())
    }

    #[inline]
    fn get_base() -> Self {
        Self(G2Projective::prime_subgroup_generator())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self::get_base().mul(&BLSFr::random(prng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.0.serialize(&mut buf).unwrap();

        buf
    }

    #[inline]
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let affine = G2Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize_unchecked(&mut buf).unwrap();

        buf
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G2Affine::deserialize(&mut reader);

        if affine.is_ok() {
            Ok(Self(affine.unwrap().into_projective()))
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G2Affine::deserialize_unchecked(&mut reader);

        if affine.is_ok() {
            Ok(Self(affine.unwrap().into_projective()))
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn unchecked_size() -> usize {
        let g = G2Affine::from(Self::get_base().0);
        g.uncompressed_size()
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        Self(G2Projective::rand(&mut prng))
    }
}

impl Neg for BLSG2 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl<'a> Add<&'a BLSG2> for BLSG2 {
    type Output = BLSG2;

    #[inline]
    fn add(self, rhs: &'a Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> Sub<&'a BLSG2> for BLSG2 {
    type Output = BLSG2;

    #[inline]
    fn sub(self, rhs: &'a Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> Mul<&'a BLSFr> for BLSG2 {
    type Output = BLSG2;

    #[inline]
    fn mul(self, rhs: &'a BLSFr) -> Self::Output {
        Self(self.0.mul(&rhs.0.into_repr()))
    }
}

impl<'a> AddAssign<&'a BLSG2> for BLSG2 {
    #[inline]
    fn add_assign(&mut self, rhs: &BLSG2) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a BLSG2> for BLSG2 {
    #[inline]
    fn sub_assign(&mut self, rhs: &BLSG2) {
        self.0.sub_assign(&rhs.0)
    }
}
