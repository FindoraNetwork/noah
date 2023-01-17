use crate::bls12_381::BLSScalar;
use crate::errors::AlgebraError;
use crate::prelude::{derive_prng_from_hash, *};
use ark_bls12_381::{G1Affine, G1Projective};
use ark_ec::{CurveGroup, Group as ArkGroup, VariableBaseMSM};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{
    boxed::Box,
    fmt::{Debug, Display, Formatter},
    format,
    vec::Vec,
};
use digest::{consts::U64, Digest};
use wasm_bindgen::prelude::*;

/// The wrapped struct for ark_bls12_381::G1Projective
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct BLSG1(pub(crate) G1Projective);

impl Debug for BLSG1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> ark_std::fmt::Result {
        <G1Affine as Display>::fmt(&self.0.into_affine(), f)
    }
}

impl Group for BLSG1 {
    type ScalarType = BLSScalar;
    const COMPRESSED_LEN: usize = 48;

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.double())
    }

    #[inline]
    fn get_identity() -> Self {
        Self(G1Projective::zero())
    }

    #[inline]
    fn get_base() -> Self {
        Self(G1Projective::generator())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self(G1Projective::rand(prng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let affine = G1Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize_with_mode(&mut buf, Compress::Yes).unwrap();

        buf
    }

    #[inline]
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let affine = G1Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize_with_mode(&mut buf, Compress::No).unwrap();

        buf
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        let affine = G1Affine::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes);

        if affine.is_ok() {
            Ok(Self(G1Projective::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let affine = G1Affine::deserialize_with_mode(bytes, Compress::No, Validate::No);

        if affine.is_ok() {
            Ok(Self(G1Projective::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn unchecked_size() -> usize {
        G1Affine::default().serialized_size(Compress::No)
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        Self(G1Projective::rand(&mut prng))
    }

    #[inline]
    fn multi_exp(scalars: &[&Self::ScalarType], points: &[&Self]) -> Self {
        let scalars_raw: Vec<_> = scalars.iter().map(|r| r.0).collect();
        let points_raw = G1Projective::normalize_batch(
            &points.iter().map(|r| r.0).collect::<Vec<G1Projective>>(),
        );

        Self(G1Projective::msm(&points_raw, scalars_raw.as_ref()).unwrap())
    }
}

impl<'a> Add<&'a BLSG1> for BLSG1 {
    type Output = BLSG1;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> Sub<&'a BLSG1> for BLSG1 {
    type Output = BLSG1;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> Mul<&'a BLSScalar> for BLSG1 {
    type Output = BLSG1;

    #[inline]
    fn mul(self, rhs: &BLSScalar) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> AddAssign<&'a BLSG1> for BLSG1 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a BLSG1) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a BLSG1> for BLSG1 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a BLSG1) {
        self.0.sub_assign(&rhs.0)
    }
}

impl<'a> MulAssign<&'a BLSScalar> for BLSG1 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a BLSScalar) {
        self.0.mul_assign(rhs.0.clone())
    }
}

impl Neg for BLSG1 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}
