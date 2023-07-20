use crate::bls12_381::BLSScalar;
use crate::prelude::*;
use ark_bls12_381::{G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup as ArkCurveGroup, Group as ArkGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{
    fmt::{Debug, Display, Formatter},
    vec::Vec,
};
use digest::{consts::U64, Digest};
use wasm_bindgen::prelude::*;

/// The wrapped struct for `ark_bls12_381::G2Projective`
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct BLSG2(pub(crate) G2Projective);

impl Debug for BLSG2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> ark_std::fmt::Result {
        <G2Affine as Display>::fmt(&self.0.into_affine(), f)
    }
}

impl Group for BLSG2 {
    type ScalarType = BLSScalar;
    const COMPRESSED_LEN: usize = 96;
    const UNCOMPRESSED_LEN: usize = 192;

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
        Self(G2Projective::generator())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self(G2Projective::rand(prng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.0.serialize_with_mode(&mut buf, Compress::Yes).unwrap();

        buf
    }

    #[inline]
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let affine = G2Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize_with_mode(&mut buf, Compress::No).unwrap();

        buf
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        let affine = G2Affine::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes)
            .map_err(|_| AlgebraError::DeserializationError)?;

        Ok(Self(affine.into_group()))
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let affine = G2Affine::deserialize_with_mode(bytes, Compress::No, Validate::No)
            .map_err(|_| AlgebraError::DeserializationError)?;

        Ok(Self(affine.into_group()))
    }

    #[inline]
    fn unchecked_size() -> usize {
        G2Affine::default().serialized_size(Compress::No)
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

impl<'a> Mul<&'a BLSScalar> for BLSG2 {
    type Output = BLSG2;

    #[inline]
    fn mul(self, rhs: &'a BLSScalar) -> Self::Output {
        Self(self.0.mul(&rhs.0))
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

impl<'a> MulAssign<&'a BLSScalar> for BLSG2 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a BLSScalar) {
        self.0.mul_assign(rhs.0)
    }
}
