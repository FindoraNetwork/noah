use crate::bn254::{BN254Fq, BN254Scalar};
use crate::prelude::*;
use ark_bn254::{Fq, G1Affine, G1Projective};
use ark_ec::{CurveGroup, Group as ArkGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{
    fmt::{Debug, Display, Formatter},
    vec::Vec,
};
use digest::{consts::U64, Digest};
use wasm_bindgen::prelude::*;

/// The wrapped struct for ark_bn254::G1Projective
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct BN254G1(pub(crate) G1Projective);

impl Debug for BN254G1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> ark_std::fmt::Result {
        <G1Affine as Display>::fmt(&self.0.into_affine(), f)
    }
}

impl Group for BN254G1 {
    type ScalarType = BN254Scalar;
    const COMPRESSED_LEN: usize = 32;
    const UNCOMPRESSED_LEN: usize = 64;

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
        let affine = G1Affine::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes)
            .map_err(|_| AlgebraError::DeserializationError)?;

        Ok(Self(G1Projective::from(affine)))
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let affine = G1Affine::deserialize_with_mode(bytes, Compress::No, Validate::No)
            .map_err(|_| AlgebraError::DeserializationError)?;

        Ok(Self(G1Projective::from(affine)))
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
        Self::common_multi_exp(scalars, points)
    }
}

impl<'a> Add<&'a BN254G1> for BN254G1 {
    type Output = BN254G1;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> Sub<&'a BN254G1> for BN254G1 {
    type Output = BN254G1;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> Mul<&'a BN254Scalar> for BN254G1 {
    type Output = BN254G1;

    #[inline]
    fn mul(self, rhs: &BN254Scalar) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> AddAssign<&'a BN254G1> for BN254G1 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a BN254G1) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a BN254G1> for BN254G1 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a BN254G1) {
        self.0.sub_assign(&rhs.0)
    }
}

impl<'a> MulAssign<&'a BN254Scalar> for BN254G1 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a BN254Scalar) {
        self.0.mul_assign(rhs.0)
    }
}

impl Neg for BN254G1 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl BN254G1 {
    /// Get the x-coordinate of the BN254 affine point.
    #[inline]
    pub fn get_x(&self) -> BN254Fq {
        BN254Fq(self.0.x)
    }
    /// Get the y-coordinate of the BN254 affine point.
    #[inline]
    pub fn get_y(&self) -> BN254Fq {
        BN254Fq(self.0.y)
    }
    /// Construct from the x-coordinate and y-coordinate
    pub fn from_xy(x: BN254Fq, y: BN254Fq) -> Self {
        if x.is_zero() && y.is_zero() {
            Self(G1Projective::zero())
        } else {
            Self(G1Projective::new(x.0, y.0, Fq::one()))
        }
    }

    #[inline]
    fn common_multi_exp(scalars: &[&<Self as Group>::ScalarType], points: &[&Self]) -> Self {
        use ark_ec::VariableBaseMSM;

        let scalars_raw: Vec<_> = scalars.iter().map(|r| r.0).collect();
        let points_raw = G1Projective::normalize_batch(
            &points.iter().map(|r| r.0).collect::<Vec<G1Projective>>(),
        );

        Self(G1Projective::msm(&points_raw, scalars_raw.as_ref()).unwrap())
    }
}
