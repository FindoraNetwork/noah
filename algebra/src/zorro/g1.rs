use crate::errors::AlgebraError;
use crate::prelude::*;
use crate::zorro::ZorroScalar;
use ark_bulletproofs::curve::zorro::{G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, Group as ArkGroup, VariableBaseMSM};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::fmt::{Debug, Formatter};
use digest::consts::U64;
use digest::Digest;
use wasm_bindgen::prelude::wasm_bindgen;

/// The wrapped struct for `ark_bulletproofs::curve::zorro::G1Projective`
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct ZorroG1(pub(crate) G1Projective);

impl Neg for ZorroG1 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Debug for ZorroG1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0.into_affine(), f)
    }
}

impl ZorroG1 {
    /// Get the raw data.
    pub fn get_raw(&self) -> G1Affine {
        self.0.into_affine()
    }

    /// From the raw data.
    pub fn from_raw(raw: G1Affine) -> Self {
        Self(raw.into_group())
    }
}

impl<'a> Add<&'a ZorroG1> for ZorroG1 {
    type Output = ZorroG1;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> Sub<&'a ZorroG1> for ZorroG1 {
    type Output = ZorroG1;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> Mul<&'a ZorroScalar> for ZorroG1 {
    type Output = ZorroG1;

    #[inline]
    fn mul(self, rhs: &ZorroScalar) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> AddAssign<&'a ZorroG1> for ZorroG1 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a ZorroG1) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a ZorroG1> for ZorroG1 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a ZorroG1) {
        self.0.sub_assign(&rhs.0)
    }
}

impl<'a> MulAssign<&'a ZorroScalar> for ZorroG1 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a ZorroScalar) {
        self.0.mul_assign(rhs.0.clone())
    }
}

impl Group for ZorroG1 {
    type ScalarType = ZorroScalar;
    const COMPRESSED_LEN: usize = 33;

    #[inline]
    fn double(&self) -> Self {
        Self(G1Projective::double(&self.0))
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
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G1Affine::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes);

        if affine.is_ok() {
            Ok(Self(G1Projective::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G1Affine::deserialize_with_mode(&mut reader, Compress::No, Validate::No);

        if affine.is_ok() {
            Ok(Self(G1Projective::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn unchecked_size() -> usize {
        let g = G1Affine::from(Self::get_base().0);
        g.uncompressed_size()
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

        Self(G1Projective::msm(&points_raw, &scalars_raw).unwrap())
    }
}
