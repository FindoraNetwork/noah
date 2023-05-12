use crate::prelude::*;
use crate::secp256k1::SECP256K1Scalar;
use crate::secq256k1::SECQ256K1Scalar;
use ark_ec::{AffineRepr, CurveGroup as ArkCurveGroup, Group as ArkGroup, VariableBaseMSM};
use ark_secp256k1::{Affine, Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{
    fmt::{Debug, Formatter},
    vec::Vec,
};
use digest::consts::U64;
use digest::Digest;
use wasm_bindgen::prelude::wasm_bindgen;

/// The wrapped struct for `ark_secp256k1::Projective`
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq, Hash)]
pub struct SECP256K1G1(pub(crate) Projective);

impl SECP256K1G1 {
    /// Obtain the x coordinate in the affine representation.
    pub fn get_x(&self) -> SECQ256K1Scalar {
        SECQ256K1Scalar((self.0.into_affine().x).clone())
    }

    /// Obtain the y coordinate in the affine representation.
    pub fn get_y(&self) -> SECQ256K1Scalar {
        SECQ256K1Scalar((self.0.into_affine().y).clone())
    }

    /// Obtain a point using the x coordinate (which would be SECQ256K1Scalar).
    pub fn get_point_from_x(x: &SECQ256K1Scalar) -> Result<Self> {
        let point = Affine::get_point_from_x_unchecked(x.0.clone(), false)
            .ok_or(AlgebraError::DeserializationError)?
            .into_group();
        Ok(Self(point))
    }

    /// Get the raw data.
    pub fn get_raw(&self) -> Affine {
        self.0.into_affine()
    }

    /// From the raw data.
    pub fn from_raw(raw: Affine) -> Self {
        Self(raw.into_group())
    }
}

impl Debug for SECP256K1G1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> ark_std::fmt::Result {
        ark_std::fmt::Debug::fmt(&self.0.into_affine(), f)
    }
}

impl Group for SECP256K1G1 {
    type ScalarType = SECP256K1Scalar;
    const COMPRESSED_LEN: usize = 33;
    const UNCOMPRESSED_LEN: usize = 65;

    #[inline]
    fn double(&self) -> Self {
        Self(Projective::double(&self.0))
    }

    #[inline]
    fn get_identity() -> Self {
        Self(Projective::zero())
    }

    #[inline]
    fn get_base() -> Self {
        Self(Projective::generator())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self(Projective::rand(prng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let affine = Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize_with_mode(&mut buf, Compress::Yes).unwrap();

        buf
    }

    #[inline]
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let affine = Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize_with_mode(&mut buf, Compress::No).unwrap();

        buf
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        let affine = Affine::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes);

        if affine.is_ok() {
            Ok(Self(Projective::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(AlgebraError::DeserializationError)
        }
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let affine = Affine::deserialize_with_mode(bytes, Compress::No, Validate::No);

        if affine.is_ok() {
            Ok(Self(Projective::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(AlgebraError::DeserializationError)
        }
    }

    #[inline]
    fn unchecked_size() -> usize {
        Affine::default().serialized_size(Compress::No)
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        Self(Projective::rand(&mut prng))
    }

    #[inline]
    fn multi_exp(scalars: &[&Self::ScalarType], points: &[&Self]) -> Self {
        let scalars_raw: Vec<_> = scalars.iter().map(|r| r.0).collect();
        let points_raw =
            Projective::normalize_batch(&points.iter().map(|r| r.0).collect::<Vec<Projective>>());

        Self(Projective::msm(&points_raw, scalars_raw.as_ref()).unwrap())
    }
}

impl Neg for SECP256K1G1 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let point = self.0.clone();
        Self(Projective::neg(point))
    }
}

impl<'a> Add<&'a SECP256K1G1> for SECP256K1G1 {
    type Output = SECP256K1G1;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> Sub<&'a SECP256K1G1> for SECP256K1G1 {
    type Output = SECP256K1G1;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> Mul<&'a SECP256K1Scalar> for SECP256K1G1 {
    type Output = SECP256K1G1;

    #[inline]
    fn mul(self, rhs: &SECP256K1Scalar) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> AddAssign<&'a SECP256K1G1> for SECP256K1G1 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a SECP256K1G1) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a SECP256K1G1> for SECP256K1G1 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a SECP256K1G1) {
        self.0.sub_assign(&rhs.0)
    }
}

impl<'a> MulAssign<&'a SECP256K1Scalar> for SECP256K1G1 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a SECP256K1Scalar) {
        self.0.mul_assign(rhs.0.clone())
    }
}
