use crate::errors::AlgebraError;
use crate::prelude::*;
use crate::prelude::{derive_prng_from_hash, CryptoRng, Group, RngCore};
use crate::secp256k1::SECP256K1Scalar;
use crate::secq256k1::SECQ256K1Scalar;
use ark_bulletproofs::curve::secp256k1::{FrParameters, G1Affine, G1Projective};
use ark_ec::short_weierstrass_jacobian::GroupProjective;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FftParameters, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt::{Debug, Formatter};
use digest::consts::U64;
use digest::Digest;
use wasm_bindgen::prelude::wasm_bindgen;

/// The wrapped struct for `ark_bulletproofs::curve::secp256k1::G1Projective`
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq, Hash)]
pub struct SECP256K1G1(pub(crate) G1Projective);

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
        let point = G1Affine::get_point_from_x(x.0.clone(), false)
            .ok_or(eg!(NoahError::DeserializationError))?
            .into_projective();
        Ok(Self(point))
    }

    /// Get the raw data.
    pub fn get_raw(&self) -> G1Affine {
        self.0.into_affine()
    }

    /// From the raw data.
    pub fn from_raw(raw: G1Affine) -> Self {
        Self(raw.into_projective())
    }
}

impl Debug for SECP256K1G1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0.into_affine(), f)
    }
}

impl Group for SECP256K1G1 {
    type ScalarType = SECP256K1Scalar;
    const COMPRESSED_LEN: usize = 33;

    #[inline]
    fn double(&self) -> Self {
        Self(ProjectiveCurve::double(&self.0))
    }

    #[inline]
    fn get_identity() -> Self {
        Self(G1Projective::zero())
    }

    #[inline]
    fn get_base() -> Self {
        Self(G1Projective::prime_subgroup_generator())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self(G1Projective::rand(prng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let affine = G1Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize(&mut buf).unwrap();

        buf
    }

    #[inline]
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let affine = G1Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize_unchecked(&mut buf).unwrap();

        buf
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G1Affine::deserialize(&mut reader);

        if affine.is_ok() {
            Ok(Self(G1Projective::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G1Affine::deserialize_unchecked(&mut reader);

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
        let scalars_raw = scalars
            .iter()
            .map(|r| r.0.into_repr())
            .collect::<Vec<<FrParameters as FftParameters>::BigInt>>();
        let points_raw = G1Projective::batch_normalization_into_affine(
            &points.iter().map(|r| r.0).collect::<Vec<G1Projective>>(),
        );

        Self(ark_ec::msm::VariableBase::msm(&points_raw, &scalars_raw))
    }
}

impl Neg for SECP256K1G1 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let point = self.0.clone();
        Self(GroupProjective::neg(point))
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
        Self(self.0.mul(&rhs.0.into_repr()))
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
