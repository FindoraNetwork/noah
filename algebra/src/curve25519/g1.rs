use crate::curve25519::Curve25519Scalar;
use crate::errors::AlgebraError;
use crate::prelude::*;
use crate::zorro::ZorroScalar;
use crate::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};
use ark_bulletproofs::curve::curve25519::{G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use digest::consts::U64;
use digest::Digest;
use wasm_bindgen::prelude::*;

/// The wrapped struct for `ark_ed_on_bls12_381::EdwardsProjective`
#[wasm_bindgen]
#[derive(Clone, PartialEq, Debug, Copy)]
pub struct Curve25519Point(pub(crate) G1Projective);

impl Hash for Curve25519Point {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_string().as_bytes().hash(state)
    }
}

impl Default for Curve25519Point {
    #[inline]
    fn default() -> Self {
        Self(G1Projective::default())
    }
}

impl Ord for Curve25519Point {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .to_string()
            .as_bytes()
            .cmp(other.0.to_string().as_bytes())
    }
}

impl PartialOrd for Curve25519Point {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for Curve25519Point {}

impl Curve25519Point {
    /// Multiply the point by the cofactor
    #[inline]
    pub fn mul_by_cofactor(&self) -> Self {
        Self(self.0.into_affine().mul_by_cofactor_to_projective())
    }
}

impl Group for Curve25519Point {
    type ScalarType = Curve25519Scalar;
    const COMPRESSED_LEN: usize = 32;

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
        Self(G1Projective::prime_subgroup_generator())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(G1Projective::rand(rng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.0.serialize(&mut buf).unwrap();

        buf
    }

    #[inline]
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.0.serialize_unchecked(&mut buf).unwrap();

        buf
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G1Affine::deserialize(&mut reader);

        if let Ok(affine) = affine {
            Ok(Self(G1Projective::from(affine))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DecompressElementError))
        }
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G1Affine::deserialize_unchecked(&mut reader);

        if let Ok(affine) = affine {
            Ok(Self(G1Projective::from(affine))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DecompressElementError))
        }
    }

    #[inline]
    fn unchecked_size() -> usize {
        let g = Self::get_base().0;
        g.uncompressed_size()
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        let point = UniformRand::rand(&mut prng);
        Self(point)
    }
}

impl<'a> Add<&'a Curve25519Point> for Curve25519Point {
    type Output = Curve25519Point;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a Curve25519Point> for Curve25519Point {
    type Output = Curve25519Point;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<'a> Mul<&'a Curve25519Scalar> for Curve25519Point {
    type Output = Curve25519Point;

    #[inline]
    fn mul(self, rhs: &Curve25519Scalar) -> Self::Output {
        Self(self.0.mul(&rhs.0.into_repr()))
    }
}

impl<'a> AddAssign<&'a Curve25519Point> for Curve25519Point {
    #[inline]
    fn add_assign(&mut self, rhs: &Curve25519Point) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a Curve25519Point> for Curve25519Point {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a Curve25519Point) {
        self.0.sub_assign(&rhs.0)
    }
}

impl Neg for Curve25519Point {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Curve25519Point {
    /// Get the x-coordinate of the Jubjub affine point.
    #[inline]
    pub fn get_x(&self) -> ZorroScalar {
        let affine_point = G1Affine::from(self.0);
        ZorroScalar(affine_point.x)
    }
    /// Get the y-coordinate of the Jubjub affine point.
    #[inline]
    pub fn get_y(&self) -> ZorroScalar {
        let affine_point = G1Affine::from(self.0);
        ZorroScalar(affine_point.y)
    }
}
