use crate::bls12_381::BLSScalar;
use crate::errors::AlgebraError;
use crate::jubjub::JubjubScalar;
use crate::prelude::*;
use crate::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ed_on_bls12_381::{EdwardsAffine as AffinePoint, EdwardsProjective};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use digest::consts::U64;
use digest::Digest;

/// The wrapped struct for `ark_ed_on_bls12_381::EdwardsProjective`
#[derive(Clone, PartialEq, Debug, Copy)]
pub struct JubjubPoint(pub EdwardsProjective);

impl Hash for JubjubPoint {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_string().as_bytes().hash(state)
    }
}

impl Default for JubjubPoint {
    #[inline]
    fn default() -> Self {
        Self(EdwardsProjective::default())
    }
}

impl Ord for JubjubPoint {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .to_string()
            .as_bytes()
            .cmp(other.0.to_string().as_bytes())
    }
}

impl PartialOrd for JubjubPoint {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for JubjubPoint {}

impl JubjubPoint {
    /// Multiply the point by the cofactor
    #[inline]
    pub fn mul_by_cofactor(&self) -> Self {
        Self(self.0.into_affine().mul_by_cofactor_to_projective())
    }
}

impl Group for JubjubPoint {
    type ScalarType = JubjubScalar;
    const COMPRESSED_LEN: usize = 32;

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.double())
    }

    #[inline]
    fn get_identity() -> Self {
        Self(EdwardsProjective::zero())
    }

    #[inline]
    fn get_base() -> Self {
        Self(EdwardsProjective::prime_subgroup_generator())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(EdwardsProjective::rand(rng))
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

        let affine = AffinePoint::deserialize(&mut reader);

        if let Ok(affine) = affine {
            Ok(Self(EdwardsProjective::from(affine))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DecompressElementError))
        }
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = AffinePoint::deserialize_unchecked(&mut reader);

        if let Ok(affine) = affine {
            Ok(Self(EdwardsProjective::from(affine))) // safe unwrap
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

impl<'a> Add<&'a JubjubPoint> for JubjubPoint {
    type Output = JubjubPoint;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a JubjubPoint> for JubjubPoint {
    type Output = JubjubPoint;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<'a> Mul<&'a JubjubScalar> for JubjubPoint {
    type Output = JubjubPoint;

    #[inline]
    fn mul(self, rhs: &JubjubScalar) -> Self::Output {
        Self(self.0.mul(&rhs.0.into_repr()))
    }
}

impl<'a> AddAssign<&'a JubjubPoint> for JubjubPoint {
    #[inline]
    fn add_assign(&mut self, rhs: &JubjubPoint) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a JubjubPoint> for JubjubPoint {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a JubjubPoint) {
        self.0.sub_assign(&rhs.0)
    }
}

impl Neg for JubjubPoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl JubjubPoint {
    /// Get the x-coordinate of the Jubjub affine point.
    #[inline]
    pub fn get_x(&self) -> BLSScalar {
        let affine_point = AffinePoint::from(self.0);
        BLSScalar(affine_point.x)
    }
    /// Get the y-coordinate of the Jubjub affine point.
    #[inline]
    pub fn get_y(&self) -> BLSScalar {
        let affine_point = AffinePoint::from(self.0);
        BLSScalar(affine_point.y)
    }
}
