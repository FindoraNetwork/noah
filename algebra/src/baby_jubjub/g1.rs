use crate::baby_jubjub::BabyJubjubScalar;
use crate::bn254::BN254Scalar;
use crate::prelude::*;
use crate::traits::TECurve;
use crate::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    new_bn254_fr,
};
use ark_ec::{AffineRepr, CurveGroup as ArkCurveGroup, Group as ArkGroup};
use ark_ed_on_bn254::{EdwardsAffine as AffinePoint, EdwardsProjective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{string::ToString, vec::Vec};
use digest::consts::U64;
use digest::Digest;

/// The wrapped struct for `ark_ed_on_bn254::EdwardsProjective`
#[derive(Clone, PartialEq, Debug, Copy, Default)]
pub struct BabyJubjubPoint(pub EdwardsProjective);

impl Hash for BabyJubjubPoint {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_string().as_bytes().hash(state)
    }
}

impl Ord for BabyJubjubPoint {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .to_string()
            .as_bytes()
            .cmp(other.0.to_string().as_bytes())
    }
}

impl PartialOrd for BabyJubjubPoint {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for BabyJubjubPoint {}

impl BabyJubjubPoint {
    /// Multiply the point by the cofactor
    #[inline]
    pub fn mul_by_cofactor(&self) -> Self {
        Self(self.0.into_affine().mul_by_cofactor_to_group())
    }
}

impl Group for BabyJubjubPoint {
    type ScalarType = BabyJubjubScalar;
    const COMPRESSED_LEN: usize = 32;
    const UNCOMPRESSED_LEN: usize = 64;

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
        Self(EdwardsProjective::generator())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(EdwardsProjective::rand(rng))
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
        let affine = AffinePoint::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes);

        if let Ok(affine) = affine {
            Ok(Self(EdwardsProjective::from(affine))) // safe unwrap
        } else {
            Err(AlgebraError::DecompressElementError)
        }
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let affine = AffinePoint::deserialize_with_mode(bytes, Compress::No, Validate::No);

        if let Ok(affine) = affine {
            Ok(Self(EdwardsProjective::from(affine))) // safe unwrap
        } else {
            Err(AlgebraError::DecompressElementError)
        }
    }

    #[inline]
    fn unchecked_size() -> usize {
        AffinePoint::default().serialized_size(Compress::No)
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

impl<'a> Add<&'a BabyJubjubPoint> for BabyJubjubPoint {
    type Output = BabyJubjubPoint;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a BabyJubjubPoint> for BabyJubjubPoint {
    type Output = BabyJubjubPoint;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<'a> Mul<&'a BabyJubjubScalar> for BabyJubjubPoint {
    type Output = BabyJubjubPoint;

    #[inline]
    fn mul(self, rhs: &BabyJubjubScalar) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> AddAssign<&'a BabyJubjubPoint> for BabyJubjubPoint {
    #[inline]
    fn add_assign(&mut self, rhs: &BabyJubjubPoint) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a BabyJubjubPoint> for BabyJubjubPoint {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a BabyJubjubPoint) {
        self.0.sub_assign(&rhs.0)
    }
}

impl<'a> MulAssign<&'a BabyJubjubScalar> for BabyJubjubPoint {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a BabyJubjubScalar) {
        self.0.mul_assign(rhs.0)
    }
}

impl Neg for BabyJubjubPoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl CurveGroup for BabyJubjubPoint {
    type BaseType = BN254Scalar;

    #[inline]
    fn get_x(&self) -> Self::BaseType {
        let affine_point = AffinePoint::from(self.0);
        BN254Scalar(affine_point.x)
    }

    #[inline]
    fn get_y(&self) -> Self::BaseType {
        let affine_point = AffinePoint::from(self.0);
        BN254Scalar(affine_point.y)
    }

    #[inline]
    fn new(x: &Self::BaseType, y: &Self::BaseType) -> Self {
        Self(EdwardsProjective::from(AffinePoint::new_unchecked(
            x.0, y.0,
        )))
    }

    #[inline]
    fn get_point_div_by_cofactor() -> Self {
        // This is a point that is the base point divided by the cofactor,
        // but, however, still in the subgroup.
        //
        // This is because among all the 8 points for P such as 8P = G,
        // one of them is in the subgroup spanned by G.
        let x = new_bn254_fr!(
            "21203262999653643426297788520157772073732315680991985809818023872395048906927"
        );
        let y = new_bn254_fr!(
            "9527268222859104004218785105844981434522971679550559578340699358791462330091"
        );

        Self(EdwardsProjective::from(AffinePoint::new(x.0, y.0)))
    }

    #[inline]
    fn multiply_by_cofactor(&self) -> Self {
        self.double().double().double()
    }
}

impl TECurve for BabyJubjubPoint {
    #[inline]
    fn get_edwards_d() -> Vec<u8> {
        [
            115, 20, 40, 251, 6, 43, 108, 115, 41, 168, 1, 142, 238, 190, 152, 36, 97, 70, 132,
            231, 222, 210, 95, 122, 192, 22, 16, 130, 129, 189, 117, 21,
        ]
        .to_vec()
    }

    #[inline]
    fn get_edwards_a() -> Vec<u8> {
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]
        .to_vec()
    }
}

#[cfg(test)]
mod test {
    use crate::prelude::*;

    #[test]
    fn correctness_div_by_cofactor() {
        assert_eq!(
            super::BabyJubjubPoint::get_point_div_by_cofactor().multiply_by_cofactor(),
            super::BabyJubjubPoint::get_base()
        );
    }
}
