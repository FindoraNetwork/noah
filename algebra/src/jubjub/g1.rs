use crate::bls12_381::BLSScalar;
use crate::jubjub::JubjubScalar;
use crate::prelude::*;
use crate::traits::TECurve;
use crate::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    new_bls12_381_fr,
};
use ark_ec::{AffineRepr, CurveGroup as ArkCurveGroup, Group as ArkGroup};
use ark_ed_on_bls12_381::{EdwardsAffine as AffinePoint, EdwardsProjective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{string::ToString, vec::Vec};
use digest::consts::U64;
use digest::Digest;

/// The wrapped struct for `ark_ed_on_bls12_381::EdwardsProjective`
#[derive(Clone, PartialEq, Debug, Copy, Default)]
pub struct JubjubPoint(pub EdwardsProjective);

impl Hash for JubjubPoint {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_string().as_bytes().hash(state)
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
        Self(self.0.into_affine().mul_by_cofactor_to_group())
    }
}

impl Group for JubjubPoint {
    type ScalarType = JubjubScalar;
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
        Self(self.0.mul(&rhs.0))
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

impl<'a> MulAssign<&'a JubjubScalar> for JubjubPoint {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a JubjubScalar) {
        self.0.mul_assign(rhs.0)
    }
}

impl Neg for JubjubPoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl CurveGroup for JubjubPoint {
    type BaseType = BLSScalar;

    #[inline]
    fn get_x(&self) -> Self::BaseType {
        let affine_point = AffinePoint::from(self.0);
        BLSScalar(affine_point.x)
    }

    #[inline]
    fn get_y(&self) -> Self::BaseType {
        let affine_point = AffinePoint::from(self.0);
        BLSScalar(affine_point.y)
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
        let x = new_bls12_381_fr!(
            "37283441954580174170554388175493150130054720173248049475226975321836017924287"
        );
        let y = new_bls12_381_fr!(
            "38161757907713225632814750034917660204320126559701604632199511537313216752811"
        );

        Self(EdwardsProjective::from(AffinePoint::new(x.0, y.0)))
    }

    #[inline]
    fn multiply_by_cofactor(&self) -> Self {
        self.double().double().double()
    }
}

impl TECurve for JubjubPoint {
    #[inline]
    fn get_edwards_d() -> Vec<u8> {
        [
            177, 62, 52, 214, 214, 95, 6, 1, 38, 157, 87, 55, 109, 127, 45, 41, 212, 127, 189, 230,
            7, 146, 253, 245, 72, 43, 250, 75, 231, 24, 147, 42,
        ]
        .to_vec()
    }

    #[inline]
    fn get_edwards_a() -> Vec<u8> {
        [
            0, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115,
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
            super::JubjubPoint::get_point_div_by_cofactor().multiply_by_cofactor(),
            super::JubjubPoint::get_base()
        );
    }
}
