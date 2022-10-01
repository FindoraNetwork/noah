use crate::{
    bls12_381::BLSScalar,
    cmp::Ordering,
    errors::AlgebraError,
    hash::{Hash, Hasher},
    prelude::*,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ed_on_bls12_381::{EdwardsAffine as AffinePoint, EdwardsProjective, Fr};
use ark_ff::{BigInteger, Field, FpParameters, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use digest::{generic_array::typenum::U64, Digest};
use num_bigint::BigUint;
use num_traits::Num;
use wasm_bindgen::prelude::wasm_bindgen;

/// The number of bytes for a scalar value over Jubjub
pub const JUBJUB_SCALAR_LEN: usize = 32;

/// The wrapped struct for `ark_ed_on_bls12_381::Fr`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Debug, Hash)]
pub struct JubjubScalar(pub(crate) Fr);

/// The wrapped struct for `ark_ed_on_bls12_381::EdwardsProjective`
#[derive(Clone, PartialEq, Debug, Copy)]
pub struct JubjubPoint(pub EdwardsProjective);

impl Default for JubjubPoint {
    #[inline]
    fn default() -> Self {
        // note: Arkworks-rs library's default is point of infinity,
        // here we use the base point.
        Self::get_base()
    }
}

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

impl One for JubjubScalar {
    #[inline]
    fn one() -> Self {
        Self(Fr::one())
    }
}

impl Zero for JubjubScalar {
    #[inline]
    fn zero() -> Self {
        Self(Fr::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.eq(&Fr::zero())
    }
}

impl Add for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Mul for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Sum<JubjubScalar> for JubjubScalar {
    #[inline]
    fn sum<I: Iterator<Item = JubjubScalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a> Add<&'a JubjubScalar> for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> AddAssign<&'a JubjubScalar> for JubjubScalar {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a JubjubScalar> for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> MulAssign<&'a JubjubScalar> for JubjubScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a JubjubScalar> for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> SubAssign<&'a JubjubScalar> for JubjubScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Sum<&'a JubjubScalar> for JubjubScalar {
    #[inline]
    fn sum<I: Iterator<Item = &'a JubjubScalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl Neg for JubjubScalar {
    type Output = JubjubScalar;

    #[inline]
    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl From<u32> for JubjubScalar {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<u64> for JubjubScalar {
    #[inline]
    fn from(value: u64) -> Self {
        Self(Fr::from(value))
    }
}

impl Into<BigUint> for JubjubScalar {
    #[inline]
    fn into(self) -> BigUint {
        self.0.into_repr().into()
    }
}

impl<'a> From<&'a BigUint> for JubjubScalar {
    #[inline]
    fn from(src: &BigUint) -> Self {
        Self(Fr::from(src.clone()))
    }
}

impl Scalar for JubjubScalar {
    #[inline]
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(Fr::rand(rng))
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        Self::random(&mut prng)
    }

    #[inline]
    fn capacity() -> usize {
        ark_ed_on_bls12_381::FrParameters::CAPACITY as usize
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self::from(6u64)
    }

    #[inline]
    fn get_field_size_le_bytes() -> Vec<u8> {
        [
            183, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204, 147, 32, 104, 166, 0, 59, 52,
            1, 1, 59, 103, 6, 169, 175, 51, 101, 234, 180, 125, 14,
        ]
        .to_vec()
    }

    #[inline]
    fn get_field_size_biguint() -> BigUint {
        BigUint::from_str_radix(
            "6554484396890773809930967563523245729705921265872317281365359162392183254199",
            10,
        )
        .unwrap()
    }

    #[inline]
    fn get_little_endian_u64(&self) -> Vec<u64> {
        let a = self.0.into_repr().to_bytes_le();
        let a1 = u8_le_slice_to_u64(&a[0..8]);
        let a2 = u8_le_slice_to_u64(&a[8..16]);
        let a3 = u8_le_slice_to_u64(&a[16..24]);
        let a4 = u8_le_slice_to_u64(&a[24..]);
        vec![a1, a2, a3, a4]
    }

    #[inline]
    fn bytes_len() -> usize {
        JUBJUB_SCALAR_LEN
    }

    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        (self.0).into_repr().to_bytes_le()
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::bytes_len() {
            return Err(eg!(AlgebraError::DeserializationError));
        }
        let mut array = vec![0u8; Self::bytes_len()];
        array[0..bytes.len()].copy_from_slice(bytes);

        Ok(Self(Fr::from_le_bytes_mod_order(bytes)))
    }

    #[inline]
    fn inv(&self) -> Result<Self> {
        let a = self.0.inverse();
        if a.is_none() {
            return Err(eg!(AlgebraError::GroupInversionError));
        }
        Ok(Self(a.unwrap()))
    }

    #[inline]
    fn square(&self) -> Self {
        Self(self.0.square())
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

#[cfg(test)]
mod jubjub_groups_test {
    use crate::{
        jubjub::{JubjubPoint, JubjubScalar},
        prelude::*,
        traits::group_tests::{test_scalar_operations, test_scalar_serialization},
    };
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_scalar_ops() {
        test_scalar_operations::<JubjubScalar>();
    }

    #[test]
    fn scalar_deser() {
        test_scalar_serialization::<JubjubScalar>();
    }

    #[test]
    fn scalar_from_to_bytes() {
        let small_value = JubjubScalar::from(165747u32);
        let small_value_bytes = small_value.to_bytes();
        let expected_small_value_bytes: [u8; 32] = [
            115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(small_value_bytes, expected_small_value_bytes);

        let small_value_from_bytes = JubjubScalar::from_bytes(&small_value_bytes).unwrap();
        assert_eq!(small_value_from_bytes, small_value);
    }

    #[test]
    fn schnorr_identification_protocol() {
        let mut rng = ChaCha20Rng::from_entropy();

        // Private key
        let alpha = JubjubScalar::random(&mut rng);

        // Public key
        let base = JubjubPoint::get_base();
        let u = base.mul(&alpha);

        // Verifier challenge
        let c = JubjubScalar::random(&mut rng);

        // Prover commitment
        let alpha_t = JubjubScalar::random(&mut rng);
        let u_t = base.mul(&alpha_t);

        // Prover response
        let alpha_z = alpha_t.add(&c.mul(&alpha));

        // Proof verification
        let left = base.mul(&alpha_z);
        let right = u_t.add(&u.mul(&c));

        assert_eq!(left, right);
    }
}
