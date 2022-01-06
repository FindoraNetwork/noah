use crate::{
    bls12_381::BLSScalar,
    errors::AlgebraError,
    groups::{Group, GroupArithmetic, One, Scalar, ScalarArithmetic, Zero},
};
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_381::{
    EdwardsAffine as AffinePoint, EdwardsProjective as ExtendedPoint, Fr,
};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
    rand::{CryptoRng, RngCore},
    One as ArkOne, UniformRand, Zero as ArkZero,
};
use digest::{generic_array::typenum::U64, Digest};
use rand_chacha::ChaCha20Rng;
use ruc::*;
use utils::{derive_prng_from_hash, u8_le_slice_to_u64};

#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct JubjubScalar(pub(crate) Fr);
#[derive(Clone, PartialEq, Debug, Copy)]
pub struct JubjubPoint(pub(crate) ExtendedPoint);

impl Default for JubjubPoint {
    #[inline]
    fn default() -> Self {
        // Note: Arkworks-rs library's deafult is point of infinity,
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
            .cmp(&other.0.to_string().as_bytes())
    }
}

impl PartialOrd for JubjubPoint {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub const JUBJUB_SCALAR_LEN: usize = 32;

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

impl ScalarArithmetic for JubjubScalar {
    #[inline]
    fn add(&self, b: &Self) -> Self {
        Self(self.0.add(&b.0))
    }

    #[inline]
    fn add_assign(&mut self, b: &Self) {
        (self.0).add_assign(&b.0);
    }

    #[inline]
    fn mul(&self, b: &Self) -> Self {
        Self(self.0.mul(&b.0))
    }

    #[inline]
    fn mul_assign(&mut self, b: &Self) {
        (self.0).mul_assign(&b.0);
    }

    #[inline]
    fn sub(&self, b: &Self) -> Self {
        Self(self.0.sub(&b.0))
    }

    #[inline]
    fn sub_assign(&mut self, b: &Self) {
        (self.0).sub_assign(&b.0);
    }

    #[inline]
    fn inv(&self) -> Result<Self> {
        let a = self.0.inverse();
        if bool::from(a.is_none()) {
            return Err(eg!(AlgebraError::GroupInversionError));
        }
        Ok(Self(a.unwrap()))
    }
}

impl Scalar for JubjubScalar {
    #[inline]
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(Fr::rand(rng))
    }

    #[inline]
    fn from_u32(value: u32) -> Self {
        Self::from_u64(value as u64)
    }

    #[inline]
    fn from_u64(value: u64) -> Self {
        Self(Fr::from(value))
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D, ChaCha20Rng>(hash);
        Self::random(&mut prng)
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self::from_u64(6)
    }

    #[inline]
    fn get_field_size_lsf_bytes() -> Vec<u8> {
        [
            183, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204, 147, 32, 104, 166,
            0, 59, 52, 1, 1, 59, 103, 6, 169, 175, 51, 101, 234, 180, 125, 14,
        ]
        .to_vec()
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
        if bytes.len() != JUBJUB_SCALAR_LEN {
            return Err(eg!(AlgebraError::ParameterError));
        }
        Ok(Self(Fr::from_le_bytes_mod_order(&bytes)))
    }

    #[inline]
    fn from_le_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::bytes_len() {
            return Err(eg!(AlgebraError::DeserializationError));
        }
        let mut array = vec![0u8; Self::bytes_len()];
        array[0..bytes.len()].copy_from_slice(bytes);
        Self::from_bytes(&array)
    }
}

impl Eq for JubjubPoint {}

impl JubjubPoint {
    #[inline]
    pub fn mul_by_cofactor(&self) -> Self {
        Self(self.0.into_affine().scale_by_cofactor())
    }
}

impl Group for JubjubPoint {
    const COMPRESSED_LEN: usize = 32;

    #[inline]
    fn get_identity() -> Self {
        Self(ExtendedPoint::zero())
    }

    #[inline]
    fn get_base() -> Self {
        Self(ExtendedPoint::prime_subgroup_generator())
    }

    #[inline]
    fn get_random_base<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(ExtendedPoint::rand(rng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.0.serialize(&mut buf).unwrap();

        buf
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = AffinePoint::deserialize(&mut reader);

        if affine.is_ok() {
            Ok(Self(ExtendedPoint::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DecompressElementError))
        }
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D, ChaCha20Rng>(hash);
        let point = UniformRand::rand(&mut prng);
        Self(point)
    }
}

impl GroupArithmetic for JubjubPoint {
    type S = JubjubScalar;

    #[inline]
    fn mul(&self, scalar: &JubjubScalar) -> Self {
        Self(self.0.mul(&scalar.0.into_repr()))
    }

    #[inline]
    fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    #[inline]
    fn sub(&self, other: &Self) -> Self {
        Self(self.0 - other.0)
    }

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.double())
    }
}

impl JubjubPoint {
    /// Get the x-coordinate of the Jubjub affine point.
    #[inline]
    pub fn get_x(&self) -> BLSScalar {
        let affine_point = AffinePoint::from(self.0);
        BLSScalar::new(affine_point.x)
    }
    /// Get the y-coordinate of the Jubjub affine point.
    #[inline]
    pub fn get_y(&self) -> BLSScalar {
        let affine_point = AffinePoint::from(self.0);
        BLSScalar::new(affine_point.y)
    }
}

#[cfg(test)]
mod jubjub_groups_test {
    use crate::{
        groups::{
            group_tests::{test_scalar_operations, test_scalar_serialization},
            Group, GroupArithmetic, Scalar, ScalarArithmetic,
        },
        jubjub::{JubjubPoint, JubjubScalar},
    };
    use ark_std::rand::SeedableRng;
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
        let small_value = JubjubScalar::from_u32(165747);
        let small_value_bytes = small_value.to_bytes();
        let expected_small_value_bytes: [u8; 32] = [
            115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(small_value_bytes, expected_small_value_bytes);

        let small_value_from_bytes =
            JubjubScalar::from_bytes(&small_value_bytes).unwrap();
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
