use crate::errors::AlgebraError;
use crate::prelude::*;
use ark_bulletproofs_secq256k1::curve::secq256k1::{Fr, FrParameters, G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, BigInteger320, FftField, FftParameters, Field, FpParameters, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    result::Result as StdResult,
    str::FromStr,
    One, UniformRand, Zero,
};
use digest::{generic_array::typenum::U64, Digest};
use num_bigint::BigUint;
use num_traits::Num;
use ruc::eg;
use wasm_bindgen::prelude::*;

/// The number of bytes for a scalar value over the secq256k1 curve
pub const SECQ256K1_SCALAR_LEN: usize = 32;

/// The wrapped struct for [`ark_bulletproofs_secq256k1::curve::secq256k1::Fr`](https://github.com/FindoraNetwork/ark-bulletproofs-secq256k1/blob/main/src/curve/secq256k1/fr.rs)
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct SECQ256K1Scalar(pub(crate) Fr);

impl Debug for SECQ256K1Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <BigUint as Debug>::fmt(
            &<BigInteger320 as Into<BigUint>>::into(self.0.into_repr()),
            f,
        )
    }
}

/// The wrapped struct for [`ark_bulletproofs_secq256k1::curve::secq256k1::G1Projective`](https://github.com/FindoraNetwork/ark-bulletproofs-secq256k1/blob/main/src/curve/secq256k1/g1.rs)
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct SECQ256K1G1(pub(crate) G1Projective);

impl Debug for SECQ256K1G1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0.into_affine(), f)
    }
}

impl FromStr for SECQ256K1Scalar {
    type Err = AlgebraError;

    fn from_str(string: &str) -> StdResult<Self, AlgebraError> {
        let res = Fr::from_str(string);

        if res.is_ok() {
            Ok(Self(res.unwrap()))
        } else {
            Err(AlgebraError::DeserializationError)
        }
    }
}

impl One for SECQ256K1Scalar {
    #[inline]
    fn one() -> Self {
        SECQ256K1Scalar(Fr::one())
    }
}

impl Zero for SECQ256K1Scalar {
    #[inline]
    fn zero() -> Self {
        Self(Fr::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Add for SECQ256K1Scalar {
    type Output = SECQ256K1Scalar;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Mul for SECQ256K1Scalar {
    type Output = SECQ256K1Scalar;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> Add<&'a SECQ256K1Scalar> for SECQ256K1Scalar {
    type Output = SECQ256K1Scalar;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> AddAssign<&'a SECQ256K1Scalar> for SECQ256K1Scalar {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a SECQ256K1Scalar> for SECQ256K1Scalar {
    type Output = SECQ256K1Scalar;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> SubAssign<&'a SECQ256K1Scalar> for SECQ256K1Scalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a SECQ256K1Scalar> for SECQ256K1Scalar {
    type Output = SECQ256K1Scalar;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> MulAssign<&'a SECQ256K1Scalar> for SECQ256K1Scalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl Neg for SECQ256K1Scalar {
    type Output = SECQ256K1Scalar;

    #[inline]
    fn neg(self) -> Self {
        Self(self.0.neg())
    }
}

impl From<u32> for SECQ256K1Scalar {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<u64> for SECQ256K1Scalar {
    #[inline]
    fn from(value: u64) -> Self {
        Self(Fr::from(value))
    }
}

impl Scalar for SECQ256K1Scalar {
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
        ark_bulletproofs_secq256k1::curve::secq256k1::FrParameters::CAPACITY as usize
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self(Fr::multiplicative_generator())
    }

    #[inline]
    fn get_field_size_biguint() -> BigUint {
        BigUint::from_str_radix(
            "115792089237316195423570985008687907853269984665640564039457584007908834671663",
            10,
        )
        .unwrap()
    }

    #[inline]
    fn get_field_size_le_bytes() -> Vec<u8> {
        [
            0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ]
        .to_vec()
    }

    #[inline]
    fn get_little_endian_u64(&self) -> Vec<u64> {
        let a = self.0.into_repr().to_bytes_le();
        let a1 = u8_le_slice_to_u64(&a[0..8]);
        let a2 = u8_le_slice_to_u64(&a[8..16]);
        let a3 = u8_le_slice_to_u64(&a[16..24]);
        let a4 = u8_le_slice_to_u64(&a[24..32]);
        let a5 = u8_le_slice_to_u64(&a[32..]);
        vec![a1, a2, a3, a4, a5]
    }

    #[inline]
    fn bytes_len() -> usize {
        SECQ256K1_SCALAR_LEN
    }

    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()[..SECQ256K1_SCALAR_LEN].to_vec()
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
    fn pow(&self, exponent: &[u64]) -> Self {
        let len = exponent.len();
        let mut array = [0u64; 5];
        array[..len].copy_from_slice(exponent);
        Self(self.0.pow(&array))
    }
}

impl SECQ256K1Scalar {
    /// Get the raw data.
    pub fn get_raw(&self) -> Fr {
        self.0.clone()
    }

    /// From the raw data.
    pub fn from_raw(raw: Fr) -> Self {
        Self(raw)
    }
}

impl Neg for SECQ256K1G1 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Group for SECQ256K1G1 {
    type ScalarType = SECQ256K1Scalar;
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
        Self::get_base().mul(&SECQ256K1Scalar::random(prng))
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

impl Into<BigUint> for SECQ256K1Scalar {
    #[inline]
    fn into(self) -> BigUint {
        let value: BigUint = self.0.into_repr().into();
        value
    }
}

impl<'a> From<&'a BigUint> for SECQ256K1Scalar {
    #[inline]
    fn from(value: &'a BigUint) -> Self {
        Self(Fr::from(value.clone()))
    }
}

impl SECQ256K1G1 {
    /// Get the raw data.
    pub fn get_raw(&self) -> G1Affine {
        self.0.into_affine()
    }

    /// From the raw data.
    pub fn from_raw(raw: G1Affine) -> Self {
        Self(raw.into_projective())
    }
}

impl<'a> Add<&'a SECQ256K1G1> for SECQ256K1G1 {
    type Output = SECQ256K1G1;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> Sub<&'a SECQ256K1G1> for SECQ256K1G1 {
    type Output = SECQ256K1G1;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> Mul<&'a SECQ256K1Scalar> for SECQ256K1G1 {
    type Output = SECQ256K1G1;

    #[inline]
    fn mul(self, rhs: &SECQ256K1Scalar) -> Self::Output {
        Self(self.0.mul(&rhs.0.into_repr()))
    }
}

impl<'a> AddAssign<&'a SECQ256K1G1> for SECQ256K1G1 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a SECQ256K1G1) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a SECQ256K1G1> for SECQ256K1G1 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a SECQ256K1G1) {
        self.0.sub_assign(&rhs.0)
    }
}

impl<'a> MulAssign<&'a SECQ256K1Scalar> for SECQ256K1G1 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a SECQ256K1Scalar) {
        self.0.mul_assign(rhs.0.clone())
    }
}

#[cfg(test)]
mod secq256k1_groups_test {
    use crate::{
        prelude::*,
        secq256k1::{SECQ256K1Scalar, SECQ256K1G1},
        traits::group_tests::{test_scalar_operations, test_scalar_serialization},
    };
    use ark_bulletproofs_secq256k1::curve::secq256k1::G1Affine;
    use ark_ec::ProjectiveCurve;
    use ark_std::test_rng;

    #[test]
    fn test_scalar_ops() {
        test_scalar_operations::<SECQ256K1Scalar>();
    }

    #[test]
    fn scalar_deser() {
        test_scalar_serialization::<SECQ256K1Scalar>();
    }

    #[test]
    fn scalar_from_to_bytes() {
        let small_value = SECQ256K1Scalar::from(165747u32);
        let small_value_bytes = small_value.to_bytes();
        let expected_small_value_bytes: [u8; 32] = [
            115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(small_value_bytes, expected_small_value_bytes);

        let small_value_from_bytes = SECQ256K1Scalar::from_bytes(&small_value_bytes).unwrap();
        assert_eq!(small_value_from_bytes, small_value);
    }

    #[test]
    fn curve_points_respresentation_of_g1() {
        let mut prng = test_rng();

        let g1 = SECQ256K1G1::get_base();
        let s1 = SECQ256K1Scalar::from(50 + prng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = SECQ256K1G1::random(&mut prng);

        // This is the projective representation of g1
        let g1_projective = g1.0;
        let g1_prime_projective = g1_prime.0;

        // This is the affine representation of g1_prime
        let g1_prime_affine = G1Affine::from(g1_prime_projective);

        let g1_pr_plus_g1_prime_pr = g1_projective.add(&g1_prime_projective);

        // These two operations correspond to summation of points,
        // one in projective form and the other in affine form
        let g1_pr_plus_g1_prime_af = g1_projective.add_mixed(&g1_prime_affine);
        assert_eq!(g1_pr_plus_g1_prime_pr, g1_pr_plus_g1_prime_af);

        let g1_pr_plus_g1_prime_af = g1_projective.add_mixed(&g1_prime_projective.into_affine());
        assert_eq!(g1_pr_plus_g1_prime_pr, g1_pr_plus_g1_prime_af);
    }

    #[test]
    fn test_serialization_of_points() {
        let mut prng = test_rng();

        let g1 = SECQ256K1G1::random(&mut prng);
        let g1_bytes = g1.to_compressed_bytes();
        let g1_recovered = SECQ256K1G1::from_compressed_bytes(&g1_bytes).unwrap();
        assert_eq!(g1, g1_recovered);
    }
}
