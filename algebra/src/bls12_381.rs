use crate::{errors::AlgebraError, jubjub::JubjubScalar, prelude::*, traits::Pairing};
use ark_bls12_381::{
    fr::FrParameters, Bls12_381 as Bls12381pairing, Fq12Parameters, Fr, G1Affine, G1Projective,
    G2Affine, G2Projective,
};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, FftField, FftParameters, Field, Fp12, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    fmt::{Debug, Display, Formatter},
    result::Result as StdResult,
    str::FromStr,
};
use digest::{generic_array::typenum::U64, Digest};
use num_bigint::BigUint;
use wasm_bindgen::prelude::*;

/// The number of bytes for a scalar value over BLS12-381
pub const BLS12_381_SCALAR_LEN: usize = 32;

/// The wrapped struct for `ark_bls12_381::Fr`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub struct BLSScalar(pub(crate) Fr);

impl Debug for BLSScalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let biguint = BigUint::from(self.0.clone());
        <BigUint as Display>::fmt(&biguint, f)
    }
}

/// The wrapped struct for `ark_bls12_381::G1Projective`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct BLSG1(pub(crate) G1Projective);

/// The wrapped struct for `ark_bls12_381::G2Projective`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct BLSG2(pub(crate) G2Projective);

/// The wrapped struct for `Fp12<ark_bls12_381::Fq12Parameters>`,
/// which is the pairing result
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct BLSGt(pub(crate) Fp12<Fq12Parameters>);

impl FromStr for BLSScalar {
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

impl From<&JubjubScalar> for BLSScalar {
    fn from(scalar: &JubjubScalar) -> Self {
        let bytes = scalar.to_bytes();
        BLSScalar::from_bytes(&bytes).unwrap()
    }
}

impl Into<BigUint> for &BLSScalar {
    fn into(self) -> BigUint {
        self.0.into_repr().into()
    }
}

impl From<&BigUint> for BLSScalar {
    fn from(src: &BigUint) -> Self {
        Self(Fr::from(src.clone()))
    }
}

impl One for BLSScalar {
    #[inline]
    fn one() -> Self {
        BLSScalar(Fr::one())
    }
}

impl Zero for BLSScalar {
    #[inline]
    fn zero() -> Self {
        Self(Fr::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Add for BLSScalar {
    type Output = BLSScalar;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Mul for BLSScalar {
    type Output = BLSScalar;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> Add<&'a BLSScalar> for BLSScalar {
    type Output = BLSScalar;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> AddAssign<&'a BLSScalar> for BLSScalar {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a BLSScalar> for BLSScalar {
    type Output = BLSScalar;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> SubAssign<&'a BLSScalar> for BLSScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a BLSScalar> for BLSScalar {
    type Output = BLSScalar;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> MulAssign<&'a BLSScalar> for BLSScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl Neg for BLSScalar {
    type Output = BLSScalar;

    #[inline]
    fn neg(self) -> Self {
        Self(self.0.neg())
    }
}

impl From<u32> for BLSScalar {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<u64> for BLSScalar {
    #[inline]
    fn from(value: u64) -> Self {
        Self(Fr::from(value))
    }
}

impl Scalar for BLSScalar {
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
    fn multiplicative_generator() -> Self {
        Self(Fr::multiplicative_generator())
    }

    #[inline]
    fn get_field_size_le_bytes() -> Vec<u8> {
        [
            0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4,
            0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29,
            0x53, 0xa7, 0xed, 0x73,
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
        BLS12_381_SCALAR_LEN
    }

    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
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
        let mut array = [0u64; 4];
        array[..len].copy_from_slice(exponent);
        Self(self.0.pow(&array))
    }
}

impl Group for BLSG1 {
    type ScalarType = BLSScalar;
    const COMPRESSED_LEN: usize = 48;

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
    fn random<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self::get_base().mul(&BLSScalar::random(prng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let affine = G1Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize(&mut buf).unwrap();

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

impl<'a> Add<&'a BLSG1> for BLSG1 {
    type Output = BLSG1;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> Sub<&'a BLSG1> for BLSG1 {
    type Output = BLSG1;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> Mul<&'a BLSScalar> for BLSG1 {
    type Output = BLSG1;

    #[inline]
    fn mul(self, rhs: &BLSScalar) -> Self::Output {
        Self(self.0.mul(&rhs.0.into_repr()))
    }
}

impl<'a> AddAssign<&'a BLSG1> for BLSG1 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a BLSG1) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a BLSG1> for BLSG1 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a BLSG1) {
        self.0.sub_assign(&rhs.0)
    }
}

impl Group for BLSG2 {
    type ScalarType = BLSScalar;
    const COMPRESSED_LEN: usize = 96;

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.double())
    }

    #[inline]
    fn get_identity() -> Self {
        Self(G2Projective::zero())
    }

    #[inline]
    fn get_base() -> Self {
        Self(G2Projective::prime_subgroup_generator())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self::get_base().mul(&BLSScalar::random(prng))
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

        let affine = G2Affine::deserialize(&mut reader);

        if affine.is_ok() {
            Ok(Self(affine.unwrap().into_projective()))
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        Self(G2Projective::rand(&mut prng))
    }
}

impl<'a> Add<&'a BLSG2> for BLSG2 {
    type Output = BLSG2;

    #[inline]
    fn add(self, rhs: &'a Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> Sub<&'a BLSG2> for BLSG2 {
    type Output = BLSG2;

    #[inline]
    fn sub(self, rhs: &'a Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> Mul<&'a BLSScalar> for BLSG2 {
    type Output = BLSG2;

    #[inline]
    fn mul(self, rhs: &'a BLSScalar) -> Self::Output {
        Self(self.0.mul(&rhs.0.into_repr()))
    }
}

impl<'a> AddAssign<&'a BLSG2> for BLSG2 {
    #[inline]
    fn add_assign(&mut self, rhs: &BLSG2) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a BLSG2> for BLSG2 {
    #[inline]
    fn sub_assign(&mut self, rhs: &BLSG2) {
        self.0.sub_assign(&rhs.0)
    }
}

/// The pairing engine for BLS12-381
pub struct BLSPairingEngine;

impl Pairing for BLSPairingEngine {
    type ScalarField = BLSScalar;
    type G1 = BLSG1;
    type G2 = BLSG2;
    type Gt = BLSGt;

    #[inline]
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt {
        BLSGt(Bls12381pairing::pairing(a.0, b.0))
    }
}

impl<'a> Add<&'a BLSGt> for BLSGt {
    type Output = BLSGt;

    #[inline]
    fn add(self, rhs: &'a BLSGt) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> Sub<&'a BLSGt> for BLSGt {
    type Output = BLSGt;

    #[inline]
    fn sub(self, rhs: &'a BLSGt) -> Self::Output {
        let mut rhs_inverse = rhs.0.clone();
        rhs_inverse.conjugate();

        Self(self.0.mul(&rhs_inverse))
    }
}

impl<'a> Mul<&'a BLSScalar> for BLSGt {
    type Output = BLSGt;

    fn mul(self, rhs: &'a BLSScalar) -> Self::Output {
        let mut acc = Self::get_identity();

        // This is a simple double-and-add implementation of group element
        // multiplication, moving from most significant to least
        // significant bit of the scalar.
        //
        // We skip the leading bit because it's always unset for Fq
        // elements.
        for bit in rhs
            .0
            .into_repr()
            .to_bytes_le()
            .iter()
            .rev()
            .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1u8) == 1u8))
            .skip(1)
        {
            acc = acc.double();
            if bit {
                acc = acc.add(&self)
            }
        }

        acc
    }
}

impl<'a> AddAssign<&'a BLSGt> for BLSGt {
    #[inline]
    fn add_assign(&mut self, rhs: &'a BLSGt) {
        self.0.mul_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a BLSGt> for BLSGt {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a BLSGt) {
        let mut rhs_inverse = rhs.0.clone();
        rhs_inverse.conjugate();

        self.0.mul_assign(&rhs_inverse)
    }
}

impl Group for BLSGt {
    type ScalarType = BLSScalar;

    const COMPRESSED_LEN: usize = 576;

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.mul(&self.0))
    }

    #[inline]
    fn get_identity() -> Self {
        Self(Fp12::<Fq12Parameters>::one())
    }

    #[inline]
    fn get_base() -> Self {
        BLSPairingEngine::pairing(&BLSG1::get_base(), &BLSG2::get_base())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self::get_base().mul(&BLSScalar::random(prng))
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

        let res = Fp12::<Fq12Parameters>::deserialize(&mut reader);

        if res.is_ok() {
            Ok(Self(res.unwrap()))
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        Self(Fp12::<Fq12Parameters>::rand(&mut prng))
    }
}

#[cfg(test)]
mod bls12_381_groups_test {
    use crate::{
        bls12_381::{BLSGt, BLSPairingEngine, BLSScalar, BLSG1, BLSG2},
        prelude::*,
        traits::{
            group_tests::{test_scalar_operations, test_scalar_serialization},
            Pairing,
        },
    };
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::ProjectiveCurve;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_scalar_ops() {
        test_scalar_operations::<BLSScalar>();
    }

    #[test]
    fn scalar_deser() {
        test_scalar_serialization::<BLSScalar>();
    }

    #[test]
    fn scalar_from_to_bytes() {
        let small_value = BLSScalar::from(165747u32);
        let small_value_bytes = small_value.to_bytes();
        let expected_small_value_bytes: [u8; 32] = [
            115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(small_value_bytes, expected_small_value_bytes);

        let small_value_from_bytes = BLSScalar::from_bytes(&small_value_bytes).unwrap();
        assert_eq!(small_value_from_bytes, small_value);
    }

    #[test]
    fn hard_coded_group_elements() {
        let base_bls_gt = BLSGt::get_base();
        let expected_base = BLSPairingEngine::pairing(&BLSG1::get_base(), &BLSG2::get_base());
        assert_eq!(base_bls_gt, expected_base);
    }

    #[test]
    fn bilinear_properties() {
        let identity_g1 = BLSG1::get_identity();
        let identity_g2 = BLSG2::get_identity();
        let identity_gt_computed = BLSPairingEngine::pairing(&identity_g1, &identity_g2);
        let identity_gt = BLSGt::get_identity();
        assert_eq!(identity_gt, identity_gt_computed);

        let mut rng = ChaCha20Rng::from_entropy();

        let s1 = BLSScalar::from(50 + rng.next_u32() % 50);
        let s2 = BLSScalar::from(50 + rng.next_u32() % 50);

        let base_g1 = BLSG1::get_base();
        let base_g2 = BLSG2::get_base();

        let s1_base_g1 = base_g1.mul(&s1);
        let s2_base_g2 = base_g2.mul(&s2);

        let gt_mapped_element = BLSPairingEngine::pairing(&s1_base_g1, &s2_base_g2);

        let gt_base_computed = BLSPairingEngine::pairing(&base_g1, &base_g2);
        let base_gt = BLSGt::get_base();
        assert_eq!(base_gt, gt_base_computed);

        assert_eq!(
            gt_mapped_element,
            BLSPairingEngine::pairing(&base_g1, &s2_base_g2).mul(&s1)
        );
        assert_eq!(
            gt_mapped_element,
            BLSPairingEngine::pairing(&s1_base_g1, &base_g2).mul(&s2)
        );

        assert_eq!(gt_mapped_element, gt_base_computed.mul(&s1).mul(&s2));
        assert_eq!(gt_mapped_element, gt_base_computed.mul(&s2).mul(&s1));
    }

    #[test]
    fn curve_points_respresentation_of_g1() {
        let mut rng = ChaCha20Rng::from_entropy();

        let g1 = BLSG1::get_base();
        let s1 = BLSScalar::from(50 + rng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = BLSG1::random(&mut rng);

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
    fn curve_points_respresentation_of_g2() {
        let mut rng = ChaCha20Rng::from_entropy();

        let g1 = BLSG2::get_base();
        let s1 = BLSScalar::from(50 + rng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = BLSG2::random(&mut rng);

        // This is the projective representation of g1
        let g1_projective = g1.0;
        let g1_prime_projective = g1_prime.0;

        // This is the affine representation of g1_prime
        let g1_prime_affine = G2Affine::from(g1_prime_projective);

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
        let mut rng = ChaCha20Rng::from_entropy();

        let g1 = BLSG1::random(&mut rng);
        let g1_bytes = g1.to_compressed_bytes();
        let g1_recovered = BLSG1::from_compressed_bytes(&g1_bytes).unwrap();
        assert_eq!(g1, g1_recovered);

        let g2 = BLSG2::random(&mut rng);
        let g2_bytes = g2.to_compressed_bytes();
        let g2_recovered = BLSG2::from_compressed_bytes(&g2_bytes).unwrap();
        assert_eq!(g2, g2_recovered);

        let gt = BLSGt::random(&mut rng);
        let gt_bytes = gt.to_compressed_bytes();
        let gt_recovered = BLSGt::from_compressed_bytes(&gt_bytes).unwrap();
        assert_eq!(gt, gt_recovered);
    }
}
