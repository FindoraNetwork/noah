use crate::{
    errors::AlgebraError,
    groups::{
        Group, GroupArithmetic, One, Pairing, Scalar as ZeiScalar, ScalarArithmetic,
        Zero,
    },
    jubjub::JubjubScalar,
};
use ark_bls12_381::{
    fr::FrParameters, Bls12_381 as Bls12381pairing, Fq12Parameters, Fr, G1Affine,
    G1Projective, G2Affine, G2Projective,
};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, FftField, FftParameters, Field, Fp12, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    rand::{CryptoRng, RngCore},
    result::Result as StdResult,
    str::FromStr,
    One as ArkOne, UniformRand, Zero as ArkZero,
};
use digest::{generic_array::typenum::U64, Digest};
use num_bigint::BigUint;
use rand_chacha::ChaCha20Rng;
use ruc::*;
use utils::{derive_prng_from_hash, u8_le_slice_to_u64};
use wasm_bindgen::prelude::*;

/// The number of bytes for a scalar value over BLS12-381
pub const BLS12_381_SCALAR_LEN: usize = 32;

/// The wrapped struct for `ark_bls12_381::Fr`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct BLSScalar(Fr);

/// The wrapped struct for `ark_bls12_381::G1Projective`
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BLSG1(pub(crate) G1Projective);

/// The wrapped struct for `ark_bls12_381::G2Projective`
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BLSG2(pub(crate) G2Projective);

/// The wrapped struct for `Fp12<ark_bls12_381::Fq12Parameters>`,
/// which is the pairing result
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug)]
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
        self.get_scalar().into_repr().into()
    }
}

impl From<&BigUint> for BLSScalar {
    fn from(src: &BigUint) -> Self {
        Self(Fr::from(src.clone()))
    }
}

impl BLSScalar {
    #[inline]
    pub fn new(elem: Fr) -> Self {
        Self(elem)
    }

    #[inline]
    pub fn get_scalar(&self) -> Fr {
        self.0
    }

    #[inline]
    pub fn from_le_bits(bits: &[bool]) -> Result<Self> {
        let res = Fr::from_repr(<Fr as PrimeField>::BigInt::from_bits_le(bits));

        if let Some(fr) = res {
            Ok(Self(fr))
        } else {
            Err(eg!(AlgebraError::BitConversionError))
        }
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

impl ScalarArithmetic for BLSScalar {
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
        if a.is_none() {
            return Err(eg!(AlgebraError::GroupInversionError));
        }
        Ok(Self(a.unwrap()))
    }

    #[inline]
    fn neg(&self) -> Self {
        Self(self.0.neg())
    }

    #[inline]
    fn pow(&self, exponent: &[u64]) -> Self {
        let len = exponent.len();
        let mut array = [0u64; 4];
        array[..len].copy_from_slice(exponent);
        Self(self.0.pow(&array))
    }
}

impl ZeiScalar for BLSScalar {
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
        Self(Fr::multiplicative_generator())
    }

    #[inline]
    fn get_field_size_lsf_bytes() -> Vec<u8> {
        [
            0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff,
            0x02, 0xa4, 0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
            0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73,
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
        Self::from_le_bytes(&array).c(d!())
    }

    #[inline]
    fn from_le_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Fr::from_le_bytes_mod_order(bytes)))
    }
}

impl Group for BLSG1 {
    const COMPRESSED_LEN: usize = 48;

    #[inline]
    fn get_identity() -> Self {
        Self(G1Projective::zero())
    }

    #[inline]
    fn get_base() -> Self {
        Self(G1Projective::prime_subgroup_generator())
    }

    #[inline]
    fn get_random_base<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
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
        let mut prng = derive_prng_from_hash::<D, ChaCha20Rng>(hash);
        Self(G1Projective::rand(&mut prng))
    }

    #[inline]
    fn vartime_multi_exp(scalars: &[&Self::S], points: &[&Self]) -> Self {
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

impl GroupArithmetic for BLSG1 {
    type S = BLSScalar;

    #[inline]
    fn add(&self, other: &Self) -> Self {
        Self(self.0.add(&other.0))
    }

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.double())
    }

    #[inline]
    fn mul(&self, other: &BLSScalar) -> Self {
        Self(self.0.mul(&other.0.into_repr()))
    }

    #[inline]
    fn sub(&self, other: &Self) -> Self {
        Self(self.0.sub(&other.0))
    }
}

impl Group for BLSG2 {
    const COMPRESSED_LEN: usize = 96;

    #[inline]
    fn get_identity() -> Self {
        Self(G2Projective::zero())
    }

    #[inline]
    fn get_base() -> Self {
        Self(G2Projective::prime_subgroup_generator())
    }

    #[inline]
    fn get_random_base<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
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
        let mut prng = derive_prng_from_hash::<D, ChaCha20Rng>(hash);
        Self(G2Projective::rand(&mut prng))
    }
}

impl GroupArithmetic for BLSG2 {
    type S = BLSScalar;

    #[inline]
    fn add(&self, other: &Self) -> Self {
        Self(self.0.add(&other.0))
    }

    #[inline]
    fn mul(&self, other: &BLSScalar) -> Self {
        Self(self.0.mul(&other.0.into_repr()))
    }

    #[inline]
    fn sub(&self, other: &Self) -> Self {
        Self(self.0.sub(&other.0))
    }

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.double())
    }
}

pub struct Bls12381;

impl Pairing for Bls12381 {
    type ScalarField = BLSScalar;
    type G1 = BLSG1;
    type G2 = BLSG2;
    type Gt = BLSGt;

    #[inline]
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt {
        BLSGt(Bls12381pairing::pairing(a.0, b.0))
    }
}

impl GroupArithmetic for BLSGt {
    type S = BLSScalar;

    #[inline]
    fn add(&self, other: &Self) -> Self {
        let r = self.0.mul(other.0);
        Self(r)
    }

    #[inline]
    fn mul(&self, scalar: &BLSScalar) -> Self {
        let mut acc = Self::get_identity();

        // This is a simple double-and-add implementation of group element
        // multiplication, moving from most significant to least
        // significant bit of the scalar.
        //
        // We skip the leading bit because it's always unset for Fq
        // elements.
        for bit in scalar
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
                acc = acc.add(self)
            }
        }

        acc
    }

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.mul(&self.0))
    }

    #[inline]
    fn sub(&self, other: &Self) -> Self {
        let mut other_inverse = other.0;
        other_inverse.conjugate();

        Self(self.0.mul(&other_inverse))
    }
}

impl Group for BLSGt {
    const COMPRESSED_LEN: usize = 576;

    #[inline]
    fn get_identity() -> Self {
        Self(Fp12::<Fq12Parameters>::one())
    }

    #[inline]
    fn get_base() -> Self {
        Bls12381::pairing(&BLSG1::get_base(), &BLSG2::get_base())
    }

    #[inline]
    fn get_random_base<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
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
        let mut prng = derive_prng_from_hash::<D, ChaCha20Rng>(hash);
        Self(Fp12::<Fq12Parameters>::rand(&mut prng))
    }
}

#[cfg(test)]
mod bls12_381_groups_test {
    use crate::{
        bls12_381::{BLSGt, BLSScalar, Bls12381, BLSG1, BLSG2},
        groups::{
            group_tests::{test_scalar_operations, test_scalar_serialization},
            Group, GroupArithmetic, Pairing, Scalar,
        },
    };
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::ProjectiveCurve;
    use ark_std::{
        ops::Add,
        rand::{RngCore, SeedableRng},
    };
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_scalar_ops() {
        test_scalar_operations::<super::BLSScalar>();
    }

    #[test]
    fn scalar_deser() {
        test_scalar_serialization::<super::BLSScalar>();
    }

    #[test]
    fn scalar_from_to_bytes() {
        let small_value = BLSScalar::from_u32(165747);
        let small_value_bytes = small_value.to_bytes();
        let expected_small_value_bytes: [u8; 32] = [
            115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(small_value_bytes, expected_small_value_bytes);

        let small_value_from_bytes = BLSScalar::from_bytes(&small_value_bytes).unwrap();
        assert_eq!(small_value_from_bytes, small_value);
    }

    #[test]
    fn hard_coded_group_elements() {
        let base_bls_gt = BLSGt::get_base();
        let expected_base = Bls12381::pairing(&BLSG1::get_base(), &BLSG2::get_base());
        assert_eq!(base_bls_gt, expected_base);
    }

    #[test]
    fn bilinear_properties() {
        let identity_g1 = BLSG1::get_identity();
        let identity_g2 = BLSG2::get_identity();
        let identity_gt_computed = Bls12381::pairing(&identity_g1, &identity_g2);
        let identity_gt = BLSGt::get_identity();
        assert_eq!(identity_gt, identity_gt_computed);

        let mut rng = ChaCha20Rng::from_entropy();

        let s1 = BLSScalar::from_u32(50 + rng.next_u32() % 50);
        let s2 = BLSScalar::from_u32(50 + rng.next_u32() % 50);

        let base_g1 = BLSG1::get_base();
        let base_g2 = BLSG2::get_base();

        let s1_base_g1 = base_g1.mul(&s1);
        let s2_base_g2 = base_g2.mul(&s2);

        let gt_mapped_element = Bls12381::pairing(&s1_base_g1, &s2_base_g2);

        let gt_base_computed = Bls12381::pairing(&base_g1, &base_g2);
        let base_gt = BLSGt::get_base();
        assert_eq!(base_gt, gt_base_computed);

        assert_eq!(
            gt_mapped_element,
            Bls12381::pairing(&base_g1, &s2_base_g2).mul(&s1)
        );
        assert_eq!(
            gt_mapped_element,
            Bls12381::pairing(&s1_base_g1, &base_g2).mul(&s2)
        );

        assert_eq!(gt_mapped_element, gt_base_computed.mul(&s1).mul(&s2));
        assert_eq!(gt_mapped_element, gt_base_computed.mul(&s2).mul(&s1));
    }

    #[test]
    fn curve_points_respresentation_of_g1() {
        let mut rng = ChaCha20Rng::from_entropy();

        let g1 = BLSG1::get_base();
        let s1 = BLSScalar::from_u32(50 + rng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = BLSG1::get_random_base(&mut rng);

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

        let g1_pr_plus_g1_prime_af =
            g1_projective.add_mixed(&g1_prime_projective.into_affine());
        assert_eq!(g1_pr_plus_g1_prime_pr, g1_pr_plus_g1_prime_af);
    }

    #[test]
    fn curve_points_respresentation_of_g2() {
        let mut rng = ChaCha20Rng::from_entropy();

        let g1 = BLSG2::get_base();
        let s1 = BLSScalar::from_u32(50 + rng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = BLSG2::get_random_base(&mut rng);

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

        let g1_pr_plus_g1_prime_af =
            g1_projective.add_mixed(&g1_prime_projective.into_affine());
        assert_eq!(g1_pr_plus_g1_prime_pr, g1_pr_plus_g1_prime_af);
    }

    #[test]
    fn test_serialization_of_points() {
        let mut rng = ChaCha20Rng::from_entropy();

        let g1 = BLSG1::get_random_base(&mut rng);
        let g1_bytes = g1.to_compressed_bytes();
        let g1_recovered = BLSG1::from_compressed_bytes(&g1_bytes).unwrap();
        assert_eq!(g1, g1_recovered);

        let g2 = BLSG2::get_random_base(&mut rng);
        let g2_bytes = g2.to_compressed_bytes();
        let g2_recovered = BLSG2::from_compressed_bytes(&g2_bytes).unwrap();
        assert_eq!(g2, g2_recovered);

        let gt = BLSGt::get_random_base(&mut rng);
        let gt_bytes = gt.to_compressed_bytes();
        let gt_recovered = BLSGt::from_compressed_bytes(&gt_bytes).unwrap();
        assert_eq!(gt, gt_recovered);
    }
}
