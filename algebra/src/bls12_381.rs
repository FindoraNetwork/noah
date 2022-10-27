use crate::{
    errors::AlgebraError,
    prelude::*,
    traits::{Domain, Pairing},
};
use ark_bls12_381::{
    fr::FrParameters, Bls12_381 as Bls12381pairing, Fq, Fq12Parameters, Fr, G1Affine, G1Projective,
    G2Affine, G2Projective,
};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{
    BigInteger, BigInteger256, FftField, FftParameters, Field, Fp12, FpParameters, PrimeField,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::BTreeMap;
use ark_std::{
    fmt::{Debug, Display, Formatter},
    result::Result as StdResult,
    str::FromStr,
};
use digest::{generic_array::typenum::U64, Digest};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Num;
use wasm_bindgen::prelude::*;

#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelIterator, ParallelIterator};

/// The number of bytes for a scalar value over BLS12-381
pub const BLS12_381_SCALAR_LEN: usize = 32;

/// The wrapped struct for [`ark_bls12_381::Fr`](https://docs.rs/ark-bls12-381/0.3.0/ark_bls12_381/fr/struct.FrParameters.html)
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct BLSScalar(pub(crate) Fr);

impl Debug for BLSScalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <BigUint as Debug>::fmt(
            &<BigInteger256 as Into<BigUint>>::into(self.0.into_repr()),
            f,
        )
    }
}

/// The wrapped struct for [`ark_bls12_381::G1Projective`](https://docs.rs/ark-bls12-381/0.3.0/ark_bls12_381/g1/type.G1Projective.html)
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct BLSG1(pub(crate) G1Projective);

impl Debug for BLSG1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <G1Affine as Display>::fmt(&self.0.into_affine(), f)
    }
}

/// The wrapped struct for [`ark_bls12_381::G2Projective`](https://docs.rs/ark-bls12-381/0.3.0/ark_bls12_381/g2/type.G2Projective.html)
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct BLSG2(pub(crate) G2Projective);

impl Debug for BLSG2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <G2Affine as Display>::fmt(&self.0.into_affine(), f)
    }
}

/// The wrapped struct for [`Fp12<ark_bls12_381::Fq12Parameters>`](https://docs.rs/ark-bls12-381/0.3.0/ark_bls12_381/fq12/struct.Fq12Parameters.html),
/// which is the pairing result
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq, Debug)]
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

impl BLSScalar {
    /// Create a new scalar element from the arkworks-rs representation.
    pub const fn new(is_positive: bool, limbs: &[u64]) -> Self {
        type Params = <Fr as PrimeField>::Params;
        BLSScalar(Fr::const_from_str(
            &limbs,
            is_positive,
            Params::R2,
            Params::MODULUS,
            Params::INV,
        ))
    }
}

/// A convenient macro to initialize a field element over the BLS12-381 curve.
#[macro_export]
macro_rules! new_bls12_381 {
    ($c0:expr) => {{
        let (is_positive, limbs) = ark_ff::ark_ff_macros::to_sign_and_limbs!($c0);
        BLSScalar::new(is_positive, &limbs)
    }};
}

impl Into<BigUint> for BLSScalar {
    #[inline]
    fn into(self) -> BigUint {
        self.0.into_repr().into()
    }
}

impl<'a> From<&'a BigUint> for BLSScalar {
    #[inline]
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

impl Sum<BLSScalar> for BLSScalar {
    #[inline]
    fn sum<I: Iterator<Item = BLSScalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
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

impl<'a> Sum<&'a BLSScalar> for BLSScalar {
    #[inline]
    fn sum<I: Iterator<Item = &'a BLSScalar>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
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
    fn capacity() -> usize {
        FrParameters::CAPACITY as usize
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self(Fr::multiplicative_generator())
    }

    #[inline]
    fn get_field_size_biguint() -> BigUint {
        BigUint::from_str_radix(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513",
            10,
        )
        .unwrap()
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

    fn square(&self) -> Self {
        Self(self.0.square())
    }
}

impl Domain for BLSScalar {
    type Field = Fr;

    #[inline]
    fn get_field(&self) -> Self::Field {
        self.0
    }

    #[inline]
    fn from_field(field: Self::Field) -> Self {
        Self(field)
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

    #[inline]
    fn multi_exp_unsafe(scalars: &[&Self::ScalarType], points: &[&Self]) -> Self {
        let scalars_raw = scalars
            .iter()
            .map(|r| r.0.into_repr())
            .collect::<Vec<<FrParameters as FftParameters>::BigInt>>();
        let points_raw = G1Projective::batch_normalization_into_affine(
            &points.iter().map(|r| r.0).collect::<Vec<G1Projective>>(),
        );

        Self(msm_unsafe(&points_raw, &scalars_raw))
    }
}

/// The result of this function is only approximately `ln(a)`
/// [`Explanation of usage`]
///
/// [`Explanation of usage`]: https://github.com/scipr-lab/zexe/issues/79#issue-556220473
fn ln_without_floats(a: usize) -> usize {
    // log2(a) * ln(2)
    (ark_std::log2(a) * 69 / 100) as usize
}

/// Bucketed MSM
pub fn msm_unsafe(bases: &[G1Affine], scalars: &[BigInteger256]) -> G1Projective {
    let size = ark_std::cmp::min(bases.len(), scalars.len());
    let scalars = &scalars[..size];
    let bases = &bases[..size];

    let num_non_zero_entries: usize = scalars
        .iter()
        .map(|x| if x.is_zero() { 0 } else { 1 })
        .sum();

    let scalars_and_bases_iter = scalars.iter().zip(bases).filter(|(s, _)| !s.is_zero());

    let c = if num_non_zero_entries < 512 {
        3
    } else {
        ln_without_floats(num_non_zero_entries) - 3
    };

    let num_bits = <Fr as PrimeField>::Params::MODULUS_BITS as usize;
    let fr_one = Fr::one().into_repr();

    let zero = G1Projective::zero();
    let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

    // Each window is of size `c`.
    // We divide up the bits 0..num_bits into windows of size `c`, and
    // in parallel process each such window.
    let window_sums: Vec<_> = ark_std::cfg_into_iter!(window_starts)
        .map(|w_start| {
            let mut buckets = Vec::new();
            for _ in 0..(1 << c) {
                let v = Vec::<G1Affine>::with_capacity(num_non_zero_entries);
                buckets.push(v);
            }
            // This clone is cheap, because the iterator contains just a
            // pointer and an index into the original vectors.
            scalars_and_bases_iter.clone().for_each(|(&scalar, base)| {
                if scalar == fr_one {
                    // We only process unit scalars once in the first window.
                    if w_start == 0 {
                        buckets[0].push(base.clone());
                    }
                } else {
                    let mut scalar = scalar;

                    // We right-shift by w_start, thus getting rid of the
                    // lower bits.
                    scalar.divn(w_start as u32);

                    // We mod the remaining bits by 2^{window size}, thus taking `c` bits.
                    let scalar = scalar.as_ref()[0] % (1 << c);

                    // If the scalar is non-zero, we update the corresponding
                    // bucket.
                    // (Recall that `buckets` doesn't have a zero bucket.)
                    if scalar != 0 {
                        buckets[scalar as usize].push(base.clone());
                    }
                }
            });

            // Prepare to sum all the buckets
            let buckets_sum = reduce_buckets(&mut buckets);

            // Compute sum_{i in 0..num_buckets} (sum_{j in i..num_buckets} bucket[j])
            // This is computed below for b buckets, using 2b curve additions.
            //
            // We could first normalize `buckets` and then use mixed-addition
            // here, but that's slower for the kinds of groups we care about
            // (Short Weierstrass curves and Twisted Edwards curves).
            // In the case of Short Weierstrass curves,
            // mixed addition saves ~4 field multiplications per addition.
            // However normalization (with the inversion batched) takes ~6
            // field multiplications per element,
            // hence batch normalization is a slowdown.

            // `running_sum` = sum_{j in i..num_buckets} bucket[j],
            // where we iterate backward from i = num_buckets to 0.
            let mut res = buckets_sum[0].clone();
            let mut running_sum = G1Projective::zero();
            buckets_sum[1..].into_iter().rev().for_each(|b| {
                running_sum += b;
                res += &running_sum;
            });
            res
        })
        .collect();

    // We store the sum for the lowest window.
    let lowest = *window_sums.first().unwrap();

    // We're traversing windows from high to low.
    lowest
        + &window_sums[1..]
            .iter()
            .rev()
            .fold(zero, |mut total, sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total.double_in_place();
                }
                total
            })
}

/// Reduce the buckets
pub fn reduce_buckets(buckets: &mut Vec<Vec<G1Affine>>) -> Vec<G1Projective> {
    const THRESHOLD: usize = 16;

    let mut res = vec![G1Projective::zero(); buckets.len()];

    loop {
        let mut flag_all_below_threshold = true;

        // construct a list of divisors
        let mut divisors_all_buckets = BTreeMap::<usize, Vec<Fq>>::new();
        let mut num_divisors = 0usize;
        for (i, bucket) in buckets.iter_mut().enumerate() {
            let len = bucket.len();
            if len > THRESHOLD {
                flag_all_below_threshold = false;
                let mut divisors = Vec::with_capacity(len / 2);

                if len.is_odd() {
                    for chunk in bucket[1..].chunks_exact(2) {
                        divisors.push(chunk[1].x.clone() - &chunk[0].x);
                    }
                } else {
                    for chunk in bucket.chunks_exact(2) {
                        divisors.push(chunk[1].x.clone() - &chunk[0].x);
                    }
                }
                num_divisors += divisors.len();
                divisors_all_buckets.insert(i, divisors);
            } else if len != 0 {
                let mut sum = G1Projective::zero();
                bucket.iter().for_each(|x| sum.add_assign_mixed(x));
                bucket.clear();
                res[i] = sum;
            }
        }

        if flag_all_below_threshold {
            break;
        }

        // compute the batch inversion
        let mut sketchpad = Vec::<Fq>::with_capacity(num_divisors);
        for (_, divisors) in divisors_all_buckets.iter() {
            sketchpad.extend_from_slice(&divisors);
        }
        ark_ff::batch_inversion(&mut sketchpad);
        let mut idx = 0;
        for (_, divisors) in divisors_all_buckets.iter_mut() {
            let divisors_len = divisors.len();
            *divisors = sketchpad[idx..idx + divisors_len].to_vec();
            idx += divisors_len;
        }

        for (i, bucket) in divisors_all_buckets.iter() {
            let len = buckets[*i].len();

            let src: &[G1Affine] = if len.is_odd() {
                &buckets[*i][1..]
            } else {
                &buckets[*i][..]
            };

            let dest: Vec<G1Affine> = src
                .chunks_exact(2)
                .enumerate()
                .map(|(i, points)| {
                    let x2_minus_x1_inv: Fq = bucket[i].clone();
                    let y2_minus_y1: Fq = points[1].y.clone() - &points[0].y;

                    let m = y2_minus_y1 * x2_minus_x1_inv;
                    let x_3 = m.square() - &points[0].x - &points[1].x;
                    let y_3 = m * (points[0].x - &x_3) - &points[0].y;

                    G1Affine {
                        x: x_3,
                        y: y_3,
                        infinity: false,
                    }
                })
                .collect();

            if len.is_odd() {
                buckets[*i].truncate(1);
                buckets[*i].extend_from_slice(&dest);
            } else {
                buckets[*i] = dest;
            }
        }
    }

    res
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

impl<'a> MulAssign<&'a BLSScalar> for BLSG1 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a BLSScalar) {
        self.0.mul_assign(rhs.0.clone())
    }
}

impl Neg for BLSG1 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
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
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let affine = G2Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize_unchecked(&mut buf).unwrap();

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
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G2Affine::deserialize_unchecked(&mut reader);

        if affine.is_ok() {
            Ok(Self(affine.unwrap().into_projective()))
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn unchecked_size() -> usize {
        let g = G2Affine::from(Self::get_base().0);
        g.uncompressed_size()
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

impl Neg for BLSG2 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
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

impl Neg for BLSGt {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut v = self.0;
        v.conjugate();
        Self(v)
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
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.0.serialize_unchecked(&mut buf).unwrap();

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
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let res = Fp12::<Fq12Parameters>::deserialize_unchecked(&mut reader);

        if res.is_ok() {
            Ok(Self(res.unwrap()))
        } else {
            Err(eg!(AlgebraError::DeserializationError))
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

        let mut prng = test_rng();

        let s1 = BLSScalar::from(50 + prng.next_u32() % 50);
        let s2 = BLSScalar::from(50 + prng.next_u32() % 50);

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
        let mut prng = test_rng();

        let g1 = BLSG1::get_base();
        let s1 = BLSScalar::from(50 + prng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = BLSG1::random(&mut prng);

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
        let mut prng = test_rng();

        let g1 = BLSG2::get_base();
        let s1 = BLSScalar::from(50 + prng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = BLSG2::random(&mut prng);

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
        let mut prng = test_rng();

        let g1 = BLSG1::random(&mut prng);
        let g1_bytes = g1.to_compressed_bytes();
        let g1_recovered = BLSG1::from_compressed_bytes(&g1_bytes).unwrap();
        assert_eq!(g1, g1_recovered);

        let g2 = BLSG2::random(&mut prng);
        let g2_bytes = g2.to_compressed_bytes();
        let g2_recovered = BLSG2::from_compressed_bytes(&g2_bytes).unwrap();
        assert_eq!(g2, g2_recovered);

        let gt = BLSGt::random(&mut prng);
        let gt_bytes = gt.to_compressed_bytes();
        let gt_recovered = BLSGt::from_compressed_bytes(&gt_bytes).unwrap();
        assert_eq!(gt, gt_recovered);
    }
}
