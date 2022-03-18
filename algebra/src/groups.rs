use ark_std::{
    borrow::Borrow,
    fmt::Debug,
    rand::{CryptoRng, RngCore},
};
use digest::{generic_array::typenum::U64, Digest};
use ruc::err::*;
use serde::{Deserialize, Serialize};
use utils::shift_u8_vec;
use crate::errors::AlgebraError;

pub trait GroupArithmetic {
    type S: Scalar;
    fn mul(&self, scalar: &Self::S) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn double(&self) -> Self;
}

pub trait One {
    fn one() -> Self;
}

pub trait Zero {
    fn zero() -> Self;
    fn is_zero(&self) -> bool;
}

pub trait ScalarArithmetic: Clone + One + Zero + Sized {
    fn add(&self, b: &Self) -> Self;
    fn add_assign(&mut self, b: &Self);
    fn mul(&self, b: &Self) -> Self;
    fn mul_assign(&mut self, b: &Self);
    fn sub(&self, b: &Self) -> Self;
    fn sub_assign(&mut self, b: &Self);
    fn inv(&self) -> Result<Self>;
    fn neg(&self) -> Self {
        Self::zero().sub(self)
    }

    /// exponent form: least significant limb first, with u64 limbs
    fn pow(&self, exponent: &[u64]) -> Self {
        let mut base = self.clone();
        let mut result = Self::one();
        for exp_u64 in exponent {
            let mut e = *exp_u64;
            // we have to square the base for 64 times.
            for _ in 0..64 {
                if e % 2 == 1 {
                    result.mul_assign(&base);
                }
                base = base.mul(&base);
                e >>= 1;
            }
        }
        result
    }
}

pub trait Scalar:
    Copy + Debug + PartialEq + Eq + ScalarArithmetic + Serialize + for<'de> Deserialize<'de>
{
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self;
    fn from_u32(value: u32) -> Self;
    fn from_u64(value: u64) -> Self;
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default;

    // multiplicative generator of order r, which is also a quadratic nonresidue
    fn multiplicative_generator() -> Self;
    fn get_field_size_lsf_bytes() -> Vec<u8>;
    fn field_size_minus_one_half() -> Vec<u8> {
        let mut q_minus_1_half_le = Self::get_field_size_lsf_bytes();
        // divide by 2 by shifting, first bit is one since F is odd prime
        shift_u8_vec(&mut q_minus_1_half_le);
        q_minus_1_half_le
    }
    fn get_little_endian_u64(&self) -> Vec<u64>;
    fn bytes_len() -> usize;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
    fn from_le_bytes(bytes: &[u8]) -> Result<Self>;
}

pub trait Group:
    Debug
    + Sized
    + PartialEq
    + Eq
    + Clone
    + GroupArithmetic
    + Serialize
    + for<'de> Deserialize<'de>
{
    const COMPRESSED_LEN: usize;

    fn get_identity() -> Self;
    fn get_base() -> Self;
    fn get_random_base<R: CryptoRng + RngCore>(rng: &mut R) -> Self;

    fn to_compressed_bytes(&self) -> Vec<u8>;
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self>;
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default;

    fn naive_multi_exp<I, H>(scalars: I, points: H) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<Self::S>,
        H: IntoIterator,
        H::Item: Borrow<Self>,
    {
        let mut r = Self::get_identity();
        for (s, p) in scalars.into_iter().zip(points.into_iter()) {
            r = r.add(&p.borrow().mul(s.borrow()))
        }
        r
    }

    #[inline]
    fn multi_exp<I, H>(scalars: I, points: H) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<Self::S>,
        H: IntoIterator,
        H::Item: Borrow<Self>,
    {
        Self::naive_multi_exp(scalars, points)
    }

    #[inline]
    fn vartime_multi_exp(scalars: &[&Self::S], points: &[&Self]) -> Self {
        if scalars.is_empty() {
            Self::get_identity()
        } else {
            pippenger(scalars, points).unwrap()
        }
    }
}

pub trait Pairing {
    type ScalarField: Scalar;
    type G1: Group<S = Self::ScalarField>;
    type G2: Group<S = Self::ScalarField>;
    type Gt: Group<S = Self::ScalarField>;
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt;
}

pub fn scalar_to_radix_2_power_w<S: Scalar>(scalar: &S, w: usize) -> Vec<i8> {
    if *scalar == S::from_u32(0) {
        return vec![0i8];
    }
    let scalar64 = scalar.get_little_endian_u64();

    let radix: u64 = 1 << (w as u64);
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let mut digits = vec![];

    let mut i = 0;
    loop {
        // Construct a buffer of bits of the scalar, starting at `bit_offset`.
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;
        if u64_idx >= scalar64.len() {
            digits.push(carry as i8);
            break;
        }
        let is_last = u64_idx == scalar64.len() - 1;

        // Read the bits from the scalar
        let bit_buf = if bit_idx < 64 - w || is_last {
            // This window's bits are contained in a single u64,
            scalar64[u64_idx] >> (bit_idx as u64)
        } else {
            // Combine the current u64's bits with the bits from the next u64
            (scalar64[u64_idx] >> bit_idx) | (scalar64[1 + u64_idx] << (64 - bit_idx))
        };

        // Read the actual coefficient value from the window
        let coef = carry + (bit_buf & window_mask); // coef = [0, 2^r)

        // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
        carry = (coef + (radix / 2)) >> w;
        digits.push(((coef as i64) - (carry << w) as i64) as i8);
        i += 1;
    }

    while digits.len() > 1 && *digits.last().unwrap() == 0i8 {
        // safe unwrap
        digits.pop();
    }
    digits
}


pub fn pippenger<G: Group>(scalars: &[&G::S], elems: &[&G]) -> Result<G> {
    let size = scalars.len();

    if size == 0 {
        return Err(eg!(AlgebraError::ParameterError));
    }

    let w = if size < 500 {
        6
    } else if size < 800 {
        7
    } else {
        8
    };

    let two_power_w: usize = 1 << w;
    let digits_vec: Vec<Vec<i8>> = scalars
        .iter()
        .map(|s| scalar_to_radix_2_power_w::<G::S>(s, w))
        .collect();

    let mut digits_count = 0;
    for digits in digits_vec.iter() {
        if digits.len() > digits_count {
            digits_count = digits.len();
        }
    }

    // init all the buckets
    let mut buckets: Vec<_> = (0..two_power_w / 2).map(|_| G::get_identity()).collect();

    let mut cols = (0..digits_count).rev().map(|index| {
        // empty each bucket
        for b in buckets.iter_mut() {
            *b = G::get_identity();
        }
        for (digits, elem) in digits_vec.iter().zip(elems) {
            if index >= digits.len() {
                continue;
            }
            let digit = digits[index];
            if digit > 0 {
                let b_index = (digit - 1) as usize;
                buckets[b_index] = buckets[b_index].add(elem);
            }
            if digit < 0 {
                let b_index = (-(digit + 1)) as usize;
                buckets[b_index] = buckets[b_index].sub(elem);
            }
        }
        let mut intermediate_sum = buckets[buckets.len() - 1].clone();
        let mut sum = buckets[buckets.len() - 1].clone();
        for i in (0..buckets.len() - 1).rev() {
            intermediate_sum = intermediate_sum.add(&buckets[i]);
            sum = sum.add(&intermediate_sum);
        }
        sum
    });

    let two_power_w_int = Scalar::from_u64(two_power_w as u64);
    // This unwrap is safe as the list of scalars is non empty at this point.
    let hi_col = cols.next().unwrap();
    let res = cols.fold(hi_col, |total, p| total.mul(&two_power_w_int).add(&p));
    Ok(res)
}

#[cfg(test)]
pub(crate) mod group_tests {
    use crate::groups::{scalar_to_radix_2_power_w, Scalar};

    pub(crate) fn test_scalar_operations<S: Scalar>() {
        let a = S::from_u32(40);
        let b = S::from_u32(60);
        let c = a.add(&b);
        let d = S::from_u32(100);
        assert_eq!(c, d);

        let mut x = S::from_u32(0);
        x.add_assign(&a);
        x.add_assign(&b);
        assert_eq!(x, d);

        let a = S::from_u32(10);
        let b = S::from_u32(40);
        let c = a.mul(&b);
        let d = S::from_u32(400);
        assert_eq!(c, d);

        let mut x = S::from_u32(1);
        x.mul_assign(&a);
        x.mul_assign(&b);
        assert_eq!(x, d);

        let a = S::from_u32(0xFFFFFFFF);
        let b = S::from_u32(1);
        let c = a.add(&b);
        let d = S::from_u64(0x100000000);
        assert_eq!(c, d);

        let a = S::from_u32(0xFFFFFFFF);
        let b = S::from_u32(1);
        let c = a.mul(&b);
        let d = S::from_u32(0xFFFFFFFF);
        assert_eq!(c, d);

        let a = S::from_u32(40);
        let b = S::from_u32(60);
        let c = b.sub(&a);
        let d = S::from_u32(20);
        assert_eq!(c, d);

        let mut x = S::from_u32(120);
        x.sub_assign(&b);
        x.sub_assign(&a);
        assert_eq!(x, d);

        let a = S::from_u32(40);
        let b = a.neg();
        let c = b.add(&a);
        let d = S::from_u32(0);
        assert_eq!(c, d);

        let a = S::from_u32(40);
        let b = a.inv().unwrap();
        let c = b.mul(&a);
        let d = S::from_u32(1);
        assert_eq!(c, d);

        let a = S::from_u32(3);
        let b = vec![20];
        let c = a.pow(&b[..]);
        let d = S::from_u64(3486784401);
        assert_eq!(c, d);
    }

    pub(crate) fn test_scalar_serialization<S: Scalar>() {
        let a = S::from_u32(100);
        let bytes = a.to_bytes();
        let b = S::from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(a, b);
    }

    pub(crate) fn test_to_radix<S: Scalar>() {
        let int = S::from_u32(41);
        let w = 2;
        let r = scalar_to_radix_2_power_w(&int, w);
        let expected = [1i8, -2, -1, 1]; // 41 = 1 + -2*4 + -1*16 + 64
        assert_eq!(r.as_slice(), expected.as_ref());

        let int = S::from_u32(0);
        let w = 2;
        let r = scalar_to_radix_2_power_w(&int, w);
        let expected = [0i8];
        assert_eq!(expected.as_ref(), r.as_slice());

        let int = S::from_u32(1000);
        let w = 6;
        let r = scalar_to_radix_2_power_w(&int, w);
        let expected = [-24, 16];
        assert_eq!(expected.as_ref(), r.as_slice());
    }
}

#[cfg(test)]
mod multi_exp_tests {
    use crate::bls12_381::{BLSGt, BLSG1, BLSG2};
    use crate::groups::{Group, Scalar};
    use crate::ristretto::RistrettoPoint;

    #[test]
    fn test_multiexp_ristretto() {
        run_multiexp_test::<RistrettoPoint>();
    }
    #[test]
    fn test_multiexp_blsg1() {
        run_multiexp_test::<BLSG1>();
    }
    #[test]
    fn test_multiexp_blsg2() {
        run_multiexp_test::<BLSG2>();
    }
    #[test]
    fn test_multiexp_blsgt() {
        run_multiexp_test::<BLSGt>();
    }

    fn run_multiexp_test<G: Group>() {
        let g = G::vartime_multi_exp(&[], &[]);
        assert_eq!(g, G::get_identity());

        let g1 = G::get_base();
        let zero = G::S::from_u32(0);
        let g = G::vartime_multi_exp(&[&zero], &[&g1]);
        assert_eq!(g, G::get_identity());

        let g1 = G::get_base();
        let one = Scalar::from_u32(1);
        let g = G::vartime_multi_exp(&[&one], &[&g1]);
        assert_eq!(g, G::get_base());

        let g1 = G::get_base();
        let g1p = G::get_base();
        let one = Scalar::from_u32(1);
        let zero = Scalar::from_u32(0);
        let g = G::vartime_multi_exp(&[&one, &zero], &[&g1, &g1p]);
        assert_eq!(g, G::get_base());

        let g1 = G::get_base();
        let g2 = g1.add(&g1);
        let g3 = g1.mul(&Scalar::from_u32(500));
        let thousand = Scalar::from_u32(1000);
        let two = Scalar::from_u32(2);
        let three = Scalar::from_u32(3);
        let g = G::vartime_multi_exp(&[&thousand, &two, &three], &[&g1, &g2, &g3]);
        let expected = G::get_base().mul(&Scalar::from_u32(1000 + 4 + 1500));
        assert_eq!(g, expected);
    }
}
