use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use ruc::err::*;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use utils::shift_u8_vec;

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
    // generation
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self;
    fn from_u32(value: u32) -> Self;
    fn from_u64(value: u64) -> Self;
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default;
    // multiplicative generator of r-1 order, that is also a quadratic nonresidue
    fn multiplicative_generator() -> Self;

    // field size
    fn get_field_size_lsf_bytes() -> Vec<u8>;
    fn field_size_minus_one_half() -> Vec<u8> {
        let mut q_minus_1_half_le = Self::get_field_size_lsf_bytes();
        // divide by 2 by shifting, first bit is one since F is odd prime
        shift_u8_vec(&mut q_minus_1_half_le);
        q_minus_1_half_le
    }
    fn get_little_endian_u64(&self) -> Vec<u64>;
    fn bytes_len() -> usize;
    // serialization
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

    /// Pick a random base/generator inside the group
    /// The generic algorithm consists of the following steps:
    /// 1. pick a fix generator g
    /// 2. sample a random scalar x
    /// 3. check that gcd(x,q)=1 where q is the order of the group
    /// 4. return g^x
    fn get_random_base<R: CryptoRng + RngCore>(_prng: &mut R) -> Self {
        panic!("Not implemented.");
    } // TODO ticket #445 (redmine)

    // compression/serialization helpers
    fn to_compressed_bytes(&self) -> Vec<u8>;
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self>;
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default;
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
    //let mut digits_count = scalar64.len()*64/w; //upper bound
    let mut i = 0;
    //for i in 0..digits_count {
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
        carry = (coef + (radix / 2) as u64) >> w;
        digits.push(((coef as i64) - (carry << w) as i64) as i8);
        i += 1;
    }

    while digits.len() > 1 && *digits.last().unwrap() == 0i8 {
        // safe unwrap
        digits.pop();
    }
    digits
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
