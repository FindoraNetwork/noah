use crate::prelude::*;
use ark_ff::FftField;
pub use ark_ff::LegendreSymbol;
use ark_std::{fmt::Debug, vec, vec::Vec};
use digest::{generic_array::typenum::U64, Digest};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// The trait for scalars
pub trait Scalar:
    Copy
    + Default
    + Debug
    + PartialEq
    + Eq
    + Serialize
    + for<'de> Deserialize<'de>
    + Into<BigUint>
    + for<'a> From<&'a BigUint>
    + Clone
    + One
    + Zero
    + Sized
    + Add<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Sum<Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> MulAssign<&'a Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> Sum<&'a Self>
    + From<u32>
    + From<u64>
    + Neg<Output = Self>
    + Sync
    + Send
{
    /// Return a random scalar
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self;

    /// Sample a scalar based on a hash value
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default;

    /// Return multiplicative generator of order r,
    /// which is also required to be a quadratic nonresidue
    fn multiplicative_generator() -> Self;

    /// Return the capacity.
    fn capacity() -> usize;

    /// Return the little-endian byte representations of the field size
    fn get_field_size_le_bytes() -> Vec<u8>;

    /// Return the field size as a BigUint
    fn get_field_size_biguint() -> BigUint;

    /// Return the little-endian byte representation of `(field_size - 1) / 2`,
    /// assuming that `field_size` is odd
    fn field_size_minus_one_half() -> Vec<u8> {
        let mut q_minus_1_half_le = Self::get_field_size_le_bytes();
        // divide by 2 by shifting, first bit is one since F is odd prime
        shift_u8_vec(&mut q_minus_1_half_le);
        q_minus_1_half_le
    }

    /// Return a representation of the scalar as a vector of u64 in the little-endian order
    fn get_little_endian_u64(&self) -> Vec<u64>;

    /// Return the len of the byte representation
    fn bytes_len() -> usize;

    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Convert from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Return the modular inverse of the scalar if it exists
    fn inv(&self) -> Result<Self>;

    /// Return the square of the field element
    fn square(&self) -> Self;

    /// Return the square root.
    fn sqrt(&self) -> Option<Self>;

    /// Return the legendre symbol of the field element
    fn legendre(&self) -> LegendreSymbol;

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

    /// Convert into BigUint, often for debug.
    fn into_biguint(self) -> BigUint {
        self.into()
    }
}

/// The trait for domain.
pub trait Domain: Scalar {
    /// The field that is able to be used in FFTs.
    type Field: FftField;

    /// Return fft field.
    fn get_field(&self) -> Self::Field;

    /// Sample a domain based on a fft field.
    fn from_field(field: Self::Field) -> Self;
}

/// The trait for group elements
pub trait Group:
    Debug
    + Default
    + Copy
    + Sized
    + PartialEq
    + Eq
    + Clone
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self::ScalarType, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + Serialize
    + Neg
    + for<'de> Deserialize<'de>
{
    /// The scalar type
    type ScalarType: Scalar;

    /// The number of bytes for a compressed representation of a group element
    const COMPRESSED_LEN: usize;

    /// The number of bytes for a uncompressed representation of a group element
    const UNCOMPRESSED_LEN: usize;

    /// Return the doubling of the group element
    fn double(&self) -> Self;

    /// Return the identity element (i.e., 0 * G)
    fn get_identity() -> Self;

    /// Return the base element (i.e., 1 * G)
    fn get_base() -> Self;

    /// Return a random element
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self;

    /// Convert to bytes in the compressed representation
    fn to_compressed_bytes(&self) -> Vec<u8>;

    /// Convert from bytes in the compressed representation
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self>;

    /// Convert to bytes in the unchecked representation
    fn to_unchecked_bytes(&self) -> Vec<u8>;

    /// Convert from bytes in the unchecked representation
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self>;

    /// Return the size of unchecked bytes.
    fn unchecked_size() -> usize;

    /// Sample a group element based on a hash value
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default;

    /// Compute the multiscalar multiplication
    #[inline]
    fn multi_exp(scalars: &[&Self::ScalarType], points: &[&Self]) -> Self {
        if scalars.is_empty() {
            Self::get_identity()
        } else {
            pippenger(scalars, points).unwrap()
        }
    }
}

/// Trait for Pedersen commitment.
pub trait PedersenCommitment<G: Group>: Default {
    /// Return the generator for the value part.
    fn generator(&self) -> G;
    /// Return the generator for the blinding part.
    fn blinding_generator(&self) -> G;
    /// Compute the Pedersen commitment over the Ristretto group.
    fn commit(&self, value: G::ScalarType, blinding: G::ScalarType) -> G;
}

/// The trait for a pair of groups for pairing
pub trait Pairing {
    /// The scalar type
    type ScalarField: Scalar;

    /// The first group
    type G1: Group<ScalarType = Self::ScalarField>;

    /// The second group
    type G2: Group<ScalarType = Self::ScalarField>;

    /// The target group
    type Gt: Group<ScalarType = Self::ScalarField>;

    /// The pairing operation
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt;

    /// The product of pairing operation
    fn product_of_pairings(a: &[Self::G1], b: &[Self::G2]) -> Self::Gt;
}

/// The trait for get x-coordinate and y-coordinate.
pub trait CurveGroup: Group {
    /// The scalar type
    type BaseType: Scalar;

    /// Get the x-coordinate.
    fn get_x(&self) -> Self::BaseType;

    /// Get the y-coordinate.
    fn get_y(&self) -> Self::BaseType;

    /// Construct from x and y coordinates.
    fn new(x: &Self::BaseType, y: &Self::BaseType) -> Self;

    /// Get the base point divided by the cofactor.
    fn get_point_div_by_cofactor() -> Self;

    /// Multiply by the cofactor.
    fn multiply_by_cofactor(&self) -> Self;
}

/// A trait that labels a curve to be based on twisted Edwards, which is requested by the constraint system.
pub trait TECurve: CurveGroup {}

/// Convert the scalar into a vector of small chunks, each of size `w`
pub fn scalar_to_radix_2_power_w<S: Scalar>(scalar: &S, w: usize) -> Vec<i8> {
    assert!(w <= 7);
    if *scalar == S::from(0u32) {
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

/// Run the pippenger algorithm to compute multiscalar multiplication
pub fn pippenger<G: Group>(scalars: &[&G::ScalarType], elems: &[&G]) -> Result<G> {
    let size = scalars.len();

    if size == 0 {
        return Err(AlgebraError::ParameterError);
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
        .map(|s| scalar_to_radix_2_power_w::<G::ScalarType>(s, w))
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
                buckets[b_index].add_assign(elem);
            }
            if digit < 0 {
                let b_index = (-(digit + 1)) as usize;
                buckets[b_index].sub_assign(elem);
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

    let two_power_w_int = G::ScalarType::from(two_power_w as u64);
    // This unwrap is safe as the list of scalars is non empty at this point.
    let hi_col = cols.next().unwrap();
    let res = cols.fold(hi_col, |total, p| total.mul(&two_power_w_int).add(&p));
    Ok(res)
}

#[cfg(test)]
pub(crate) mod group_tests {
    use crate::traits::{scalar_to_radix_2_power_w, Scalar};

    pub(crate) fn test_scalar_operations<S: Scalar>() {
        let a = S::from(40u32);
        let b = S::from(60u32);
        let c = a.add(&b);
        let d = S::from(100u32);
        assert_eq!(c, d);

        let mut x = S::from(0u32);
        x.add_assign(&a);
        x.add_assign(&b);
        assert_eq!(x, d);

        let a = S::from(10u32);
        let b = S::from(40u32);
        let c = a.mul(&b);
        let d = S::from(400u32);
        assert_eq!(c, d);

        let mut x = S::from(1u32);
        x.mul_assign(&a);
        x.mul_assign(&b);
        assert_eq!(x, d);

        let a = S::from(0xFFFFFFFFu32);
        let b = S::from(1u32);
        let c = a.add(&b);
        let d = S::from(0x100000000u64);
        assert_eq!(c, d);

        let a = S::from(0xFFFFFFFFu32);
        let b = S::from(1u32);
        let c = a.mul(&b);
        let d = S::from(0xFFFFFFFFu32);
        assert_eq!(c, d);

        let a = S::from(40u32);
        let b = S::from(60u32);
        let c = b.sub(&a);
        let d = S::from(20u32);
        assert_eq!(c, d);

        let mut x = S::from(120u32);
        x.sub_assign(&b);
        x.sub_assign(&a);
        assert_eq!(x, d);

        let a = S::from(40u32);
        let b = a.neg();
        let c = b.add(&a);
        let d = S::from(0u32);
        assert_eq!(c, d);

        let a = S::from(40u32);
        let b = a.inv().unwrap();
        let c = b.mul(&a);
        let d = S::from(1u32);
        assert_eq!(c, d);

        let a = S::from(3u32);
        let b = vec![20];
        let c = a.pow(&b[..]);
        let d = S::from(3486784401u64);
        assert_eq!(c, d);

        let v = S::get_field_size_biguint().to_bytes_le();
        assert_eq!(v, S::get_field_size_le_bytes());
    }

    pub(crate) fn test_scalar_serialization<S: Scalar>() {
        let a = S::from(100u32);
        let bytes = a.to_bytes();
        let b = S::from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(a, b);
    }

    pub(crate) fn test_to_radix<S: Scalar>() {
        let int = S::from(41u32);
        let w = 2;
        let r = scalar_to_radix_2_power_w(&int, w);
        let expected = [1i8, -2, -1, 1]; // 41 = 1 + -2*4 + -1*16 + 64
        assert_eq!(r.as_slice(), expected.as_ref());

        let int = S::from(0u32);
        let w = 2;
        let r = scalar_to_radix_2_power_w(&int, w);
        let expected = [0i8];
        assert_eq!(expected.as_ref(), r.as_slice());

        let int = S::from(1000u32);
        let w = 6;
        let r = scalar_to_radix_2_power_w(&int, w);
        let expected = [-24, 16];
        assert_eq!(expected.as_ref(), r.as_slice());
    }
}

#[cfg(test)]
mod multi_exp_tests {
    use crate::bls12_381::BLSGt;
    use crate::bls12_381::BLSG1;
    use crate::bls12_381::BLSG2;
    use crate::ristretto::RistrettoPoint;
    use crate::traits::Group;

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
        let g = G::multi_exp(&[], &[]);
        assert_eq!(g, G::get_identity());

        let g1 = G::get_base();
        let zero = G::ScalarType::from(0u32);
        let g = G::multi_exp(&[&zero], &[&g1]);
        assert_eq!(g, G::get_identity());

        let g1 = G::get_base();
        let one = G::ScalarType::from(1u32);
        let g = G::multi_exp(&[&one], &[&g1]);
        assert_eq!(g, G::get_base());

        let g1 = G::get_base();
        let g1p = G::get_base();
        let one = G::ScalarType::from(1u32);
        let zero = G::ScalarType::from(0u32);
        let g = G::multi_exp(&[&one, &zero], &[&g1, &g1p]);
        assert_eq!(g, G::get_base());

        let g1 = G::get_base();
        let g2 = g1.add(&g1);
        let g3 = g1.mul(&G::ScalarType::from(500u32));
        let thousand = G::ScalarType::from(1000u32);
        let two = G::ScalarType::from(2u32);
        let three = G::ScalarType::from(3u32);
        let g = G::multi_exp(&[&thousand, &two, &three], &[&g1, &g2, &g3]);
        let expected = G::get_base().mul(&G::ScalarType::from((1000 + 4 + 1500) as u32));
        assert_eq!(g, expected);
    }
}
