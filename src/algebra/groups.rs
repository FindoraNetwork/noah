use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub trait GroupArithmetic<S> {
  fn mul(&self, scalar: &S) -> Self;
  fn add(&self, other: &Self) -> Self;
  fn sub(&self, other: &Self) -> Self;
}

pub trait Scalar:
  Debug + Sized + PartialEq + Eq + Clone + Serialize + for<'de> Deserialize<'de>
{
  // generation
  fn random_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Self;
  fn from_u32(value: u32) -> Self;
  fn from_u64(value: u64) -> Self;
  fn from_hash<D>(hash: D) -> Self
    where D: Digest<OutputSize = U64> + Default;

  //arithmetic
  fn add(&self, b: &Self) -> Self;
  fn mul(&self, b: &Self) -> Self;
  fn sub(&self, b: &Self) -> Self;
  fn inv(&self) -> Self;
  fn neg(&self) -> Self {
    Self::from_u32(0).sub(self)
  }
  fn pow(&self) -> Self;

  fn get_little_endian_u64(&self) -> Vec<u64>;
  // serialization
  fn to_bytes(&self) -> Vec<u8>;
  fn from_bytes(bytes: &[u8]) -> Self;
}

pub trait Group<S>:
  Debug + Sized + PartialEq + Eq + Clone + Serialize + for<'de> Deserialize<'de> + GroupArithmetic<S>
{
  const COMPRESSED_LEN: usize;
  const SCALAR_BYTES_LEN: usize;
  fn get_identity() -> Self;
  fn get_base() -> Self;

  // compression/serialization helpers
  fn to_compressed_bytes(&self) -> Vec<u8>;
  fn from_compressed_bytes(bytes: &[u8]) -> Option<Self>;
  fn from_hash<D>(hash: D) -> Self
    where D: Digest<OutputSize = U64> + Default;
}

pub(crate) fn scalar_to_radix_2_power_w<S: Scalar>(scalar: &S, w: usize) -> Vec<i8> {
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
    digits.pop();
  }
  digits
}

#[cfg(test)]
pub(crate) mod group_tests {
  use crate::algebra::groups::{scalar_to_radix_2_power_w, Scalar};

  pub(crate) fn test_scalar_operations<S: Scalar>() {
    let a = S::from_u32(40);
    let b = S::from_u32(60);
    let c = a.add(&b);
    let d = S::from_u32(100);
    assert_eq!(c, d);

    let a = S::from_u32(10);
    let b = S::from_u32(40);
    let c = a.mul(&b);
    let d = S::from_u32(400);
    assert_eq!(c, d);

    let a = S::from_u32(0xFFFFFFFF);
    let b = S::from_u32(1);
    let c = a.add(&b);
    let d = S::from_u64(0x100000000);
    assert_eq!(c, d);
  }

  pub(crate) fn test_scalar_serialization<S: Scalar>() {
    let a = S::from_u32(100);
    let bytes = a.to_bytes();
    let b = S::from_bytes(bytes.as_slice());
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
