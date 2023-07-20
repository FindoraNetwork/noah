#![deny(warnings)]
#![allow(clippy::upper_case_acronyms)]

use crate::prelude::*;
use ark_std::{string::String, vec, vec::Vec};
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_chacha::ChaCha20Rng;

const BASE64_PADDING_CONFIG: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);

const BASE64_ENGINE: GeneralPurpose = GeneralPurpose::new(&URL_SAFE, BASE64_PADDING_CONFIG);

/// Convert an 8 byte array (big-endian) into a u64
pub fn u8_be_slice_to_u64(slice: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(slice);
    u64::from_be_bytes(a)
}

/// Convert an 8 byte array (little-endian) into a u64
pub fn u8_le_slice_to_u64(slice: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(slice);
    u64::from_le_bytes(a)
}

/// Convert a slice into a u32 (big-endian)
pub fn u8_be_slice_to_u32(slice: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(slice);
    u32::from_be_bytes(a)
}

/// Convert a slice into a u32 (little-endian)
pub fn u8_le_slice_to_u32(slice: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(slice);
    u32::from_le_bytes(a)
}

/// Compute the minimum power of two that is greater or equal to the input
pub fn min_greater_equal_power_of_two(n: u32) -> u32 {
    2.0f64.powi((n as f64).log2().ceil() as i32) as u32
}

/// Convert u64 into a pair of u32
pub fn u64_to_u32_pair(x: u64) -> (u32, u32) {
    ((x & 0xFFFF_FFFF) as u32, (x >> 32) as u32)
}

/// Convert the input into the base64 encoding
pub fn b64enc<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    BASE64_ENGINE.encode(input)
}

/// Reconstruct from the base64 encoding
pub fn b64dec<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>> {
    BASE64_ENGINE
        .decode(input)
        .map_err(|_| AlgebraError::DeserializationError)
}

/// Derive a ChaCha20Rng PRNG from a digest from a hash function
pub fn derive_prng_from_hash<D>(hash: D) -> ChaCha20Rng
where
    D: Digest<OutputSize = U64> + Default,
{
    const SEED_SIZE: usize = 32;
    let mut seed: [u8; SEED_SIZE] = [0; SEED_SIZE];
    let result = hash.finalize();
    seed.copy_from_slice(&result[0..SEED_SIZE]);
    ChaCha20Rng::from_seed(seed)
}

/// Shift a big integer (represented as a little-endian bytes vector) by one bit.
pub fn shift_u8_vec(r: &mut Vec<u8>) {
    let mut next = 0u8;
    for e in r.iter_mut().rev() {
        let prev = *e;
        *e = (*e >> 1) | next;
        next = (prev % 2) << 7;
    }
    if *r.last().unwrap() == 0 && r.len() > 1 {
        r.pop();
    }
}

/// Convert a u64 slice into a shrink bytes (little-endian)
pub fn u64_lsf_to_bytes(slice: &[u64]) -> Vec<u8> {
    let mut bytes = vec![];
    for a in slice {
        bytes.extend(&a.to_le_bytes()[..])
    }
    while let Some(b) = bytes.last() {
        if *b != 0 {
            break;
        }
        bytes.pop();
    }
    bytes
}

/// Convert a u64 slice from a shrink bytes (little-endian)
pub fn u64_limbs_from_bytes(slice: &[u8]) -> Vec<u64> {
    let mut r: Vec<u64> = vec![];
    let n = slice.len() / 8;
    for i in 0..n {
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(&slice[i * 8..(i + 1) * 8]);
        r.push(u64::from_le_bytes(u64_bytes));
    }
    if slice.len() % 8 != 0 {
        let bytes = &slice[n * 8..];
        let mut u64_bytes = [0u8; 8];
        u64_bytes[..bytes.len()].copy_from_slice(bytes);
        r.push(u64::from_le_bytes(u64_bytes));
    }
    r
}

/// Save parameters to a file
#[cfg(feature = "std")]
pub fn save_to_file(params_ser: &[u8], out_filename: ark_std::path::PathBuf) {
    use ark_std::io::Write;
    let filename = out_filename.to_str().unwrap();
    let mut f = ark_std::fs::File::create(filename).expect("Unable to create file");
    f.write_all(params_ser).expect("Unable to write data");
}

/// A short-hand macro for not matching an expression
#[macro_export]
macro_rules! not_matches {
   ($expression:expr, $( $pattern:pat_param )|+ $( if $guard: expr )?) => {
        match $expression {
            $( $pattern )|+ $( if $guard )? => false,
            _ => true
        }
    }
}

#[cfg(test)]
mod test {
    use ark_std::vec;

    #[test]
    fn test_shift_u8_vec() {
        let mut v = vec![0];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![0]);

        let mut v = vec![1];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![0]);

        let mut v = vec![2];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![1]);

        let mut v = vec![255];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![127]);

        let mut v = vec![0, 1];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![128]);
        let mut v = vec![0, 0, 1];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![0, 128]);
    }

    #[test]
    fn test_u8_be_slice_to_u32() {
        let array = [0xFA_u8, 0x01, 0xC6, 0x73];
        let n = super::u8_be_slice_to_u32(&array);
        assert_eq!(0xFA01C673, n);
    }

    #[test]
    fn u8_be_slice_to_u64() {
        let array = [0xFA_u8, 0x01, 0xC6, 0x73, 0x22, 0xE4, 0x98, 0xA2];
        let n = super::u8_be_slice_to_u64(&array);
        assert_eq!(0xFA01C67322E498A2, n);
    }

    #[test]
    fn u64_lsf_to_bytes() {
        let n = vec![1, 2, 3, 4, 5];
        let bytes = super::u64_lsf_to_bytes(&n);
        assert!(bytes.len() < n.len() * 8);
        let nn = super::u64_limbs_from_bytes(&bytes);
        assert_eq!(n, nn);
    }

    #[test]
    fn min_greater_equal_power_of_two() {
        assert_eq!(16, super::min_greater_equal_power_of_two(16));
        assert_eq!(16, super::min_greater_equal_power_of_two(15));
        assert_eq!(16, super::min_greater_equal_power_of_two(9));
        assert_eq!(8, super::min_greater_equal_power_of_two(8));
        assert_eq!(8, super::min_greater_equal_power_of_two(6));
        assert_eq!(8, super::min_greater_equal_power_of_two(5));
        assert_eq!(4, super::min_greater_equal_power_of_two(4));
        assert_eq!(4, super::min_greater_equal_power_of_two(3));
        assert_eq!(2, super::min_greater_equal_power_of_two(2));
        assert_eq!(1, super::min_greater_equal_power_of_two(1));
        assert_eq!(0, super::min_greater_equal_power_of_two(0));
    }

    #[test]
    fn u64_to_u32_pair() {
        assert_eq!((32, 0), super::u64_to_u32_pair(32u64));
        assert_eq!(
            (0xFFFFFFFF, 0xFFFFFFFF),
            super::u64_to_u32_pair(0xFFFFFFFFFFFFFFFFu64)
        );
        assert_eq!(
            (0, 0xFFFFFFFF),
            super::u64_to_u32_pair(0xFFFFFFFF00000000u64)
        );
    }

    #[test]
    fn test_not_matches_macro() {
        let foofoo = 'g';
        assert!(not_matches!(foofoo, 'a'..='f'));

        let barbar = Some(4);
        assert!(not_matches!(barbar, Some(x) if x < 2));
    }
}
