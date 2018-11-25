//zei utils 

use curve25519_dalek::scalar::Scalar;
use rand::RngCore;

//random byte generator
pub fn randombytes(x: &mut [u8]) {
    let mut rng = rand::OsRng::new().unwrap();
    rng.fill_bytes(x);
}

//random data helper
pub fn random_data_test_helper(len: usize) -> Vec<u8> {
    let mut message = Vec::with_capacity(len);
    randombytes(&mut message);
    message
}

//helper to convert slice to ixed array of 32bytes
pub fn slice_to_fixed32(data: &[u8]) -> [u8; 32] {
        //convert slice to fixed
        let mut a: [u8; 32] = Default::default();
        a.copy_from_slice(&data[0..32]);
        return a;
}


//Borrowed from https://github.com/dalek-cryptography/x25519-dalek/blob/master/src/x25519.rs
/// "Decode" a scalar from a 32-byte array.
///
/// By "decode" here, what is really meant is applying key clamping by twiddling
/// some bits.
///
/// # Returns
///
/// A `Scalar`.
#[inline(always)]
pub fn decode_scalar(scalar: &[u8; 32]) -> Scalar {
    let mut s: [u8; 32] = scalar.clone();

    s[0]  &= 248;
    s[31] &= 127;
    s[31] |= 64;

    Scalar::from_bits(s)
}

//
//Borrowed from https://github.com/briansmith/ring
//

//converts a unsigned 32bit integer to a big endien byte representation
#[inline(always)]
pub fn be_u8_from_u32(value: u32) -> [u8; 4] {
    [
        ((value >> 24) & 0xff) as u8,
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8
    ]
}

//converts big endien byte representation to a unsigned 32bit integer 
#[inline(always)]
pub fn u32_from_be_u8(buffer: &[u8; 4]) -> u32 {
        u32::from(buffer[0]) << 24 |
        u32::from(buffer[1]) << 16 |
        u32::from(buffer[2]) << 8 |
        u32::from(buffer[3])
}

