// Utility functions

//**base58 translation functions**

use num_bigint::{BigInt};
use num_bigint::Sign::Plus;

use num_traits::{Zero};
use num_traits::{FromPrimitive,ToPrimitive};
use std::panic;


static BASE58_ALPHABET: &'static [u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static BASE58_INVERSE: [Option<u8>; 128] =  [
    None,     None,     None,     None,     None,     None,     None,     None,//0-7
    None,     None,     None,     None,     None,     None,     None,     None,//8-15
    None,     None,     None,     None,     None,     None,     None,     None,//16-23
    None,     None,     None,     None,     None,     None,     None,     None,//24-31
    None,     None,     None,     None,     None,     None,     None,     None,//32-39
    None,     None,     None,     None,     None,     None,     None,     None,//40-47
    None,     Some(0),  Some(1),  Some(2),  //48  *,1,2,3
    Some(3),  Some(4),  Some(5),  Some(6),  //52  4,5,6,7
    Some(7),  Some(8),  None,     None,     //56  8,9,*,*
    None,     None,     None,     None,     //60 
    None,     Some(9),  Some(10), Some(11), //64  *,A,B,C
    Some(12), Some(13), Some(14), Some(15), //68  D,E,F,G
    Some(16), None,     Some(17), Some(18), //72  H,*,J,K
    Some(19), Some(20), Some(21), None,     //76  L,M,N,*
    Some(22), Some(23), Some(24), Some(25), //80  P,Q,R,S,
    Some(26), Some(27), Some(28), Some(29), //84  T,U,V,W
    Some(30), Some(31), Some(32), None,     //88  X,Y,Z,*
    None,     None,     None,     None,     //92
    None,     Some(33), Some(34), Some(35), //96  *,a,b,c 
    Some(36), Some(37), Some(38), Some(39), //100 d,e,f,g
    Some(40), Some(41), Some(42), Some(43), //104 h,i,j,k 
    None,     Some(44), Some(45), Some(46), //108 *,m,n,o 
    Some(47), Some(48), Some(49), Some(50), //112 p,q,r,s 
    Some(51), Some(52), Some(53), Some(54), //116 t,u,v,w
    Some(55), Some(56), Some(57), None,     //120 x,y,z,*
    None,     None,     None,     None      //124-127
];

pub fn to_base58(data: &[u8]) -> String {
    /*
     * I convert a u8 slice @data into a base58 string.
     * @data is read as a Bigendian big integer.
     * Leading zero bytes are replaced with '1' base58 symbol
     *
     */

    let strlen_upper_bound = (1.0 + (data.len() as f64) * 1.4) as usize; // upper bound un log_58(256)
    let mut ret = Vec::with_capacity(strlen_upper_bound);
    let mut leading_zeroes = 0;
    for d in data {
        if *d != 0u8 {
          break;
        }
        leading_zeroes += 1;
    }
    let mut data_as_int = BigInt::from_bytes_be(Plus, data);
    while !data_as_int.is_zero(){
        let quo: BigInt = &data_as_int / 58;
        let x: BigInt = &quo * 58;
        let rem: BigInt = &data_as_int - x;
        data_as_int = quo;
        let (_, bytes) = rem.to_bytes_be();
        let index: u8 = bytes[0];
        ret.push(BASE58_ALPHABET[index as usize]);
    }
    for _ in 0..leading_zeroes{
       ret.push(BASE58_ALPHABET[0]); 
    }
    ret.reverse();
    String::from_utf8(ret).unwrap()

}

pub fn from_base58(data: &str) -> Vec<u8> {
    /*
     * I convert a string in base58 format to bigendian vector of bytes.
     * Leading ones base58 chars in original strings are translates to leading 0u8 in results
     *
     */

    let mut big_int: BigInt = Zero::zero();
    let mut factor = BigInt::from_u8(1).unwrap();

    let mut leading_ones = 0;
    for d in data.chars() {
        if d != '1' {
          break;
        }
        leading_ones += 1;
    }

    for d in data.chars().rev(){
        let base58 = match BASE58_INVERSE[d as usize] {
          Some(x) => x as u32,
          None => {
              panic!("Bad base58 format");
          }
        };
        big_int += &factor * base58;
        factor *= 58;
    }

    let mut vec: Vec<u8> = Vec::new();
    while !big_int.is_zero(){
        let byte: BigInt = &big_int % 256;
        big_int = &big_int / 256;
        vec.push(byte.to_u8().unwrap());
    }

    for _ in 0..leading_ones{
        vec.push(0u8);
    }

    vec.reverse();
    vec
}

#[cfg(test)]
mod test {
    use crate::utils::*;

    #[test]
    fn test_base58_encoding_decoding() {
        let v = vec![1,2,3,4,5];
        let b58_str = to_base58(&v[..]);
        assert_eq!(v, from_base58(&b58_str[..]));
    }

    #[test]
    fn test_base58_leading_zeroes() {
        let v = vec![0,1,2,3,4,5];
        let b58_str = to_base58(&v[..]);
        assert_eq!(v, from_base58(&b58_str[..]));
    }
    
}
