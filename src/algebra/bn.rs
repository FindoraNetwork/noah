use super::groups::{Group};
use super::pairing::Pairing;
use rand::{CryptoRng, Rng};
use digest::Digest;
use digest::generic_array::typenum::U64;
use crate::utils::u8_bigendian_slice_to_u32;
use std::fmt;
use bn::{Group as BNGroup};

pub struct BNScalar(pub(crate) bn::Fr);
pub struct BNG1(pub(crate) bn::G1);
pub struct BNG2(pub(crate) bn::G2);
#[derive(Clone, PartialEq, Eq)]
pub struct BNGt(pub(crate) bn::Gt);

impl fmt::Debug for BNScalar{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Fr:{}", rustc_serialize::json::encode(&self.0).unwrap())
    }
}

impl PartialEq for BNScalar{
    fn eq(&self, other: &BNScalar) -> bool{
        self.0 == other.0
    }
}

impl Eq for BNScalar {}

impl Clone for BNScalar {
    fn clone(&self) -> BNScalar{
        BNScalar(self.0.clone())
    }
}

impl crate::algebra::groups::Scalar for BNScalar {
    // scalar generation
    fn random_scalar<R: CryptoRng + Rng>(rng: &mut R) -> BNScalar{
        // hack to use rand_04::Rng rather than rand::Rng
        let mut random_bytes = [0u8;16];
        rng.fill_bytes(&mut random_bytes);
        let mut seed = [0u32;4];
        for i in 0..4{
            seed[i] = u8_bigendian_slice_to_u32(&random_bytes[i*4..(i+1)*4]);
        }

        use rand_04::SeedableRng;
        let mut prng_04 = rand_04::ChaChaRng::from_seed(&seed);
        BNScalar(bn::Fr::random(&mut prng_04))
    }

    fn from_u32(value: u32) -> BNScalar{
        Self::from_u64(value as u64)
    }

    fn from_u64(value: u64) -> BNScalar {
        let mut v  = value;
        let two = bn::Fr::one() + bn::Fr::one();
        let mut result = bn::Fr::zero();
        let mut two_pow_i = bn::Fr::one();
        for _ in 0..64{
            if v == 0 {break;}
            if v&1 == 1u64 {
                result = result + two_pow_i;
            }
            v = v>>1;
            two_pow_i = two_pow_i * two;
        }
        BNScalar(result)
    }

    fn from_hash<D>(hash: D) -> BNScalar
        where D: Digest<OutputSize = U64> + Default{
        let result = hash.result();
        let mut seed = [0u32; 16];
        for i in 0..16{
            seed[i] = u8_bigendian_slice_to_u32(&result.as_slice()[i*4..(i+1)*4]);
        }
        use rand_04::SeedableRng;
        let mut prng = rand_04::ChaChaRng::from_seed(&seed);
        BNScalar(bn::Fr::random(&mut prng))
    }

    // scalar arithmetic
    fn add(&self, b: &BNScalar) -> BNScalar{
        BNScalar(self.0 + b.0)
    }
    fn mul(&self, b: &BNScalar) -> BNScalar{
        BNScalar(self.0 * b.0)
    }

    //scalar serialization
    fn to_bytes(a: &BNScalar) -> Vec<u8>{
        let json = rustc_serialize::json::encode(&a.0).unwrap();
        let bytes = json.into_bytes();
        bytes

    }
    fn from_bytes(bytes: &[u8]) -> BNScalar {
        let json = &String::from_utf8(bytes.to_vec()).unwrap();
        BNScalar(rustc_serialize::json::decode(json).unwrap())
    }
}

impl fmt::Debug for BNG1{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Fr:{}", rustc_serialize::json::encode(&self.0).unwrap())
    }
}

impl PartialEq for BNG1{
    fn eq(&self, other: &BNG1) -> bool{
        self.0 == other.0
    }
}

impl Eq for BNG1 {}

impl Clone for BNG1 {
    fn clone(&self) -> BNG1{
        BNG1(self.0.clone())
    }
}



impl Group for BNG1{
    type ScalarType = BNScalar;
    const COMPRESSED_LEN: usize = 0; // TODO
    const SCALAR_BYTES_LEN: usize = 0; // TODO
    fn get_identity() -> BNG1{
        BNG1(bn::G1::zero())
    }
    fn get_base() -> BNG1{
        BNG1(bn::G1::one())
    }

    // compression/serialization helpers
    fn to_compressed_bytes(&self) -> Vec<u8>{
        rustc_serialize::json::encode(&self.0).unwrap().into_bytes()
    }
    fn from_compressed_bytes(bytes: &[u8]) -> Option<BNG1>{
        let json = &String::from_utf8(bytes.to_vec()).unwrap();
        match rustc_serialize::json::decode(json){
            Ok(x) => Some(BNG1(x)),
            Err(_) => None,
        }
    }

    //arithmetic
    fn mul(&self, scalar: &BNScalar) -> BNG1 {
        return BNG1(self.0 * scalar.0)
    }
    fn add(&self, other: &Self) -> BNG1{
        BNG1(self.0 + other.0)
    }
    fn sub(&self, other: &Self) -> BNG1{
        BNG1(self.0 - other.0)
    }
}


impl fmt::Debug for BNG2{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Fr:{}", rustc_serialize::json::encode(&self.0).unwrap())
    }
}

impl PartialEq for BNG2{
    fn eq(&self, other: &BNG2) -> bool{
        self.0 == other.0
    }
}

impl Eq for BNG2 {}

impl Clone for BNG2 {
    fn clone(&self) -> BNG2{
        BNG2(self.0.clone())
    }
}



impl Group for BNG2{
    type ScalarType = BNScalar;
    const COMPRESSED_LEN: usize = 0; // TODO
    const SCALAR_BYTES_LEN: usize = 0; // TODO
    fn get_identity() -> BNG2{
        BNG2(bn::G2::zero())
    }
    fn get_base() -> BNG2{
        BNG2(bn::G2::one())
    }

    // compression/serialization helpers
    fn to_compressed_bytes(&self) -> Vec<u8>{
        rustc_serialize::json::encode(&self.0).unwrap().into_bytes()
    }
    fn from_compressed_bytes(bytes: &[u8]) -> Option<BNG2>{
        let json = &String::from_utf8(bytes.to_vec()).unwrap();
        match rustc_serialize::json::decode(json){
            Ok(x) => Some(BNG2(x)),
            Err(_) => None,
        }
    }

    //arithmetic
    fn mul(&self, scalar: &BNScalar) -> BNG2 {
        return BNG2(self.0 * scalar.0)
    }
    fn add(&self, other: &Self) -> BNG2{
        BNG2(self.0 + other.0)
    }
    fn sub(&self, other: &Self) -> BNG2{
        BNG2(self.0 - other.0)
    }
}

impl fmt::Debug for BNGt{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Fr: Some Gt Element")
    }
}

impl Pairing for BNGt {
    type G1 = BNG1;
    type G2 = BNG2;
    type ScalarType = BNScalar;

    fn pairing(a: &Self::G1, b: &Self::G2) -> BNGt{
        BNGt(bn::pairing(a.0, b.0))
    }
    fn scalar_mul(&self, a: &Self::ScalarType) -> BNGt{
        BNGt(self.0.pow(a.0))
    }
    fn add(&self, other: &Self) -> BNGt{
        BNGt(self.0 * other.0)
    }

    fn g1_mul_scalar(a: &Self::G1, b: &Self::ScalarType) -> Self::G1{
        a.mul(b)
    }
    fn g2_mul_scalar(a: &Self::G2, b: &Self::ScalarType) -> Self::G2{
        a.mul(b)
    }
}

#[cfg(test)]
mod elgamal_over_bn_groups {
    use crate::basic_crypto::elgamal::elgamal_test;

    #[test]
    fn verification_g1(){
        elgamal_test::verification::<super::BNG1>();
    }

    #[test]
    fn decryption_g1(){
        elgamal_test::decryption::<super::BNG1>();
    }

    #[test]
    fn verification_g2(){
        elgamal_test::verification::<super::BNG1>();
    }

    #[test]
    fn decryption_g2(){
        elgamal_test::decryption::<super::BNG2>();
    }


    /*
    #[test]
    fn to_json(){
        elgamal_test::to_json::<super::BNG1>();
    }

    #[test]
    fn to_message_pack(){
        elgamal_test::to_message_pack::<super::BNG1>();
    }
    */
}