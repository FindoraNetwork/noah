use super::groups::{Group, Scalar};
use super::pairing::Pairing;
use rand::{CryptoRng, Rng};
use rand_04::Rand;
use digest::Digest;
use digest::generic_array::typenum::U64;
use crate::utils::u8_bigendian_slice_to_u32;
use std::fmt;
use pairing::bls12_381::{Fr, G1, G2, Fq12, FrRepr};
use pairing::{PrimeField, Field, EncodedPoint};
use pairing::{CurveProjective,CurveAffine};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de::{Visitor, SeqAccess};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BLSScalar(pub(crate) Fr);
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BLSG1(pub(crate) G1);
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BLSG2(pub(crate) G2);
#[derive(Clone, PartialEq, Eq)]
pub struct BLSGt(pub(crate) Fq12);

impl Scalar for BLSScalar {
    // scalar generation
    fn random_scalar<R: CryptoRng + Rng>(rng: &mut R) -> BLSScalar{
        // hack to use rand_04::Rng rather than rand::Rng
        let mut random_bytes = [0u8;16];
        rng.fill_bytes(&mut random_bytes);
        let mut seed = [0u32;4];
        for i in 0..4{
            seed[i] = u8_bigendian_slice_to_u32(&random_bytes[i*4..(i+1)*4]);
        }

        use rand_04::SeedableRng;
        let mut prng_04 = rand_04::ChaChaRng::from_seed(&seed);
        BLSScalar(Fr::rand(&mut prng_04))
    }

    fn from_u32(value: u32) -> BLSScalar{
        Self::from_u64(value as u64)
    }

    fn from_u64(value: u64) -> BLSScalar {
        let mut v  = value;
        let mut result = Fr::zero();
        let mut two_pow_i = Fr::one();
        for _ in 0..64{
            if v == 0 {break;}
            if v&1 == 1u64 {
                result.add_assign(&two_pow_i);
                //result = result + two_pow_i;
            }
            v = v>>1;
            two_pow_i.double();// = two_pow_i * two;
        }
        BLSScalar(result)
    }

    fn from_hash<D>(hash: D) -> BLSScalar
        where D: Digest<OutputSize = U64> + Default{
        let result = hash.result();
        let mut seed = [0u32; 16];
        for i in 0..16{
            seed[i] = u8_bigendian_slice_to_u32(&result.as_slice()[i*4..(i+1)*4]);
        }
        use rand_04::SeedableRng;
        let mut prng = rand_04::ChaChaRng::from_seed(&seed);
        BLSScalar(Fr::rand(&mut prng))
    }

    // scalar arithmetic
    fn add(&self, b: &BLSScalar) -> BLSScalar{
        let mut m = self.0.clone();
        m.add_assign(&b.0);
        BLSScalar(m)
    }
    fn mul(&self, b: &BLSScalar) -> BLSScalar{
        let mut m = self.0.clone();
        m.mul_assign(&b.0);
        BLSScalar(m)
    }

    //scalar serialization
    fn to_bytes(&self) -> Vec<u8>{
        let repr = FrRepr::from(self.0);
        let mut v = vec![];
        for a in &repr.0 {
            let array = crate::utils::u64_to_bigendian_u8array(*a);
            v.extend_from_slice(&array[..])
        }
        v
    }

    fn from_bytes(bytes: &[u8]) -> BLSScalar {
        let mut repr_array = [0u64; 4];
        for i in 0..4 {
            let slice = &bytes[i * 8..i * 8 + 8];
            repr_array[i]  = crate::utils::u8_bigendian_slice_to_u64(slice);

        }
        let fr_repr = FrRepr(repr_array);
        BLSScalar(Fr::from_repr(fr_repr).unwrap())
    }
}

impl Serialize for BLSScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&base64::encode(self.to_bytes().as_slice()))
        } else {
            serializer.serialize_bytes(self.to_bytes().as_slice())
        }
    }
}

impl<'de> Deserialize<'de> for BLSScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        struct ScalarVisitor;

        impl<'de> Visitor<'de> for ScalarVisitor{
            type Value = BLSScalar;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a encoded BLSG2 element")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<BLSScalar, E>
                where E: serde::de::Error
            {
                Ok(BLSScalar::from_bytes(v))
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<BLSScalar, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut vec: Vec<u8> = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    vec.push(x);
                }
                Ok(BLSScalar::from_bytes(vec.as_slice()))
            }
            fn visit_str<E>(self, s: &str) -> Result<BLSScalar, E>
                where E: serde::de::Error
            {
                self.visit_bytes(&base64::decode(s).map_err(serde::de::Error::custom)?)
            }
        }
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(ScalarVisitor)
        } else {
            deserializer.deserialize_bytes(ScalarVisitor)
        }
    }
}


impl Group<BLSScalar> for BLSG1{
    const COMPRESSED_LEN: usize = 48;
    const SCALAR_BYTES_LEN: usize = 32;
    fn get_identity() -> BLSG1{
        BLSG1(G1::zero())
    }
    fn get_base() -> BLSG1{
        BLSG1(G1::one())
    }

    // compression/serialization helpers
    fn to_compressed_bytes(&self) -> Vec<u8>{
        let v = self.0.into_affine().into_compressed().as_ref().to_vec();
        v
    }
    fn from_compressed_bytes(bytes: &[u8]) -> Option<BLSG1>{
        let some: G1 = G1::one();
        let mut compressed = some.into_affine().into_compressed();
        let mut_bytes = compressed.as_mut();
        for i in 0..48{
            mut_bytes[i] = bytes[i];
        }
        let affine = compressed.into_affine().unwrap();
        let g1 = G1::from(affine);

        Some(BLSG1(g1))
    }

    //arithmetic
    fn mul(&self, scalar: &BLSScalar) -> BLSG1 {
        let mut m = self.0.clone();
        m.mul_assign(scalar.0);
        BLSG1(m)
    }
    fn add(&self, other: &Self) -> BLSG1{
        let mut m = self.0.clone();
        m.add_assign(&other.0);
        BLSG1(m)
    }
    fn sub(&self, other: &Self) -> BLSG1{
        let mut m = self.0.clone();
        m.sub_assign(&other.0);
        BLSG1(m)
    }
}

impl Serialize for BLSG1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
    S: Serializer
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&base64::encode(self.to_compressed_bytes().as_slice()))
        } else {
            serializer.serialize_bytes(self.to_compressed_bytes().as_slice())
        }
    }
}

impl<'de> Deserialize<'de> for BLSG1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        struct G1Visitor;

        impl<'de> Visitor<'de> for G1Visitor{
            type Value = BLSG1;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a encoded ElGamal Ciphertext")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<BLSG1, E>
                where E: serde::de::Error
            {
                Ok(BLSG1::from_compressed_bytes(v).unwrap()) //TODO handle error
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<BLSG1, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut vec: Vec<u8> = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    vec.push(x);
                }
                Ok(BLSG1::from_compressed_bytes(vec.as_slice()).unwrap())
            }
            fn visit_str<E>(self, s: &str) -> Result<BLSG1, E>
                where E: serde::de::Error
            {
                self.visit_bytes(&base64::decode(s).map_err(serde::de::Error::custom)?)
            }
        }
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(G1Visitor)
        } else {
            deserializer.deserialize_bytes(G1Visitor)
        }
    }
}

impl Group<BLSScalar> for BLSG2{
    const COMPRESSED_LEN: usize = 96; // TODO
    const SCALAR_BYTES_LEN: usize = 32; // TODO
    fn get_identity() -> BLSG2{
        BLSG2(G2::zero())
    }
    fn get_base() -> BLSG2{
        BLSG2(G2::one())
    }

    // compression/serialization helpers
    fn to_compressed_bytes(&self) -> Vec<u8>{
        let v = self.0.into_affine().into_compressed().as_ref().to_vec();
        v
    }
    fn from_compressed_bytes(bytes: &[u8]) -> Option<BLSG2>{
        let some: G2 = G2::one();
        let mut compressed = some.into_affine().into_compressed();
        let mut_bytes = compressed.as_mut();
        for i in 0..96{
            mut_bytes[i] = bytes[i];
        }
        let affine = compressed.into_affine().unwrap();
        let g2 = G2::from(affine);

        Some(BLSG2(g2))
    }

    //arithmetic
    fn mul(&self, scalar: &BLSScalar) -> BLSG2 {
        let mut m = self.0.clone();
        m.mul_assign(scalar.0);
        BLSG2(m)
        //return BLSG2(self.0 * scalar.0)
    }
    fn add(&self, other: &Self) -> BLSG2{
        let mut m = self.0.clone();
        m.add_assign(&other.0);
        BLSG2(m)
    }
    fn sub(&self, other: &Self) -> BLSG2{
        let mut m = self.0.clone();
        m.sub_assign(&other.0);
        BLSG2(m)
    }
}


impl Serialize for BLSG2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&base64::encode(self.to_compressed_bytes().as_slice()))
        } else {
            serializer.serialize_bytes(self.to_compressed_bytes().as_slice())
        }
    }
}

impl<'de> Deserialize<'de> for BLSG2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        struct G2Visitor;

        impl<'de> Visitor<'de> for G2Visitor{
            type Value = BLSG2;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a encoded BLSG2 element")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<BLSG2, E>
                where E: serde::de::Error
            {
                Ok(BLSG2::from_compressed_bytes(v).unwrap()) //TODO handle error
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<BLSG2, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut vec: Vec<u8> = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    vec.push(x);
                }
                Ok(BLSG2::from_compressed_bytes(vec.as_slice()).unwrap())
            }
            fn visit_str<E>(self, s: &str) -> Result<BLSG2, E>
                where E: serde::de::Error
            {
                self.visit_bytes(&base64::decode(s).map_err(serde::de::Error::custom)?)
            }
        }
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(G2Visitor)
        } else {
            deserializer.deserialize_bytes(G2Visitor)
        }
    }
}

impl fmt::Debug for BLSGt{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Fr: Some Gt Element")
    }
}

impl Pairing<BLSScalar> for BLSGt {
    type G1 = BLSG1;
    type G2 = BLSG2;

    fn pairing(a: &Self::G1, b: &Self::G2) -> Self{
        BLSGt( a.0.into_affine().pairing_with(&b.0.into_affine()))
    }
    fn scalar_mul(&self, a: &BLSScalar) -> BLSGt{

        let r = self.0.pow(a.0.into_repr().as_ref());
        BLSGt(r)
    }
    fn add(&self, other: &Self) -> BLSGt{
        let mut m = other.0.clone();
        m.mul_assign(&self.0);
        BLSGt(m)
    }

    fn g1_mul_scalar(a: &Self::G1, b: &BLSScalar) -> Self::G1{
        a.mul(b)
    }
    fn g2_mul_scalar(a: &Self::G2, b: &BLSScalar) -> Self::G2{
        a.mul(b)
    }
    fn get_identity() -> BLSGt{
        BLSGt(Fq12::one())
    }

}

#[cfg(test)]
mod bls12_381_groups_test{
    use crate::algebra::groups::group_tests::{test_scalar_operations, test_scalar_serialization};

    #[test]
    fn test_scalar_ops(){
        test_scalar_operations::<super::BLSScalar>();
    }

    #[test]
    fn scalar_deser(){
        test_scalar_serialization::<super::BLSScalar>();
    }
}

#[cfg(test)]
mod elgamal_over_bls_groups {
    use crate::basic_crypto::elgamal::elgamal_test;

    #[test]
    fn verification_g1(){
        elgamal_test::verification::<super::BLSScalar,super::BLSG1>();
    }

    #[test]
    fn decryption_g1(){
        elgamal_test::decryption::<super::BLSScalar,super::BLSG1>();
    }

    #[test]
    fn to_json_g1(){
        elgamal_test::to_json::<super::BLSScalar,super::BLSG1>();
    }


    #[test]
    fn to_message_pack_g1(){
        elgamal_test::to_message_pack::<super::BLSScalar,super::BLSG1>();
    }

    #[test]
    fn verification_g2(){
        elgamal_test::verification::<super::BLSScalar,super::BLSG1>();
    }

    #[test]
    fn decryption_g2(){
        elgamal_test::decryption::<super::BLSScalar,super::BLSG2>();
    }

    #[test]
    fn to_json_g2(){
        elgamal_test::to_json::<super::BLSScalar,super::BLSG2>();
    }

    #[test]
    fn to_message_pack_g2(){
        elgamal_test::to_message_pack::<super::BLSScalar,super::BLSG2>();
    }

}

#[cfg(test)]
mod credentials_over_bls_12_381 {

    #[test]
    fn single_attribute(){
        crate::credentials::credentials_tests::single_attribute::<super::BLSScalar, super::BLSGt>();
    }

    #[test]
    fn two_attributes(){
        crate::credentials::credentials_tests::two_attributes::<super::BLSScalar,super::BLSGt>();
    }

    #[test]
    fn ten_attributes(){
        crate::credentials::credentials_tests::ten_attributes::<super::BLSScalar,super::BLSGt>();
    }

    #[test]
    fn to_json_credential_structures(){
        crate::credentials::credentials_tests::to_json_credential_structures::<super::BLSScalar,super::BLSGt>();
    }

    #[test]
    fn to_msg_pack_credential_structures(){
        crate::credentials::credentials_tests::to_msg_pack_credential_structures::<super::BLSScalar,super::BLSGt>();
    }


    /*
    #[test]
    fn to_json_issuer_priv_key(){
        crate::credentials::credentials_tests::to_json_issuer_priv_key::<super::BLSGt>();
    }

    #[test]
    fn to_msg_pack_issuer_priv_key(){
        crate::credentials::credentials_tests::to_msg_pack_issuer_priv_key::<super::BLSGt>();
    }

    #[test]
    fn to_json_user_pub_key(){
        crate::credentials::credentials_tests::to_json_user_pub_key::<super::BLSGt>();
    }

    #[test]
    fn to_msg_pack_user_pub_key(){
        crate::credentials::credentials_tests::to_msg_pack_user_pub_key::<super::BLSGt>();
    }
    */
}