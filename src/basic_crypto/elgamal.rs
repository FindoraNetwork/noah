use crate::errors::ZeiError;
use rand::{CryptoRng, Rng};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de::{Visitor, SeqAccess};
use crate::serialization::ZeiFromToBytes;
use crate::algebra::groups::{Group, Scalar};
use std::marker::PhantomData;


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElGamalPublicKey<G>(pub(crate) G);  //PK = sk*G


#[derive(Debug, PartialEq, Eq)]
pub struct ElGamalSecretKey<S>(pub(crate) S); //sk

pub fn elgamal_generate_secret_key<R:CryptoRng + Rng, G: Group>(prng: &mut R) -> ElGamalSecretKey<G::ScalarType>{
    ElGamalSecretKey(G::ScalarType::random_scalar(prng))
}

pub fn elgamal_derive_public_key<G: Group>(
    base: &G,
    secret_key: &ElGamalSecretKey<G::ScalarType>,
) -> ElGamalPublicKey<G>
{
    ElGamalPublicKey(base.mul(&secret_key.0))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElGamalCiphertext<G> {
    pub(crate) e1: G, //r*G
    pub(crate) e2: G, //m*G + r*PK
}


impl<G: Group> ZeiFromToBytes for ElGamalCiphertext<G>{
    fn zei_to_bytes(&self) -> Vec<u8>{
        let mut v  = vec![];
        v.extend_from_slice(self.e1.to_compressed_bytes().as_slice());
        v.extend_from_slice(self.e2.to_compressed_bytes().as_slice());
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Self{
        ElGamalCiphertext{
            e1: G::from_compressed_bytes(&bytes[0..G::COMPRESSED_LEN]).unwrap(),
            e2: G::from_compressed_bytes(&bytes[G::COMPRESSED_LEN..]).unwrap(),
        }
    }
}


impl<G: Group> Serialize for ElGamalPublicKey<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer
    {
        serializer.serialize_bytes(self.0.to_compressed_bytes().as_slice())
    }
}

impl<'de, G: Group> Deserialize<'de> for ElGamalPublicKey<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        struct ElGamalVisitor<G: Group> {
            marker: PhantomData<fn()->ElGamalPublicKey<G>>
        }

        impl<G: Group> ElGamalVisitor<G> {
            fn new() -> Self {
                ElGamalVisitor {
                    marker: PhantomData
                } 
            }
        }

        impl<'de, G: Group> Visitor<'de> for ElGamalVisitor<G> {
            type Value = ElGamalPublicKey<G>;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a encoded ElGamalPublicKey")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<ElGamalPublicKey<G>, E>
                where E: serde::de::Error
            {
                let point = G::from_compressed_bytes(v).unwrap();
                Ok(ElGamalPublicKey::<G>(point))
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<ElGamalPublicKey<G>, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut vec: Vec<u8> = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    vec.push(x);
                }
                let point = G::from_compressed_bytes(vec.as_slice()).unwrap();
                Ok(ElGamalPublicKey::<G>(point))
            }
        }
        deserializer.deserialize_bytes(ElGamalVisitor::new())
    }
}


impl<Sc: Scalar> Serialize for ElGamalSecretKey<Sc> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer
    {
        let bytes = Sc::to_bytes(&self.0);
        serializer.serialize_bytes(bytes.as_slice())
    }
}

impl<'de, S: Scalar> Deserialize<'de> for ElGamalSecretKey<S> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        struct ElGamalVisitor<S: Scalar> {
            marker: PhantomData<fn()->ElGamalSecretKey<S>>
        }

        impl<S: Scalar> ElGamalVisitor<S> {
            fn new() -> Self {
                ElGamalVisitor {
                    marker: PhantomData
                } 
            }
        }


        impl<'de, S: Scalar> Visitor<'de> for ElGamalVisitor<S>{
            type Value = ElGamalSecretKey<S>;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a encoded ElGamalSecretKey")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<ElGamalSecretKey<S>, E>
                where E: serde::de::Error
            {
                let scalar = S::from_bytes(&v);
                Ok(ElGamalSecretKey::<S>(scalar))
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<ElGamalSecretKey<S>, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut bytes = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    bytes.push(x);
                }
                let scalar = S::from_bytes(bytes.as_slice());
                Ok(ElGamalSecretKey::<S>(scalar))
            }
        }
        deserializer.deserialize_bytes(ElGamalVisitor::new())
    }
}

impl<G: Group> Serialize for ElGamalCiphertext<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer
    {

        serializer.serialize_bytes(self.zei_to_bytes().as_slice())
    }
}

impl<'de, G: Group> Deserialize<'de> for ElGamalCiphertext<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        struct ElGamalVisitor<G: Group> {
            marker: PhantomData<fn()->ElGamalCiphertext<G>>
        }

        impl<G: Group> ElGamalVisitor<G> {
            fn new() -> Self {
                ElGamalVisitor {
                    marker: PhantomData
                } 
            }
        }

        impl<'de, G: Group> Visitor<'de> for ElGamalVisitor<G>{
            type Value = ElGamalCiphertext<G>;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a encoded ElGamal Ciphertext")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<ElGamalCiphertext<G>, E>
                where E: serde::de::Error
            {
                Ok(ElGamalCiphertext::<G>::zei_from_bytes(v))
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<ElGamalCiphertext<G>, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut vec: Vec<u8> = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    vec.push(x);
                }
                Ok(ElGamalCiphertext::<G>::zei_from_bytes(vec.as_slice()))
            }
        }
        deserializer.deserialize_bytes(ElGamalVisitor::new())
    }
}

/// I return an ElGamal ciphertext pair as (r*G, m*g + r*PK), where G is a curve base point
pub fn elgamal_encrypt<G:Group>(
    base: &G,
    m: &G::ScalarType,
    r: &G::ScalarType,
    public_key: &ElGamalPublicKey<G>
) ->ElGamalCiphertext<G>
{
    let e1 = base.mul(r);
    let e2 = base.mul(m).add(&(public_key.0).mul(r));

    ElGamalCiphertext::<G>{
        e1,
        e2,
    }
}

/// I verify that ctext encrypts m (ctext.e2 - ctext.e1 * sk = m* G)
pub fn elgamal_verify<G:Group>(
    base: &G,
    m: &G::ScalarType,
    ctext: &ElGamalCiphertext<G>,
    secret_key: &ElGamalSecretKey<G::ScalarType>,
) -> Result<(), ZeiError>{
    match  base.mul(m).add(&ctext.e1.mul(&secret_key.0)) == ctext.e2 {
        true => Ok(()),
        false => Err(ZeiError::ElGamalVerificationError)
    }
}

/// I decrypt en el gamal ciphertext via brute force
/// Return ZeiError::ElGamalDecryptionError if value is not in the range [0..2^32-1]
pub fn elgamal_decrypt< G:Group>(
    base: &G,
    ctext: &ElGamalCiphertext<G>,
    secret_key: &ElGamalSecretKey<G::ScalarType>,
    ) -> Result<G::ScalarType, ZeiError>
{
    elgamal_decrypt_hinted::<G>(base, ctext, secret_key, 0, u32::max_value())
}

/// I decrypt en el gamal ciphertext via brute force in the range [lower_bound..upper_bound]
/// Return ZeiError::ElGamalDecryptionError if value is not in the range.
pub fn elgamal_decrypt_hinted<G: Group>(
    base: &G,
    ctext: &ElGamalCiphertext<G>,
    secret_key: &ElGamalSecretKey<G::ScalarType>,
    lower_bound: u32,
    upper_bound: u32,
) -> Result<G::ScalarType, ZeiError>
{
    let encoded = &ctext.e2.sub(&ctext.e1.mul(&secret_key.0));

    brute_force::<G>(base, &encoded, lower_bound, upper_bound)
}

fn brute_force<G: Group>(base: &G, encoded: &G, lower_bound: u32, upper_bound: u32) -> Result<G::ScalarType, ZeiError>{

    let mut b = base.mul(&G::ScalarType::from_u32(lower_bound));
    for i in lower_bound..upper_bound{
        //let s = G::ScalarType::from_u32(i);
        if b == *encoded{
            return Ok (G::ScalarType::from_u32(i));
        }
        b = b.add(base);
    }
    Err(ZeiError::ElGamalDecryptionError)
}


pub mod elgamal_test{
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use crate::errors::ZeiError;
    use crate::basic_crypto::elgamal::{ElGamalCiphertext, ElGamalPublicKey, ElGamalSecretKey};
    use serde::ser::Serialize;
    use serde::de::Deserialize;
    use rmp_serde::Deserializer;
    use crate::algebra::groups::{Group, Scalar};

    pub fn verification<G: Group>(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = G::get_base();

        let secret_key = super::elgamal_generate_secret_key::<_,G>(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        let m = G::ScalarType::from_u32(100u32);
        let r = G::ScalarType::random_scalar(&mut prng);
        let ctext = super::elgamal_encrypt::<G>(&base, &m, &r, &public_key);
        assert_eq!(Ok(()), super::elgamal_verify::<G>(&base, &m, &ctext, &secret_key));

        let wrong_m = G::ScalarType::from_u32(99u32);
        let err = super::elgamal_verify(&base, &wrong_m, &ctext, &secret_key).err().unwrap();
        assert_eq!(ZeiError::ElGamalVerificationError,err);
    }

    pub fn decryption<G: Group>(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = G::get_base();

        let secret_key = super::elgamal_generate_secret_key::<_, G>(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        let m = G::ScalarType::from_u32(100u32);
        let r = G::ScalarType::random_scalar(&mut prng);
        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
        assert_eq!(Ok(()), super::elgamal_verify(&base, &m, &ctext, &secret_key));

        assert_eq!(m, super::elgamal_decrypt(&base, &ctext, &secret_key).unwrap());
        assert_eq!(m, super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 200).unwrap());

        let err  = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 50).err().unwrap();
        assert_eq!(ZeiError::ElGamalDecryptionError, err);

        let err  = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300).err().unwrap();
        assert_eq!(ZeiError::ElGamalDecryptionError, err);

        let m = G::ScalarType::from_u64(u64::max_value());
        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
        assert_eq!(Ok(()), super::elgamal_verify(&base, &m, &ctext, &secret_key));

        let err  = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300).err().unwrap();
        assert_eq!(ZeiError::ElGamalDecryptionError, err);
    }

    pub fn to_json<G: Group>(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = G::get_base();

        let secret_key = super::elgamal_generate_secret_key::<_, G>(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        //keys serialization
        let json_str = serde_json::to_string(&secret_key).unwrap();
        let sk_de: ElGamalSecretKey<G::ScalarType> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(secret_key, sk_de);

        let json_str = serde_json::to_string(&public_key).unwrap();
        let pk_de: ElGamalPublicKey<G> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(public_key, pk_de);


        //ciphertext serialization
        let m = G::ScalarType::from_u32(100u32);
        let r = G::ScalarType::random_scalar(&mut prng);

        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
        let json_str = serde_json::to_string(&ctext).unwrap();
        let ctext_de: ElGamalCiphertext<G> = serde_json::from_str(&json_str).unwrap();

        assert_eq!(ctext, ctext_de);
    }

    pub fn to_message_pack<G: Group>(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = G::get_base();

        let secret_key = super::elgamal_generate_secret_key::<_, G>(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        //keys serialization
        let mut vec = vec![];
        secret_key.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let sk_de: ElGamalSecretKey<G::ScalarType> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(secret_key, sk_de);

        //public key serialization
        let mut vec = vec![];
        public_key.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let pk_de: ElGamalPublicKey<G> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(public_key, pk_de);

        //ciphertext serialization
        let m = G::ScalarType::from_u32(100u32);
        let r = G::ScalarType::random_scalar(&mut prng);

        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);

        let mut vec = vec![];
        ctext.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();

        let mut de = Deserializer::new(&vec[..]);
        let ctext_de: ElGamalCiphertext<G> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(ctext, ctext_de);
    }

}