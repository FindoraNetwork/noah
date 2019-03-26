use crate::errors::ZeiError;
use rand::{CryptoRng, Rng};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de::{Visitor, SeqAccess};
use crate::serialization::ZeiFromToBytes;
use crate::algebra::groups::Group;
use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElGamalPublicKey<G: Group>(pub(crate) G);  //PK = sk*G


#[derive(Debug, PartialEq, Eq)]
pub struct ElGamalSecretKey<G: Group>(pub(crate) G::ScalarType); //sk

pub fn elgamal_generate_secret_key<R:CryptoRng + Rng, G: Group>(prng: &mut R) -> ElGamalSecretKey<G>{
    ElGamalSecretKey(G::gen_random_scalar(prng))
}

pub fn elgamal_derive_public_key<G: Group>(
    base: &G,
    secret_key: &ElGamalSecretKey<G>,
) -> ElGamalPublicKey<G>
{
    ElGamalPublicKey(base.mul_by_scalar(&secret_key.0))
}

pub const ELGAMAL_CTEXT_LEN: usize = 64; //2 compressed ristretto points

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElGamalCiphertext<G: Group> {
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
        let len = G::get_compressed_len();
        ElGamalCiphertext{
            e1: G::from_compressed_bytes(&bytes[0..len]).unwrap(),
            e2: G::from_compressed_bytes(&bytes[len..]).unwrap(),
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

impl<'de> Deserialize<'de> for ElGamalPublicKey<RistrettoPoint> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        struct ElGamalVisitor;

        impl<'de> Visitor<'de> for ElGamalVisitor {
            type Value = ElGamalPublicKey<RistrettoPoint>;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a encoded ElGamalPublicKey")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<ElGamalPublicKey<RistrettoPoint>, E>
                where E: serde::de::Error
            {
                let point = RistrettoPoint::from_compressed_bytes(v).unwrap();
                Ok(ElGamalPublicKey::<RistrettoPoint>(point))
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<ElGamalPublicKey<RistrettoPoint>, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut vec: Vec<u8> = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    vec.push(x);
                }
                let point = RistrettoPoint::from_compressed_bytes(vec.as_slice()).unwrap();
                Ok(ElGamalPublicKey::<RistrettoPoint>(point))
            }
        }
        deserializer.deserialize_bytes(ElGamalVisitor)
    }
}


impl<G: Group> Serialize for ElGamalSecretKey<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer
    {
        let bytes = G::scalar_to_bytes(&self.0);
        serializer.serialize_bytes(bytes.as_slice())
    }
}

impl<'de> Deserialize<'de> for ElGamalSecretKey<RistrettoPoint> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        struct ElGamalVisitor;

        impl<'de> Visitor<'de> for ElGamalVisitor{
            type Value = ElGamalSecretKey<RistrettoPoint>;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a encoded ElGamalSecretKey")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<ElGamalSecretKey<RistrettoPoint>, E>
                where E: serde::de::Error
            {
                let mut array = [0u8; 32];
                array.copy_from_slice(v);
                let scalar = Scalar::from_bits(array);
                Ok(ElGamalSecretKey::<RistrettoPoint>(scalar))
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<ElGamalSecretKey<RistrettoPoint>, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut bytes = [0u8;32];
                let mut i = 0;
                while let Some(x) = seq.next_element().unwrap() {
                    bytes[i] = x;
                    i += 1;
                }
                let scalar = Scalar::from_bits(bytes);
                Ok(ElGamalSecretKey::<RistrettoPoint>(scalar))
            }
        }
        deserializer.deserialize_bytes(ElGamalVisitor)
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

impl<'de> Deserialize<'de> for ElGamalCiphertext<RistrettoPoint> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        struct ElGamalVisitor;

        impl<'de> Visitor<'de> for ElGamalVisitor{
            type Value = ElGamalCiphertext<RistrettoPoint>;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a encoded ElGamal Ciphertext")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<ElGamalCiphertext<RistrettoPoint>, E>
                where E: serde::de::Error
            {
                Ok(ElGamalCiphertext::<RistrettoPoint>::zei_from_bytes(v))
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<ElGamalCiphertext<RistrettoPoint>, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut vec: Vec<u8> = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    vec.push(x);
                }
                Ok(ElGamalCiphertext::<RistrettoPoint>::zei_from_bytes(vec.as_slice()))
            }
        }
        deserializer.deserialize_bytes(ElGamalVisitor)
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
    let e1 = base.mul_by_scalar(r);
    let e2 = base.mul_by_scalar(m).add(&(public_key.0).mul_by_scalar(r));

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
    secret_key: &ElGamalSecretKey<G>,
) -> Result<(), ZeiError>{
    match  base.mul_by_scalar(m).add(&ctext.e1.mul_by_scalar(&secret_key.0)) == ctext.e2 {
        true => Ok(()),
        false => Err(ZeiError::ElGamalVerificationError)
    }
}

/// I decrypt en el gamal ciphertext via brute force
/// Return ZeiError::ElGamalDecryptionError if value is not in the range [0..2^32-1]
pub fn elgamal_decrypt< G:Group>(
    base: &G,
    ctext: &ElGamalCiphertext<G>,
    secret_key: &ElGamalSecretKey<G>,
    ) -> Result<G::ScalarType, ZeiError>
{
    elgamal_decrypt_hinted::<G>(base, ctext, secret_key, 0, u32::max_value())
}

/// I decrypt en el gamal ciphertext via brute force in the range [lower_bound..upper_bound]
/// Return ZeiError::ElGamalDecryptionError if value is not in the range.
pub fn elgamal_decrypt_hinted<G: Group>(
    base: &G,
    ctext: &ElGamalCiphertext<G>,
    secret_key: &ElGamalSecretKey<G>,
    lower_bound: u32,
    upper_bound: u32,
) -> Result<G::ScalarType, ZeiError>
{
    let encoded = &ctext.e2.sub(&ctext.e1.mul_by_scalar(&secret_key.0));

    brute_force::<G>(base, &encoded, lower_bound, upper_bound)
}

fn brute_force<G: Group>(base: &G, encoded: &G, lower_bound: u32, upper_bound: u32) -> Result<G::ScalarType, ZeiError>{

    for i in lower_bound..upper_bound{
        let s = G::scalar_from_u32(i);
        if base.mul_by_scalar(&s) == *encoded {
            return Ok(s);
        }
    }
    Err(ZeiError::ElGamalDecryptionError)
}

#[cfg(test)]
mod test{
    use bulletproofs::PedersenGens;
    use curve25519_dalek::scalar::Scalar;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use crate::errors::ZeiError;
    use crate::basic_crypto::elgamal::{ElGamalCiphertext, ElGamalPublicKey, ElGamalSecretKey};
    use serde::ser::Serialize;
    use serde::de::Deserialize;
    use rmp_serde::Deserializer;
    use curve25519_dalek::ristretto::RistrettoPoint;

    #[test]
    fn verification(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = PedersenGens::default().B;

        let secret_key = super::elgamal_generate_secret_key::<_,RistrettoPoint>(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        let m = Scalar::from(100u32);
        let r = Scalar::random(&mut prng);
        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
        assert_eq!(Ok(()), super::elgamal_verify(&base, &m, &ctext, &secret_key));

        let wrong_m = &Scalar::from(99u32);
        let err = super::elgamal_verify(&base, wrong_m, &ctext, &secret_key).err().unwrap();
        assert_eq!(ZeiError::ElGamalVerificationError,err);
    }

    #[test]
    fn decrypt(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = PedersenGens::default().B;

        let secret_key = super::elgamal_generate_secret_key::<_, RistrettoPoint>(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        let m = Scalar::from(100u32);
        let r = Scalar::random(&mut prng);
        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
        assert_eq!(Ok(()), super::elgamal_verify(&base, &m, &ctext, &secret_key));

        assert_eq!(m, super::elgamal_decrypt(&base, &ctext, &secret_key).unwrap());
        assert_eq!(m, super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 200).unwrap());

        let err  = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 50).err().unwrap();
        assert_eq!(ZeiError::ElGamalDecryptionError, err);

        let err  = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300).err().unwrap();
        assert_eq!(ZeiError::ElGamalDecryptionError, err);

        let m = Scalar::from(u64::max_value());
        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
        assert_eq!(Ok(()), super::elgamal_verify(&base, &m, &ctext, &secret_key));

        let err  = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300).err().unwrap();
        assert_eq!(ZeiError::ElGamalDecryptionError, err);
    }

    #[test]
    fn to_json(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = PedersenGens::default().B;

        let secret_key = super::elgamal_generate_secret_key::<_, RistrettoPoint>(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        //keys serialization
        let json_str = serde_json::to_string(&secret_key).unwrap();
        let sk_de: ElGamalSecretKey<RistrettoPoint> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(secret_key, sk_de);

        let json_str = serde_json::to_string(&public_key).unwrap();
        let pk_de: ElGamalPublicKey<RistrettoPoint> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(public_key, pk_de);


        //ciphertext serialization
        let m = Scalar::from(100u32);
        let r = Scalar::random(&mut prng);

        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
        let json_str = serde_json::to_string(&ctext).unwrap();
        let ctext_de: ElGamalCiphertext<RistrettoPoint> = serde_json::from_str(&json_str).unwrap();

        assert_eq!(ctext, ctext_de);
    }

    #[test]
    fn to_message_pack(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = PedersenGens::default().B;

        let secret_key = super::elgamal_generate_secret_key::<_, RistrettoPoint>(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        //keys serialization
        let mut vec = vec![];
        secret_key.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let sk_de: ElGamalSecretKey<RistrettoPoint> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(secret_key, sk_de);

        //public key serialization
        let mut vec = vec![];
        public_key.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let pk_de: ElGamalPublicKey<RistrettoPoint> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(public_key, pk_de);

        //ciphertext serialization
        let m = Scalar::from(100u32);
        let r = Scalar::random(&mut prng);

        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);

        let mut vec = vec![];
        ctext.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();

        let mut de = Deserializer::new(&vec[..]);
        let ctext_de: ElGamalCiphertext<RistrettoPoint> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(ctext, ctext_de);
    }

}