use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use crate::errors::ZeiError;
use rand::{CryptoRng, Rng};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de::{Visitor, SeqAccess};

pub struct ElGamalPublicKey(pub(crate) CompressedRistretto);  //PK = sk*G
pub struct ElGamalSecretKey(pub(crate) Scalar); //sk

pub fn elgamal_generate_secret_key<R:CryptoRng + Rng>(prng: &mut R) -> ElGamalSecretKey{
    ElGamalSecretKey(Scalar::random(prng))
}

pub fn elgamal_derive_public_key(
    base: &RistrettoPoint,
    secret_key: &ElGamalSecretKey
) -> ElGamalPublicKey
{
    ElGamalPublicKey((base * secret_key.0).compress())
}

#[derive(Debug, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    e1: CompressedRistretto, //r*G
    e2: CompressedRistretto, //m*G + r*PK
}

impl Serialize for ElGamalCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer
    {
        let mut v = vec![];
        v.extend_from_slice(self.e1.as_bytes());
        v.extend_from_slice(self.e2.as_bytes());
        serializer.serialize_bytes(v.as_slice())
    }
}

impl<'de> Deserialize<'de> for ElGamalCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        struct ElGamalVisitor;

        impl<'de> Visitor<'de> for ElGamalVisitor {
            type Value = ElGamalCiphertext;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a encoded ElGamal Ciphertext")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<ElGamalCiphertext, E>
                where E: serde::de::Error
            {
                Ok(ElGamalCiphertext{
                    e1: CompressedRistretto::from_slice(&v[0..32]),
                    e2: CompressedRistretto::from_slice(&v[32..]),
                })
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<ElGamalCiphertext, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut vec: Vec<u8> = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    vec.push(x);
                }
                Ok(ElGamalCiphertext{
                    e1: CompressedRistretto::from_slice(&vec[0..32]),
                    e2: CompressedRistretto::from_slice(&vec[32..]),
                })
            }
        }
        deserializer.deserialize_bytes(ElGamalVisitor)
    }
}


/// I return an ElGamal ciphertext pair as (r*G, m*g + r*PK), where G is a curve base point
pub fn elgamal_encrypt(
    base: &RistrettoPoint,
    m: &Scalar,
    r: &Scalar,
    public_key: &ElGamalPublicKey
) -> Result<ElGamalCiphertext, ZeiError>
{
    let pk = (public_key.0).decompress().ok_or(ZeiError::DecompressElementError)?;
    let e1 = r * base;
    let e2 = m * base + r*pk;

    Ok(ElGamalCiphertext{
        e1: e1.compress(),
        e2: e2.compress(),
    })
}

/// I verify that ctext encrypts m (ctext.e2 - ctext.e1 * sk = m* G)
pub fn elgamal_verify(
    base: &RistrettoPoint,
    m: &Scalar,
    ctext: &ElGamalCiphertext,
    secret_key: &ElGamalSecretKey
) -> Result<(), ZeiError>{

    let sk = secret_key.0;
    let e1 = ctext.e1.decompress().ok_or(ZeiError::DecompressElementError)?;
    let e2 = ctext.e2.decompress().ok_or(ZeiError::DecompressElementError)?;

    match  m * base + sk * e1 == e2 {
        true => Ok(()),
        false => Err(ZeiError::ElGamalVerificationError)
    }
}

/// I decrypt en el gamal ciphertext via brute force
/// Return ZeiError::ElGamalDecryptionError if value is not in the range [0..2^32-1]
pub fn elgamal_decrypt(
    base: &RistrettoPoint,
    ctext: &ElGamalCiphertext,
    secret_key: &ElGamalSecretKey,
    ) -> Result<Scalar, ZeiError>
{
    elgamal_decrypt_hinted(base, ctext, secret_key, 0, u32::max_value())
}

/// I decrypt en el gamal ciphertext via brute force in the range [lower_bound..upper_bound]
/// Return ZeiError::ElGamalDecryptionError if value is not in the range.
pub fn elgamal_decrypt_hinted(
    base: &RistrettoPoint,
    ctext: &ElGamalCiphertext,
    secret_key: &ElGamalSecretKey,
    lower_bound: u32,
    upper_bound: u32,
) -> Result<Scalar, ZeiError>
{
    let sk = secret_key.0;
    let e1 = ctext.e1.decompress().ok_or(ZeiError::DecompressElementError)?;
    let e2 = ctext.e2.decompress().ok_or(ZeiError::DecompressElementError)?;


    let encoded = e2 - e1 * sk;

    brute_force(base, &encoded, lower_bound, upper_bound)
}

fn brute_force(base: &RistrettoPoint, encoded: &RistrettoPoint, lower_bound: u32, upper_bound: u32) -> Result<Scalar, ZeiError>{

    for i in lower_bound..upper_bound{
        let s = Scalar::from(i);
        if base * s == *encoded {
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
    use crate::basic_crypto::elgamal::ElGamalCiphertext;
    use serde::ser::Serialize;
    use serde::de::Deserialize;
    use rmp_serde::Deserializer;

    #[test]
    fn verification(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = PedersenGens::default().B;

        let secret_key = super::elgamal_generate_secret_key(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        let m = Scalar::from(100u32);
        let r = Scalar::random(&mut prng);
        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key).unwrap();
        assert_eq!(Ok(()), super::elgamal_verify(&base, &m, &ctext, &secret_key));

        let wrong_m = &Scalar::from(99u32);
        let err = super::elgamal_verify(&base, wrong_m, &ctext, &secret_key).err().unwrap();
        assert_eq!(ZeiError::ElGamalVerificationError,err);
    }

    #[test]
    fn decrypt(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = PedersenGens::default().B;

        let secret_key = super::elgamal_generate_secret_key(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        let m = Scalar::from(100u32);
        let r = Scalar::random(&mut prng);
        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key).unwrap();
        assert_eq!(Ok(()), super::elgamal_verify(&base, &m, &ctext, &secret_key));

        assert_eq!(m, super::elgamal_decrypt(&base, &ctext, &secret_key).unwrap());
        assert_eq!(m, super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 200).unwrap());

        let err  = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 50).err().unwrap();
        assert_eq!(ZeiError::ElGamalDecryptionError, err);

        let err  = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300).err().unwrap();
        assert_eq!(ZeiError::ElGamalDecryptionError, err);

        let m = Scalar::from(u64::max_value());
        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key).unwrap();
        assert_eq!(Ok(()), super::elgamal_verify(&base, &m, &ctext, &secret_key));

        let err  = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300).err().unwrap();
        assert_eq!(ZeiError::ElGamalDecryptionError, err);
    }

    #[test]
    fn to_json(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = PedersenGens::default().B;

        let secret_key = super::elgamal_generate_secret_key(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        let m = Scalar::from(100u32);
        let r = Scalar::random(&mut prng);

        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key).unwrap();
        let json_str = serde_json::to_string(&ctext).unwrap();
        let ctext_de: ElGamalCiphertext = serde_json::from_str(&json_str).unwrap();

        assert_eq!(ctext, ctext_de);
    }

    #[test]
    fn to_message_pack(){
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let base = PedersenGens::default().B;

        let secret_key = super::elgamal_generate_secret_key(&mut prng);
        let public_key = super::elgamal_derive_public_key(&base, &secret_key);

        let m = Scalar::from(100u32);
        let r = Scalar::random(&mut prng);

        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key).unwrap();

        let mut vec = vec![];
        ctext.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();

        let mut de = Deserializer::new(&vec[..]);
        let ctext_de: ElGamalCiphertext = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(ctext, ctext_de);
    }

}