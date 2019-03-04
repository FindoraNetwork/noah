use bulletproofs::{RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use schnorr::SecretKey;
use crate::proofs::chaum_pedersen::ChaumPedersenCommitmentEqProofMultiple;
use crate::proofs::chaum_pedersen::ChaumPedersenCommitmentEqProof;

// preferred approach for handling of fields of types that don't provide correct default serde serialize/deserialize

pub trait ZeiFromToBytes {
    fn zei_to_bytes(&self) -> Vec<u8>;
    fn zei_from_bytes(bytes: &[u8]) -> Self;
}

impl ZeiFromToBytes for SecretKey{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> SecretKey{
        SecretKey::from_bytes(bytes).unwrap()
    }
}

impl ZeiFromToBytes for Scalar{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Scalar{
        let mut bits = [0u8; 32];
        bits.copy_from_slice(bytes);
        Scalar::from_bits(bits)
    }
}

impl ZeiFromToBytes for CompressedRistretto{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> CompressedRistretto{
        CompressedRistretto::from_slice(bytes)
    }
}

impl ZeiFromToBytes for RangeProof{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> RangeProof{
        RangeProof::from_bytes(bytes).unwrap()
    }
}

impl ZeiFromToBytes for ChaumPedersenCommitmentEqProof{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.c3.zei_to_bytes());
        v.extend_from_slice(&self.c4.zei_to_bytes());
        v.extend_from_slice(&self.z1.zei_to_bytes());
        v.extend_from_slice(&self.z2.zei_to_bytes());
        v.extend_from_slice(&self.z3.zei_to_bytes());
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> ChaumPedersenCommitmentEqProof{
        ChaumPedersenCommitmentEqProof{
            c3: CompressedRistretto::zei_from_bytes(&bytes[0..32]),
            c4: CompressedRistretto::zei_from_bytes(&bytes[32..64]),
            z1: Scalar::zei_from_bytes(&bytes[64..96]),
            z2: Scalar::zei_from_bytes(&bytes[96..128]),
            z3: Scalar::zei_from_bytes(&bytes[128..160]),
        }
    }
}
impl ZeiFromToBytes for ChaumPedersenCommitmentEqProofMultiple{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.c1_eq_c2.zei_to_bytes());
        v.extend_from_slice(&self.zero.zei_to_bytes());
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> ChaumPedersenCommitmentEqProofMultiple{
        let c1_eq_c2 =
            ChaumPedersenCommitmentEqProof::zei_from_bytes(&bytes[0..32*5]);
        let zero =
            ChaumPedersenCommitmentEqProof::zei_from_bytes(&bytes[32*5..]);
        ChaumPedersenCommitmentEqProofMultiple{
            c1_eq_c2,
            zero
        }
    }
}


pub mod keypair {
    use schnorr::Keypair;
    use serde::{self, Serializer, Deserializer};
    use serde::de::Visitor;
    use serde::de::SeqAccess;

    pub fn serialize<S>(kp: &Keypair, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer,
    {
        let bytes = kp.to_bytes();
        serializer.serialize_bytes(&bytes[..])
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Keypair, D::Error>
    where D: Deserializer<'de>,
    {
        struct KeypairVisitor;

        impl<'de> Visitor<'de> for KeypairVisitor {
            type Value = Keypair;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid Keypair")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Keypair, V::Error>
                where
                    V: SeqAccess<'de>
            {
                let mut vec = vec![];
                for _ in 0..64{
                    let x = seq.next_element().map_err(serde::de::Error::custom)?.unwrap();
                    vec.push(x);
                }
                Keypair::from_bytes(vec.as_slice()).map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_bytes(KeypairVisitor)
    }
}

pub mod public_key {
    use schnorr::PublicKey;
    use serde::{self, Serializer, Deserializer};
    use serde::de::Visitor;
    use serde::de::SeqAccess;

    pub fn serialize<S>(pk: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        let bytes = pk.to_bytes();
        serializer.serialize_bytes(&bytes[..])
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
        where D: Deserializer<'de>,
    {
        struct PublickeyVisitor;

        impl<'de> Visitor<'de> for PublickeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid PublicKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<PublicKey, V::Error>
                where
                    V: SeqAccess<'de>
            {
                let mut vec = vec![];
                for _ in 0..32{
                    let x = seq.next_element().map_err(serde::de::Error::custom)?.unwrap();
                    vec.push(x);
                }
                PublicKey::from_bytes(vec.as_slice()).map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_bytes(PublickeyVisitor)
    }
}

pub mod secret_key {
    use schnorr::SecretKey;
    use serde::{self, Serializer, Deserializer};
    use serde::de::Visitor;
    use serde::de::SeqAccess;

    pub fn serialize<S>(sk: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        let bytes = sk.to_bytes();
        serializer.serialize_bytes(&bytes[..])
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretKey, D::Error>
        where D: Deserializer<'de>,
    {
        struct SecretkeyVisitor;

        impl<'de> Visitor<'de> for SecretkeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid SecretKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<SecretKey, V::Error>
                where
                    V: SeqAccess<'de>
            {
                let mut vec = vec![];
                for _ in 0..32{
                    let x = seq.next_element().map_err(serde::de::Error::custom)?.unwrap();
                    vec.push(x);
                }
                SecretKey::from_bytes(vec.as_slice()).map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_bytes(SecretkeyVisitor)
    }
}

pub mod scalar {
    use curve25519_dalek::scalar::Scalar;
    use serde::{self, Serializer, Deserializer};
    use serde::de::SeqAccess;
    use serde::de::Visitor;

    pub fn serialize<S>(sc: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer,
    {
        let bytes = sc.to_bytes();
        serializer.serialize_bytes(&bytes[..])
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where D: Deserializer<'de>,
    {
        struct ScalarVisitor;

        impl<'de> Visitor<'de> for ScalarVisitor {
            type Value = Scalar;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid Scalar")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Scalar, V::Error>
                where
                    V: SeqAccess<'de>
            {
                let mut vec = vec![];
                for _ in 0..32{
                    let x = seq.next_element().map_err(serde::de::Error::custom)?.unwrap();
                    vec.push(x);
                }
                let mut bytes = [0u8;32];
                bytes.copy_from_slice(vec.as_slice());
                Ok(Scalar::from_bits(bytes))
            }
        }
        deserializer.deserialize_bytes(ScalarVisitor)
    }
}

pub mod compressed_ristretto {
    use curve25519_dalek::ristretto::CompressedRistretto;
    use serde::{self, de, Serializer, Deserializer};
    use serde::de::Visitor;
    use serde::de::SeqAccess;

    pub fn serialize<S>(cr: &CompressedRistretto, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer,
    {
        let bytes = cr.to_bytes();
        serializer.serialize_bytes(&bytes[..])
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<CompressedRistretto, D::Error>
    where D: Deserializer<'de>,
    {
        struct CRVisitor;

        impl<'de> Visitor<'de> for CRVisitor {
            type Value = CompressedRistretto;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid CompressedRistretto")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<CompressedRistretto, V::Error>
                where
                    V: SeqAccess<'de>
            {
                let mut vec = vec![];
                for _ in 0..32{
                    let x = seq.next_element().map_err(de::Error::custom)?.unwrap();
                    vec.push(x);
                }
                Ok(CompressedRistretto::from_slice(vec.as_slice()))
            }
        }
        deserializer.deserialize_bytes(CRVisitor)
    }
}

pub mod range_proof{
    use bulletproofs::RangeProof;
    use serde::{self, Serializer, Deserializer};
    use serde::de::Visitor;
    use serde::de::SeqAccess;

    pub fn serialize<S>(rp: &RangeProof, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        let bytes = rp.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<RangeProof, D::Error>
        where D: Deserializer<'de>,
    {
        struct RPVisitor;
        let mut len = 0usize;

        impl<'de> Visitor<'de> for RPVisitor {
            type Value = RangeProof;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid RangeProof")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<RangeProof, V::Error>
                where
                    V: SeqAccess<'de>
            {
                let mut vec: Vec<u8> = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    vec.push(x);
                }
                let rp = RangeProof::from_bytes(vec.as_slice()).unwrap();
                Ok(rp)
            }
        }
        deserializer.deserialize_bytes(RPVisitor)
    }
}

pub mod signature {
    use serde::{self, de, Deserialize, Serializer, Deserializer};
    use schnorr::Signature;

    pub fn serialize<S>(s: &Signature, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        let bytes = s.to_bytes();
        let encoded = hex::encode(&bytes[..]);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
        where D: Deserializer<'de>,
    {
        let sign_str = String::deserialize(deserializer)?;
        let vector = hex::decode(sign_str).map_err(de::Error::custom)?;
        let bytes = vector.as_slice();
        let signature = Signature::from_bytes(bytes).map_err(de::Error::custom)?;
        Ok(signature)
    }
}

pub mod option_bytes {
    use serde::{self, Deserialize, Serializer, Deserializer};
    use crate::serialization::ZeiFromToBytes;
    use serde::de::SeqAccess;
    use serde::de::Visitor;

    struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor{
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            formatter.write_str("a valid ZeiFromTo Object")
        }

        fn visit_seq<V>(self, mut seq: V) -> Result<Vec<u8>, V::Error>
            where
                V: SeqAccess<'de>,
        {
            let mut vec: Vec<u8> = vec![];
            while let Some(x) = seq.next_element().unwrap() {
                vec.push(x);
            }
            Ok(vec)
        }
    }

    pub fn serialize<S,T>(object: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer, T: ZeiFromToBytes,
    {
        if object.is_none() {
            serializer.serialize_none()
        }
        else {
            let bytes = object.as_ref().unwrap().zei_to_bytes();
            //let encoded = hex::encode(&bytes[..]);
            serializer.serialize_bytes(bytes.as_slice())
        }
    }
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
        where D: Deserializer<'de>, T: ZeiFromToBytes,
    {

        let vec: Option<Vec<u8>> = Option::deserialize(deserializer)?;

        if vec.is_some() {
            Ok(Some(T::zei_from_bytes(vec.unwrap().as_slice())))

        }
        else {
            Ok(None)
        }
    }
}
