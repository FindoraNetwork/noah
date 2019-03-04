use bulletproofs::{RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use schnorr::SecretKey;
use crate::proofs::chaum_pedersen::ChaumPedersenCommitmentEqProofMultiple;
use crate::proofs::chaum_pedersen::ChaumPedersenCommitmentEqProof;
use schnorr::Signature;
use schnorr::PublicKey;
use schnorr::Keypair;
use crate::keys::ZeiSignature;
use serde::Serialize;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serializer;

// preferred approach for handling of fields of types that don't provide correct default serde serialize/deserialize

/// Helper trait to serialize zei and foreign objects that implement from/to bytes/bits
pub trait ZeiFromToBytes {
    fn zei_to_bytes(&self) -> Vec<u8>;
    fn zei_from_bytes(bytes: &[u8]) -> Self;
}

impl ZeiFromToBytes for Signature{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Signature{
        Signature::from_bytes(bytes).unwrap()
    }
}

impl ZeiFromToBytes for PublicKey{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> PublicKey{
        PublicKey::from_bytes(bytes).unwrap()
    }
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

impl ZeiFromToBytes for Keypair{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Keypair{
        Keypair::from_bytes(bytes).unwrap()
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

impl ZeiFromToBytes for ZeiSignature{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.to_bytes();
        let mut vec = vec![];
        vec.extend_from_slice(&bytes[..]);
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Self {
        ZeiSignature(Signature::from_bytes(bytes).unwrap())
    }
}

impl Serialize for ZeiSignature{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer
    {
        serializer.serialize_bytes(self.zei_to_bytes().as_slice())
    }
}

impl<'de> Deserialize<'de> for ZeiSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        let v = deserializer.deserialize_bytes(zei_obj_serde::BytesVisitor).unwrap();
        Ok(ZeiSignature::zei_from_bytes(v.as_slice()))
    }
}

pub mod zei_obj_serde {
    use crate::serialization::ZeiFromToBytes;
    use serde::Serializer;
    use serde::de::Visitor;
    use serde::de::SeqAccess;
    use serde::Deserializer;

    pub struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
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


    pub fn serialize<S, T>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer, T: ZeiFromToBytes
    {
        let bytes = obj.zei_to_bytes();
        serializer.serialize_bytes(&bytes[..])
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where D: Deserializer<'de>, T: ZeiFromToBytes,
    {
        let v = deserializer.deserialize_bytes(BytesVisitor).unwrap();
        Ok(T::zei_from_bytes(v.as_slice()))
    }
}

pub mod option_bytes {
    use serde::{self, Deserialize, Serializer, Deserializer};
    use crate::serialization::ZeiFromToBytes;

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
