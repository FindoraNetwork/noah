use crate::errors::ZeiError;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::RangeProof;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ruc::{err::*, *};

/// Helper trait to serialize zei and foreign objects that implement from/to bytes/bits
pub trait ZeiFromToBytes: Sized {
    fn zei_to_bytes(&self) -> Vec<u8>;
    fn zei_from_bytes(bytes: &[u8]) -> Result<Self>;
}

impl ZeiFromToBytes for RangeProof {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<RangeProof> {
        RangeProof::from_bytes(bytes).map_err(|_| eg!(ZeiError::DeserializationError)) // TODO import error message
    }
}

impl ZeiFromToBytes for R1CSProof {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<R1CSProof> {
        R1CSProof::from_bytes(bytes).map_err(|_| eg!(ZeiError::DeserializationError)) // TODO import error message
    }
}

impl ZeiFromToBytes for CompressedEdwardsY {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<CompressedEdwardsY> {
        Ok(CompressedEdwardsY::from_slice(bytes))
    }
}

impl ZeiFromToBytes for x25519_dalek::PublicKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(self.as_bytes());
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<x25519_dalek::PublicKey> {
        if bytes.len() < 32 {
            return Err(eg!(ZeiError::SerializationError));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[0..32]);
        Ok(x25519_dalek::PublicKey::from(array))
    }
}

impl ZeiFromToBytes for x25519_dalek::StaticSecret {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<x25519_dalek::StaticSecret> {
        if bytes.len() < 32 {
            return Err(eg!(ZeiError::SerializationError));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[0..32]);
        Ok(x25519_dalek::StaticSecret::from(array))
    }
}

pub mod zei_obj_serde {
    use crate::serialization::ZeiFromToBytes;
    use crate::{b64dec, b64enc};
    use serde::de::SeqAccess;
    use serde::de::Visitor;
    use serde::Deserializer;
    use serde::Serializer;

    pub struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(
            &self,
            formatter: &mut ::core::fmt::Formatter,
        ) -> core::fmt::Result {
            formatter.write_str("a valid ZeiFromTo Object")
        }

        fn visit_seq<V>(self, mut seq: V) -> core::result::Result<Vec<u8>, V::Error>
        where
            V: SeqAccess<'de>,
        {
            let mut vec: Vec<u8> = vec![];
            while let Some(x) = seq.next_element().map_err(serde::de::Error::custom)? {
                vec.push(x);
            }
            Ok(vec)
        }

        fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Vec<u8>, E> {
            let mut vec: Vec<u8> = vec![];
            vec.extend_from_slice(v);
            Ok(vec)
        }

        fn visit_str<E>(self, v: &str) -> core::result::Result<Vec<u8>, E>
        where
            E: serde::de::Error,
        {
            b64dec(v).map_err(serde::de::Error::custom)
        }
    }

    pub fn serialize<S, T>(
        obj: &T,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: ZeiFromToBytes,
    {
        let bytes = obj.zei_to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&b64enc(&bytes))
        } else {
            serializer.serialize_bytes(&bytes[..])
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> core::result::Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: ZeiFromToBytes,
    {
        if deserializer.is_human_readable() {
            let bytes = deserializer.deserialize_str(BytesVisitor)?;
            T::zei_from_bytes(bytes.as_slice()).map_err(serde::de::Error::custom)
        } else {
            let v = deserializer.deserialize_bytes(BytesVisitor)?;
            T::zei_from_bytes(v.as_slice()).map_err(serde::de::Error::custom)
        }
    }
}
