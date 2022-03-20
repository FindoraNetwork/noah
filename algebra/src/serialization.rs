use crate::{
    bls12_381::{BLSGt, BLSScalar, BLSG1, BLSG2},
    jubjub::{JubjubPoint, JubjubScalar},
    prelude::*,
    ristretto::{CompressedEdwardsY, CompressedRistretto, RistrettoPoint, RistrettoScalar},
    serialize_deserialize,
};
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::RangeProof;
use serde::Serializer;

macro_rules! to_from_bytes_scalar {
    ($t:ident) => {
        impl ZeiFromToBytes for $t {
            fn zei_to_bytes(&self) -> Vec<u8> {
                let mut v = vec![];
                v.extend_from_slice(&self.to_bytes()[..]);
                v
            }
            fn zei_from_bytes(bytes: &[u8]) -> Result<$t> {
                $t::from_bytes(bytes)
                    .map_err(|_| eg!(crate::errors::ZeiError::DeserializationError))
            }
        }
    };
}

to_from_bytes_scalar!(RistrettoScalar);
to_from_bytes_scalar!(JubjubScalar);
to_from_bytes_scalar!(BLSScalar);

impl ZeiFromToBytes for CompressedRistretto {
    #[inline]
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
    #[inline]
    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            curve25519_dalek::ristretto::CompressedRistretto::from_slice(bytes),
        ))
    }
}

impl ZeiFromToBytes for CompressedEdwardsY {
    #[inline]
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
    #[inline]
    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(CompressedEdwardsY(
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(bytes),
        ))
    }
}

serialize_deserialize!(CompressedRistretto);
serialize_deserialize!(CompressedEdwardsY);
serialize_deserialize!(RistrettoScalar);
serialize_deserialize!(JubjubScalar);
serialize_deserialize!(BLSScalar);

macro_rules! to_from_bytes_group {
    ($g:ident) => {
        impl ZeiFromToBytes for $g {
            fn zei_to_bytes(&self) -> Vec<u8> {
                self.to_compressed_bytes()
            }
            fn zei_from_bytes(bytes: &[u8]) -> Result<$g> {
                $g::from_compressed_bytes(bytes)
                    .map_err(|_| eg!(crate::errors::ZeiError::SerializationError))
            }
        }
    };
}

to_from_bytes_group!(RistrettoPoint);
to_from_bytes_group!(JubjubPoint);
to_from_bytes_group!(BLSG1);
to_from_bytes_group!(BLSG2);
to_from_bytes_group!(BLSGt);

serialize_deserialize!(RistrettoPoint);
serialize_deserialize!(JubjubPoint);
serialize_deserialize!(BLSG1);
serialize_deserialize!(BLSG2);
serialize_deserialize!(BLSGt);

/// Helper trait to serialize zei and foreign objects that implement from/to bytes/bits
pub trait ZeiFromToBytes: Sized {
    /// convert to bytes
    fn zei_to_bytes(&self) -> Vec<u8>;
    /// reconstruct from bytes
    fn zei_from_bytes(bytes: &[u8]) -> Result<Self>;
}

impl ZeiFromToBytes for RangeProof {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<RangeProof> {
        RangeProof::from_bytes(bytes).map_err(|_| eg!(ZeiError::DeserializationError))
    }
}

impl ZeiFromToBytes for R1CSProof {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<R1CSProof> {
        R1CSProof::from_bytes(bytes).map_err(|_| eg!(ZeiError::DeserializationError))
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

/// Module for serialization for Zei objects
pub mod zei_obj_serde {
    use crate::serialization::ZeiFromToBytes;
    use crate::utils::{b64dec, b64enc};
    use serde::de::SeqAccess;
    use serde::de::Visitor;
    use serde::Deserializer;
    use serde::Serializer;

    /// reader for serialized data
    pub struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("a valid ZeiFromTo Object")
        }

        fn visit_seq<V>(self, mut seq: V) -> Result<Vec<u8>, V::Error>
        where
            V: SeqAccess<'de>,
        {
            let mut vec: Vec<u8> = vec![];
            while let Some(x) = seq.next_element().map_err(serde::de::Error::custom)? {
                vec.push(x);
            }
            Ok(vec)
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Vec<u8>, E> {
            let mut vec: Vec<u8> = vec![];
            vec.extend_from_slice(v);
            Ok(vec)
        }

        fn visit_str<E>(self, v: &str) -> Result<Vec<u8>, E>
        where
            E: serde::de::Error,
        {
            b64dec(v).map_err(serde::de::Error::custom)
        }
    }

    /// serialize the data
    pub fn serialize<S, T>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
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

    /// deserialize the data
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
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
