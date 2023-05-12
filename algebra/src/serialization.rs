use crate::{
    bls12_381::{BLSFq, BLSGt, BLSScalar, BLSG1, BLSG2},
    ed25519::{Ed25519Point, Ed25519Scalar},
    jubjub::{JubjubPoint, JubjubScalar},
    prelude::*,
    ristretto::{CompressedEdwardsY, CompressedRistretto, RistrettoPoint, RistrettoScalar},
    secp256k1::{SECP256K1Scalar, SECP256K1G1},
    secq256k1::SECQ256K1Proof,
    secq256k1::{SECQ256K1Scalar, SECQ256K1G1},
    zorro::{ZorroFq, ZorroG1, ZorroProof, ZorroScalar},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{io::Cursor, vec, vec::Vec};
use bulletproofs::RangeProof;
use serde::Serializer;

macro_rules! to_from_bytes_scalar {
    ($t:ident) => {
        impl NoahFromToBytes for $t {
            fn noah_to_bytes(&self) -> Vec<u8> {
                let mut v = vec![];
                v.extend_from_slice(&self.to_bytes()[..]);
                v
            }
            fn noah_from_bytes(bytes: &[u8]) -> Result<$t> {
                $t::from_bytes(bytes).map_err(|_| crate::errors::AlgebraError::DeserializationError)
            }
        }
    };
}

to_from_bytes_scalar!(BLSScalar);
to_from_bytes_scalar!(BLSFq);
to_from_bytes_scalar!(JubjubScalar);
to_from_bytes_scalar!(SECQ256K1Scalar);
to_from_bytes_scalar!(SECP256K1Scalar);
to_from_bytes_scalar!(ZorroScalar);
to_from_bytes_scalar!(ZorroFq);
to_from_bytes_scalar!(RistrettoScalar);
to_from_bytes_scalar!(Ed25519Scalar);

impl NoahFromToBytes for CompressedRistretto {
    #[inline]
    fn noah_to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
    #[inline]
    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            curve25519_dalek::ristretto::CompressedRistretto::from_slice(bytes),
        ))
    }
}

impl NoahFromToBytes for CompressedEdwardsY {
    #[inline]
    fn noah_to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
    #[inline]
    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(CompressedEdwardsY(
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(bytes),
        ))
    }
}

serialize_deserialize!(BLSScalar);
serialize_deserialize!(BLSFq);
serialize_deserialize!(JubjubScalar);
serialize_deserialize!(SECQ256K1Scalar);
serialize_deserialize!(SECP256K1Scalar);
serialize_deserialize!(ZorroScalar);
serialize_deserialize!(ZorroFq);
serialize_deserialize!(RistrettoScalar);
serialize_deserialize!(Ed25519Scalar);
serialize_deserialize!(CompressedRistretto);
serialize_deserialize!(CompressedEdwardsY);

macro_rules! to_from_bytes_group {
    ($g:ident) => {
        impl NoahFromToBytes for $g {
            fn noah_to_bytes(&self) -> Vec<u8> {
                self.to_compressed_bytes()
            }
            fn noah_from_bytes(bytes: &[u8]) -> Result<$g> {
                $g::from_compressed_bytes(bytes)
                    .map_err(|_| crate::errors::AlgebraError::DeserializationError)
            }
        }
    };
}

to_from_bytes_group!(BLSG1);
to_from_bytes_group!(BLSG2);
to_from_bytes_group!(BLSGt);
to_from_bytes_group!(JubjubPoint);
to_from_bytes_group!(SECQ256K1G1);
to_from_bytes_group!(SECP256K1G1);
to_from_bytes_group!(ZorroG1);
to_from_bytes_group!(RistrettoPoint);
to_from_bytes_group!(Ed25519Point);

serialize_deserialize!(BLSG1);
serialize_deserialize!(BLSG2);
serialize_deserialize!(BLSGt);
serialize_deserialize!(JubjubPoint);
serialize_deserialize!(SECQ256K1G1);
serialize_deserialize!(SECP256K1G1);
serialize_deserialize!(ZorroG1);
serialize_deserialize!(RistrettoPoint);
serialize_deserialize!(Ed25519Point);

/// Helper trait to serialize Noah's and foreign objects that implement from/to bytes/bits
pub trait NoahFromToBytes: Sized {
    /// convert to bytes
    fn noah_to_bytes(&self) -> Vec<u8>;
    /// reconstruct from bytes
    fn noah_from_bytes(bytes: &[u8]) -> Result<Self>;
}

impl NoahFromToBytes for RangeProof {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn noah_from_bytes(bytes: &[u8]) -> Result<RangeProof> {
        RangeProof::from_bytes(bytes).map_err(|_| AlgebraError::DeserializationError)
    }
}

impl NoahFromToBytes for bulletproofs::r1cs::R1CSProof {
    fn noah_to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
    fn noah_from_bytes(bytes: &[u8]) -> Result<bulletproofs::r1cs::R1CSProof> {
        bulletproofs::r1cs::R1CSProof::from_bytes(bytes)
            .map_err(|_| AlgebraError::DeserializationError)
    }
}

impl NoahFromToBytes for SECQ256K1Proof {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        self.serialize_with_mode(&mut cursor, Compress::Yes)
            .unwrap();
        cursor.into_inner()
    }
    fn noah_from_bytes(bytes: &[u8]) -> Result<SECQ256K1Proof> {
        ark_bulletproofs::r1cs::R1CSProof::deserialize_with_mode(
            bytes,
            Compress::Yes,
            Validate::Yes,
        )
        .map_err(|_| AlgebraError::DeserializationError)
    }
}

impl NoahFromToBytes for ZorroProof {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        self.serialize_with_mode(&mut cursor, Compress::Yes)
            .unwrap();
        cursor.into_inner()
    }
    fn noah_from_bytes(bytes: &[u8]) -> Result<ZorroProof> {
        ark_bulletproofs::r1cs::R1CSProof::deserialize_with_mode(
            bytes,
            Compress::Yes,
            Validate::Yes,
        )
        .map_err(|_| AlgebraError::DeserializationError)
    }
}

impl NoahFromToBytes for x25519_dalek::PublicKey {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(self.as_bytes());
        v
    }
    fn noah_from_bytes(bytes: &[u8]) -> Result<x25519_dalek::PublicKey> {
        if bytes.len() < 32 {
            return Err(AlgebraError::SerializationError);
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[0..32]);
        Ok(x25519_dalek::PublicKey::from(array))
    }
}

impl NoahFromToBytes for x25519_dalek::StaticSecret {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn noah_from_bytes(bytes: &[u8]) -> Result<x25519_dalek::StaticSecret> {
        if bytes.len() < 32 {
            return Err(AlgebraError::SerializationError);
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[0..32]);
        Ok(x25519_dalek::StaticSecret::from(array))
    }
}

/// Module for serialization for Noah objects
pub mod noah_obj_serde {
    use crate::serialization::NoahFromToBytes;
    use crate::utils::{b64dec, b64enc};
    use ark_std::{vec, vec::Vec};
    use serde::de::SeqAccess;
    use serde::de::Visitor;
    use serde::Deserializer;
    use serde::Serializer;

    /// Reader for serialized data
    pub struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("a valid NoahFromTo Object")
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

    /// Serialize the data
    pub fn serialize<S, T>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: NoahFromToBytes,
    {
        let bytes = obj.noah_to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&b64enc(&bytes))
        } else {
            serializer.serialize_bytes(&bytes[..])
        }
    }

    /// Deserialize the data
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: NoahFromToBytes,
    {
        if deserializer.is_human_readable() {
            let bytes = deserializer.deserialize_str(BytesVisitor)?;
            T::noah_from_bytes(bytes.as_slice()).map_err(serde::de::Error::custom)
        } else {
            let v = deserializer.deserialize_bytes(BytesVisitor)?;
            T::noah_from_bytes(v.as_slice()).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn check_compressed_len<T: Group + NoahFromToBytes>() {
        let mut prng = test_rng();
        let point = T::random(&mut prng);
        assert_eq!(point.to_compressed_bytes().len(), T::COMPRESSED_LEN);
        assert_eq!(point.to_unchecked_bytes().len(), T::UNCOMPRESSED_LEN);
        assert_eq!(point.noah_to_bytes().len(), T::COMPRESSED_LEN);
    }

    #[test]
    fn test_compressed_len() {
        check_compressed_len::<BLSG1>();
        check_compressed_len::<BLSG2>();
        check_compressed_len::<BLSGt>();
        check_compressed_len::<JubjubPoint>();
        check_compressed_len::<SECQ256K1G1>();
        check_compressed_len::<SECP256K1G1>();
        check_compressed_len::<ZorroG1>();
        check_compressed_len::<RistrettoPoint>();
        check_compressed_len::<Ed25519Point>();
    }
}
