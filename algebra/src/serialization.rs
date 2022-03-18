use crate::{
    bls12_381::{BLSGt, BLSScalar, BLSG1, BLSG2},
    groups::{Group, Scalar},
    jubjub::{JubjubPoint, JubjubScalar},
    ristretto::{
        CompressedEdwardsY, CompressedRistretto, RistrettoPoint, RistrettoScalar,
    },
};
use ruc::*;
use serde::Serializer;
use utils::serialization::ZeiFromToBytes;

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
                    .map_err(|_| eg!(utils::errors::ZeiError::DeserializationError))
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
                    .map_err(|_| eg!(utils::errors::ZeiError::SerializationError))
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
