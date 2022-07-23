use crate::primitives::asymmetric_encryption::dh_keypair;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zei_algebra::secp256k1::{SECP256K1Scalar, SECP256K1G1, SECP256K1_SCALAR_LEN};
use zei_algebra::{bls12_381::BLSScalar, prelude::*};

/// The length of the secret key for anonymous transfer.
pub const AXFR_SECRET_KEY_LENGTH: usize = SECP256K1_SCALAR_LEN;
/// The length of the public key for anonymous transfer.
pub const AXFR_PUBLIC_KEY_LENGTH: usize = SECP256K1G1::COMPRESSED_LEN;

/// The spending key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
pub struct AXfrSecretKey(pub(crate) SECP256K1Scalar);

/// The public key.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
pub struct AXfrPubKey(pub(crate) SECP256K1G1);

impl ZeiFromToBytes for AXfrPubKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.to_compressed_bytes()
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<AXfrPubKey> {
        if bytes.len() != AXFR_PUBLIC_KEY_LENGTH {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let group_element = SECP256K1G1::from_compressed_bytes(bytes);
            match group_element {
                Ok(g) => Ok(AXfrPubKey(g)),
                _ => Err(eg!(ZeiError::ParameterError)),
            }
        }
    }
}

/// Keypair associated with an Anonymous records. It is used to spending it.
#[wasm_bindgen]
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone)]
/// The key pair for anonymous payment.
pub struct AXfrKeyPair {
    /// The random seed that generates the secret key.
    pub(crate) secret_key: AXfrSecretKey,
    /// The public key of Schnorr signature.
    pub(crate) pub_key: AXfrPubKey,
}

impl AXfrKeyPair {
    /// Generate a Schnorr keypair from `prng`.
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let spend_key = AXfrSecretKey(SECP256K1Scalar::random(prng));
        Self::from_secret_key(spend_key)
    }

    /// Return the public key
    pub fn get_public_key(&self) -> AXfrPubKey {
        self.pub_key.clone()
    }

    /// Return the spend key
    pub fn get_secret_key(&self) -> AXfrSecretKey {
        self.secret_key.clone()
    }

    /// Return the key pair from the spending key.
    pub fn from_secret_key(secret_key: AXfrSecretKey) -> Self {
        let (dh_sk, dh_pk) = dh_keypair(secret_key.0);

        Self {
            secret_key: AXfrSecretKey(dh_sk),
            pub_key: AXfrPubKey(dh_pk),
        }
    }
}

impl AXfrSecretKey {
    /// Return the BLS12-381 scalar representation of the secret key.
    pub fn get_secret_key_scalars(&self) -> Result<[BLSScalar; 2]> {
        let bytes = self.0.to_bytes();

        let first = BLSScalar::from_bytes(&bytes[0..31])?;
        let second = BLSScalar::from_bytes(&bytes[31..])?;

        Ok([first, second])
    }
}

impl AXfrPubKey {
    /// Return the BLS12-381 scalar representation of the public key.
    pub fn get_public_key_scalars(&self) -> Result<[BLSScalar; 3]> {
        let bytes = self
            .0
            .get_x()
            .to_bytes()
            .iter()
            .chain(self.0.get_y().to_bytes().iter())
            .copied()
            .collect::<Vec<u8>>();

        let first = BLSScalar::from_bytes(&bytes[0..31])?;
        let second = BLSScalar::from_bytes(&bytes[31..62])?;
        let third = BLSScalar::from_bytes(&bytes[62..])?;

        Ok([first, second, third])
    }
}

impl ZeiFromToBytes for AXfrKeyPair {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend_from_slice(self.get_secret_key().0.zei_to_bytes().as_slice());
        vec.extend_from_slice(self.pub_key.zei_to_bytes().as_slice());
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECP256K1Scalar::bytes_len() + SECP256K1G1::COMPRESSED_LEN {
            return Err(eg!(ZeiError::DeserializationError));
        }

        let secret_key = AXfrSecretKey(
            SECP256K1Scalar::from_bytes(&bytes[0..SECP256K1Scalar::bytes_len()]).c(d!())?,
        );

        let offset = SECP256K1Scalar::bytes_len();
        let pub_key = AXfrPubKey::zei_from_bytes(&bytes[offset..]).c(d!())?;

        Ok(AXfrKeyPair {
            secret_key,
            pub_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::keys::{AXfrKeyPair, AXfrPubKey};
    use zei_algebra::prelude::*;
    use zei_algebra::secp256k1::SECP256K1G1;

    fn check_from_to_bytes<G: Group>() {
        let seed = [0_u8; 32];
        let mut prng = rand_chacha::ChaChaRng::from_seed(seed);
        let key_pair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);

        let public_key = key_pair.get_public_key();

        // Public key
        let public_key_bytes = public_key.zei_to_bytes();
        let public_key_from_bytes = AXfrPubKey::zei_from_bytes(&public_key_bytes).unwrap();
        assert_eq!(public_key, public_key_from_bytes);
    }

    #[test]
    pub(crate) fn ecdsa_from_to_bytes() {
        check_from_to_bytes::<SECP256K1G1>();
    }
}
