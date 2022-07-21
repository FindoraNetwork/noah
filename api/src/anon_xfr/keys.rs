use crate::primitives::asymmetric_encryption::dh_keypair;
use digest::Digest;
use merlin::Transcript;
use num_bigint::BigUint;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha512;
use wasm_bindgen::prelude::*;
use zei_algebra::bs257::{BS257Scalar, BS257G1};
use zei_algebra::secp256k1::{SECP256K1Scalar, SECP256K1G1, SECP256K1_SCALAR_LEN};
use zei_algebra::{bls12_381::BLSScalar, cmp::min, prelude::*};
use zei_crypto::basic::rescue::RescueInstance;

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

/// The complete signature, which will not be revealed to the outside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
pub struct AXfrSignature {
    pub scalar_r: SECP256K1Scalar,
    pub scalar_s: SECP256K1Scalar,
    pub recovery: u8,
}

/// The public input part of the signature.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
pub struct AXfrSignatureInstance {
    pub scalar_r: SECP256K1Scalar,
    pub recovery: u8,
}

/// The witness part of the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
pub struct AXfrSignatureWitness {
    pub pub_key: AXfrPubKey,
    pub scalar_r: SECP256K1Scalar,
    pub scalar_s: SECP256K1Scalar,
    pub recovery: u8,
}

impl AXfrSignature {
    pub fn to_instance_and_witness(
        &self,
        pub_key: &AXfrPubKey,
    ) -> Result<(AXfrSignatureInstance, AXfrSignatureWitness)> {
        let instance = AXfrSignatureInstance {
            scalar_r: self.scalar_r,
            recovery: self.recovery,
        };

        let witness = AXfrSignatureWitness {
            pub_key: pub_key.clone(),
            scalar_r: self.scalar_r,
            scalar_s: self.scalar_s,
            recovery: self.recovery,
        };

        Ok((instance, witness))
    }
}

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
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
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

    /// Generate an ECDSA signature.
    pub fn sign<R: CryptoRng + RngCore, D: Digest<OutputSize = U64> + Default>(
        &self,
        prng: &mut R,
        digest: D,
    ) -> Result<AXfrSignature> {
        let k = SECP256K1Scalar::random(prng);
        let point_r = SECP256K1G1::get_base().mul(&k);

        let r_raw = point_r.get_x();
        let r_biguint: BigUint = r_raw.into();
        let n_biguint = SECP256K1Scalar::get_field_size_biguint();
        let r_mod_n_biguint = r_biguint % n_biguint;
        let r = SECP256K1Scalar::from(&r_mod_n_biguint);

        let mut z_bytes = [0u8; 32];
        z_bytes.copy_from_slice(&digest.finalize().as_slice());

        let z_biguint = BigUint::from_bytes_le(&z_bytes);
        let z = SECP256K1Scalar::from(&z_biguint);

        let mut s = (z + r * self.0) * k.inv()?;

        let mut recovery: u8 = if r_biguint.eq(&r_mod_n_biguint) { 0 } else { 2 };

        let y_raw = point_r.get_y();
        let y_biguint: BigUint = y_raw.into();
        let lsb_biguint = y_biguint.bitand(BigUint::one());

        if lsb_biguint == BigUint::one() {
            recovery += 1;
        }

        Ok(AXfrSignature {
            scalar_r: r,
            scalar_s: s,
            recovery,
        })
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
            .collect::<Vec<u8>>();

        let first = BLSScalar::from_bytes(&bytes[0..31])?;
        let second = BLSScalar::from_bytes(&bytes[31..62])?;
        let third = BLSScalar::from_bytes(&bytes[62..])?;

        Ok([first, second, third])
    }

    /// Verify an ECDSA signature.
    /// This should not be used: the ECDSA signature leaks the public key,
    /// and therefore a different method is needed to verify those signatures.
    pub fn verify<D: Digest<OutputSize = U64> + Default>(
        &self,
        sig: &AXfrSignature,
        digest: D,
    ) -> Result<()> {
        /// Important: must reject signatures with zeros.
        if sig.scalar_r.is_zero() || sig.scalar_s.is_zero() {
            return Err(eg!(ZeiError::SignatureError));
        }

        let mut z_bytes = [0u8; 32];
        z_bytes.copy_from_slice(&digest.finalize().as_slice());

        let z_biguint = BigUint::from_bytes_le(&z_bytes);
        let z = SECP256K1Scalar::from(&z_biguint);

        let u_1 = z * sig.scalar_s.inv()?;
        let u_2 = sig.scalar_r * sig.scalar_s.inv()?;

        let point_r = SECP256K1G1::get_base().mul(&u_1) + &self.0.mul(&u_2);

        let r_raw = point_r.get_x();
        let r_biguint: BigUint = r_raw.into();
        let n_biguint = SECP256K1Scalar::get_field_size_biguint();
        let r_mod_n_biguint = r_biguint % n_biguint;
        let r = SECP256K1Scalar::from(&r_mod_n_biguint);

        if r != sig.scalar_r {
            return Err(eg!(ZeiError::SignatureError));
        }
        Ok(())
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

        let mut offset = SECP256K1Scalar::bytes_len();
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
    use sha2::Sha512;
    use std::ptr::hash;
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

    #[test]
    pub(crate) fn ecdsa_test() {
        let seed = [0_u8; 32];
        let mut prng = rand_chacha::ChaChaRng::from_seed(seed);
        let key_pair = AXfrKeyPair::generate(&mut prng);

        let public_key = key_pair.get_public_key();

        let mut hasher = Sha512::new();
        let mut random_bytes = [0u8; 32];
        prng.fill_bytes(&mut random_bytes);
        hasher.update(&random_bytes);

        let secret_key = key_pair.get_secret_key();

        let sig = secret_key.sign(&mut prng, hasher).unwrap();
        public_key.verify(&sig, hasher).unwrap();
    }
}
