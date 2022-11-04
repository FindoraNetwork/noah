use aes_gcm::{aead::Aead, KeyInit};
use core::hash::{Hash, Hasher};
use digest::{generic_array::GenericArray, Digest};
use ed25519_dalek::{PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey};
use noah_algebra::{
    bls12_381::BLSScalar,
    cmp::Ordering,
    prelude::*,
    secp256k1::{SECP256K1Scalar, SECP256K1G1},
};
use noah_crypto::basic::hybrid_encryption::{
    hybrid_decrypt_with_ed25519_secret_key, hybrid_encrypt_ed25519, NoahHybridCiphertext,
};
use wasm_bindgen::prelude::*;

/// The length of the secret key for anonymous transfer.
pub const AXFR_SECRET_KEY_LENGTH: usize = 33; // keytype + Bytes
/// The length of the public key for anonymous transfer.
pub const AXFR_PUBLIC_KEY_LENGTH: usize = 33; // keytype (+positive) + Bytes

/// The spending key.
#[derive(Debug)]
pub enum AXfrSecretKey {
    Ed25519(Ed25519SecretKey),
    Secp256k1(SECP256K1Scalar),
}

impl Clone for AXfrSecretKey {
    fn clone(&self) -> Self {
        Self::noah_from_bytes(&self.noah_to_bytes()).unwrap()
    }
}

impl Eq for AXfrSecretKey {}

impl PartialEq for AXfrSecretKey {
    fn eq(&self, other: &AXfrSecretKey) -> bool {
        self.noah_to_bytes().eq(&other.noah_to_bytes())
    }
}

impl Ord for AXfrSecretKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.noah_to_bytes().cmp(&other.noah_to_bytes())
    }
}

impl PartialOrd for AXfrSecretKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Default for AXfrSecretKey {
    fn default() -> Self {
        AXfrSecretKey::Secp256k1(SECP256K1Scalar::default())
    }
}

impl Hash for AXfrSecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            AXfrSecretKey::Ed25519(sk) => {
                sk.as_bytes().hash(state);
            }
            AXfrSecretKey::Secp256k1(sk) => {
                sk.hash(state);
            }
        }
    }
}

impl NoahFromToBytes for AXfrSecretKey {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(AXFR_SECRET_KEY_LENGTH);
        match self {
            AXfrSecretKey::Ed25519(p) => {
                bytes[0] = 0;
                bytes.extend(p.as_bytes());
            }
            AXfrSecretKey::Secp256k1(p) => {
                bytes[0] = 1;
                bytes.append(&mut p.noah_to_bytes());
            }
        }
        bytes
    }

    fn noah_from_bytes(bytes: &[u8]) -> Result<AXfrSecretKey> {
        if bytes.len() != AXFR_SECRET_KEY_LENGTH {
            Err(eg!(NoahError::DeserializationError))
        } else {
            match bytes[0] {
                0 => match Ed25519SecretKey::from_bytes(&bytes[1..]) {
                    Ok(s) => Ok(AXfrSecretKey::Ed25519(s)),
                    _ => Err(eg!(NoahError::ParameterError)),
                },
                _ => match SECP256K1Scalar::noah_from_bytes(&bytes[1..]) {
                    Ok(s) => Ok(AXfrSecretKey::Secp256k1(s)),
                    _ => Err(eg!(NoahError::ParameterError)),
                },
            }
        }
    }
}

/// The public key.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct AXfrPubKey(pub(crate) AXfrPubKeyInner);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AXfrPubKeyInner {
    Ed25519(Ed25519PublicKey),
    Secp256k1(SECP256K1G1),
}

impl Default for AXfrPubKeyInner {
    fn default() -> Self {
        AXfrPubKeyInner::Secp256k1(SECP256K1G1::default())
    }
}

impl Hash for AXfrPubKeyInner {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            AXfrPubKeyInner::Ed25519(pk) => {
                pk.as_bytes().hash(state);
            }
            AXfrPubKeyInner::Secp256k1(pk) => {
                pk.hash(state);
            }
        }
    }
}

impl NoahFromToBytes for AXfrPubKey {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(AXFR_PUBLIC_KEY_LENGTH);
        match self.inner() {
            AXfrPubKeyInner::Ed25519(p) => {
                bytes[0] = u8::MAX;
                bytes.extend(p.as_bytes()); // 32
            }
            AXfrPubKeyInner::Secp256k1(p) => {
                bytes.extend(p.to_compressed_bytes()); // 33
            }
        }
        bytes
    }

    fn noah_from_bytes(bytes: &[u8]) -> Result<AXfrPubKey> {
        if bytes.len() != AXFR_PUBLIC_KEY_LENGTH {
            Err(eg!(NoahError::DeserializationError))
        } else {
            match bytes[0] {
                u8::MAX => match Ed25519PublicKey::from_bytes(&bytes[1..]) {
                    Ok(g) => Ok(AXfrPubKey(AXfrPubKeyInner::Ed25519(g))),
                    _ => Err(eg!(NoahError::ParameterError)),
                },
                _ => match SECP256K1G1::from_compressed_bytes(bytes) {
                    Ok(g) => Ok(AXfrPubKey(AXfrPubKeyInner::Secp256k1(g))),
                    _ => Err(eg!(NoahError::ParameterError)),
                },
            }
        }
    }
}

/// Keypair associated with an Anonymous records. It is used to spending it.
#[wasm_bindgen]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
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
        let spend_key = AXfrSecretKey::Secp256k1(SECP256K1Scalar::random(prng));
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
        let pk = match &secret_key {
            AXfrSecretKey::Secp256k1(sk) => {
                AXfrPubKeyInner::Secp256k1(SECP256K1G1::get_base().mul(sk))
            }
            AXfrSecretKey::Ed25519(sk) => AXfrPubKeyInner::Ed25519(sk.into()),
        };
        Self {
            secret_key,
            pub_key: AXfrPubKey(pk),
        }
    }
}

impl AXfrSecretKey {
    /// Return the BLS12-381 scalar representation of the secret key.
    pub fn get_secret_key_scalars(&self) -> Result<[BLSScalar; 2]> {
        let bytes = match self {
            AXfrSecretKey::Ed25519(sk) => sk.as_bytes().to_vec(),
            AXfrSecretKey::Secp256k1(sk) => sk.to_bytes(),
        };

        let first = BLSScalar::from_bytes(&bytes[0..31])?;
        let second = BLSScalar::from_bytes(&bytes[31..])?;

        Ok([first, second])
    }

    #[inline]
    /// Decrypt a ciphertext.
    pub fn decrypt(&self, ctext: &[u8]) -> Result<Vec<u8>> {
        if ctext.is_empty() {
            return Err(eg!(NoahError::DecryptionError));
        }
        match (ctext[0], self) {
            (0, AXfrSecretKey::Ed25519(sk)) => {
                let ctext = NoahHybridCiphertext::noah_from_bytes(&ctext[1..])?;
                Ok(hybrid_decrypt_with_ed25519_secret_key(&ctext, sk))
            }
            (1, AXfrSecretKey::Secp256k1(sk)) => {
                let share_len = SECP256K1G1::COMPRESSED_LEN + 1;
                if ctext.len() < share_len {
                    return Err(eg!(NoahError::DecryptionError));
                }
                let share = SECP256K1G1::from_compressed_bytes(&ctext[1..share_len])?;
                let dh = share.mul(sk);

                let mut hasher = sha2::Sha512::new();
                hasher.update(&dh.to_compressed_bytes());

                let mut key = [0u8; 32];
                key.copy_from_slice(&hasher.finalize().as_slice()[0..32]);

                let nonce = GenericArray::from_slice(&[0u8; 12]);

                let gcm = {
                    let res = aes_gcm::Aes256Gcm::new_from_slice(key.as_slice());

                    if res.is_err() {
                        return Err(eg!(NoahError::DecryptionError));
                    }

                    res.unwrap()
                };

                let res = {
                    let res = gcm.decrypt(nonce, &ctext[share_len..]);

                    if res.is_err() {
                        return Err(eg!(NoahError::DecryptionError));
                    }

                    res.unwrap()
                };
                Ok(res)
            }
            _ => Err(eg!(NoahError::DecryptionError)),
        }
    }
}

impl AXfrPubKey {
    /// Get the inner type.
    pub fn inner(&self) -> &AXfrPubKeyInner {
        &self.0
    }

    /// Return the BLS12-381 scalar representation of the public key.
    pub fn get_public_key_scalars(&self) -> Result<[BLSScalar; 3]> {
        let bytes = match self.inner() {
            AXfrPubKeyInner::Ed25519(pk) => pk.to_bytes().to_vec(),
            AXfrPubKeyInner::Secp256k1(pk) => pk
                .get_x()
                .to_bytes()
                .iter()
                .chain(pk.get_y().to_bytes().iter())
                .copied()
                .collect::<Vec<u8>>(),
        };

        let first = BLSScalar::from_bytes(&bytes[0..31])?;
        let second = BLSScalar::from_bytes(&bytes[31..62])?;
        let third = BLSScalar::from_bytes(&bytes[62..])?;

        Ok([first, second, third])
    }

    /// Encrypt the message
    pub fn encrypt<R: CryptoRng + RngCore>(&self, prng: &mut R, msg: &[u8]) -> Result<Vec<u8>> {
        let mut bytes = vec![];
        match self.inner() {
            AXfrPubKeyInner::Ed25519(pk) => {
                bytes.push(0);
                bytes.append(&mut hybrid_encrypt_ed25519(prng, &pk, msg).noah_to_bytes());
            }
            AXfrPubKeyInner::Secp256k1(pk) => {
                bytes.push(1);
                let share_scalar = SECP256K1Scalar::random(prng);
                let share = SECP256K1G1::get_base().mul(&share_scalar);
                bytes.append(&mut share.to_compressed_bytes());

                let dh = pk.mul(&share_scalar);

                let mut hasher = sha2::Sha512::new();
                hasher.update(&dh.to_compressed_bytes());

                let mut key = [0u8; 32];
                key.copy_from_slice(&hasher.finalize().as_slice()[0..32]);

                let nonce = GenericArray::from_slice(&[0u8; 12]);

                let gcm = {
                    let res = aes_gcm::Aes256Gcm::new_from_slice(key.as_slice());

                    if res.is_err() {
                        return Err(eg!(NoahError::EncryptionError));
                    }

                    res.unwrap()
                };

                let ctext = {
                    let res = gcm.encrypt(nonce, msg);

                    if res.is_err() {
                        return Err(eg!(NoahError::EncryptionError));
                    }

                    res.unwrap()
                };
                bytes.append(&mut ctext);
            }
        };

        Ok(bytes)
    }
}

impl NoahFromToBytes for AXfrKeyPair {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend_from_slice(self.get_secret_key().noah_to_bytes().as_slice());
        vec.extend_from_slice(self.pub_key.noah_to_bytes().as_slice());
        vec
    }

    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != AXFR_PUBLIC_KEY_LENGTH + AXFR_SECRET_KEY_LENGTH {
            return Err(eg!(NoahError::DeserializationError));
        }

        let secret_key = AXfrSecretKey::noah_from_bytes(&bytes[0..AXFR_SECRET_KEY_LENGTH])?;
        let pub_key = AXfrPubKey::noah_from_bytes(&bytes[AXFR_SECRET_KEY_LENGTH..])?;

        Ok(AXfrKeyPair {
            secret_key,
            pub_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::keys::{AXfrKeyPair, AXfrPubKey};
    use noah_algebra::{prelude::*, secp256k1::SECP256K1G1};

    fn check_from_to_bytes<G: Group>() {
        let mut prng = test_rng();
        let key_pair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);

        let public_key = key_pair.get_public_key();

        // Public key
        let public_key_bytes = public_key.noah_to_bytes();
        let public_key_from_bytes = AXfrPubKey::noah_from_bytes(&public_key_bytes).unwrap();
        assert_eq!(public_key, public_key_from_bytes);
    }

    #[test]
    pub(crate) fn ecdsa_from_to_bytes() {
        check_from_to_bytes::<SECP256K1G1>();
    }
}
