use aes::{
    cipher::{generic_array::GenericArray, NewCipher, StreamCipher},
    Aes256Ctr,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey};
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use serde::Serializer;
use sha2::Digest;
use wasm_bindgen::prelude::*;
use zei_algebra::errors::ZeiError;
use zei_algebra::prelude::*;
use zei_algebra::ristretto::RistrettoScalar as Scalar;
use zei_algebra::serialization::ZeiFromToBytes;
use zei_algebra::traits::Scalar as _;

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct XPublicKey {
    pub(crate) key: x25519_dalek::PublicKey,
}

impl ZeiFromToBytes for XPublicKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let mut array = [0u8; 32];
            array.copy_from_slice(bytes);
            Ok(XPublicKey {
                key: x25519_dalek::PublicKey::from(array),
            })
        }
    }
}

serialize_deserialize!(XPublicKey);

impl XPublicKey {
    pub fn from(sk: &XSecretKey) -> XPublicKey {
        XPublicKey {
            key: x25519_dalek::PublicKey::from(&sk.key),
        }
    }
}

impl PartialEq for XPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.key.as_bytes() == other.key.as_bytes()
    }
}

impl Eq for XPublicKey {}

#[wasm_bindgen]
#[derive(Clone)]
pub struct XSecretKey {
    pub(crate) key: x25519_dalek::StaticSecret,
}

impl ZeiFromToBytes for XSecretKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let mut array = [0u8; 32];
            array.copy_from_slice(bytes);
            Ok(XSecretKey {
                key: x25519_dalek::StaticSecret::from(array),
            })
        }
    }
}

serialize_deserialize!(XSecretKey);

impl XSecretKey {
    pub fn new<R: CryptoRng + RngCore>(prng: &mut R) -> XSecretKey {
        XSecretKey {
            key: x25519_dalek::StaticSecret::new(prng),
        }
    }
}

impl PartialEq for XSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.key.to_bytes() == other.key.to_bytes()
    }
}

impl Eq for XSecretKey {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ctext(pub Vec<u8>);
impl ZeiFromToBytes for Ctext {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Ctext(bytes.to_vec()))
    }
}
serialize_deserialize!(Ctext);

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct ZeiHybridCipher {
    pub(crate) ciphertext: Ctext,
    pub(crate) ephemeral_public_key: XPublicKey,
}

/// I encrypt a message under a X25519 DH public key. I implement hybrid encryption where a symmetric key
/// is derived from the public key, and the message is encrypted under this symmetric key.
pub fn hybrid_encrypt_with_x25519_key<R: CryptoRng + RngCore>(
    prng: &mut R,
    pub_key: &XPublicKey,
    message: &[u8],
) -> ZeiHybridCipher {
    let (key, ephemeral_key) = symmetric_key_from_x25519_public_key(prng, &pub_key.key);
    let ciphertext = symmetric_encrypt_fresh_key(&key, message);
    ZeiHybridCipher {
        ciphertext,
        ephemeral_public_key: XPublicKey { key: ephemeral_key },
    }
}

/// I encrypt a message under a Ed25519 signature public key. I implement hybrid encryption where a symmetric key
/// is derived from the public key, and the message is encrypted under this symmetric key.
/// I return ZeiError::DecompressElementError if public key is not well formed.
pub fn hybrid_encrypt_with_sign_key<R: CryptoRng + RngCore>(
    prng: &mut R,
    pub_key: &PublicKey,
    message: &[u8],
) -> ZeiHybridCipher {
    let (key, ephemeral_key) = symmetric_key_from_ed25519_public_key(prng, pub_key);
    let ciphertext = symmetric_encrypt_fresh_key(&key, message);

    ZeiHybridCipher {
        ciphertext,
        ephemeral_public_key: XPublicKey { key: ephemeral_key },
    }
}

/// I decrypt a hybrid ciphertext for a secret key.
/// In case of success, I return vector of plain text bytes. Otherwise, I return either
/// ZeiError::DecompressElementError or Zei::DecryptionError
pub fn hybrid_decrypt_with_x25519_secret_key(
    ctext: &ZeiHybridCipher,
    sec_key: &XSecretKey,
) -> Vec<u8> {
    let key = symmetric_key_from_x25519_secret_key(&sec_key.key, &ctext.ephemeral_public_key.key);
    symmetric_decrypt_fresh_key(&key, &ctext.ciphertext)
}

/// I decrypt a hybrid ciphertext for a secret key.
/// In case of success, I return vector of plain text bytes. Otherwise, I return either
/// ZeiError::DecompressElementError or Zei::DecryptionError
pub fn hybrid_decrypt_with_ed25519_secret_key(
    ctext: &ZeiHybridCipher,
    sec_key: &SecretKey,
) -> Vec<u8> {
    let key = symmetric_key_from_secret_key(sec_key, &ctext.ephemeral_public_key.key);
    symmetric_decrypt_fresh_key(&key, &ctext.ciphertext)
}

fn shared_key_to_32_bytes(shared_key: &x25519_dalek::SharedSecret) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(shared_key.as_bytes());
    let hash = hasher.finalize();
    let mut symmetric_key = [0u8; 32];
    symmetric_key.copy_from_slice(hash.as_slice());
    symmetric_key
}

/// I derive a 32 bytes symmetric key from a x25519 public key. I return the byte array together
/// with encoded randomness in the public key group.
fn symmetric_key_from_x25519_public_key<R: CryptoRng + RngCore>(
    prng: &mut R,
    public_key: &x25519_dalek::PublicKey,
) -> ([u8; 32], x25519_dalek::PublicKey) {
    // simulate a DH key exchange
    let ephemeral = x25519_dalek::EphemeralSecret::new(prng);
    let dh_pk = x25519_dalek::PublicKey::from(&ephemeral);

    let shared = ephemeral.diffie_hellman(public_key);

    let symmetric_key = shared_key_to_32_bytes(&shared);
    (symmetric_key, dh_pk)
}

/// I derive a 32 bytes symmetric key from a ed25519 public key. I return the byte array together
/// with the ephemeral x25519 public key. In case public key cannot be decoded into a
/// valid group element, I return ZeiError::DecompressElementError.
fn symmetric_key_from_ed25519_public_key<R>(
    prng: &mut R,
    public_key: &PublicKey,
) -> ([u8; 32], x25519_dalek::PublicKey)
where
    R: CryptoRng + RngCore,
{
    // transform ed25519 public key into a x25519 public key
    let pk_curve_point = CompressedEdwardsY::from_slice(public_key.as_bytes());
    let pk_montgomery = pk_curve_point.decompress().unwrap().to_montgomery();
    let x_public_key = x25519_dalek::PublicKey::from(pk_montgomery.to_bytes());

    symmetric_key_from_x25519_public_key(prng, &x_public_key)
}

fn sec_key_as_scalar(sk: &SecretKey) -> Scalar {
    let expanded: ExpandedSecretKey = sk.into();
    //expanded.key is not public, I need to extract it via serialization
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&expanded.to_bytes()[0..32]); //1st 32 bytes are key
    Scalar::from_bytes(&key_bytes).unwrap() // safe unwrap
}

fn symmetric_key_from_x25519_secret_key(
    sec_key: &x25519_dalek::StaticSecret,
    ephemeral_public_key: &x25519_dalek::PublicKey,
) -> [u8; 32] {
    let shared_key = sec_key.diffie_hellman(ephemeral_public_key);
    shared_key_to_32_bytes(&shared_key)
}

/// I derive a 32 bytes symmetric key from a secret key and encoded randomness in the public key
/// I return the byte array. In case encoded randomness cannot be decoded into a valid group
/// element, I return ZeiError::DecompressElementError.
fn symmetric_key_from_secret_key(
    sec_key: &SecretKey,
    ephemeral_public_key: &x25519_dalek::PublicKey,
) -> [u8; 32] {
    let scalar_sec_key = sec_key_as_scalar(sec_key);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(scalar_sec_key.to_bytes().as_slice());
    let x_secret = x25519_dalek::StaticSecret::from(bytes);
    symmetric_key_from_x25519_secret_key(&x_secret, ephemeral_public_key)
}

fn symmetric_encrypt_fresh_key(key: &[u8; 32], plaintext: &[u8]) -> Ctext {
    let kkey = GenericArray::from_slice(key);
    let ctr = GenericArray::from_slice(&[0u8; 16]); // counter can be zero because key is fresh
    let mut ctext_vec = plaintext.to_vec();
    let mut cipher = Aes256Ctr::new(kkey, ctr);
    cipher.apply_keystream(ctext_vec.as_mut_slice());
    Ctext(ctext_vec)
}

fn symmetric_decrypt_fresh_key(key: &[u8; 32], ciphertext: &Ctext) -> Vec<u8> {
    let kkey = GenericArray::from_slice(key);
    let ctr = GenericArray::from_slice(&[0u8; 16]);
    let mut plaintext_vec = ciphertext.0.clone();
    let mut cipher = Aes256Ctr::new(kkey, ctr);
    cipher.apply_keystream(plaintext_vec.as_mut_slice());
    plaintext_vec
}

#[cfg(test)]
mod test {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    #[test]
    fn key_derivation() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = Keypair::generate(&mut prng);
        let (from_pk_key, encoded_rand) =
            symmetric_key_from_ed25519_public_key(&mut prng, &keypair.public);
        let from_sk_key = symmetric_key_from_secret_key(&keypair.secret, &encoded_rand);
        assert_eq!(from_pk_key, from_sk_key);
    }

    #[test]
    fn symmetric_encryption_fresh_key() {
        let msg = b"this is a message";
        let key: [u8; 32] = [0u8; 32];
        let mut ciphertext = symmetric_encrypt_fresh_key(&key, msg);
        let decrypted = symmetric_decrypt_fresh_key(&key, &ciphertext);
        assert_eq!(msg, decrypted.as_slice());

        ciphertext.0[0] = 0xFF - ciphertext.0[0];
        let result = symmetric_decrypt_fresh_key(&key, &ciphertext);
        assert_ne!(msg, result.as_slice());
    }

    #[test]
    fn zei_hybrid_cipher() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let key_pair = Keypair::generate(&mut prng);
        let msg = b"this is another message";

        let cipherbox = hybrid_encrypt_with_sign_key(&mut prng, &key_pair.public, msg);
        let plaintext = hybrid_decrypt_with_ed25519_secret_key(&cipherbox, &key_pair.secret);
        assert_eq!(msg, plaintext.as_slice());
    }
}
