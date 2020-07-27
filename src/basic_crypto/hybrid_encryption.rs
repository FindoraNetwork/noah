use crate::errors::ZeiError;
use crate::serialization;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;

#[derive(Debug, Clone)]
pub struct XPublicKey {
  pub(crate) key: x25519_dalek::PublicKey,
}

impl PartialEq for XPublicKey {
  fn eq(&self, other: &Self) -> bool {
    self.key.as_bytes() == other.key.as_bytes()
  }
}

impl Eq for XPublicKey {}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct ZeiHybridCipher {
  pub(crate) ciphertext: Vec<u8>,
  //pub(crate) nonce: Nonce,
  #[serde(with = "serialization::zei_obj_serde")]
  pub(crate) ephemeral_public_key: XPublicKey,
}

/// I encrypt a message a under public key. I implement hybrid encryption where a symmetric public
/// is derived from the public key, and the message is encrypted under this symmetric key.
/// I return ZeiError::DecompressElementError if public key is not well formed.
pub fn hybrid_encrypt_with_sign_key<R: CryptoRng + RngCore>(
  prng: &mut R,
  pub_key: &PublicKey,
  message: &[u8])
  -> Result<ZeiHybridCipher, ZeiError> {
  let (key, ephemeral_key) = symmetric_key_from_ed25519_public_key(prng, pub_key)?;
  //let (ciphertext, nonce) = symmetric_encrypt(&key, message);
  let ciphertext = symmetric_encrypt_fresh_key(&key, message);

  Ok(ZeiHybridCipher { ciphertext,
                       //nonce,
                       ephemeral_public_key: XPublicKey { key: ephemeral_key } })
}

/// I decrypt a hybrid ciphertext for a secret key.
/// In case of success, I return vector of plain text bytes. Otherwise, I return either
/// ZeiError::DecompressElementError or Zei::DecryptionError
pub fn hybrid_decrypt(ctext: &ZeiHybridCipher, sec_key: &SecretKey) -> Result<Vec<u8>, ZeiError> {
  let key = symmetric_key_from_secret_key(sec_key, &ctext.ephemeral_public_key.key)?;
  Ok(symmetric_decrypt_fresh_key(&key, ctext.ciphertext.as_slice()))
}

fn shared_key_to_32_bytes(shared_key: &x25519_dalek::SharedSecret) -> [u8; 32] {
  let mut hasher = sha2::Sha256::new();
  hasher.input(shared_key.as_bytes());
  let hash = hasher.result();
  let mut symmetric_key = [0u8; 32];
  symmetric_key.copy_from_slice(hash.as_slice());
  symmetric_key
}

/// I derive a 32 bytes symmetric key from a x25519 public key. I return the byte array together
/// with encoded randomness in the public key group.
fn symmetric_key_from_x25519_public_key<R: CryptoRng + RngCore>(
  prng: &mut R,
  public_key: &x25519_dalek::PublicKey)
  -> ([u8; 32], x25519_dalek::PublicKey) {
  // simulate a DH key exchange
  let ephemeral = x25519_dalek::EphemeralSecret::new(prng);
  let dh_pk = x25519_dalek::PublicKey::from(&ephemeral);

  let shared = ephemeral.diffie_hellman(&public_key);

  let symmetric_key = shared_key_to_32_bytes(&shared);
  (symmetric_key, dh_pk)
}

/// I derive a 32 bytes symmetric key from a ed25519 public key. I return the byte array together
/// with the ephemeral x25519 public key. In case public key cannot be decoded into a
/// valid group element, I return ZeiError::DecompressElementError.
fn symmetric_key_from_ed25519_public_key<R>(
  prng: &mut R,
  public_key: &PublicKey)
  -> Result<([u8; 32], x25519_dalek::PublicKey), ZeiError>
  where R: CryptoRng + RngCore
{
  // transform ed25519 public key into a x25519 public key
  let pk_curve_point = CompressedEdwardsY::from_slice(public_key.as_bytes());
  let pk_montgomery = pk_curve_point.decompress().unwrap().to_montgomery();
  let x_public_key = x25519_dalek::PublicKey::from(pk_montgomery.to_bytes());

  Ok(symmetric_key_from_x25519_public_key(prng, &x_public_key))
}

fn sec_key_as_scalar(sk: &SecretKey) -> Scalar {
  let expanded: ExpandedSecretKey = sk.into();
  //expanded.key is not public, I need to extract it via serialization
  let mut key_bytes = [0u8; 32];
  key_bytes.copy_from_slice(&expanded.to_bytes()[0..32]); //1st 32 bytes are key
  Scalar::from_bits(key_bytes)
}

/// I derive a 32 bytes symmetric key from a secret key and encoded randomness in the public key
/// I return the byte array. In case encoded randomness cannot be decoded into a valid group
/// element, I return ZeiError::DecompressElementError.
fn symmetric_key_from_secret_key(sec_key: &SecretKey,
                                 ephemeral_public_key: &x25519_dalek::PublicKey)
                                 -> Result<[u8; 32], ZeiError> {
  let scalar_sec_key = sec_key_as_scalar(sec_key);
  let x_secret = x25519_dalek::StaticSecret::from(scalar_sec_key.to_bytes());
  let shared_key = x_secret.diffie_hellman(ephemeral_public_key);

  let symmetric_key = shared_key_to_32_bytes(&shared_key);
  Ok(symmetric_key)
}

use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes256Ctr;
use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey};

fn symmetric_encrypt_fresh_key(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
  let kkey = GenericArray::from_slice(key);
  let ctr = GenericArray::from_slice(&[0u8; 16]);
  let mut ctext_vec = plaintext.to_vec();
  let mut cipher = Aes256Ctr::new(&kkey, ctr);
  cipher.apply_keystream(ctext_vec.as_mut_slice());
  ctext_vec
}

fn symmetric_decrypt_fresh_key(key: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
  let kkey = GenericArray::from_slice(key);
  let ctr = GenericArray::from_slice(&[0u8; 16]);
  let mut plaintext_vec = ciphertext.to_vec();
  let mut cipher = Aes256Ctr::new(&kkey, ctr);
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
      symmetric_key_from_ed25519_public_key(&mut prng, &keypair.public).unwrap();
    let from_sk_key = symmetric_key_from_secret_key(&keypair.secret, &encoded_rand).unwrap();
    assert_eq!(from_pk_key, from_sk_key);
  }

  #[test]
  fn symmetric_encryption_fresh_key() {
    let msg = b"this is a message";
    let key: [u8; 32] = [0u8; 32];
    let mut ciphertext = symmetric_encrypt_fresh_key(&key, msg);
    let decrypted = symmetric_decrypt_fresh_key(&key, ciphertext.as_slice());
    assert_eq!(msg, decrypted.as_slice());

    ciphertext[0] = 0xFF - ciphertext[0];
    let result = symmetric_decrypt_fresh_key(&key, ciphertext.as_slice());
    assert!(msg != result.as_slice());
  }

  #[test]
  fn zei_hybrid_cipher() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let key_pair = Keypair::generate(&mut prng);
    let msg = b"this is another message";

    let cipherbox = hybrid_encrypt_with_sign_key(&mut prng, &key_pair.public, msg).unwrap();
    let plaintext = hybrid_decrypt(&cipherbox, &key_pair.secret).unwrap();
    assert_eq!(msg, plaintext.as_slice());
  }
}
