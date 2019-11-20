use crate::errors::ZeiError;
use crate::serialization;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use rand::CryptoRng;
use rand::Rng;
use sha2::Digest;

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct ZeiHybridCipher {
  pub(crate) ciphertext: Vec<u8>,
  //pub(crate) nonce: Nonce,
  #[serde(with = "serialization::zei_obj_serde")]
  pub(crate) encoded_rand: CompressedEdwardsY,
}

/// I encrypt a message a under public key. I implement hybrid encryption where a symmetric public
/// is derived from the public key, and the message is encrypted under this symmetric key.
/// I return ZeiError::DecompressElementError if public key is not well formed.
pub fn hybrid_encrypt<R: CryptoRng + Rng>(prng: &mut R,
                                          pub_key: &PublicKey,
                                          message: &[u8])
                                          -> Result<ZeiHybridCipher, ZeiError> {
  let (key, encoded_rand) = symmetric_key_from_public_key(prng, pub_key)?;
  //let (ciphertext, nonce) = symmetric_encrypt(&key, message);
  let ciphertext = symmetric_encrypt_fresh_key(&key, message);

  Ok(ZeiHybridCipher { ciphertext,
                       //nonce,
                       encoded_rand })
}

/// I decrypt a hybrid ciphertext for a secret key.
/// In case of success, I return vector of plain text bytes. Otherwise, I return either
/// ZeiError::DecompressElementError or Zei::DecryptionError
pub fn hybrid_decrypt(ctext: &ZeiHybridCipher, sec_key: &SecretKey) -> Result<Vec<u8>, ZeiError> {
  let key = symmetric_key_from_secret_key(sec_key, &ctext.encoded_rand)?;
  Ok(symmetric_decrypt_fresh_key(&key, ctext.ciphertext.as_slice()))
}

/// I derive a 32 bytes symmetric key from a public key. I return the byte array together
/// with encoded randomness in the public key group. In case public key cannot be decoded into a
/// valid group element, I return ZeiError::DecompressElementError.
fn symmetric_key_from_public_key<R>(prng: &mut R,
                                    public_key: &PublicKey)
                                    -> Result<([u8; 32], CompressedEdwardsY), ZeiError>
  where R: CryptoRng + Rng
{
  let rand = Scalar::random(prng);
  let encoded_rand = rand * KEY_BASE_POINT.decompress().unwrap(); // can always be decompressed
  let pk_curve_point = CompressedEdwardsY::from_slice(public_key.as_bytes());
  let curve_key = rand * pk_curve_point.decompress().unwrap();
  let mut hasher = sha2::Sha256::new();
  hasher.input(curve_key.compress().as_bytes());
  let hash = hasher.result();
  let mut symmetric_key = [0u8; 32];
  symmetric_key.copy_from_slice(hash.as_slice());
  Ok((symmetric_key, encoded_rand.compress()))
}

fn sec_key_as_scalar(sk: &SecretKey) -> Scalar {
  let expanded = sk.expand::<sha2::Sha512>();
  //expanded.key is not public, I need to extract it via serialization
  let mut key_bytes = [0u8; 32];
  key_bytes.copy_from_slice(&expanded.to_bytes()[0..32]); //1st 32 bytes are key
  Scalar::from_bits(key_bytes)
}

/// I derive a 32 bytes symmetric key from a secret key and encoded randomness in the public key
/// I return the byte array. In case encoded randomness cannot be decoded into a valid group
/// element, I return ZeiError::DecompressElementError.
fn symmetric_key_from_secret_key(sec_key: &SecretKey,
                                 rand: &CompressedEdwardsY)
                                 -> Result<[u8; 32], ZeiError> {
  //let curve_key = secret_key * rand.decompress()?;
  let decoded_rand = match rand.decompress() {
    Some(x) => x,
    None => return Err(ZeiError::DecompressElementError),
  };
  let aux = sec_key_as_scalar(sec_key);
  let curve_key = decoded_rand * aux;
  //let curve_key = sec_key.as_scalar_multiply_by_curve_point(&decoded_rand);
  let mut hasher = sha2::Sha256::new();
  hasher.input(curve_key.compress().as_bytes());
  let mut symmetric_key = [0u8; 32];
  let hash = hasher.result();
  symmetric_key.copy_from_slice(hash.as_slice());
  Ok(symmetric_key)
}

use crate::xfr::sig::KEY_BASE_POINT;
use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes256Ctr;
use ed25519_dalek::{PublicKey, SecretKey};

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
  use rand::SeedableRng;
  use rand_chacha::ChaChaRng;

  #[test]
  fn key_derivation() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let keypair = Keypair::generate::<sha2::Sha512, _>(&mut prng);
    let (from_pk_key, encoded_rand) =
      symmetric_key_from_public_key(&mut prng, &keypair.public).unwrap();
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
    let key_pair = Keypair::generate::<sha2::Sha512, _>(&mut prng);
    let msg = b"this is another message";

    let cipherbox = hybrid_encrypt(&mut prng, &key_pair.public, msg).unwrap();
    let plaintext = hybrid_decrypt(&cipherbox, &key_pair.secret).unwrap();
    assert_eq!(msg, plaintext.as_slice());
  }
}
