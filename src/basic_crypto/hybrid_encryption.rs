use sha2::Digest;
use crate::errors::ZeiError;
use crate::serialization;
use curve25519_dalek::scalar::Scalar;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::{Nonce,Key};
use rand::CryptoRng;
use rand::Rng;
use super::signatures::{XfrPublicKey, KEY_BASE_POINT, XfrSecretKey};
use curve25519_dalek::edwards::CompressedEdwardsY;


#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct ZeiHybridCipher {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) nonce: Nonce,
    #[serde(with = "serialization::zei_obj_serde")]
    pub(crate) encoded_rand: CompressedEdwardsY,
}

/// I encrypt a message under public key. I implement hybrid encryption where a symmetric public
/// is dereived from the public key, and the message is encrypted under a simmetric key.
/// I return ZeiError::DecompressElementError if public key is not well formed.
pub fn hybrid_encrypt<R: CryptoRng + Rng>(
    prng: &mut R,
    public_key: &XfrPublicKey,
    message: &[u8]) -> Result<ZeiHybridCipher, ZeiError>
{
    let (key, encoded_rand) = symmetric_key_from_public_key(
        prng,
        public_key)?;
    let (ciphertext, nonce) = symmetric_encrypt(&key, message);

    Ok(ZeiHybridCipher {
        ciphertext,
        nonce,
        encoded_rand,
    })
}

/// I decrypt a hybrid ciphertext for a secret key.
/// In case of success, I return vector of plain text bytes. Otherwise, I return either
/// ZeiError::DecompressElementError or Zei::DecryptionError
//TODO specify errors returned
pub fn hybrid_decrypt(ctext: &ZeiHybridCipher, secret_key: &XfrSecretKey)
    -> Result<Vec<u8>, ZeiError>
{
    let key = symmetric_key_from_secret_key(secret_key, &ctext.encoded_rand)?;
    Ok(symmetric_decrypt(&key, ctext.ciphertext.as_slice(), &ctext.nonce)?)
}

/// I derive a 32 bytes symmetric key from a public key. I return the byte array together
/// with encoded randomness in the public key group. In case public key cannot be decoded into a
/// valid group element, I return ZeiError::DecompressElementError.
fn symmetric_key_from_public_key<R>(
    prng: &mut R,
    public_key: &XfrPublicKey) -> Result<([u8;32], CompressedEdwardsY), ZeiError>
    where R: CryptoRng + Rng
{
    let rand  = Scalar::random(prng);
    let encoded_rand = &rand * KEY_BASE_POINT.decompress().unwrap(); // can always be decompressed
    let curve_key = &rand * public_key.get_curve_point()?;
    let mut hasher = sha2::Sha256::new();
    hasher.input(curve_key.compress().as_bytes());
    let hash = hasher.result();
    let mut symmetric_key = [0u8;32];
    symmetric_key.copy_from_slice(hash.as_slice());
    Ok((symmetric_key, encoded_rand.compress()))
}

/// I derive a 32 bytes symmetric key from a secret key and encoded randomness in the public key
/// I return the byte array. In case encoded randomness cannot be decoded into a valid group
/// element, I return ZeiError::DecompressElementError.
fn symmetric_key_from_secret_key(
    secret_key: &XfrSecretKey,
    rand: &CompressedEdwardsY) -> Result<[u8;32], ZeiError>
{
    //let curve_key = secret_key * rand.decompress()?;
    let decoded_rand  = match rand.decompress() {
        Some(x) => x,
        None => {return Err(ZeiError::DecompressElementError)}
    };
    let curve_key = secret_key.
        as_scalar_multiply_by_curve_point(&decoded_rand);
    let mut hasher = sha2::Sha256::new();
    hasher.input(curve_key.compress().as_bytes());
    let mut symmetric_key = [0u8;32];
    let hash = hasher.result();
    symmetric_key.copy_from_slice(hash.as_slice());
    Ok(symmetric_key)
}

/// I build a symmetric key to be used by the symmetric cipher from [u8;32] derived key array.
fn build_key(key: &[u8;32]) -> Key
{
    let mut copied_key: [u8; secretbox::KEYBYTES] = Default::default();
    copied_key.copy_from_slice(key);
    secretbox::Key(copied_key)
}

/// I symmetrically encrypt a plaintext message, ruturning ciphertext and nonce
fn symmetric_encrypt(key: &[u8;32], plaintext:&[u8]) -> (Vec<u8>, Nonce)
{
    let sk = build_key(key);
    let nonce = secretbox::gen_nonce();
    (secretbox::seal(plaintext,&nonce,&sk), nonce)
}

/// I symmetrically decrypt a ciphertext from 32 bytes key and nonce used in the encryption.
/// I return Zei::DecryptionError in case ciphertext was tampered.
fn symmetric_decrypt(
    key: &[u8;32],
    ciphertext:&[u8],
    nonce: &Nonce) -> Result<Vec<u8>, ZeiError>
{
    let sk = build_key(key);
    match secretbox::open(ciphertext, nonce, &sk){
        Ok(ciphertext) => Ok(ciphertext),
        Err(_) => Err(ZeiError::DecryptionError)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use super::super::signatures::XfrKeyPair;


    #[test]
    fn key_derivation(){
        let mut prng: ChaChaRng;
        prng  = ChaChaRng::from_seed([0u8; 32]);
        /*let sk = Scalar::random(&mut prng);
        let pk = (&sk * &base.decompress().unwrap()).compress();
        */
        let keypair = XfrKeyPair::generate(&mut prng);
        let (from_pk_key, encoded_rand) = symmetric_key_from_public_key(&mut prng, keypair.get_pk_ref()).unwrap();
        let from_sk_key = symmetric_key_from_secret_key(keypair.get_sk_ref(), &encoded_rand).unwrap();
        assert_eq!(from_pk_key, from_sk_key);
    }

    #[test]
    fn symmetric_encryption(){
        let msg = b"this is a message";
        let key: [u8;32] = [0u8;32];
        let (mut ciphertext, nonce) = symmetric_encrypt(&key, msg);
        let decrypted = symmetric_decrypt(&key,ciphertext.as_slice(), &nonce).unwrap();
        assert_eq!(msg, decrypted.as_slice());

        ciphertext[0] = 0xFF - ciphertext[0];
        let result = symmetric_decrypt(&key,ciphertext.as_slice(), &nonce);
        assert_eq!(Err(ZeiError::DecryptionError), result);
    }

    #[test]
    fn zei_hybrid_cipher(){
        let mut prng: ChaChaRng;
        prng  = ChaChaRng::from_seed([0u8; 32]);
        let key_pair = XfrKeyPair::generate(&mut prng);
        let msg = b"this is another message";


        let mut cipherbox = hybrid_encrypt(&mut prng, key_pair.get_pk_ref(), msg).unwrap();
        let plaintext = hybrid_decrypt(&cipherbox, key_pair.get_sk_ref()).unwrap();
        assert_eq!(msg, plaintext.as_slice());

        cipherbox.ciphertext.push(0u8);
        let plaintext = hybrid_decrypt(&cipherbox, key_pair.get_sk_ref());
        assert_eq!(true, plaintext.is_err());
        assert_eq!(Err(ZeiError::DecryptionError), plaintext);

        cipherbox.ciphertext.pop();

        cipherbox.ciphertext[3] = 0xFF as u8 - cipherbox.ciphertext[3];
        let plaintext = hybrid_decrypt(&cipherbox, key_pair.get_sk_ref());
        assert_eq!(true, plaintext.is_err());
        assert_eq!(Err(ZeiError::DecryptionError), plaintext);

        cipherbox.ciphertext[3] = 0xFF as u8 - cipherbox.ciphertext[3];
        let plaintext = hybrid_decrypt(&cipherbox, key_pair.get_sk_ref()).unwrap();
        assert_eq!(msg, plaintext.as_slice());
    }
}


