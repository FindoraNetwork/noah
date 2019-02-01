use blake2::VarBlake2b;
use blake2::digest::{Input, VariableOutput};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::{Nonce,Key};
use rand::CryptoRng;
use rand::Rng;
use crate::errors::Error as ZeiError;

pub fn symmetric_key_from_public_key<R>(
    prng: &mut R,
    pk: &RistrettoPoint,
    curve_base:&RistrettoPoint) -> ([u8;32], RistrettoPoint) where R: CryptoRng + Rng
{
    /*! I derive a symmetric key from an ElGamal public key over the Ristretto group. Return symmetric key, and encoded
     * randonmess to be used by secret key holder to derive the same symmetric key
    */
    let rand  = Scalar::random(prng);
    let encoded_rand = &rand * curve_base;
    let curve_key = &rand * pk;
    let mut hasher = VarBlake2b::new(32).unwrap();
    hasher.input(curve_key.compress().as_bytes());
    let hash = hasher.vec_result();
    let mut symmetric_key: [u8;32] = Default::default();
    symmetric_key.copy_from_slice(hash.as_slice());
    (symmetric_key, encoded_rand)
}

pub fn symmetric_key_from_secret_key<'a>(sk: &Scalar, rand: &RistrettoPoint) -> [u8;32]
{
    let curve_key = sk * rand;
    let mut hasher = VarBlake2b::new(32).unwrap();
    hasher.input(curve_key.compress().as_bytes());
    let mut symmetric_key: [u8;32] = Default::default();
    let hash = hasher.vec_result();
    symmetric_key.copy_from_slice(hash.as_slice());
    symmetric_key
}

pub fn build_key(key: &[u8;32]) -> Key{
    let mut copied_key: [u8; secretbox::KEYBYTES] = Default::default();
    copied_key.copy_from_slice(key);
    secretbox::Key(copied_key)
}

pub fn symmetric_encrypt(key: &[u8;32], plaintext:&[u8]) -> (Vec<u8>, Nonce){
    let sk = build_key(key);
    let nonce = secretbox::gen_nonce();
    (secretbox::seal(plaintext,&nonce,&sk), nonce)
}

pub fn symmetric_decrypt(
    key: &[u8;32],
    ciphertext:&[u8],
    nonce: &Nonce) -> Result<Vec<u8>, ZeiError>{
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
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;


    #[test]
    fn test_key_derivation(){
        let mut prng: ChaChaRng;
        prng  = ChaChaRng::from_seed([0u8; 32]);
        let sk = Scalar::random(&mut prng);
        let base = RISTRETTO_BASEPOINT_POINT;
        let pk = &sk * &base;
        let (from_pk_key, encoded_rand) = symmetric_key_from_public_key(&mut prng, &pk, &base);
        let from_sk_key = symmetric_key_from_secret_key(&sk, &encoded_rand);
        assert_eq!(from_pk_key, from_sk_key);
    }

    #[test]
    fn test_encryption(){
        let msg = b"this is a message";
        let key: [u8;32] = [0u8;32];
        let (ciphertext, nonce) = symmetric_encrypt(&key, msg);
        let decrypted = symmetric_decrypt(&key,ciphertext.as_slice(), &nonce).unwrap();
        assert_eq!(msg, decrypted.as_slice());
    }
}


