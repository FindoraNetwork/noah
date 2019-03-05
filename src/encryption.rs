use blake2::VarBlake2b;
use blake2::digest::{Input, VariableOutput};
use crate::errors::Error as ZeiError;
use crate::serialization;
use curve25519_dalek::scalar::Scalar;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::{Nonce,Key};
use rand::CryptoRng;
use rand::Rng;
use crate::keys::{ZeiPublicKey, KEY_BASE_POINT, ZeiSecretKey};
use curve25519_dalek::edwards::CompressedEdwardsY;


#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ZeiCipher {
    pub ciphertext: Vec<u8>,
    pub nonce: Nonce,
    #[serde(with = "serialization::zei_obj_serde")]
    pub encoded_rand: CompressedEdwardsY,
}

impl ZeiCipher {
    pub fn encrypt<R>(
        prng: &mut R,
        public_key: &ZeiPublicKey,
        message: &[u8]) -> Result<ZeiCipher, ZeiError>
        where R: CryptoRng + Rng
    {
        let (key, encoded_rand) = symmetric_key_from_public_key(
            prng,
            public_key)?;
        let (ciphertext, nonce) = symmetric_encrypt(&key, message);

        Ok(ZeiCipher {
            ciphertext,
            nonce,
            encoded_rand,
        })
    }

    pub fn decrypt(&self, secret_key: &ZeiSecretKey) -> Result<Vec<u8>, ZeiError>{
        let key = symmetric_key_from_secret_key(secret_key, &self.encoded_rand)?;
        Ok(symmetric_decrypt(&key, self.ciphertext.as_slice(), &self.nonce)?)
    }
}

pub fn symmetric_key_from_public_key<R>(
    prng: &mut R,
    public_key: &ZeiPublicKey) -> Result<([u8;32], CompressedEdwardsY), ZeiError> where R: CryptoRng + Rng
{
    /*! I derive a symmetric key from an ElGamal public key over the Ristretto group. Return symmetric key, and encoded
     * randonmess to be used by secret key holder to derive the same symmetric key
    */
    let rand  = Scalar::random(prng);
    let encoded_rand = &rand * KEY_BASE_POINT.decompress()?;
    let curve_key = &rand * public_key.get_curve_point()?;
    let mut hasher = VarBlake2b::new(32).unwrap();//valid unwrap, should never fail
    hasher.input(curve_key.compress().as_bytes());
    let hash = hasher.vec_result();
    let mut symmetric_key: [u8;32] = Default::default();
    symmetric_key.copy_from_slice(hash.as_slice());
    Ok((symmetric_key, encoded_rand.compress()))
}

fn symmetric_key_from_secret_key(
    secret_key: &ZeiSecretKey,
    rand: &CompressedEdwardsY) -> Result<[u8;32], ZeiError>
{
    //let curve_key = secret_key * rand.decompress()?;
    let curve_key = secret_key.
        as_scalar_multiply_by_curve_point::<blake2::Blake2b>(&rand.decompress()?);
    let mut hasher = VarBlake2b::new(32).unwrap(); //valid unwrap: this should never fail
    hasher.input(curve_key.compress().as_bytes());
    let mut symmetric_key: [u8;32] = Default::default();
    let hash = hasher.vec_result();
    symmetric_key.copy_from_slice(hash.as_slice());
    Ok(symmetric_key)
}

fn build_key(key: &[u8;32]) -> Key{
    let mut copied_key: [u8; secretbox::KEYBYTES] = Default::default();
    copied_key.copy_from_slice(key);
    secretbox::Key(copied_key)
}

fn symmetric_encrypt(key: &[u8;32], plaintext:&[u8]) -> (Vec<u8>, Nonce){
    let sk = build_key(key);
    let nonce = secretbox::gen_nonce();
    (secretbox::seal(plaintext,&nonce,&sk), nonce)
}

fn symmetric_decrypt(
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
    use crate::keys::ZeiKeyPair;


    #[test]
    fn test_key_derivation(){
        let mut prng: ChaChaRng;
        prng  = ChaChaRng::from_seed([0u8; 32]);
        /*let sk = Scalar::random(&mut prng);
        let pk = (&sk * &base.decompress().unwrap()).compress();
        */
        let keypair = ZeiKeyPair::generate(&mut prng);
        let (from_pk_key, encoded_rand) = symmetric_key_from_public_key(&mut prng, keypair.get_pk_ref()).unwrap();
        let from_sk_key = symmetric_key_from_secret_key(keypair.get_sk_ref(), &encoded_rand).unwrap();
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

    #[test]
    fn test_zei_ristretto_cipher(){
        let mut prng: ChaChaRng;
        prng  = ChaChaRng::from_seed([0u8; 32]);
        let key_pair = ZeiKeyPair::generate(&mut prng);
        let msg = b"this is another message";


        let mut cipherbox = ZeiCipher::encrypt(&mut prng, key_pair.get_pk_ref(), msg).unwrap();
        let plaintext = cipherbox.decrypt(key_pair.get_sk_ref()).unwrap();
        assert_eq!(msg, plaintext.as_slice());

        cipherbox.ciphertext.push(0u8);
        let plaintext = cipherbox.decrypt(key_pair.get_sk_ref());
        assert_eq!(true, plaintext.is_err());
        assert_eq!(Err(ZeiError::DecryptionError), plaintext);

        cipherbox.ciphertext.pop();

        cipherbox.ciphertext[3] = 0xFF as u8 - cipherbox.ciphertext[3];
        let plaintext = cipherbox.decrypt(key_pair.get_sk_ref());
        assert_eq!(true, plaintext.is_err());
        assert_eq!(Err(ZeiError::DecryptionError), plaintext);

        cipherbox.ciphertext[3] = 0xFF as u8 - cipherbox.ciphertext[3];
        let plaintext = cipherbox.decrypt(key_pair.get_sk_ref()).unwrap();
        assert_eq!(msg, plaintext.as_slice());
    }
}


