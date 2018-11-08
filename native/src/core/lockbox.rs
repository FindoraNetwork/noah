//
//Lockbox: Non Interactive Box with a known Publickey of recipient
//

//Primitive Choices
// Hash: Blake2b at 32 bytes
// Cipher: XSALSA20_POLY1305
// Curve: Curve25519 over Ristretto

//Protocol Overview:
//
//Sender -> Receiver (pk)
// 1. Sample Some Fresh Randomness (R)
// 2. Take pk^R = KEY , this key is used for encryption
// 3. Encrypt: AES_ENC(HASH(KEY), message) = cipherText
// 4. Send (cipherText, g^R) to recipient
// 5. Receiver Must Derive shared key
//      5a. Knows g^x = pk. x is secret key
//      5b. Recall sender took pk^R as key, thus REDERIVED_KEY == pk^R == (g^x)^R == g^xR == (g^R)^x
// 6. Decrypt: AES_DEC(HASH(REDERIVED_KEY), cipherText)
// 
//

use blake2_rfc::blake2b::blake2b;
use rand::{CryptoRng, Rng, OsRng};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use crate::core::util::{slice_to_fixed32, decode_scalar};
use std::iter::repeat;
use crate::core::elgamal::{SecretKey, PublicKey};
use crate::core::microsalt::secretbox::{secretbox_seal, secretbox_open};



#[derive(Serialize, Deserialize, Debug)]
pub struct Lockbox {
    //data
    pub data: Vec<u8>,
    //our blinded randomned g^R
    pub rand: CompressedRistretto,
}

impl Lockbox {

    //locks a given amount with reciever PK and returns cipher text and rand
    pub fn lock(publickey: &PublicKey, message: &[u8]) -> Lockbox {
        let mut lbox : Lockbox = Lockbox {
            data: Vec::new(),
            rand: Default::default()
        };

        //get our enc key and blinded randomness
        //g^(x*r),g^r
        let (enc_point, bigr) = Lockbox::derive_key(publickey);
        lbox.rand = bigr;
        //println!("enckey: {:?}", enc_point);
        //println!("bigr: {:?}", bigr);

        //hash key at 32 bytes
        let enc_key = blake2b(32, &[], enc_point.as_bytes()).as_bytes().to_vec();
        //println!("enckey_hash: {:?}", enc_key);
        //println!("blind open_init: {:?}", bigr);

        //output buf at input len zeroed out
        lbox.data = secretbox_seal(&slice_to_fixed32(&enc_key), message);

        return lbox;
    }

    //given the box with the corresponding secret key & randomness
    pub fn unlock(&self, secretkey: &SecretKey) -> Vec<u8> {
        //g^x = pk. x is secret key, g^R == rand 
        
        //REDERIVED_KEY == (g^R)^x
        let dec_point = self.rand.decompress().unwrap() * decode_scalar(&secretkey.as_bytes());
        //println!("bigr_open: {:?}", &lockedbox.rand);
        //println!("deckey: {:?}", dec_key.compress().to_bytes());
        //println!("deckey: {:?}", dec_point.compress());
        
        //hash key at 32 bytes
        let dec_key =  blake2b(32, &[], &dec_point.compress().to_bytes()).as_bytes().to_vec();
        //println!("deckey_hash: {:?}", dec_key);
        
        let out = secretbox_open(&slice_to_fixed32(&dec_key), &self.data).unwrap();

        return out;    
    }

    //
    //INTERNAL HELPERS
    //

    //TODO: make randomness passed around
    //given pk, samples randomness to generate the symmetric key
    // fn derive_key<T>(pk: &PublicKey, csprng: &mut T) -> ([u8; 32], CompressedRistretto) 
    //     where T: CryptoRng + Rng,
    // {
    //given pk, samples randomness to generate the symmetric key
    fn derive_key(pk: &PublicKey) -> (CompressedRistretto, CompressedRistretto) {
        //sample fresh randomness
        let mut csprng: OsRng = OsRng::new().unwrap();
        let randomness = Scalar::random(&mut csprng);

        //pk^R
        let shared_key = randomness * pk.0;
        
        //g^R where R = randomness used to derive shared key
        let blind_rand = &randomness * &RISTRETTO_BASEPOINT_TABLE;

        //blind_rand.compress().to_bytes()
        return (shared_key.compress(), blind_rand.compress());
    }



}







#[cfg(test)]
mod test {
    use super::*;
    use crate::core::hex;
    use crate::core::util::{ be_u8_from_u32 };
    use crate::core::elgamal;
        use rand::OsRng;

    #[test]
    fn test_lock_unlock() { 
        //Sample Fresh Keypair

        
        //1. Sample Fresh blinding factor [blind], its a scalar
        let mut csprng: OsRng = OsRng::new().unwrap();
        let sk = elgamal::SecretKey::new(&mut csprng).unwrap();
        let pk = elgamal::PublicKey::from_secret(&sk);


        let blinding_t = Scalar::random(&mut csprng);

        let amount: u32 = 101;

        //7. Encrypt to receiver pubkey both the amount transferred and the blinding factor [blind] 
        let mut to_encrypt = Vec::new();
        //first add amount which is fixed 4 bytes in big endian
        let encoded_amount: [u8; 4] = be_u8_from_u32(amount);
        //println!("encoded_amount: {:?}", encoded_amount);
        to_encrypt.extend_from_slice(&encoded_amount);
        //next add the blind
        to_encrypt.extend_from_slice(&blinding_t.to_bytes());

        //println!("to_encrypt: {:?}", to_encrypt);
        
        //lock em up
        let lbox = Lockbox::lock(&pk, &to_encrypt);

        //Now we unbox to check if we get same results

        //unlock encrypted box
        let unlocked = lbox.unlock(&sk);
        //extract balance value & blind value
        let (raw_amount, raw_blind) = unlocked.split_at(5);
        //println!("unlocked value: {:?}", unlocked);
        //convert to u32
        let p_amount = u32::from(raw_amount[0]) << 24 |
        u32::from(raw_amount[1]) << 16 |
        u32::from(raw_amount[2]) << 8 |
        u32::from(raw_amount[3]);

        //println!("amount open: {:?}", p_amount);
       

        //check if amounts are the same
        assert_eq!(p_amount, amount);
        



        
    }


}