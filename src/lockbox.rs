//
//Lockbox: Non Interactive Box with a known Publickey of recipient
//

//Primitive Choices
// Hash: Blake2b at 32 bytes
// Cipher: XSALSA20_POLY1305
// Curve: Curve25519 over Ristretto

// Protocol Overview:

// Sender -> Receiver (pk)
// 1. Sample Some Fresh Randomness (R)
// 2. Take pk^R = KEY , this key is used for encryption
// 3. Encrypt: AES_ENC(HASH(KEY), message) = cipherText
// 4. Send (cipherText, g^R) to recipient
// 5. Receiver Must Derive shared key
//      5a. Knows g^x = pk. x is secret key
//      5b. Recall sender took pk^R as key, thus REDERIVED_KEY == pk^R == (g^x)^R == g^xR == (g^R)^x
// 6. Decrypt: AES_DEC(HASH(REDERIVED_KEY), cipherText)



use blake2_rfc::blake2b::blake2b;
use rand::CryptoRng;
use rand::Rng;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use crate::util::decode_scalar;

use schnorr::PublicKey;
use schnorr::SecretKey;
use organism_utils::crypto::secretbox;


#[derive(Serialize, Deserialize, Debug)]
pub struct Lockbox {
    //data
    pub data: secretbox::SecretBox,
    //our blinded randomned g^R
    pub rand: CompressedRistretto,
}

impl Lockbox {

    //locks a given amount with reciever PK and returns cipher text and rand
    pub fn lock<R>(csprng: &mut R, publickey: &PublicKey, message: &[u8]) -> Lockbox 
        where R: CryptoRng + Rng, 
    {
     
        //get our enc key and blinded randomness
        //g^(x*r),g^r
        let (enc_point, bigr) = Lockbox::derive_key(csprng, publickey);

        //secret key via hash 
        let enc_key = secretbox::SymmetricKey::from_bytes(&blake2b(32, &[], enc_point.as_bytes()).as_bytes()).unwrap();

        //sample new nonce;
        let nonce = secretbox::NonceKey::generate(csprng);

        //we also add the rand to commit to it
        let b = secretbox::SecretBox::lock(&enc_key, nonce, message, bigr.as_bytes()).unwrap();

        return Lockbox {
            data: b,
            rand: bigr
        };
    }

    //given the box with the corresponding secret key & randomness
    pub fn unlock(&self, secretkey: &SecretKey) -> Vec<u8> {
        //g^x = pk. x is secret key, g^R == rand 
        
        //REDERIVED_KEY == (g^R)^x
        let dec_point = self.rand.decompress().unwrap() * decode_scalar(&secretkey.as_bytes());
        
        //hash key at 32 bytes
        let dec_key = secretbox::SymmetricKey::from_bytes(&blake2b(32, &[], &dec_point.compress().to_bytes()).as_bytes()).unwrap();

        return self.data.unlock(&dec_key, &self.rand.to_bytes()).unwrap();    
    }

    //
    //INTERNAL HELPERS
    //

    //given pk, samples randomness to generate the symmetric key
    fn derive_key<R>(csprng: &mut R, pk: &PublicKey) -> (CompressedRistretto, CompressedRistretto) 
        where R: CryptoRng + Rng, 
    {
        //sample fresh randomness
        let randomness = Scalar::random(csprng);

        //pk^R
        let shared_key = randomness * pk.get_curve_point().unwrap();
        
        //g^R where R = randomness used to derive shared key
        let blind_rand = &randomness * &RISTRETTO_BASEPOINT_TABLE;

        //blind_rand.compress().to_bytes()
        return (shared_key.compress(), blind_rand.compress());
    }

}


#[cfg(test)]
mod test {
    use super::*;
    use crate::util::{ be_u8_from_u32 };
    use rand::OsRng;
    use schnorr::PublicKey;
    use schnorr::SecretKey;
    use schnorr::Keypair;



    #[test]
    fn test_lock_unlock() { 
        //Sample Fresh Keypair
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        
        //1. Sample Fresh blinding factor [blind], its a scalar
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
        let lbox = Lockbox::lock(&mut csprng, &keypair.public, &to_encrypt);

        //Now we unbox to check if we get same results
        
        //unlock encrypted box
        let unlocked = lbox.unlock(&keypair.secret);
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