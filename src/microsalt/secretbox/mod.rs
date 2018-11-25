//! Secret-key authenticated encryption

/* 
-->http://nacl.cr.yp.to/secretbox.html
Similarly, ciphertexts in the C NaCl API are 0-padded versions of messages in the C++ NaCl API. 
Specifically: The crypto_secretbox function ensures that the first crypto_secretbox_BOXZEROBYTES
bytes of the ciphertext c are all 0. 
The caller must ensure, before calling the C NaCl crypto_secretbox function, 
that the first crypto_secretbox_ZEROBYTES bytes of the message m are all 0. 
Typical higher-level applications will work with the remaining bytes of the message; note, 
however, that mlen counts all of the bytes, including the bytes required to be 0. 
The caller must ensure, before calling the crypto_secretbox_open function, 
that the first crypto_secretbox_BOXZEROBYTES bytes of the ciphertext c are all 0. 
The crypto_secretbox_open function ensures (in case of success) that the first 
crypto_secretbox_ZEROBYTES bytes of the plaintext m are all 0.
--crypto_secretbox_xsalsa20poly1305 --
------- ZEROBYTES = 32  --------------
------- BOXZEROBYTES = 16  -----------
https://github.com/golang/crypto/blob/master/nacl/secretbox/secretbox.go
Package secretbox encrypts and authenticates small messages.
Secretbox uses XSalsa20 and Poly1305 to encrypt and authenticate messages with
secret-key cryptography. The length of messages is not hidden.
It is the caller's responsibility to ensure the uniqueness of nonces—for
example, by using nonce 1 for the first message, nonce 2 for the second
message, etc. Nonces are long enough that randomly generated nonces have
negligible risk of collision.
This package is interoperable with NaCl: https://nacl.cr.yp.to/secretbox.html.
*/
pub mod xsalsa20poly1305;
use crate::microsalt::shared;
use crate::util::{random_data_test_helper, randombytes};


const ZERO_BYTES: usize = 32;
const BOX_ZERO_BYTES: usize = 16;

///A secret key for crypto box
pub struct SecretKey(pub [u8; xsalsa20poly1305::SECRETBOX_KEY_LEN]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        //println!("Dropping Secret KEY, but must ZERO OUT MEMORY!!!!!");
        //use utils::memzero;
        //let &mut $name(ref mut v) = self;
        //memzero(v);
    }
}

pub fn key() -> SecretKey {
    let mut key = [0u8; 32]; //xsalsa20poly1305::SECRETBOX_KEY_LEN
    randombytes(&mut key);
    SecretKey(key)
}

//A Box encapsulates the cipher text and associated nonce value, it is ok to be public 
pub struct Box {
    pub nonce: [u8; xsalsa20poly1305::SECRETBOX_NONCE_LEN],
    pub cipher: Vec<u8>
}


impl SecretKey {
    //takes a plaintext message and returns an box object that holds cipher text and nonce
    pub fn lock(&self, message: &[u8]) -> Box { 
        let mut nonce = [0u8; xsalsa20poly1305::SECRETBOX_NONCE_LEN];
        randombytes(&mut nonce);
        let cipher = internal_lock(&message, &nonce, &self);
        //Return back Box 
        Box{nonce: nonce, cipher: cipher}
    }
}

impl Box {
    pub fn unlock(&self, key: &SecretKey) -> Result<Vec<u8>, ()> {
        if self.cipher.len() < BOX_ZERO_BYTES {
            return Err(());
        }

        let mut plaintext = Vec::with_capacity(self.cipher.len() + BOX_ZERO_BYTES);
        plaintext.resize(BOX_ZERO_BYTES, 0u8);
        plaintext.extend_from_slice(&self.cipher[..]);
        let m = plaintext.clone();
        let failure = xsalsa20poly1305::secretbox_open(&mut plaintext, &m, &self.nonce, &key.0);
        plaintext.drain(..ZERO_BYTES);
        if failure { Err(()) } else { Ok(plaintext) }
        
    }
}

//
//THESE ARE SPECIAL FUNCTIONS THAT DONT HAVE NONCE AND JUST ZERO, only for LOCKBOX
//

pub fn secretbox_seal(key_bytes: &[u8; xsalsa20poly1305::SECRETBOX_KEY_LEN], message: &[u8]) -> Vec<u8> {
    //default is all zero nonce
    let nonce = [0u8; xsalsa20poly1305::SECRETBOX_NONCE_LEN];
    //https://github.com/maidsafe/rust_sodium/blob/master/src/marshal.rs
    let mut cipher = Vec::with_capacity(message.len() + ZERO_BYTES);
    cipher.resize(ZERO_BYTES, 0u8);
    cipher.extend_from_slice(&message[..]);
    let m = cipher.clone();
    xsalsa20poly1305::secretbox(&mut cipher, &m, &nonce, key_bytes);
    cipher.drain(..BOX_ZERO_BYTES);

    cipher
}

pub fn secretbox_open(key_bytes: &[u8; xsalsa20poly1305::SECRETBOX_KEY_LEN], encrypted_data: &[u8]) -> Result<Vec<u8>, ()> {
    //deault is all zero nonce
    let nonce = [0u8; xsalsa20poly1305::SECRETBOX_NONCE_LEN];
    if encrypted_data.len() < BOX_ZERO_BYTES {
        return Err(());
    }

    let mut plaintext = Vec::with_capacity(encrypted_data.len() + BOX_ZERO_BYTES);

    plaintext.resize(BOX_ZERO_BYTES, 0u8);
    plaintext.extend_from_slice(&encrypted_data[..]);
    let m = plaintext.clone();
    let failure = xsalsa20poly1305::secretbox_open(&mut plaintext, &m, &nonce, &key_bytes);
    plaintext.drain(..ZERO_BYTES);
    if failure { Err(()) } else { Ok(plaintext) }
}


//interal lock function that deals with the padding 
fn internal_lock(message: &[u8], nonce: &[u8; xsalsa20poly1305::SECRETBOX_NONCE_LEN], key: &SecretKey) -> Vec<u8> { 
    //https://github.com/maidsafe/rust_sodium/blob/master/src/marshal.rs
    let mut cipher = Vec::with_capacity(message.len() + ZERO_BYTES);
    cipher.resize(ZERO_BYTES, 0u8);
    cipher.extend_from_slice(&message[..]);
    let m = cipher.clone();
    xsalsa20poly1305::secretbox(&mut cipher, &m, &nonce, &key.0);
    cipher.drain(..BOX_ZERO_BYTES);

    cipher
}



#[test]
fn test_seal_open() {
    for i in 0..256usize {
        let key = key();
        let message = random_data_test_helper(i);
        let boxy = key.lock(&message);
        let plaintext = boxy.unlock(&key);
        assert!(Ok(message) == plaintext);
    }
}

#[test]
fn test_seal_open_tamper(){
    for i in 0..256usize {
        let key = key();
        let message = random_data_test_helper(i);
        let mut boxy = key.lock(&message);
        for i in 0..boxy.cipher.len() {
            boxy.cipher[i] ^= 0x20;
            let plaintext = boxy.unlock(&key);
            assert!(Err(()) == plaintext);
            boxy.cipher[i] ^= 0x20;
        }
    }
}

#[test]
fn test_vector_known() {
        let key = SecretKey([0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
                            0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
                            0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89]);


        let message = vec![0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16, 0xeb,
                     0xeb, 0x0c, 0x7b, 0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4, 0x4b, 0x66,
                     0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc, 0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75,
                     0x1a, 0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29, 0x6c, 0xdc, 0x3c, 0x01,
                     0x23, 0x35, 0x61, 0xf4, 0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31, 0x0e,
                     0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d, 0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34,
                     0x80, 0x57, 0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a, 0x02, 0x4a, 0x83,
                     0x8f, 0x21, 0xaf, 0x1f, 0xde, 0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd,
                     0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52, 0xf0, 0xa0, 0x89, 0xbc, 0x76,
                     0x89, 0x70, 0x40, 0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64, 0x5e, 0x07,
                     0x05];

    
        //define box struct 
        let boxy = Box{
            nonce: [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd,
                           0xa8, 0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a,
                           0x0b, 0x37],

            cipher: vec![0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5, 0x2a, 0x7d, 0xfb, 0x4b, 0x3d,
                 0x33, 0x05, 0xd9, 0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73, 0xc2, 0x96,
                 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce, 0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96,
                 0xa4, 0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a, 0xc0, 0xdf, 0xc1, 0x7c,
                 0x98, 0xdc, 0xe8, 0x7b, 0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72, 0x71,
                 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2, 0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5,
                 0x17, 0x38, 0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a, 0xb9, 0x32, 0x16,
                 0x45, 0x48, 0xe5, 0x26, 0xae, 0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea,
                 0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda, 0x99, 0x83, 0x2b, 0x61, 0xca,
                 0x01, 0xb6, 0xde, 0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3, 0x79, 0x73,
                 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6, 0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a,
                 0x74, 0xe3, 0x55, 0xa5]
        };

        let cipher = internal_lock(&message, &boxy.nonce, &key);
        assert!(cipher == boxy.cipher);

        let plaintext = boxy.unlock(&key);
        assert!(Ok(message) == plaintext);
}