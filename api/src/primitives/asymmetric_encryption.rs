use aes_gcm::{aead::Aead, NewAead};
use digest::{generic_array::GenericArray, Digest};
use zei_algebra::{
    prelude::*,
    secp256k1::{SECP256K1Scalar, SECP256K1G1},
};

/// The keypair on Jubjub for DH encryption.
/// return secret key and public key.
#[inline]
pub fn dh_generate<R: CryptoRng + RngCore>(prng: &mut R) -> (SECP256K1Scalar, SECP256K1G1) {
    let secret_key = SECP256K1Scalar::random(prng);
    let base = SECP256K1G1::get_base();
    let public_key = base.mul(&secret_key);
    (secret_key, public_key)
}

/// The keypair from secret key.
/// return secret key and public key.
#[inline]
pub fn dh_keypair(secret_key: SECP256K1Scalar) -> (SECP256K1Scalar, SECP256K1G1) {
    let base = SECP256K1G1::get_base();
    let public_key = base.mul(&secret_key);
    (secret_key, public_key)
}

/// Encrypted data using the public key.
#[inline]
pub fn dh_encrypt<R: CryptoRng + RngCore>(
    prng: &mut R,
    public_key: &SECP256K1G1,
    msg: &[u8],
) -> Result<(SECP256K1G1, Vec<u8>)> {
    let share_scalar = SECP256K1Scalar::random(prng);
    let share = SECP256K1G1::get_base().mul(&share_scalar);

    let dh = public_key.mul(&share_scalar);

    let mut hasher = sha2::Sha512::new();
    hasher.update(&dh.to_compressed_bytes());

    let mut key = [0u8; 32];
    key.copy_from_slice(&hasher.finalize().as_slice()[0..32]);

    let nonce = GenericArray::from_slice(&[0u8; 12]);

    let gcm = {
        let res = aes_gcm::Aes256Gcm::new_from_slice(key.as_slice());

        if res.is_err() {
            return Err(eg!(ZeiError::EncryptionError));
        }

        res.unwrap()
    };

    let ctext = {
        let res = gcm.encrypt(nonce, msg);

        if res.is_err() {
            return Err(eg!(ZeiError::EncryptionError));
        }

        res.unwrap()
    };

    Ok((share, ctext))
}

/// Decrypt data using the secret key.
#[inline]
pub fn dh_decrypt(
    secret_key: &SECP256K1Scalar,
    share: &SECP256K1G1,
    ctext: &[u8],
) -> Result<Vec<u8>> {
    let dh = share.mul(secret_key);

    let mut hasher = sha2::Sha512::new();
    hasher.update(&dh.to_compressed_bytes());

    let mut key = [0u8; 32];
    key.copy_from_slice(&hasher.finalize().as_slice()[0..32]);

    let nonce = GenericArray::from_slice(&[0u8; 12]);

    let gcm = {
        let res = aes_gcm::Aes256Gcm::new_from_slice(key.as_slice());

        if res.is_err() {
            return Err(eg!(ZeiError::DecryptionError));
        }

        res.unwrap()
    };

    let res = {
        let res = gcm.decrypt(nonce, ctext);

        if res.is_err() {
            return Err(eg!(ZeiError::DecryptionError));
        }

        res.unwrap()
    };
    Ok(res)
}
