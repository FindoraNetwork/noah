use aes_gcm::{aead::Aead, NewAead};
use digest::{generic_array::GenericArray, Digest};
use zei_algebra::{
    jubjub::{JubjubPoint, JubjubScalar},
    prelude::*,
};

/// The keypair on Jubjub for DH encryption.
/// return secret key and public key.
#[inline]
pub fn dh_generate<R: CryptoRng + RngCore>(prng: &mut R) -> (JubjubScalar, JubjubPoint) {
    let secret_key = JubjubScalar::random(prng);
    let base = JubjubPoint::get_base();
    let public_key = base.mul(&secret_key);
    (secret_key, public_key)
}

/// The keypair from secret key.
/// return secret key and public key.
#[inline]
pub fn dh_keypair(secret_key: JubjubScalar) -> (JubjubScalar, JubjubPoint) {
    let base = JubjubPoint::get_base();
    let public_key = base.mul(&secret_key);
    (secret_key, public_key)
}

/// Encrypted data using the public key.
#[inline]
pub fn dh_encrypt<R: CryptoRng + RngCore>(
    prng: &mut R,
    public_key: &JubjubPoint,
    msg: &[u8],
) -> Result<(JubjubPoint, Vec<u8>)> {
    let share_scalar = JubjubScalar::random(prng);
    let share = JubjubPoint::get_base().mul(&share_scalar);

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
pub fn dh_decrypt(secret_key: &JubjubScalar, share: &JubjubPoint, ctext: &[u8]) -> Result<Vec<u8>> {
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
