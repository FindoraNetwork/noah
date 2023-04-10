use crate::xfr::structs::{AssetType, ASSET_TYPE_LENGTH};
use aes_gcm::{aead::Aead, KeyInit};
use digest::generic_array::GenericArray;
use noah_algebra::{
    bls12_381::BLSScalar,
    jubjub::{JubjubPoint, JubjubScalar},
    prelude::*,
    traits::Domain,
};
use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381};

impl AssetType {
    /// Generate asset type with auditor public key
    pub fn generate<R: CryptoRng + RngCore>(
        prng: &mut R,
        pk: &AuditorPublicKey,
    ) -> Result<(AssetType, BLSScalar)> {
        let sample = BLSScalar::random(prng);
        let pk_x = BLSScalar::from_field((pk.0).0.x);
        let pk_y = BLSScalar::from_field((pk.0).0.y);

        let trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[pk_x, pk_y, sample]);
        let output = trace.output.to_bytes();

        let mut bytes = [0u8; ASSET_TYPE_LENGTH];
        if ASSET_TYPE_LENGTH != output.len() {
            return Err(eg!(NoahError::ParameterError));
        }
        bytes.copy_from_slice(&output);

        Ok((AssetType(bytes), sample))
    }
}

/// An auditor’s memo that accurately describes contents of the transactions.
#[derive(Clone, Default, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TAxfrAuditorMemo(Vec<u8>);

/// The secret key for auditor.
#[derive(Debug)]
pub struct AuditorSecretKey(JubjubScalar);

/// The public key for auditor.
#[derive(Clone, Copy, Debug)]
pub struct AuditorPublicKey(JubjubPoint);

impl TAxfrAuditorMemo {
    /// Encrypt struct data to memo bytes
    pub fn encrypt<R: CryptoRng + RngCore>(
        prng: &mut R,
        pk: &AuditorPublicKey,
        plaintext: &[u8],
    ) -> Result<Self> {
        // TODO convert struct data to bytes

        let output = ecies_encrypt(prng, &pk.0, plaintext)?;
        Ok(TAxfrAuditorMemo(output.to_bytes()?))
    }

    /// Try to decryp memo bytes to struct data
    pub fn decrypt(sk: &AuditorSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let output = EciesOutput::from_bytes(ciphertext)?;
        let plaintext = ecies_decrypt(&sk.0, &output)?;

        // TODO convert bytes struct data
        Ok(plaintext)
    }
}

/// ECIES Hybrid Encryption Scheme, use Jubjub + AES-256-GCM
struct EciesOutput {
    /// ephemeral encrypt public key
    ephemeral: JubjubPoint,
    /// encrypted message
    ctext: Vec<u8>,
}

impl EciesOutput {
    /// Convert ECIES output to bytes
    fn to_bytes(self) -> Result<Vec<u8>> {
        let mut bytes = vec![];
        bytes.extend(self.ephemeral.to_compressed_bytes());
        bytes.extend(self.ctext);
        Ok(bytes)
    }

    /// Convert bytes to ECIES output
    fn from_bytes(bytes: &[u8]) -> Result<EciesOutput> {
        let len = JubjubPoint::COMPRESSED_LEN;
        if bytes.len() < len {
            return Err(eg!(NoahError::DeserializationError));
        }
        let ephemeral = JubjubPoint::from_compressed_bytes(&bytes[..len])?;
        let ctext = bytes[len..].to_vec();
        Ok(Self { ephemeral, ctext })
    }
}

/// ECIES encrypt function
fn ecies_encrypt<R: CryptoRng + RngCore>(
    prng: &mut R,
    pk: &JubjubPoint,
    plaintext: &[u8],
) -> Result<EciesOutput> {
    let ephemeral_sk = JubjubScalar::random(prng);
    let ephemeral = JubjubPoint::get_base().mul(&ephemeral_sk);

    let dh = pk.mul(&ephemeral_sk);

    let dh_x = BLSScalar::from_field(dh.0.x);
    let dh_y = BLSScalar::from_field(dh.0.y);
    let trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[dh_x, dh_y]);

    let mut key = [0u8; 32];
    key.copy_from_slice(&trace.output.to_bytes());
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let gcm = {
        let res = aes_gcm::Aes256Gcm::new_from_slice(key.as_slice());
        if res.is_err() {
            return Err(eg!(NoahError::EncryptionError));
        }
        res.unwrap()
    };

    let ctext = {
        let res = gcm.encrypt(nonce, plaintext);
        if res.is_err() {
            return Err(eg!(NoahError::EncryptionError));
        }
        res.unwrap()
    };

    Ok(EciesOutput { ephemeral, ctext })
}

/// ECIES decrypt function
fn ecies_decrypt(sk: &JubjubScalar, output: &EciesOutput) -> Result<Vec<u8>> {
    let dh = output.ephemeral.mul(&sk);

    let dh_x = BLSScalar::from_field(dh.0.x);
    let dh_y = BLSScalar::from_field(dh.0.y);
    let trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[dh_x, dh_y]);

    let mut key = [0u8; 32];
    key.copy_from_slice(&trace.output.to_bytes());
    let nonce = GenericArray::from_slice(&[0u8; 12]);

    let gcm = {
        let res = aes_gcm::Aes256Gcm::new_from_slice(key.as_slice());
        if res.is_err() {
            return Err(eg!(NoahError::DecryptionError));
        }
        res.unwrap()
    };

    let res = {
        let res = gcm.decrypt(nonce, output.ctext.as_slice());
        if res.is_err() {
            return Err(eg!(NoahError::DecryptionError));
        }
        res.unwrap()
    };
    Ok(res)
}
