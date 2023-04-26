use crate::xfr::structs::{AssetType, ASSET_TYPE_LENGTH};
use noah_algebra::{
    bls12_381::{BLSScalar, BLS12_381_SCALAR_LEN},
    jubjub::{JubjubPoint, JubjubScalar},
    prelude::*,
    traits::Domain,
};
use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381};

// If the auditor's memory includes amount, asset_type, blind and receiver address,
// then the size of the auditor's memory equals to 8 + 32 + 32 + 34 = 106.
const MAX_AUDITOR_MEMO_SIZE: usize = 106;

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
pub struct AuditorSecretKey(pub JubjubScalar);

/// The public key for auditor.
#[derive(Clone, Copy, Debug)]
pub struct AuditorPublicKey(pub JubjubPoint);

impl AuditorSecretKey {
    /// Generate an auditor secret key and public key.
    pub fn generate_keypair<R: CryptoRng + RngCore>(
        prng: &mut R,
    ) -> (AuditorSecretKey, AuditorPublicKey) {
        let sk = JubjubScalar::random(prng);
        let pk = JubjubPoint::get_base().mul(&sk);
        (AuditorSecretKey(sk), AuditorPublicKey(pk))
    }
}

impl TAxfrAuditorMemo {
    /// Encrypt struct data to memo bytes
    pub fn encrypt<R: CryptoRng + RngCore>(
        prng: &mut R,
        pk: &AuditorPublicKey,
        plaintexts: &Vec<Vec<u8>>,
    ) -> Result<(Self, JubjubScalar, JubjubPoint, JubjubPoint)> {
        // TODO convert struct data to bytes

        let output = ecies_encrypt(prng, &pk.0, plaintexts)?;
        Ok((TAxfrAuditorMemo::default(), output.1, output.2, output.3))
    }

    /// Try to decryp memo bytes to struct data
    pub fn decrypt(sk: &AuditorSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // let output = EciesOutput::from_bytes(ciphertext)?;
        // let plaintext = ecies_decrypt(&sk.0, &output)?;

        // // TODO convert bytes to struct data
        Ok(vec![])
    }
}

/// ECIES Hybrid Encryption Scheme, use Jubjub + AES-256-GCM
struct EciesOutput {
    /// ephemeral encrypt public key
    ephemeral: JubjubPoint,
    /// encrypted message
    ctexts: Vec<Vec<u8>>,
}

impl EciesOutput {
    // /// Convert ECIES output to bytes
    // fn to_bytes(self) -> Result<Vec<u8>> {
    //     let mut bytes = vec![];
    //     bytes.extend(self.ephemeral.to_compressed_bytes());
    //     // bytes.extend(self.ctext);
    //     Ok(bytes)
    // }

    // /// Convert bytes to ECIES output
    // fn from_bytes(bytes: &[u8]) -> Result<EciesOutput> {
    //     let len = JubjubPoint::COMPRESSED_LEN;
    //     if bytes.len() < len {
    //         return Err(eg!(NoahError::DeserializationError));
    //     }
    //     let ephemeral = JubjubPoint::from_compressed_bytes(&bytes[..len])?;
    //     let ctext = bytes[len..].to_vec();
    //     Ok(Self { ephemeral, ctext })
    // }
}

/// ECIES encrypt function
fn ecies_encrypt<R: CryptoRng + RngCore>(
    prng: &mut R,
    pk: &JubjubPoint,
    plaintexts: &Vec<Vec<u8>>,
) -> Result<(EciesOutput, JubjubScalar, JubjubPoint, JubjubPoint)> {
    let ephemeral_sk: JubjubScalar = JubjubScalar::random(prng);
    let ephemeral = JubjubPoint::get_base().mul(&ephemeral_sk);
    let dh: JubjubPoint = pk.mul(&ephemeral_sk);

    let ephemeral_x = BLSScalar::from_field(ephemeral.0.x);
    let ephemeral_y = BLSScalar::from_field(ephemeral.0.y);
    let dh_x = BLSScalar::from_field(dh.0.x);
    let dh_y = BLSScalar::from_field(dh.0.y);

    let mut output_len = MAX_AUDITOR_MEMO_SIZE * plaintexts.len() / BLS12_381_SCALAR_LEN;
    let remain = MAX_AUDITOR_MEMO_SIZE * plaintexts.len() % BLS12_381_SCALAR_LEN;
    if remain != 0 {
        output_len += 1;
    }

    let outpus =
        AnemoiJive381::eval_stream_cipher(&[ephemeral_x, ephemeral_y, dh_x, dh_y], output_len);

    let mut ctexts = Vec::with_capacity(plaintexts.len());

    let outpus = outpus
        .iter()
        .map(|x| x.noah_to_bytes())
        .flatten()
        .collect::<Vec<u8>>();

    for (output, plaintext) in outpus
        .chunks_exact(MAX_AUDITOR_MEMO_SIZE)
        .zip(plaintexts.iter())
    {
        let ctext = output
            .iter()
            .zip(plaintext.iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<u8>>();
        ctexts.push(ctext)
    }

    Ok((
        EciesOutput { ephemeral, ctexts },
        ephemeral_sk,
        ephemeral,
        dh,
    ))
}

/// ECIES decrypt function
fn ecies_decrypt(sk: &JubjubScalar, output: &EciesOutput) -> Result<Vec<u8>> {
    // let dh = output.ephemeral.mul(&sk);

    // let dh_x = BLSScalar::from_field(dh.0.x);
    // let dh_y = BLSScalar::from_field(dh.0.y);
    // let trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[dh_x, dh_y]);

    // let mut key = [0u8; 32];
    // key.copy_from_slice(&trace.output.to_bytes());
    // let nonce = GenericArray::from_slice(&[0u8; 12]);

    // let gcm = {
    //     let res = aes_gcm::Aes256Gcm::new_from_slice(key.as_slice());
    //     if res.is_err() {
    //         return Err(eg!(NoahError::DecryptionError));
    //     }
    //     res.unwrap()
    // };

    // let res = {
    //     let res = gcm.decrypt(nonce, &output.ctexts[0]);
    //     if res.is_err() {
    //         return Err(eg!(NoahError::DecryptionError));
    //     }
    //     res.unwrap()
    // };
    Ok(vec![])
}
