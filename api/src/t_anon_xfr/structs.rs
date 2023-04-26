use crate::{
    keys::PublicKey,
    xfr::structs::{AssetType, ASSET_TYPE_LENGTH},
};
use noah_algebra::{
    bls12_381::{BLSScalar, BLS12_381_SCALAR_LEN},
    jubjub::{JubjubPoint, JubjubScalar},
    prelude::*,
    traits::Domain,
};
use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381};

impl AssetType {
    /// Generate asset type with auditor public key.
    pub fn generate<R: CryptoRng + RngCore>(
        prng: &mut R,
        pk: &AuditorPublicKey,
    ) -> Result<(AssetType, BLSScalar)> {
        // todo()
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

/// An auditor’s memo that accurately describes contents of the transactions.
#[derive(Clone, Default, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TAxfrAuditorMemo(Vec<Vec<u8>>);

/// The secret key for auditor.
#[derive(Debug)]
pub struct AuditorSecretKey(pub JubjubScalar);

impl TAxfrAuditorMemo {
    /// Encrypt struct data to memo bytes
    pub fn new<R: CryptoRng + RngCore>(
        prng: &mut R,
        pk: &AuditorPublicKey,
        plaintexts: &[TAxfrAuditorProMemo],
    ) -> (Self, JubjubScalar, JubjubPoint, JubjubPoint) {
        let output = ecies_encrypt(prng, &pk.0, plaintexts);
        let ctext_bytes = output.0.to_bytes();

        (TAxfrAuditorMemo(ctext_bytes), output.1, output.2, output.3)
    }

    /// Try to decryp memo bytes to struct data
    pub fn decrypt(sk: &AuditorSecretKey, ciphertext: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        let ecies = EciesOutput::from_bytes(ciphertext)?;
        Ok(ecies_decrypt(&sk.0, &ecies))
    }
}

/// An auditor’s memo to be encrypted.
pub struct TAxfrAuditorProMemo {
    amount_asset_type: BLSScalar,
    blind: BLSScalar,
    receiver: PublicKey,
}

impl TAxfrAuditorProMemo {
    /// Create an auditor's memo that is to be encrypted.
    // fn new(amount_asset_type: BLSScalar, blind: BLSScalar, receiver: PublicKey) -> Self {
    //     Self {
    //         amount_asset_type,
    //         blind,
    //         receiver,
    //     }
    // }

    /// Convert auditor memo to bytes.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.amount_asset_type.noah_to_bytes());
        bytes.extend(self.blind.noah_to_bytes());
        bytes.extend(self.receiver.noah_to_bytes());
        bytes
    }
}

/// ECIES Hybrid Encryption Scheme.
struct EciesOutput {
    /// ephemeral encrypt public key.
    ephemeral: JubjubPoint,
    /// encrypted message.
    ctexts: Vec<Vec<u8>>,
}

impl EciesOutput {
    /// Convert ECIES output to bytes.
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        let mut bytes = vec![];
        bytes.push(self.ephemeral.to_compressed_bytes());
        self.ctexts.iter().for_each(|x| bytes.push(x.to_vec()));
        bytes
    }

    /// Convert bytes to ECIES output.
    fn from_bytes(bytes: &[&[u8]]) -> Result<EciesOutput> {
        let len: usize = JubjubPoint::COMPRESSED_LEN;
        if bytes[0].len() < len {
            return Err(eg!(NoahError::DeserializationError));
        }
        let ephemeral = JubjubPoint::from_compressed_bytes(&bytes[0][..len])?;

        let ctexts = bytes.iter().skip(1).map(|x| x.to_vec()).collect();

        Ok(Self { ephemeral, ctexts })
    }
}

/// ECIES encrypt function.
fn ecies_encrypt<R: CryptoRng + RngCore>(
    prng: &mut R,
    pk: &JubjubPoint,
    plaintexts: &[TAxfrAuditorProMemo],
) -> (EciesOutput, JubjubScalar, JubjubPoint, JubjubPoint) {
    let ephemeral_sk: JubjubScalar = JubjubScalar::random(prng);
    let ephemeral = JubjubPoint::get_base().mul(&ephemeral_sk);
    let dh: JubjubPoint = pk.mul(&ephemeral_sk);

    let ephemeral_x = BLSScalar::from_field(ephemeral.0.x);
    let ephemeral_y = BLSScalar::from_field(ephemeral.0.y);
    let dh_x = BLSScalar::from_field(dh.0.x);
    let dh_y = BLSScalar::from_field(dh.0.y);

    let plaintexts = plaintexts.iter().map(|x| x.to_bytes()).collect::<Vec<_>>();
    let total_memo_size = plaintexts.iter().map(|x| x.len()).sum::<usize>();

    let output_len = total_memo_size / (BLS12_381_SCALAR_LEN - 1)
        + if total_memo_size % (BLS12_381_SCALAR_LEN - 1) == 0 {
            0
        } else {
            1
        };

    let stream_blinds =
        AnemoiJive381::eval_stream_cipher(&[ephemeral_x, ephemeral_y, dh_x, dh_y], output_len);

    let stream_blinds = stream_blinds
        .iter()
        .map(|x| x.noah_to_bytes())
        .flatten()
        .collect::<Vec<u8>>();

    let mut ctexts = Vec::with_capacity(plaintexts.len());
    let mut sum = 0;

    for plaintext in plaintexts.iter() {
        let size = plaintext.len();
        let blind = &stream_blinds[sum..sum + size];
        let ctext = plaintext
            .iter()
            .zip(blind.iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<u8>>();
        ctexts.push(ctext);
        sum += size
    }

    (
        EciesOutput { ephemeral, ctexts },
        ephemeral_sk,
        ephemeral,
        dh,
    )
}

/// ECIES decrypt function.
fn ecies_decrypt(sk: &JubjubScalar, ecies: &EciesOutput) -> Vec<Vec<u8>> {
    let dh = ecies.ephemeral.mul(&sk);

    let ephemeral_x = BLSScalar::from_field(ecies.ephemeral.0.x);
    let ephemeral_y = BLSScalar::from_field(ecies.ephemeral.0.y);
    let dh_x = BLSScalar::from_field(dh.0.x);
    let dh_y = BLSScalar::from_field(dh.0.y);

    let total_memo_size = ecies.ctexts.iter().map(|x| x.len()).sum::<usize>();
    let output_len = total_memo_size / (BLS12_381_SCALAR_LEN - 1)
        + if total_memo_size % (BLS12_381_SCALAR_LEN - 1) == 0 {
            0
        } else {
            1
        };

    let stream_blinds =
        AnemoiJive381::eval_stream_cipher(&[ephemeral_x, ephemeral_y, dh_x, dh_y], output_len);

    let stream_blinds = stream_blinds
        .iter()
        .map(|x| x.noah_to_bytes())
        .flatten()
        .collect::<Vec<u8>>();

    let mut res = Vec::with_capacity(ecies.ctexts.len());
    let mut sum: usize = 0;

    for ctext in ecies.ctexts.iter() {
        let size = ctext.len();
        let blind = &stream_blinds[sum..sum + size];
        let r = ctext
            .iter()
            .zip(blind.iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<u8>>();
        res.push(r);
        sum += size
    }

    res
}
