use crate::xfr::structs::AssetType;
use noah_algebra::{
    bls12_381::{BLSScalar, BLS12_381_SCALAR_LEN},
    jubjub::{JubjubPoint, JubjubScalar},
    prelude::*,
};
use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381};
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Compute the expected number of BLS scalar elements in the memo ciphertext.
///
/// Note that the memo ciphertext consists of other information, such as:
/// - The Diffie-Hellman key exchange group element, r * G
/// - A fast-detection element
///
/// So it would consist of more elements than what we show here.
///
pub fn get_auditor_memo_length(num_inputs: usize, num_outputs: usize) -> usize {
    // Every transaction has at most one audited asset, which means that there
    // is also at most one auditor.
    //
    // The auditor will be presented all the input and output information.
    //
    // The memo first includes the sender address (3 BLS scalar elements).
    //
    // Note that, similar to anon_xfr, we prefer to consolidate assets into
    // a few addresses, and therefore, we also restrict all the inputs to
    // have the same owner (same public key).
    //
    // For each input, the memo includes:
    // - the coin commitment, which enables back-tracing.
    // - the amount
    // - the asset type (all not assets have to be the audited one)
    //
    // For each output, the memo includes:
    // - the amount
    // - the asset type
    // - the receiving address (it takes 3 BLS scalar elements)
    // - the randomizer

    return 3 + num_inputs * (1 + 1 + 1) + num_outputs * (1 + 1 + 3 + 1);
}

/// A struct for the auditor's memo.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct NabarAuditorMemo {
    /// The Diffie-Hellman key exchange group element.
    ///
    /// Note: we explicitly stress that this point is often uncompressed and unchecked,
    /// and the application should take the responsibility to make application-specific checks.
    pub dh_point_unchecked: JubjubPoint,
    /// The fast-detection element.
    pub fast_detection: BLSScalar,
    /// The body of the memo.
    pub body: Vec<BLSScalar>,
}

impl Serialize for NabarAuditorMemo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::<u8>::new();

        // We overwrite the serialization algorithm to avoid the need of recovering the point.
        bytes.extend_from_slice(&self.dh_point_unchecked.to_unchecked_bytes());
        bytes.extend_from_slice(&self.fast_detection.noah_to_bytes());

        for elem in self.body.iter() {
            bytes.extend_from_slice(&elem.noah_to_bytes());
        }

        if serializer.is_human_readable() {
            serializer.serialize_str(&b64enc(&bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for NabarAuditorMemo {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            deserializer.deserialize_str(noah_obj_serde::BytesVisitor)?
        } else {
            deserializer.deserialize_bytes(noah_obj_serde::BytesVisitor)?
        };

        let dh_point_unchecked = {
            let res = JubjubPoint::from_unchecked_bytes(&bytes[0..64]);

            if res.is_err() {
                return Err(SerdeError::custom(res.unwrap_err()));
            }

            res.unwrap()
        };

        let fast_detection = {
            let res = BLSScalar::noah_from_bytes(&bytes[64..96]);

            if res.is_err() {
                return Err(SerdeError::custom(res.unwrap_err()));
            }

            res.unwrap()
        };

        let remaining_bytes = bytes.len() - 96;
        if remaining_bytes % BLS12_381_SCALAR_LEN != 0 {
            return Err(SerdeError::custom(
                "The auditor memo does not have the correct length.",
            ));
        }

        let mut body = Vec::with_capacity(remaining_bytes / BLS12_381_SCALAR_LEN);
        for elem_bytes in bytes[96..].chunks_exact(96) {
            let res = BLSScalar::noah_from_bytes(&elem_bytes);
            if res.is_err() {
                return Err(SerdeError::custom(res.unwrap_err()));
            }
            body.push(res.unwrap());
        }

        Ok(Self {
            dh_point_unchecked,
            fast_detection,
            body,
        })
    }
}

/// SNARK-friendly signature used to authorize encryption keys.
///
/// We do not need to enforce the signature to be deterministic, and for our use case, we want a
/// signature scheme whose verification algorithm does not involve algebraic operations over the
/// scalar field (as it would be nonnative arithmetics).
///
/// We also favor a signature scheme that does not require a lot of sanity checks, such as checking
/// if some values are nonzeros.
///
/// We identify the Schnorr signature over Jubjub to be a use case. However, note that we play with
/// the hash function a bit, as we will be doing the hash function used in the Schnorr signature over
/// the BLS12-381's scalar field.
///
pub struct NabarAuditKeySignature {
    /// The s element of the signature for authorizing encryption keys.
    pub schnorr_s: JubjubScalar,
    /// the r element of the signature for authorizing encryption keys.
    pub schnorr_e: BLSScalar,
}

/// The struct for the signing key, which would be of the Schnorr signature scheme.
#[derive(Clone, Default)]
pub struct NabarAuditSigningKey(JubjubScalar);

/// The struct for the verifying key, which would be of the Schnorr signature scheme.
#[derive(Clone, Default)]
pub struct NabarAuditVerifyingKey(JubjubPoint);

/// The struct for the encryption key.
#[derive(Clone, Default)]
pub struct NabarAuditEncryptionKey(JubjubPoint);

/// The struct for the decryption key.
#[derive(Clone, Default)]
pub struct NabarAuditDecryptionKey(JubjubScalar);

impl NabarAuditSigningKey {
    /// Sample the signing key.
    pub fn sample<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self(JubjubScalar::random(prng))
    }

    /// Get the raw Jubjub scalar element.
    pub fn get_raw(&self) -> JubjubScalar {
        self.0
    }

    /// Reconstruct from the raw Jubjub scalar element.
    pub fn from_raw(raw: JubjubScalar) -> Self {
        Self(raw)
    }

    /// Compute the corresponding verifying key.
    pub fn to_verifying_key(&self) -> NabarAuditVerifyingKey {
        NabarAuditVerifyingKey(JubjubPoint::get_base().mul(&self.0))
    }

    /// Sign an encryption key.
    pub fn sign<R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        ek: &NabarAuditEncryptionKey,
    ) -> NabarAuditKeySignature {
        let k = JubjubScalar::random(prng);
        let point_r = JubjubPoint::get_base().mul(&k);

        let e = AnemoiJive381::eval_variable_length_hash(&[
            BLSScalar::zero(),
            point_r.get_x(),
            point_r.get_y(),
            ek.0.get_x(),
            ek.0.get_y(),
        ]);

        // This will perform a modular reduction.
        let e_converted = JubjubScalar::from(&e.into());

        let s = k - &(self.0 * &e_converted);

        NabarAuditKeySignature {
            schnorr_s: s,
            schnorr_e: e,
        }
    }
}

impl NabarAuditVerifyingKey {
    /// Get the raw Jubjub point element.
    pub fn get_raw(&self) -> JubjubPoint {
        self.0
    }

    /// Reconstruct from the raw Jubjub point element.
    pub fn from_raw(raw: JubjubPoint) -> Self {
        Self(raw)
    }

    /// Verify the signature of an encryption key.
    pub fn verify(
        &self,
        ek: &NabarAuditEncryptionKey,
        signature: &NabarAuditKeySignature,
    ) -> Result<()> {
        let e_converted = JubjubScalar::from(&signature.schnorr_e.into());

        let point_r_recovered =
            JubjubPoint::get_base().mul(&signature.schnorr_s) + &self.0.mul(&e_converted);

        let e = AnemoiJive381::eval_variable_length_hash(&[
            BLSScalar::zero(),
            point_r_recovered.get_x(),
            point_r_recovered.get_y(),
            ek.0.get_x(),
            ek.0.get_y(),
        ]);
        if e != signature.schnorr_e {
            Err(eg!(NoahError::SignatureError))
        } else {
            Ok(())
        }
    }
}

/// On-chain disclosure for a new asset that has the auditability.
///
/// Note: this asset is not limited to Nextgen assets. To enforce the auditability,
/// the enforcement must propagate all the ways to transparent, Maxwell, and Zerocash assets.
/// - Maxwell assets and Zerocash assets are completely suspended for auditable assets.
///   Transactions that include auditable assets in ops that involve Maxwell or Zerocash will fail.
/// - This is done by having the consensus to remember a list of all auditable assets.
///
/// The disclosure performs three things:
/// - declare that an asset code represents an auditable asset
///     (which would be verified for consistency on the platform side).
/// - provide the randomness and the signature verifying key for the auditor.
/// - provide a number of signed encryption key.
///
/// A transaction fee shall be charged for on-chain disclosure.
pub struct NabarAuditableAssetIssuance {
    /// The asset type code that has been remapped (after the domain separation,
    /// which modifies the asset type code and specifies it as an auditable asset).
    ///
    /// This should be handled by the application layer to check if the remapping
    /// is correct in respect to the randomness and the signature verifying key, which
    /// is expected to unique.
    pub remapped_asset_type: AssetType,
    /// The signature verifying key, which is a point on the Jubjub curve.
    ///
    /// However, note that the Jubjub curve has cofactor 8.
    /// Checking if the point is in the correct subgroup is cumbersome.
    ///
    /// Therefore, we choose a separate way of implementation.
    /// The issuance request should use sign_vk divided by 8.
    /// This allows the other party to get the actual point by simply
    /// multiplying by 8 (i.e., doubling three times).
    pub sign_vk_div_by_cofactor: JubjubPoint,
    /// A list of encryption keys to be authorized.
    pub enc_ek: Vec<NabarAuditEncryptionKey>,
    /// A list of signatures for such authorization.
    pub enc_sign: Vec<NabarAuditKeySignature>,
}

impl NabarAuditableAssetIssuance {
    /// Compute the actual, reconstructed signature verifying key.
    pub fn get_sign_vk(&self) -> NabarAuditVerifyingKey {
        NabarAuditVerifyingKey(self.sign_vk_div_by_cofactor.double().double().double())
    }
}

/// On-chain update notices to the list of encryption keys.
///
/// The owner of the related signature signing key

/*
/// ECIES encrypt function.
fn ecies_encrypt<R: CryptoRng + RngCore>(
    prng: &mut R,
    pk: &JubjubPoint,
    plaintexts: &[NabarAuditorMemo],
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

*/
