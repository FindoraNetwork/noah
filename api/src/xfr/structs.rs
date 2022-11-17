use crate::anon_creds::{
    ACConfidentialRevealProof, ACIssuerPublicKey, AttributeCiphertext, AttributeDecKey,
    AttributeEncKey,
};
use crate::keys::{KeyPair, KeyType, MultiSig, PublicKey};
use crate::xfr::{
    asset_mixer::AssetMixProof,
    asset_record::AssetRecordType,
    asset_tracer::{RecordDataCiphertext, RecordDataDecKey, RecordDataEncKey},
};
use bulletproofs::RangeProof;
use digest::Digest;
use noah_algebra::{
    prelude::*,
    ristretto::{
        CompressedEdwardsY, CompressedRistretto, PedersenCommitmentRistretto, RistrettoScalar,
    },
    secp256k1::{SECP256K1Scalar, SECP256K1G1},
    traits::PedersenCommitment,
};
use noah_crypto::basic::{
    chaum_pedersen::ChaumPedersenProofX,
    elgamal::elgamal_key_gen,
    hybrid_encryption::{NoahHybridCiphertext, XPublicKey, XSecretKey},
    pedersen_elgamal::PedersenElGamalEqProof,
};
use sha2::Sha512;

/// Asset Type identifier.
pub const ASSET_TYPE_LENGTH: usize = 32;

#[derive(
    Deserialize, Serialize, Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord,
)]
/// The system-wide asset type representation.
pub struct AssetType(pub [u8; ASSET_TYPE_LENGTH]);

impl AssetType {
    /// Helper function to generate an asset type with identical value in each byte.
    pub fn from_identical_byte(byte: u8) -> Self {
        Self([byte; ASSET_TYPE_LENGTH])
    }

    /// Convert AssetType into a Scalar.
    pub fn as_scalar<S: Scalar>(&self) -> S {
        // Scalar representation length for JubjubScalar, RistrettoScalar, and BLSScalar
        const MIN_SCALAR_LENGTH: usize = 32;

        /// Asset type representation length. must be less than MIN_SCALAR_LEN
        /// All scalars in this code base are representable by 32 bytes, but
        /// values are less than 2^256 -1.
        const ASSET_TYPE_NOAH_REPR_LENGTH: usize = 30;

        let mut hash = sha2::Sha256::default();
        hash.update(&self.0);
        let array = hash.finalize();
        let mut noah_repr = [0u8; MIN_SCALAR_LENGTH];
        noah_repr[0..ASSET_TYPE_NOAH_REPR_LENGTH]
            .copy_from_slice(&array[0..ASSET_TYPE_NOAH_REPR_LENGTH]);

        if MIN_SCALAR_LENGTH == S::bytes_len() {
            return S::from_bytes(&noah_repr).unwrap(); //safe unwrap
        }
        let mut v = vec![0u8; S::bytes_len()];
        v[0..ASSET_TYPE_NOAH_REPR_LENGTH].copy_from_slice(&noah_repr);
        S::from_bytes(&v).unwrap()
    }
}

/// A confidential transfer note.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrNote {
    /// The confidential transfer body.
    pub body: XfrBody,
    /// The multisiganture of the senders
    pub multisig: MultiSig,
}

/// A confidential transfer body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrBody {
    /// The list of input (blind) asset records.
    pub inputs: Vec<BlindAssetRecord>,
    /// The list of output (blind) asset records.
    pub outputs: Vec<BlindAssetRecord>,
    /// The list of proofs.
    pub proofs: XfrProofs,
    /// The memos for access tracers.
    pub asset_tracing_memos: Vec<Vec<TracerMemo>>, // each input or output can have a set of tracing memos
    /// The memos for the recipients.
    pub owners_memos: Vec<Option<OwnerMemo>>, // If confidential amount or asset type, lock the amount and/or asset type to the public key in asset_record
}

/// A transfer input or output record as seen in the ledger.
/// Amount and asset type can be confidential or non confidential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlindAssetRecord {
    /// The amount.
    pub amount: XfrAmount,
    /// The asset type.
    pub asset_type: XfrAssetType,
    /// The owner's address.
    pub public_key: PublicKey,
}

impl BlindAssetRecord {
    /// Obtain the record type, which describes the level of confidentiality.
    pub fn get_record_type(&self) -> AssetRecordType {
        AssetRecordType::from_flags(
            matches!(self.amount, XfrAmount::Confidential(_)),
            matches!(self.asset_type, XfrAssetType::Confidential(_)),
        )
    }
}

/// Amount in blind asset record: if confidential, provide commitments for lower and hight 32 bits
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum XfrAmount {
    /// Confidential amount.
    Confidential((CompressedRistretto, CompressedRistretto)), // amount is a 64 bit positive integer expressed in base 2^32 in confidential transactions
    #[serde(with = "serde_str")]
    /// Transparent amount.
    NonConfidential(u64),
}

impl XfrAmount {
    /// Return true only if amount is confidential.
    /// # Example:
    /// ```
    /// use noah::xfr::structs::XfrAmount;
    /// use noah_algebra::ristretto::CompressedRistretto;
    /// let xfr_amount = XfrAmount::Confidential((CompressedRistretto::default(), CompressedRistretto::default()));
    /// assert!(xfr_amount.is_confidential());
    /// let xfr_amount = XfrAmount::NonConfidential(100u64);
    /// assert!(!xfr_amount.is_confidential());
    /// ```
    pub fn is_confidential(&self) -> bool {
        matches!(self, XfrAmount::Confidential(_))
    }
    /// Return Some(amount) if amount is non-confidential. Otherwise, return None
    /// # Example:
    /// ```
    /// use noah::xfr::structs::XfrAmount;
    /// use noah_algebra::ristretto::CompressedRistretto;
    /// let xfr_amount = XfrAmount::NonConfidential(100u64);
    /// assert_eq!(xfr_amount.get_amount().unwrap(), 100u64);
    /// let xfr_amount = XfrAmount::Confidential((CompressedRistretto::default(), CompressedRistretto::default()));
    /// assert!(xfr_amount.get_amount().is_none());
    /// ```
    pub fn get_amount(&self) -> Option<u64> {
        match self {
            XfrAmount::NonConfidential(x) => Some(*x),
            _ => None,
        }
    }

    /// Return Some((c1,c2)), where (c1,c2) is a commitment to the amount
    /// if amount is confidential. Otherwise, return None
    /// # Example:
    /// ```
    /// use noah::xfr::structs::XfrAmount;
    /// use noah_algebra::ristretto::CompressedRistretto;
    /// let xfr_amount = XfrAmount::NonConfidential(100u64);
    /// assert!(xfr_amount.get_commitments().is_none());
    /// let xfr_amount = XfrAmount::Confidential((CompressedRistretto::default(), CompressedRistretto::default()));
    /// assert_eq!(xfr_amount.get_commitments().unwrap(), (CompressedRistretto::default(), CompressedRistretto::default()));
    /// ```
    pub fn get_commitments(&self) -> Option<(CompressedRistretto, CompressedRistretto)> {
        match self {
            XfrAmount::Confidential(x) => Some(*x),
            _ => None,
        }
    }

    /// Construct a confidential amount with an amount and an amount blind.
    pub fn from_blinds(
        pc_gens: &PedersenCommitmentRistretto,
        amount: u64,
        blind_lo: &RistrettoScalar,
        blind_hi: &RistrettoScalar,
    ) -> Self {
        let (amount_lo, amount_hi) = u64_to_u32_pair(amount);
        let comm_lo = pc_gens
            .commit(RistrettoScalar::from(amount_lo), *blind_lo)
            .compress();
        let comm_hi = pc_gens
            .commit(RistrettoScalar::from(amount_hi), *blind_hi)
            .compress();
        XfrAmount::Confidential((comm_lo, comm_hi))
    }
}

/// Asset type in BlindAsset record: if confidential, provide commitment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum XfrAssetType {
    /// Confidential asset type.
    Confidential(CompressedRistretto),
    /// Transparent asset type.
    NonConfidential(AssetType),
}

impl XfrAssetType {
    /// Return true only if amount is confidential
    /// # Example:
    /// ```
    /// use noah::xfr::structs::{AssetType, XfrAssetType};
    /// use noah_algebra::ristretto::CompressedRistretto;
    /// let xfr_asset_type = XfrAssetType::Confidential(CompressedRistretto::default());
    /// assert!(xfr_asset_type.is_confidential());
    /// let xfr_asset_type = XfrAssetType::NonConfidential(AssetType::from_identical_byte(0u8));
    /// assert!(!xfr_asset_type.is_confidential());
    /// ```
    pub fn is_confidential(&self) -> bool {
        matches!(self, XfrAssetType::Confidential(_))
    }

    /// Return Some(asset_type) if asset_type is non-confidential. Otherwise, return None
    /// # Example:
    /// ```
    /// use noah::xfr::structs::{AssetType, XfrAssetType};
    /// use noah_algebra::ristretto::CompressedRistretto;
    /// let xfr_asset_type = XfrAssetType::NonConfidential(AssetType::from_identical_byte(0u8));
    /// assert_eq!(xfr_asset_type.get_asset_type().unwrap(), AssetType::from_identical_byte(0u8));
    /// let xfr_asset_type = XfrAssetType::Confidential(CompressedRistretto::default());
    /// assert!(xfr_asset_type.get_asset_type().is_none());
    /// ```
    pub fn get_asset_type(&self) -> Option<AssetType> {
        match self {
            XfrAssetType::NonConfidential(x) => Some(*x),
            _ => None,
        }
    }

    /// Return Some(c), where c is a commitment to the asset_type
    /// if asset_type is confidential. Otherwise, return None.
    /// # Example:
    /// ```
    /// use noah::xfr::structs::{AssetType, XfrAssetType};
    /// use noah_algebra::ristretto::CompressedRistretto;
    /// let xfr_asset_type = XfrAssetType::NonConfidential(AssetType::from_identical_byte(0u8));
    /// assert!(xfr_asset_type.get_commitment().is_none());
    /// let xfr_amount = XfrAssetType::Confidential(CompressedRistretto::default());
    /// assert_eq!(xfr_amount.get_commitment().unwrap(), CompressedRistretto::default());
    /// ```
    pub fn get_commitment(&self) -> Option<CompressedRistretto> {
        match self {
            XfrAssetType::Confidential(x) => Some(*x),
            _ => None,
        }
    }

    /// Construct a confidential asset type with an asset type and asset type blind.
    pub fn from_blind(
        pc_gens: &PedersenCommitmentRistretto,
        asset_type: &AssetType,
        blind: &RistrettoScalar,
    ) -> Self {
        let comm_type = pc_gens.commit(asset_type.as_scalar(), *blind).compress();
        XfrAssetType::Confidential(comm_type)
    }
}

/// Asset tracer encryption keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTracerEncKeys {
    /// The encryption key for amounts and asset types.
    pub record_data_enc_key: RecordDataEncKey,
    /// The encryption key for the attributes.
    pub attrs_enc_key: AttributeEncKey,
    /// The encryption key for the locked information.
    pub lock_info_enc_key: XPublicKey,
}

/// Asset tracer decryption keys.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTracerDecKeys {
    /// The decryption key for amounts and asset types.
    pub record_data_dec_key: RecordDataDecKey,
    /// The decryption key for the attributes.
    pub attrs_dec_key: AttributeDecKey,
    /// The decryption key for the locked information.
    pub lock_info_dec_key: XSecretKey,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
///An asset tracer key pair.
pub struct AssetTracerKeyPair {
    /// The encryption keys.
    pub enc_key: AssetTracerEncKeys,
    /// The decryption keys.
    pub dec_key: AssetTracerDecKeys,
}

impl AssetTracerKeyPair {
    /// Generate a new keypair for asset tracing.
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let (record_data_dec_key, record_data_enc_key) = elgamal_key_gen(prng);
        let (attrs_dec_key, attrs_enc_key) = elgamal_key_gen(prng);
        let lock_info_dec_key = XSecretKey::new(prng);
        let lock_info_enc_key = XPublicKey::from(&lock_info_dec_key);
        AssetTracerKeyPair {
            enc_key: AssetTracerEncKeys {
                record_data_enc_key,
                attrs_enc_key,
                lock_info_enc_key,
            },
            dec_key: AssetTracerDecKeys {
                record_data_dec_key,
                attrs_dec_key,
                lock_info_dec_key,
            },
        }
    }
}

/// Asset and identity tracing policies for an asset.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TracingPolicies(pub Vec<TracingPolicy>);

impl TracingPolicies {
    /// Construct an empty list of policies.
    pub fn new() -> Self {
        TracingPolicies(vec![])
    }
    /// Construct from the first policy.
    pub fn from_policy(policy: TracingPolicy) -> Self {
        TracingPolicies(vec![policy])
    }
    /// Append a policy to the list.
    pub fn add(&mut self, policy: TracingPolicy) {
        self.0.push(policy);
    }
    /// Obtain a specific policy.
    pub fn get_policy(&self, index: usize) -> Option<&TracingPolicy> {
        self.0.get(index)
    }
    /// Return a reference of the policies.
    pub fn get_policies(&self) -> &[TracingPolicy] {
        self.0.as_slice()
    }
    /// Return the number of policies.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Check if the list of policies is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An asset and identity tracing policy for an asset.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TracingPolicy {
    /// The asset tracer encryption keys.
    pub enc_keys: AssetTracerEncKeys,
    /// Whether the asset tracing is on.
    pub asset_tracing: bool,
    /// The identity revealing policy.
    pub identity_tracing: Option<IdentityRevealPolicy>,
}

/// An identity reveal policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityRevealPolicy {
    /// The public key of the credential issuer.
    pub cred_issuer_pub_key: ACIssuerPublicKey,
    /// The attribute revealing map.
    pub reveal_map: Vec<bool>, // i-th is true, if i-th attribute is to be revealed
}

/// Information directed to an asset tracer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TracerMemo {
    /// The asset tracer encryption keys, used to identify the tracer.
    pub enc_key: AssetTracerEncKeys,
    /// The ciphertexts of the amounts, each amount has one for higher 32 bits, and one for the lower 32 bits.
    pub lock_amount: Option<(RecordDataCiphertext, RecordDataCiphertext)>,
    /// The ciphertexts of the asset types.
    pub lock_asset_type: Option<RecordDataCiphertext>,
    /// The ciphertexts of the attributes.
    pub lock_attributes: Vec<AttributeCiphertext>,
    /// A hybrid encryption of amount, asset type, and attributes encrypted above for faster access.
    pub lock_info: NoahHybridCiphertext,
}

/// Information directed to the recipient.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OwnerMemo {
    /// The signature used curve type.
    pub key_type: KeyType,
    /// The random point used to compute the shared point.
    pub blind_share_bytes: Vec<u8>,
    /// The ciphertext of the memo information.
    pub lock_bytes: Vec<u8>,
}

impl OwnerMemo {
    /// Construct an `OwnerMemo` for an asset record with only confidential amount.
    pub fn from_amount<R: CryptoRng + RngCore>(
        prng: &mut R,
        amount: u64,
        pub_key: &PublicKey,
    ) -> Result<(Self, (RistrettoScalar, RistrettoScalar))> {
        let (key_type, r, blind_share_bytes) = pub_key.random_scalar_with_compressed_point(prng);
        let shared_point =
            OwnerMemo::derive_shared_point(&key_type, &r, &pub_key.as_compressed_point())?;
        let amount_blinds = OwnerMemo::calc_amount_blinds(&shared_point);

        let lock_bytes = pub_key.hybrid_encrypt(prng, &amount.to_be_bytes())?;
        Ok((
            OwnerMemo {
                key_type,
                blind_share_bytes,
                lock_bytes,
            },
            amount_blinds,
        ))
    }

    /// Construct an `OwnerMemo` for an asset record with only confidential asset type.
    pub fn from_asset_type<R: CryptoRng + RngCore>(
        prng: &mut R,
        asset_type: &AssetType,
        pub_key: &PublicKey,
    ) -> Result<(Self, RistrettoScalar)> {
        let (key_type, r, blind_share_bytes) = pub_key.random_scalar_with_compressed_point(prng);
        let shared_point =
            OwnerMemo::derive_shared_point(&key_type, &r, &pub_key.as_compressed_point())?;
        let asset_type_blind = OwnerMemo::calc_asset_type_blind(&shared_point);

        let lock_bytes = pub_key.hybrid_encrypt(prng, &asset_type.0)?;
        Ok((
            OwnerMemo {
                key_type,
                blind_share_bytes,
                lock_bytes,
            },
            asset_type_blind,
        ))
    }

    /// Construct an `OwnerMemo` for an asset record with both confidential amount and confidential asset type.
    pub fn from_amount_and_asset_type<R: CryptoRng + RngCore>(
        prng: &mut R,
        amount: u64,
        asset_type: &AssetType,
        pub_key: &PublicKey,
    ) -> Result<(Self, (RistrettoScalar, RistrettoScalar), RistrettoScalar)> {
        let (key_type, r, blind_share_bytes) = pub_key.random_scalar_with_compressed_point(prng);
        let shared_point =
            OwnerMemo::derive_shared_point(&key_type, &r, &pub_key.as_compressed_point())?;
        let amount_blinds = OwnerMemo::calc_amount_blinds(&shared_point);
        let asset_type_blind = OwnerMemo::calc_asset_type_blind(&shared_point);

        let mut amount_asset_type_plaintext = vec![];
        amount_asset_type_plaintext.extend_from_slice(&amount.to_be_bytes()[..]);
        amount_asset_type_plaintext.extend_from_slice(&asset_type.0[..]);
        let lock_bytes = pub_key.hybrid_encrypt(prng, &amount_asset_type_plaintext)?;
        Ok((
            OwnerMemo {
                key_type,
                blind_share_bytes,
                lock_bytes,
            },
            amount_blinds,
            asset_type_blind,
        ))
    }

    /// Decrypt the `OwnerMemo.lock` which encrypts only the confidential amount
    /// returns error if the decrypted bytes length doesn't match.
    pub fn decrypt_amount(&self, keypair: &KeyPair) -> Result<u64> {
        let decrypted_bytes = self.decrypt(&keypair)?;
        // amount is u64, thus u64.to_be_bytes should be 8 bytes
        if decrypted_bytes.len() != 8 {
            return Err(eg!(NoahError::InconsistentStructureError));
        }
        let mut amt_be_bytes: [u8; 8] = Default::default();
        amt_be_bytes.copy_from_slice(&decrypted_bytes[..]);
        Ok(u64::from_be_bytes(amt_be_bytes))
    }

    /// Decrypt the `OwnerMemo.lock` which encrypts only the confidential asset type
    /// returns error if the decrypted bytes length doesn't match.
    pub fn decrypt_asset_type(&self, keypair: &KeyPair) -> Result<AssetType> {
        let decrypted_bytes = self.decrypt(&keypair)?;
        if decrypted_bytes.len() != ASSET_TYPE_LENGTH {
            return Err(eg!(NoahError::InconsistentStructureError));
        }
        let mut asset_type_bytes: [u8; ASSET_TYPE_LENGTH] = Default::default();
        asset_type_bytes.copy_from_slice(&decrypted_bytes[..]);
        Ok(AssetType(asset_type_bytes))
    }

    /// Decrypt the `OwnerMemo.lock` which encrypts "amount || asset type", both amount and asset type
    /// are confidential.
    pub fn decrypt_amount_and_asset_type(&self, keypair: &KeyPair) -> Result<(u64, AssetType)> {
        let decrypted_bytes = self.decrypt(&keypair)?;
        if decrypted_bytes.len() != ASSET_TYPE_LENGTH + 8 {
            return Err(eg!(NoahError::InconsistentStructureError));
        }
        let mut amt_be_bytes: [u8; 8] = Default::default();
        amt_be_bytes.copy_from_slice(&decrypted_bytes[..8]);
        let mut asset_type_bytes: [u8; ASSET_TYPE_LENGTH] = Default::default();
        asset_type_bytes.copy_from_slice(&decrypted_bytes[8..]);

        Ok((
            u64::from_be_bytes(amt_be_bytes),
            AssetType(asset_type_bytes),
        ))
    }

    /// Return the amount blind (blind_low, blind_high)
    pub fn derive_amount_blinds(
        &self,
        keypair: &KeyPair,
    ) -> Result<(RistrettoScalar, RistrettoScalar)> {
        let (key_type, s) = keypair.sec_key.as_scalar_bytes();
        let shared_point = OwnerMemo::derive_shared_point(&key_type, &s, &self.blind_share_bytes)?;
        Ok(OwnerMemo::calc_amount_blinds(&shared_point))
    }

    /// Return the asset type blind
    pub fn derive_asset_type_blind(&self, keypair: &KeyPair) -> Result<RistrettoScalar> {
        let (key_type, s) = keypair.sec_key.as_scalar_bytes();
        let shared_point = OwnerMemo::derive_shared_point(&key_type, &s, &self.blind_share_bytes)?;
        Ok(OwnerMemo::calc_asset_type_blind(&shared_point))
    }
}

impl OwnerMemo {
    // Decrypt the lock.
    fn decrypt(&self, keypair: &KeyPair) -> Result<Vec<u8>> {
        keypair.hybrid_decrypt(&self.lock_bytes)
    }

    // Given a shared point, calculate the amount blinds.
    fn calc_amount_blinds(shared_point: &[u8]) -> (RistrettoScalar, RistrettoScalar) {
        (
            OwnerMemo::hash_to_scalar(&shared_point, b"amount_low"),
            OwnerMemo::hash_to_scalar(&shared_point, b"amount_high"),
        )
    }

    // Given a shared point, calculate the asset type blind.
    fn calc_asset_type_blind(shared_point: &[u8]) -> RistrettoScalar {
        OwnerMemo::hash_to_scalar(&shared_point, b"asset_type")
    }

    // Return the shared point.
    fn derive_shared_point(key_type: &KeyType, s: &[u8], p: &[u8]) -> Result<Vec<u8>> {
        match key_type {
            KeyType::Ed25519 => {
                let scalar = RistrettoScalar::from_bytes(s)?;
                let point = CompressedEdwardsY::from_slice(p);
                let shared_point = point.mul(&scalar);
                Ok(shared_point.to_bytes().to_vec())
            }
            KeyType::Secp256k1 => {
                let scalar = SECP256K1Scalar::from_bytes(s)?;
                let point = SECP256K1G1::from_compressed_bytes(p)?;
                let shared_point = point.mul(&scalar);
                Ok(shared_point.to_compressed_bytes())
            }
            KeyType::EthAddress => Err(eg!("Address not supported")),
        }
    }

    // Derive scalars from the shared point.
    fn hash_to_scalar(point: &[u8], aux: &'static [u8]) -> RistrettoScalar {
        let mut hasher = Sha512::new();
        hasher.update(point);
        hasher.update(aux);
        RistrettoScalar::from_hash(hasher)
    }
}

/// A BlindAssetRecord with revealed commitment openings.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct OpenAssetRecord {
    /// The blind version of the asset record.
    pub blind_asset_record: BlindAssetRecord,
    #[serde(with = "serde_str")]
    /// The amount.
    pub amount: u64,
    /// The blinding factors for the amount, one for higher 32 bits, one for lower 32 bits.
    pub amount_blinds: (RistrettoScalar, RistrettoScalar), // use RistrettoScalar::zero() if not needed
    /// The asset type.
    pub asset_type: AssetType,
    /// The blinding factor for the asset type.
    pub type_blind: RistrettoScalar, // use RistrettoScalar::zero() if not needed
}

impl OpenAssetRecord {
    /// Return the record type.
    pub fn get_record_type(&self) -> AssetRecordType {
        self.blind_asset_record.get_record_type()
    }
    /// Return the asset type.
    pub fn get_asset_type(&self) -> &AssetType {
        &self.asset_type
    }
    /// Return the amount.
    pub fn get_amount(&self) -> &u64 {
        &self.amount
    }
    /// Return the public key.
    pub fn get_pub_key(&self) -> &PublicKey {
        &self.blind_asset_record.public_key
    }
}

/// An input or output record and associated information (policies and memos).
/// It contains all the information used to the do a valid confidential transfer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetRecord {
    /// The opened version of the asset record.
    pub open_asset_record: OpenAssetRecord,
    /// The tracing policies.
    pub tracing_policies: TracingPolicies,
    /// The identity proof for asset tracers, one for each tracer.
    pub identity_proofs: Vec<Option<ACConfidentialRevealProof>>,
    /// The memo for asset tracers, one for each tracer.
    pub asset_tracers_memos: Vec<TracerMemo>,
    /// The owner memo.
    pub owner_memo: Option<OwnerMemo>,
}

/// An asset record template.
#[derive(Deserialize, Serialize)]
pub struct AssetRecordTemplate {
    /// The amount.
    #[serde(with = "serde_str")]
    pub amount: u64,
    /// The asset type.
    pub asset_type: AssetType,
    /// The ownership's address.
    pub public_key: PublicKey,
    /// The record type of this asset.
    pub asset_record_type: AssetRecordType,
    /// The tracing polices for this asset.
    pub asset_tracing_policies: TracingPolicies,
}

/// The amount and asset type part proof for confidential transfer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AssetTypeAndAmountProof {
    /// Multi-asset with any degree of confidentiality
    AssetMix(AssetMixProof),
    /// The proof for confidential amounts in the single-asset case.
    ConfAmount(XfrRangeProof), // single-type and transparent, confidential amount
    /// The proof for confidential asset type in the single-asset case.
    ConfAsset(Box<ChaumPedersenProofX>),
    /// Both proofs for fully confidential single-asset.
    ConfAll(Box<(XfrRangeProof, ChaumPedersenProofX)>),
    /// No proof for a transparent transaction.
    NoProof,
}

/// The proofs for a confidential transfer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrProofs {
    /// The amount and asset type proof.
    pub asset_type_and_amount_proof: AssetTypeAndAmountProof,
    /// The access tracing proof.
    pub asset_tracing_proof: AssetTracingProofs,
}

/// The range proof building block of the amount and asset type part.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct XfrRangeProof {
    /// The Bulletproofs range proof.
    #[serde(with = "noah_obj_serde")]
    pub range_proof: RangeProof,
    /// Lower 32 bits transfer amount difference commitment.
    pub xfr_diff_commitment_low: CompressedRistretto,
    /// Higher 32 bits transfer amount difference commitment.
    pub xfr_diff_commitment_high: CompressedRistretto,
}

/// The asset tracing proofs.
/// Proof of records' data and identity tracing
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTracingProofs {
    /// The list of amount and asset type proofs.
    pub asset_type_and_amount_proofs: Vec<PedersenElGamalEqProof>, // One proof for each tracing key
    /// The identity revealing proofs for each input.
    pub inputs_identity_proofs: Vec<Vec<Option<ACConfidentialRevealProof>>>, // None if asset policy does not require identity tracing for input. Otherwise, value proves that ElGamal ciphertexts encrypts encrypts attributes that satisfy an credential verification
    /// The identity revealing proofs for each output.
    pub outputs_identity_proofs: Vec<Vec<Option<ACConfidentialRevealProof>>>, // None if asset policy does not require identity tracing for output. Otherwise, value proves that ElGamal ciphertexts encrypts encrypts attributes that satisfy an credential verification
}

impl PartialEq for XfrRangeProof {
    fn eq(&self, other: &XfrRangeProof) -> bool {
        self.range_proof.to_bytes() == other.range_proof.to_bytes()
            && self.xfr_diff_commitment_low == other.xfr_diff_commitment_low
            && self.xfr_diff_commitment_high == other.xfr_diff_commitment_high
    }
}

impl Eq for XfrRangeProof {}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum CompatibleKeyType {
    Old,
    New(KeyType),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum CompatibleBlindShare {
    Old(CompressedEdwardsY),
    New(Vec<u8>),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum CompatibleLock {
    Old(NoahHybridCiphertext),
    New(Vec<u8>),
}

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

impl<'de> Deserialize<'de> for OwnerMemo {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            KeyType,
            BlindShare,
            BlindShareBytes,
            Lock,
            LockBytes,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        formatter.write_str("`blind_share` or `lock` or `key_type`")
                    }

                    fn visit_str<E>(self, value: &str) -> std::result::Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "key_type" => Ok(Field::KeyType),
                            "blind_share" => Ok(Field::BlindShare),
                            "blind_share_bytes" => Ok(Field::BlindShareBytes),
                            "lock" => Ok(Field::Lock),
                            "lock_bytes" => Ok(Field::LockBytes),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct OwnerMemoVisitor;

        impl<'de> Visitor<'de> for OwnerMemoVisitor {
            type Value = OwnerMemo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct OwnerMemo")
            }

            fn visit_seq<V>(self, mut seq: V) -> std::result::Result<OwnerMemo, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let com_key_type = seq
                    .next_element::<CompatibleKeyType>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let key_type = match com_key_type {
                    CompatibleKeyType::Old => KeyType::Ed25519,
                    CompatibleKeyType::New(k) => k,
                };
                let com_blind_share = seq
                    .next_element::<CompatibleBlindShare>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let blind_share_bytes = match com_blind_share {
                    CompatibleBlindShare::Old(k) => k.0.to_bytes().to_vec(),
                    CompatibleBlindShare::New(k) => k,
                };
                let com_lock = seq
                    .next_element::<CompatibleLock>()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let lock_bytes = match com_lock {
                    CompatibleLock::Old(k) => k.noah_to_bytes(),
                    CompatibleLock::New(k) => k,
                };
                Ok(OwnerMemo {
                    key_type,
                    blind_share_bytes,
                    lock_bytes,
                })
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<OwnerMemo, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut key_type = None;
                let mut blind_share_bytes = None;
                let mut lock_bytes = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::KeyType => {
                            if key_type.is_some() {
                                return Err(de::Error::duplicate_field("key_type"));
                            }
                            key_type = Some(map.next_value()?);
                        }
                        Field::BlindShare => {
                            if blind_share_bytes.is_some() {
                                return Err(de::Error::duplicate_field("blind_share"));
                            }
                            let tmp = map.next_value::<CompressedEdwardsY>()?;
                            blind_share_bytes = Some(tmp.0.to_bytes().to_vec());
                        }
                        Field::BlindShareBytes => {
                            if blind_share_bytes.is_some() {
                                return Err(de::Error::duplicate_field("blind_share"));
                            }
                            blind_share_bytes = Some(map.next_value()?);
                        }
                        Field::Lock => {
                            if lock_bytes.is_some() {
                                return Err(de::Error::duplicate_field("lock"));
                            }
                            let tmp = map.next_value::<NoahHybridCiphertext>()?;
                            lock_bytes = Some(tmp.noah_to_bytes());
                        }
                        Field::LockBytes => {
                            if lock_bytes.is_some() {
                                return Err(de::Error::duplicate_field("lock"));
                            }
                            lock_bytes = Some(map.next_value()?);
                        }
                    }
                }
                let key_type = key_type.unwrap_or(KeyType::Ed25519);
                let blind_share_bytes =
                    blind_share_bytes.ok_or_else(|| de::Error::missing_field("blind_share"))?;
                let lock_bytes = lock_bytes.ok_or_else(|| de::Error::missing_field("lock"))?;
                Ok(OwnerMemo {
                    key_type,
                    blind_share_bytes,
                    lock_bytes,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &[
            "key_type",
            "blind_share",
            "blind_share_bytes",
            "lock",
            "lock_bytes",
        ];
        deserializer.deserialize_struct("OwnerMemo", FIELDS, OwnerMemoVisitor)
    }
}
