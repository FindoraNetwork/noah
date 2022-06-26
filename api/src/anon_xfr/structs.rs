use crate::anon_xfr::decrypt_memo;
use crate::anon_xfr::keys::{KeyPair, PublicKey, Signature, ViewKey};
use crate::xfr::structs::{AssetType, OwnerMemo};
use aes_gcm::aead::Aead;
use aes_gcm::NewAead;
use digest::generic_array::GenericArray;
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zei_algebra::jubjub::{JubjubPoint, JubjubScalar, JUBJUB_SCALAR_LEN};
use zei_algebra::{bls12_381::BLSScalar, prelude::*};
use zei_crypto::basic::hybrid_encryption::{
    hybrid_encrypt_x25519, XPublicKey, XSecretKey, ZeiHybridCiphertext,
};
use zei_crypto::basic::rescue::RescueInstance;
use zei_plonk::plonk::constraint_system::VarIndex;

pub type Nullifier = BLSScalar;
pub type Commitment = BLSScalar;
pub type BlindFactor = BLSScalar;

/// A Merkle tree node.
#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MTNode {
    pub siblings1: BLSScalar,
    pub siblings2: BLSScalar,
    pub is_left_child: u8,
    pub is_right_child: u8,
}

/// Asset record to be put as leaves on the tree.
#[wasm_bindgen]
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AnonBlindAssetRecord {
    pub commitment: BLSScalar,
}

impl AnonBlindAssetRecord {
    pub fn from_oabar(oabar: &OpenAnonBlindAssetRecord) -> AnonBlindAssetRecord {
        AnonBlindAssetRecord {
            commitment: oabar.compute_commitment(),
        }
    }
}

/// A Merkle tree leaf.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MTLeafInfo {
    pub path: MTPath,
    pub root: BLSScalar,
    pub root_version: u64,
    pub uid: u64,
}

impl Default for MTLeafInfo {
    fn default() -> Self {
        MTLeafInfo {
            path: MTPath { nodes: vec![] },
            root: BLSScalar::zero(),
            root_version: 0,
            uid: 0,
        }
    }
}

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct OpenAnonBlindAssetRecord {
    pub(crate) amount: u64,
    pub(crate) asset_type: AssetType,
    pub(crate) blind: BLSScalar,
    pub(crate) pub_key: AXfrPubKey,
    pub(crate) owner_memo: Option<AxfrOwnerMemo>,
    pub(crate) mt_leaf_info: Option<MTLeafInfo>,
}

impl OpenAnonBlindAssetRecord {
    pub fn update_mt_leaf_info(&mut self, mt_leat_info: MTLeafInfo) {
        self.mt_leaf_info = Some(mt_leat_info);
    }
}

impl OpenAnonBlindAssetRecord {
    /// Get record amount
    pub fn get_amount(&self) -> u64 {
        self.amount
    }

    /// Get record asset type
    pub fn get_asset_type(&self) -> AssetType {
        self.asset_type
    }

    /// Get record public_key
    pub fn pub_key_ref(&self) -> &AXfrPubKey {
        &self.pub_key
    }

    /// Get record's owner memo
    pub fn get_owner_memo(&self) -> Option<AxfrOwnerMemo> {
        self.owner_memo.clone()
    }

    /// computes record's amount||asset type||pub key commitment
    pub fn compute_commitment(&self) -> Commitment {
        let hash = RescueInstance::new();
        let cur = hash.rescue(&[
            self.blind,
            BLSScalar::from(self.amount),
            self.asset_type.as_scalar(),
            BLSScalar::zero(),
        ])[0];
        hash.rescue(&[
            cur,
            self.pub_key.0.point_ref().get_x(),
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0]
    }
}

#[derive(Default)]
pub struct OpenAnonBlindAssetRecordBuilder {
    pub(crate) oabar: OpenAnonBlindAssetRecord,
}

// Builder pattern
impl OpenAnonBlindAssetRecordBuilder {
    /// Created new OpenAnonBlindAssetRecord builder
    pub fn new() -> Self {
        OpenAnonBlindAssetRecordBuilder {
            ..Default::default()
        }
    }

    /// Specify amount
    pub fn amount(mut self, amount: u64) -> Self {
        self.oabar.amount = amount;
        self
    }

    /// Specify asset_type
    pub fn asset_type(mut self, asset_type: AssetType) -> Self {
        self.oabar.asset_type = asset_type;
        self
    }

    /// Specify public_key
    pub fn pub_key(mut self, pub_key: AXfrPubKey) -> Self {
        self.oabar.pub_key = pub_key;
        self
    }

    /// Update mt_leaf_info
    pub fn mt_leaf_info(mut self, mt_leaf_info: MTLeafInfo) -> Self {
        self.oabar.update_mt_leaf_info(mt_leaf_info);
        self
    }

    /// Finalize builder:
    /// If built via constructor + builder methods, it samples commitment blinding and key randomization factor and
    /// creates associated owner memo.
    /// If built via `Self::from_abar(...)`, return Err(ZeiError::InconsistentStructureError)
    pub fn finalize<R: CryptoRng + RngCore>(mut self, prng: &mut R) -> Result<Self> {
        if self.oabar.owner_memo.is_some() {
            return Err(eg!(ZeiError::InconsistentStructureError));
        }

        self.oabar.blind = BLSScalar::random(prng);
        let mut msg = vec![];
        msg.extend_from_slice(&self.oabar.amount.to_le_bytes());
        msg.extend_from_slice(&self.oabar.asset_type.0);
        msg.extend_from_slice(&self.oabar.blind.to_bytes());

        self.oabar.owner_memo = Some(AxfrOwnerMemo::new(prng, &self.oabar.pub_key.0, &msg)?);
        Ok(self)
    }

    /// Run a sanity check and if ok, return Ok(OpenBlindAssetRecord)
    pub fn build(self) -> Result<OpenAnonBlindAssetRecord> {
        self.sanity_check().c(d!())?;
        Ok(self.oabar)
    }
}

impl OpenAnonBlindAssetRecordBuilder {
    /// Builds an OpenAssetRecord from an BlindAssetRecord, opening keys, owner memo and decryption keys
    /// Return error if decrypted `owner_memo` is inconsistent with `record`
    pub fn from_abar(
        record: &AnonBlindAssetRecord,
        owner_memo: OwnerMemo,
        key_pair: &AXfrKeyPair,
        dec_key: &XSecretKey,
    ) -> Result<Self> {
        let (amount, asset_type, blind) =
            decrypt_memo(&owner_memo, dec_key, key_pair, record).c(d!())?;
        let mut builder = OpenAnonBlindAssetRecordBuilder::new()
            .pub_key(key_pair.pub_key())
            .amount(amount)
            .asset_type(asset_type);

        builder.oabar.blind = blind;
        builder.oabar.owner_memo = Some(owner_memo);
        Ok(builder)
    }

    fn sanity_check(&self) -> Result<()> {
        // 1. check public key is non-default
        if self.oabar.pub_key == AXfrPubKey::default() {
            return Err(eg!(ZeiError::InconsistentStructureError));
        }

        // 2. OwnerMemo is not None
        if self.oabar.owner_memo.is_none() {
            return Err(eg!(ZeiError::InconsistentStructureError));
        }
        Ok(())
    }
}

/// An authentication path of a ternary Merkle tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MTPath {
    pub nodes: Vec<MTNode>,
}

impl MTPath {
    pub fn new(nodes: Vec<MTNode>) -> Self {
        Self { nodes }
    }
}

const AXFR_SECRET_KEY_LENGTH: usize = JUBJUB_SCALAR_LEN;
const AXFR_PUBLIC_KEY_LENGTH: usize = JubjubPoint::COMPRESSED_LEN;

/// Public key used to address an Anonymous records and verify transaction spending it
#[wasm_bindgen]
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default, Hash, Ord, PartialOrd, Copy,
)]
pub struct AXfrPubKey(pub(crate) PublicKey);

/// Keypair associated with an Anonymous records. It is used to spending it.
#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct AXfrKeyPair(pub(crate) KeyPair);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct AXfrSignature(pub(crate) Signature);

impl AXfrKeyPair {
    /// Generate a new signature key pair
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> AXfrKeyPair {
        AXfrKeyPair(KeyPair::generate(prng))
    }

    /// Return public key
    pub fn pub_key(&self) -> AXfrPubKey {
        AXfrPubKey(self.0.pub_key.clone())
    }

    /// Return the key pair
    pub fn from_secret_scalar(secret: JubjubScalar) -> Self {
        AXfrKeyPair(KeyPair::from_secret_scalar(secret))
    }

    /// Return secret key scalar value
    pub(crate) fn get_secret_scalar(&self) -> JubjubScalar {
        self.0.get_secret_scalar()
    }

    pub fn sign<R: CryptoRng + RngCore>(&self, prng: &mut R, msg: &[u8]) -> AXfrSignature {
        AXfrSignature(self.0.sign(prng, msg))
    }
}

impl ZeiFromToBytes for AXfrKeyPair {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.zei_to_bytes()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != (AXFR_SECRET_KEY_LENGTH + AXFR_PUBLIC_KEY_LENGTH) {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let keypair: KeyPair = KeyPair::zei_from_bytes(bytes).c(d!(""))?;

            Ok(AXfrKeyPair(keypair))
        }
    }
}

impl AXfrPubKey {
    /// return a reference to the EC group point defining the public key
    pub fn as_jubjub_point(&self) -> &JubjubPoint {
        self.0.point_ref()
    }

    /// Signature verification function
    pub fn verify(&self, msg: &[u8], sig: &AXfrSignature) -> Result<()> {
        self.0.verify(msg, &sig.0).c(d!())
    }
}

impl ZeiFromToBytes for AXfrPubKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.zei_to_bytes()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != AXFR_PUBLIC_KEY_LENGTH {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let point: JubjubPoint =
                JubjubPoint::zei_from_bytes(bytes).c(d!("error in deserializing JubJub point"))?;
            Ok(AXfrPubKey {
                0: PublicKey::from_point(point),
            })
        }
    }
}

pub(crate) struct PayerWitnessVars {
    pub(crate) sec_key: VarIndex,
    pub(crate) uid: VarIndex,
    pub(crate) amount: VarIndex,
    pub(crate) asset_type: VarIndex,
    pub(crate) path: MerklePathVars,
    pub(crate) blind: VarIndex,
}

pub(crate) struct PayeeWitnessVars {
    pub(crate) amount: VarIndex,
    pub(crate) blind: VarIndex,
    pub(crate) asset_type: VarIndex,
    pub(crate) pubkey_x: VarIndex,
}

// cs variables for a Merkle node
pub struct MerkleNodeVars {
    pub siblings1: VarIndex,
    pub siblings2: VarIndex,
    pub is_left_child: VarIndex,
    pub is_right_child: VarIndex,
}

// cs variables for a merkle authentication path
pub struct MerklePathVars {
    pub nodes: Vec<MerkleNodeVars>,
}

// cs variables for an accumulated element
pub struct AccElemVars {
    pub uid: VarIndex,
    pub commitment: VarIndex,
}

// cs variables for the nullifier PRF inputs
pub(crate) struct NullifierInputVars {
    pub(crate) uid_amount: VarIndex,
    pub(crate) asset_type: VarIndex,
    pub(crate) pub_key_x: VarIndex,
}

#[derive(Debug, Clone)]
pub struct PayerWitness {
    pub sec_key: JubjubScalar,
    pub amount: u64,
    pub asset_type: BLSScalar,
    pub uid: u64,
    pub path: MTPath,
    pub blind: BlindFactor,
}

#[derive(Debug, Clone)]
pub struct PayeeWitness {
    pub amount: u64,
    pub blind: BlindFactor,
    pub asset_type: BLSScalar,
    pub pubkey_x: BLSScalar,
}

/// Information directed to secret key holder of a BlindAssetRecord
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AxfrOwnerMemo {
    pub share: JubjubPoint,
    pub ctext: Vec<u8>,
}

impl AxfrOwnerMemo {
    fn new<R: CryptoRng + RngCore>(prng: &mut R, pub_key: &PublicKey, msg: &[u8]) -> Result<Self> {
        let share_scalar = JubjubScalar::random(prng);
        let share = JubjubPoint::get_base().mul(&share_scalar);

        let dh = pub_key.0.mul(&share_scalar);

        let mut hasher = sha2::Sha512::new();
        hasher.update(dh.as_bytes());
        let hash = hasher.finalize();

        let nonce = GenericArray::from_slice(&[0u8; 16]);

        let gcm = aes_gcm::Aes256Gcm::new_from_slice(hash.as_slice()).c(d!())?;
        let ctext = gcm.encrypt(nonce, msg).c(d!())?;

        Ok(Self { share, ctext })
    }

    fn decrypt(&self, view_key: &ViewKey) -> Result<Vec<u8>> {
        let dh = self.share.mul(&view_key.0);

        let mut hasher = sha2::Sha512::new();
        hasher.update(dh.as_bytes());
        let hash = hasher.finalize();

        let nonce = GenericArray::from_slice(&[0u8; 16]);

        let gcm = aes_gcm::Aes256Gcm::new_from_slice(hash.as_slice()).c(d!())?;
        gcm.decrypt(nonce, &self.ctext).c(d!())
    }
}

#[cfg(test)]
mod test {
    use crate::anon_xfr::structs::{AXfrKeyPair, AXfrPubKey};
    use rand_chacha::ChaChaRng;
    use zei_algebra::prelude::*;

    #[test]
    fn test_axfr_pub_key_serialization() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);

        let pub_key: AXfrPubKey = keypair.pub_key();

        let bytes = pub_key.zei_to_bytes();
        assert_ne!(bytes.len(), 0);

        let reformed_pub_key = AXfrPubKey::zei_from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(pub_key, reformed_pub_key);
    }

    #[test]
    fn test_axfr_key_pair_serialization() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);

        let bytes: Vec<u8> = keypair.zei_to_bytes();
        assert_ne!(bytes.len(), 0);

        let reformed_key_pair = AXfrKeyPair::zei_from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(keypair, reformed_key_pair);
    }
}
