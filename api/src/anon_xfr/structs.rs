use crate::anon_xfr::{
    decrypt_memo,
    keys::{AXfrKeyPair, AXfrPubKey},
};
use crate::xfr::structs::{AssetType, OwnerMemo};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zei_algebra::{
    bls12_381::{BLSPairingEngine, BLSScalar},
    prelude::*,
};
use zei_crypto::basic::hybrid_encryption::{hybrid_encrypt_x25519, XPublicKey, XSecretKey};
use zei_crypto::basic::rescue::RescueInstance;
use zei_plonk::{plonk::indexer::PlonkPf, poly_commit::kzg_poly_com::KZGCommitmentScheme};

pub type Nullifier = BLSScalar;
pub type Commitment = BLSScalar;
pub type BlindFactor = BLSScalar;

/// A Merkle tree node which consists of the following:
/// * `siblings1` - the 1st sibling of the tree node
/// * `siblings2` - the 2nd sibling of the tree node
/// * `is_left_child` - indicates whether the tree node is the left child of its parent
/// * `is_right_child` - indicates whether the tree node is the right child of its parent
#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MTNode {
    pub siblings1: BLSScalar,
    pub siblings2: BLSScalar,
    pub is_left_child: u8,
    pub is_right_child: u8,
}

pub type SnarkProof = PlonkPf<KZGCommitmentScheme<BLSPairingEngine>>;

/// Anonymous transfers structure
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AXfrNote {
    /// The body part of AnonFee
    pub body: AXfrBody,
    /// The spending proof (assuming non-malleability)
    pub anon_xfr_proof: SnarkProof,
    /// The non-malleability tag
    pub non_malleability_tag: BLSScalar,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AXfrBody {
    pub inputs: Vec<Nullifier>,
    pub outputs: Vec<AnonBlindAssetRecord>,
    pub merkle_root: BLSScalar,
    pub merkle_root_version: u64,
    pub owner_memos: Vec<OwnerMemo>,
}

/// Asset record to be published
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

/// MT PATH, merkle root value, leaf identifier
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
    pub(crate) owner_memo: Option<OwnerMemo>,
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
    pub fn get_owner_memo(&self) -> Option<OwnerMemo> {
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
    pub fn finalize<R: CryptoRng + RngCore>(
        mut self,
        prng: &mut R,
        enc_key: &XPublicKey,
    ) -> Result<Self> {
        if self.oabar.owner_memo.is_some() {
            return Err(eg!(ZeiError::InconsistentStructureError));
        }

        self.oabar.blind = BLSScalar::random(prng);
        let mut msg = vec![];
        msg.extend_from_slice(&self.oabar.amount.to_le_bytes());
        msg.extend_from_slice(&self.oabar.asset_type.0);
        msg.extend_from_slice(&self.oabar.blind.to_bytes());
        let cipher = hybrid_encrypt_x25519(prng, enc_key, &msg);
        let memo = OwnerMemo {
            blind_share: Default::default(),
            lock: cipher,
        };
        self.oabar.owner_memo = Some(memo);
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
