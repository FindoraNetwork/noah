use crate::anon_xfr::{
    decrypt_memo,
    keys::{AXfrKeyPair, AXfrPubKey, AXfrViewKey},
};
use crate::xfr::structs::AssetType;
use aes_gcm::{aead::Aead, NewAead};
use digest::{generic_array::GenericArray, Digest};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zei_algebra::{
    bls12_381::BLSScalar,
    jubjub::{JubjubPoint, JubjubScalar},
    prelude::*,
};
use zei_crypto::basic::rescue::RescueInstance;
use zei_plonk::plonk::constraint_system::VarIndex;

/// The nullifier.
pub type Nullifier = BLSScalar;
/// The commitment.
pub type Commitment = BLSScalar;
/// The blinding factor.
pub type BlindFactor = BLSScalar;

/// A Merkle tree node.
#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MTNode {
    /// The first sibling in a three-ary tree.
    pub siblings1: BLSScalar,
    /// The second sibling in a tree-ary tree.
    pub siblings2: BLSScalar,
    /// Whether this node is the left chlid of the parent.
    pub is_left_child: u8,
    /// Whether this node is the right child of the parent.
    pub is_right_child: u8,
}

/// Asset record to be put as leaves on the tree.
#[wasm_bindgen]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnonAssetRecord {
    /// The commitment.
    pub commitment: BLSScalar,
}

impl AnonAssetRecord {
    /// Generate the anonymous asset record from the opened version.
    pub fn from_oabar(oabar: &OpenAnonAssetRecord) -> AnonAssetRecord {
        AnonAssetRecord {
            commitment: oabar.compute_commitment(),
        }
    }
}

/// A Merkle tree leaf.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MTLeafInfo {
    /// The Merkle tree path.
    pub path: MTPath,
    /// The root hash.
    pub root: BLSScalar,
    /// The version of the Merkle tree.
    pub root_version: u64,
    /// The ID of the commitment.
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
/// An opened anonymous asset record.
pub struct OpenAnonAssetRecord {
    pub(crate) amount: u64,
    pub(crate) asset_type: AssetType,
    pub(crate) blind: BLSScalar,
    pub(crate) pub_key: AXfrPubKey,
    pub(crate) owner_memo: Option<AxfrOwnerMemo>,
    pub(crate) mt_leaf_info: Option<MTLeafInfo>,
}

impl OpenAnonAssetRecord {
    /// Set the Merkle tree leaf information.
    pub fn update_mt_leaf_info(&mut self, mt_leat_info: MTLeafInfo) {
        self.mt_leaf_info = Some(mt_leat_info);
    }
}

impl OpenAnonAssetRecord {
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

    /// Compute the record's amount||asset type||pub key commitment
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
            self.pub_key.0.get_x(),
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0]
    }
}

#[derive(Default)]
/// The builder for an opened anonymous asset record.
pub struct OpenAnonAssetRecordBuilder {
    pub(crate) oabar: OpenAnonAssetRecord,
}

impl OpenAnonAssetRecordBuilder {
    /// Created new OpenAnonBlindAssetRecord builder
    pub fn new() -> Self {
        OpenAnonAssetRecordBuilder {
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
    pub fn pub_key(mut self, pub_key: &AXfrPubKey) -> Self {
        self.oabar.pub_key = pub_key.clone();
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

        self.oabar.owner_memo = Some(AxfrOwnerMemo::new(prng, &self.oabar.pub_key, &msg)?);
        Ok(self)
    }

    /// Run a sanity check and if ok, return Ok(OpenBlindAssetRecord)
    pub fn build(self) -> Result<OpenAnonAssetRecord> {
        self.sanity_check().c(d!())?;
        Ok(self.oabar)
    }
}

impl OpenAnonAssetRecordBuilder {
    /// Build an OpenAssetRecord from an BlindAssetRecord, opening keys, owner memo and decryption keys
    /// Return error if decrypted `owner_memo` is inconsistent with `record`
    pub fn from_abar(
        record: &AnonAssetRecord,
        owner_memo: AxfrOwnerMemo,
        key_pair: &AXfrKeyPair,
    ) -> Result<Self> {
        let (amount, asset_type, blind) = decrypt_memo(&owner_memo, key_pair, record).c(d!())?;
        let mut builder = OpenAnonAssetRecordBuilder::new()
            .pub_key(&key_pair.get_pub_key())
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
    /// A list of tree nodes.
    pub nodes: Vec<MTNode>,
}

impl MTPath {
    /// Create a new Merkle path.
    pub fn new(nodes: Vec<MTNode>) -> Self {
        Self { nodes }
    }
}

pub(crate) struct PayerWitnessVars {
    pub(crate) spend_key: VarIndex,
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

/// The allocated variables for a Merkle tree node.
pub struct MerkleNodeVars {
    /// The allocated variable for the first sibling.
    pub siblings1: VarIndex,
    /// The allocated variable for the second sibling.
    pub siblings2: VarIndex,
    /// Whether this node is the left child of its parent.
    pub is_left_child: VarIndex,
    /// Whether this node is the right child of its parent.
    pub is_right_child: VarIndex,
}

/// The allocated variables for a Merkle tree path.
pub struct MerklePathVars {
    /// The list of allocated Merkle tree nodes.
    pub nodes: Vec<MerkleNodeVars>,
}

/// The allocated variables for a Merkle tree leaf.
pub struct AccElemVars {
    /// The ID of this commitment.
    pub uid: VarIndex,
    /// The commitment.
    pub commitment: VarIndex,
}

pub(crate) struct NullifierInputVars {
    pub(crate) uid_amount: VarIndex,
    pub(crate) asset_type: VarIndex,
    pub(crate) pub_key_x: VarIndex,
}

#[derive(Debug, Clone)]
/// The witness for the payer.
pub struct PayerWitness {
    /// The spending key.
    pub spend_key: BLSScalar,
    /// The amount.
    pub amount: u64,
    /// The asset type.
    pub asset_type: BLSScalar,
    /// The ID of the commitment to be nullified.
    pub uid: u64,
    /// The Merkle tree path.
    pub path: MTPath,
    /// The blinding factor in the output commitment.
    pub blind: BlindFactor,
}

#[derive(Debug, Clone)]
/// The witness for the payee.
pub struct PayeeWitness {
    /// The amount.
    pub amount: u64,
    /// The blinding factor in the output commitment.
    pub blind: BlindFactor,
    /// The asset type.
    pub asset_type: BLSScalar,
    /// The x coordinate of the public key.
    pub pubkey_x: BLSScalar,
}

/// Information directed to secret key holder of a BlindAssetRecord
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AxfrOwnerMemo {
    /// The random point used to generate the shared point.
    pub point: JubjubPoint,
    /// The ciphertext.
    pub ctext: Vec<u8>,
}

impl AxfrOwnerMemo {
    /// Crate an encrypted memo using the public key.
    pub fn new<R: CryptoRng + RngCore>(
        prng: &mut R,
        pub_key: &AXfrPubKey,
        msg: &[u8],
    ) -> Result<Self> {
        let share_scalar = JubjubScalar::random(prng);
        let share = JubjubPoint::get_base().mul(&share_scalar);

        let dh = pub_key.0.mul(&share_scalar);

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

        Ok(Self {
            point: share,
            ctext,
        })
    }

    /// Decrypt a memo using the viewing key.
    pub fn decrypt(&self, view_key: &AXfrViewKey) -> Result<Vec<u8>> {
        let dh = self.point.mul(&view_key.0);

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
            let res = gcm.decrypt(nonce, self.ctext.as_slice());

            if res.is_err() {
                return Err(eg!(ZeiError::DecryptionError));
            }

            res.unwrap()
        };
        Ok(res)
    }
}

#[cfg(test)]
mod test {
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::anon_xfr::structs::AXfrPubKey;
    use rand_chacha::ChaChaRng;
    use zei_algebra::prelude::*;

    #[test]
    fn test_axfr_pub_key_serialization() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);

        let pub_key: AXfrPubKey = keypair.get_pub_key();

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
