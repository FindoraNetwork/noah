use crate::anon_xfr::{axfr_hybrid_decrypt, axfr_hybrid_encrypt, commit, decrypt_memo};
use crate::keys::{KeyPair, PublicKey, SecretKey};
use crate::parameters::params::AddressFormat::{ED25519, SECP256K1};
use crate::xfr::structs::AssetType;
use noah_algebra::{bls12_381::BLSScalar, prelude::*};
use noah_plonk::plonk::constraint_system::VarIndex;
use serde::Serialize;
use wasm_bindgen::prelude::*;

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
    /// The left child of its parent in a three-ary tree.
    pub left: BLSScalar,
    /// The mid child of its parent in a three-ary tree.
    pub mid: BLSScalar,
    /// The right child of its parent in a three-ary tree.
    pub right: BLSScalar,
    /// Whether this node is the left child of the parent.
    pub is_left_child: u8,
    /// Whether this node is the mid child of the parent.
    pub is_mid_child: u8,
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
        let (commitment, _) = commit(
            oabar.pub_key_ref(),
            oabar.get_blind(),
            oabar.get_amount(),
            oabar.get_asset_type().as_scalar(),
        )
        .unwrap();

        AnonAssetRecord { commitment }
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
            path: MTPath::new(vec![]),
            root: BLSScalar::zero(),
            root_version: 0,
            uid: 0,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
/// An opened anonymous asset record.
pub struct OpenAnonAssetRecord {
    pub(crate) amount: u64,
    pub(crate) asset_type: AssetType,
    pub(crate) blind: BLSScalar,
    pub(crate) pub_key: PublicKey,
    pub(crate) owner_memo: Option<AxfrOwnerMemo>,
    pub(crate) mt_leaf_info: Option<MTLeafInfo>,
}

impl Default for OpenAnonAssetRecord {
    fn default() -> Self {
        Self {
            amount: 0,
            asset_type: AssetType::default(),
            blind: BLSScalar::default(),
            pub_key: PublicKey::default(SECP256K1),
            owner_memo: None,
            mt_leaf_info: None,
        }
    }
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
    pub fn pub_key_ref(&self) -> &PublicKey {
        &self.pub_key
    }

    /// Get the blinding value
    pub fn get_blind(&self) -> BLSScalar {
        self.blind
    }

    /// Get record's owner memo
    pub fn get_owner_memo(&self) -> Option<AxfrOwnerMemo> {
        self.owner_memo.clone()
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
    pub fn pub_key(mut self, pub_key: &PublicKey) -> Self {
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
    /// If built via `Self::from_abar(...)`, return Err(NoahError::InconsistentStructureError)
    pub fn finalize<R: CryptoRng + RngCore>(mut self, prng: &mut R) -> Result<Self> {
        if self.oabar.owner_memo.is_some() {
            return Err(eg!(NoahError::InconsistentStructureError));
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
        key_pair: &KeyPair,
    ) -> Result<Self> {
        let (amount, asset_type, blind) = decrypt_memo(&owner_memo, key_pair, record).c(d!())?;
        let mut builder = OpenAnonAssetRecordBuilder::new()
            .pub_key(&key_pair.get_pk())
            .amount(amount)
            .asset_type(asset_type);

        builder.oabar.blind = blind;
        builder.oabar.owner_memo = Some(owner_memo);
        Ok(builder)
    }

    fn sanity_check(&self) -> Result<()> {
        // 1. check public key is non-default
        if self.oabar.pub_key == PublicKey::default(SECP256K1)
            || self.oabar.pub_key == PublicKey::default(ED25519)
        {
            return Err(eg!(NoahError::InconsistentStructureError));
        }

        // 2. OwnerMemo is not None
        if self.oabar.owner_memo.is_none() {
            return Err(eg!(NoahError::InconsistentStructureError));
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
    pub(crate) public_key_type: VarIndex,
    pub(crate) public_key_scalars: [VarIndex; 3],
}

/// The allocated variables for a Merkle tree node.
pub struct MerkleNodeVars {
    /// The allocated variable for the left.
    pub left: VarIndex,
    /// The allocated variable for the mid.
    pub mid: VarIndex,
    /// The allocated variable for the right.
    pub right: VarIndex,
    /// Whether this node is the left child of its parent.
    pub is_left_child: VarIndex,
    /// Whether this node is the mid child of its parent
    pub is_mid_child: VarIndex,
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

#[derive(Debug, Clone)]
/// The witness for the payer.
pub struct PayerWitness {
    /// The secret key.
    pub secret_key: SecretKey,
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
    /// The public key.
    pub public_key: PublicKey,
}

/// Information directed to secret key holder of a BlindAssetRecord
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AxfrOwnerMemo(Vec<u8>);

impl AxfrOwnerMemo {
    /// Crate an encrypted memo using the public key.
    pub fn new<R: CryptoRng + RngCore>(
        prng: &mut R,
        pub_key: &PublicKey,
        msg: &[u8],
    ) -> Result<Self> {
        let ctext = axfr_hybrid_encrypt(pub_key, prng, msg)?;
        Ok(Self(ctext))
    }

    /// Decrypt a memo using the viewing key.
    pub fn decrypt(&self, secret_key: &SecretKey) -> Result<Vec<u8>> {
        axfr_hybrid_decrypt(secret_key, &self.0)
    }

    /// Return the size of the memo.
    pub fn size(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod test {
    use crate::anon_xfr::structs::PublicKey;
    use crate::keys::KeyPair;
    use crate::parameters::AddressFormat::SECP256K1;
    use noah_algebra::prelude::*;

    #[test]
    fn test_axfr_pub_key_serialization() {
        let mut prng = test_rng();
        let keypair = KeyPair::sample(&mut prng, SECP256K1);

        let pub_key: PublicKey = keypair.get_pk();

        let bytes = pub_key.noah_to_bytes();
        assert_ne!(bytes.len(), 0);

        let reformed_pub_key = PublicKey::noah_from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(pub_key, reformed_pub_key);
    }

    #[test]
    fn test_axfr_key_pair_serialization() {
        let mut prng = test_rng();
        let keypair = KeyPair::sample(&mut prng, SECP256K1);

        let bytes: Vec<u8> = keypair.noah_to_bytes();
        assert_ne!(bytes.len(), 0);

        let reformed_key_pair = KeyPair::noah_from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(keypair, reformed_key_pair);
    }
}
