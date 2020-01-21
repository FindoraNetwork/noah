use crate::api::anon_creds::ACIssuerPublicKey;
use crate::api::conf_cred_reveal::ConfidentialAC;
use crate::basic_crypto::elgamal::{ElGamalCiphertext, ElGamalPublicKey};
use crate::basic_crypto::hybrid_encryption::ZeiHybridCipher;
use crate::crypto::chaum_pedersen::ChaumPedersenProofX;
use crate::crypto::pedersen_elgamal::PedersenElGamalEqProof;
use crate::errors::ZeiError;
use crate::serialization;
use crate::xfr::asset_mixer::AssetMixProof;
use crate::xfr::sig::{XfrMultiSig, XfrPublicKey};
use curve25519_dalek::edwards::CompressedEdwardsY;

use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

pub type AssetType = [u8; 16];

/// I represent a transfer note
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]

pub struct XfrNote {
  pub body: XfrBody,
  pub multisig: XfrMultiSig,
}

impl XfrNote {
  pub fn outputs_iter(&self) -> std::slice::Iter<BlindAssetRecord> {
    self.body.outputs.iter()
  }
}

/// I am the body of a transfer note
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrBody {
  pub inputs: Vec<BlindAssetRecord>,
  pub outputs: Vec<BlindAssetRecord>,
  pub proofs: XfrProofs,
}

pub type EGPubKey = ElGamalPublicKey<RistrettoPoint>;
type EGPubKeyId = crate::api::conf_cred_reveal::ElGamalPublicKey;
type EGCText = ElGamalCiphertext<RistrettoPoint>;

/// I'm a bundle of public keys for the asset issuer
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetIssuerPubKeys {
  pub eg_ristretto_pub_key: EGPubKey,
  pub eg_blsg1_pub_key: EGPubKeyId,
}
/// I represent an Asset Record as presented in the public ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlindAssetRecord {
  // amount is a 64 bit positive integer expressed in base 2^32 in confidential transaction
  // commitments and ciphertext
  pub issuer_public_key: Option<AssetIssuerPubKeys>, //None if issuer tracking is not required
  pub issuer_lock_amount: Option<(EGCText, EGCText)>, //None if issuer tracking not required or amount is not confidential
  pub issuer_lock_type: Option<EGCText>,
  pub amount_commitments: Option<(CompressedRistretto, CompressedRistretto)>, //None if not confidential transfer
  //pub(crate) issuer_lock_id: Option<(ElGamalCiphertext, ElGamalCiphertext)>, TODO
  pub amount: Option<u64>,           // None if confidential transfers
  pub asset_type: Option<AssetType>, // None if confidential asset
  pub public_key: XfrPublicKey, // ownership address
  pub asset_type_commitment: Option<CompressedRistretto>, //Noe if not confidential asset
  pub blind_share: CompressedEdwardsY, // Used by pukey holder to derive blinding factors
  pub lock: Option<ZeiHybridCipher>, // If confidential transfer or confidential type lock the amount and or type to the pubkey in asset_record
}

/// I'm a BlindAssetRecors with revealed commitment openings.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAssetRecord {
  pub(crate) asset_record: BlindAssetRecord, //TODO have a reference here, and lifetime parameter. We will avoid copying info unnecessarily.
  pub(crate) amount: u64,
  pub(crate) amount_blinds: (Scalar, Scalar),
  pub(crate) asset_type: AssetType,
  pub(crate) type_blind: Scalar,
}

impl OpenAssetRecord {
  pub fn get_asset_type(&self) -> &AssetType {
    &self.asset_type
  }
  pub fn get_amount(&self) -> &u64 {
    &self.amount
  }
  pub fn get_pub_key(&self) -> &XfrPublicKey {
    &self.asset_record.public_key
  }
}

/// I'am a plaintext asset record, used to indicate output information when creating a transfer note
#[derive(Deserialize, Serialize)]
pub struct AssetRecord {
  pub amount: u64,
  pub asset_type: AssetType,
  pub public_key: XfrPublicKey, // ownership address
}

impl AssetRecord {
  pub fn new(amount: u64,
             asset_type: AssetType,
             public_key: XfrPublicKey)
             -> Result<AssetRecord, ZeiError> {
    Ok(AssetRecord { amount,
                     asset_type,
                     public_key })
  }
}

// TODO is this clippy warning a problem?
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AssetAmountProof {
  AssetMix(AssetMixProof),        // multi-type fully confidential Xfr
  ConfAmount(XfrRangeProof),      // single-type and public, confidental amount
  ConfAsset(ChaumPedersenProofX), // single-type confidential, public amount
  ConfAll((XfrRangeProof, ChaumPedersenProofX)), // fully confidential single type
  NoProof,                        // non-confidential transaction
}

/// I contain the proofs of a transfer note
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrProofs {
  pub asset_amount_proof: AssetAmountProof,
  pub asset_tracking_proof: AssetTrackingProofs,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct XfrRangeProof {
  #[serde(with = "serialization::zei_obj_serde")]
  pub range_proof: RangeProof,
  pub xfr_diff_commitment_low: CompressedRistretto, //lower 32 bits transfer amount difference commitment
  pub xfr_diff_commitment_high: CompressedRistretto, //higher 32 bits transfer amount difference commitment
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTrackingProof {
  pub(crate) amount_proof: Option<(PedersenElGamalEqProof, PedersenElGamalEqProof)>, // None if confidential amount flag is off. Otherwise, value proves that decryption of issuer_lock_amount yields the same as value committed in amount_commitment in BlindAssetRecord output
  pub(crate) asset_type_proof: Option<PedersenElGamalEqProof>, //None if confidential asset_type is off. Otherwise, value proves that decryption of issuer_lock_amount yields the same as value committed in amount_commitment in BlindAssetRecord output
  pub(crate) identity_proof: Option<ConfidentialAC>, //None if asset policy does not require identity tracking. Otherwise, value proves that ElGamal ciphertexts encrypts encrypts attributes that satisfy an credential verification
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTrackingProofs {
  pub aggregate_amount_asset_type_proof: Option<PedersenElGamalEqProof>, // None if confidential amount and confidential asset type flag are off. Otherwise, value proves that decryption of issuer_lock_amounts and/or asset type yield the same as values committed in amount_commitments in BlindAssetRecord outputs
  pub identity_proofs: Vec<Option<ConfidentialAC>>, //None if asset policy does not require identity tracking. Otherwise, value proves that ElGamal ciphertexts encrypts encrypts attributes that satisfy an credential verification
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdRevealPolicy {
  pub cred_issuer_pub_key: ACIssuerPublicKey,
  pub bitmap: Vec<bool>,
}

impl PartialEq for XfrRangeProof {
  fn eq(&self, other: &XfrRangeProof) -> bool {
    self.range_proof.to_bytes() == other.range_proof.to_bytes()
    && self.xfr_diff_commitment_low == other.xfr_diff_commitment_low
    && self.xfr_diff_commitment_high == other.xfr_diff_commitment_high
  }
}

impl Eq for XfrRangeProof {}

#[cfg(test)]
mod test {
  use super::{XfrBody, XfrNote, XfrProofs};
  use crate::xfr::lib::tests::create_xfr;
  use crate::xfr::lib::XfrType;
  use crate::xfr::sig::XfrMultiSig;
  use crate::xfr::structs::{AssetAmountProof, AssetTrackingProofs};
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
  use rmp_serde::{Deserializer, Serializer};
  use serde::de::Deserialize;
  use serde::ser::Serialize;

  fn do_test_serialization(xfr_type: XfrType, asset_tracking: bool) {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let asset_type = [0u8; 16];
    let input_amount = [(10u64, asset_type), (20u64, asset_type)];
    let out_amount = [(1u64, asset_type),
                      (2u64, asset_type),
                      (1u64, asset_type),
                      (10u64, asset_type),
                      (16u64, asset_type)];

    let (xfr_note, _, _, _, _) = create_xfr(&mut prng,
                                            &input_amount,
                                            &out_amount,
                                            xfr_type,
                                            asset_tracking);

    //serializing signatures
    let mut vec = vec![];
    assert_eq!(true,
               xfr_note.multisig
                       .serialize(&mut Serializer::new(&mut vec))
                       .is_ok());
    let mut de = Deserializer::new(&vec[..]);
    let multisig_de: XfrMultiSig = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(xfr_note.multisig, multisig_de);

    //serializing proofs
    let mut vec = vec![];
    assert_eq!(true,
               xfr_note.body
                       .proofs
                       .serialize(&mut Serializer::new(&mut vec))
                       .is_ok());
    let mut de = Deserializer::new(&vec[..]);
    let proofs_de = XfrProofs::deserialize(&mut de).unwrap();
    assert_eq!(xfr_note.body.proofs, proofs_de);

    let json_str = serde_json::to_string(&xfr_note.body.proofs.asset_tracking_proof).unwrap();
    let proofs_de: AssetTrackingProofs = serde_json::from_str(json_str.as_str()).unwrap();
    assert_eq!(xfr_note.body.proofs.asset_tracking_proof, proofs_de);

    let json_str = serde_json::to_string(&xfr_note.body.proofs.asset_amount_proof).unwrap();
    let proofs_de: AssetAmountProof = serde_json::from_str(json_str.as_str()).unwrap();
    assert_eq!(xfr_note.body.proofs.asset_amount_proof, proofs_de);

    //serializing body
    let mut vec = vec![];
    assert_eq!(true,
               xfr_note.body
                       .serialize(&mut Serializer::new(&mut vec))
                       .is_ok());
    let mut de = Deserializer::new(&vec[..]);
    let body_de = XfrBody::deserialize(&mut de).unwrap();
    assert_eq!(xfr_note.body, body_de);

    let json_str = serde_json::to_string(&xfr_note.body).unwrap();
    let body_de: XfrBody = serde_json::from_str(json_str.as_str()).unwrap();
    assert_eq!(xfr_note.body, body_de);

    let bincode_vec = bincode::serialize(&xfr_note.body).unwrap();
    let body_de: XfrBody = bincode::deserialize(bincode_vec.as_slice()).unwrap();
    assert_eq!(xfr_note.body, body_de);

    //serializing whole Xfr
    let mut vec = vec![];
    assert_eq!(true,
               xfr_note.serialize(&mut Serializer::new(&mut vec)).is_ok());
    let mut de = Deserializer::new(&vec[..]);
    let xfr_de = XfrNote::deserialize(&mut de).unwrap();
    assert_eq!(xfr_note, xfr_de);

    let bincode_vec = bincode::serialize(&xfr_note).unwrap();
    let note_de: XfrNote = bincode::deserialize(bincode_vec.as_slice()).unwrap();
    assert_eq!(xfr_note, note_de);

    let json_str = serde_json::to_string(&xfr_note).unwrap();
    let note_de: XfrNote = serde_json::from_str(json_str.as_str()).unwrap();
    assert_eq!(xfr_note, note_de);
  }

  #[test]
  fn test_serialization() {
    do_test_serialization(XfrType::PublicAmount_PublicAssetType_SingleAsset, false);
    do_test_serialization(XfrType::PublicAmount_ConfidentialAssetType_SingleAsset,
                          false);
    do_test_serialization(XfrType::ConfidentialAmount_PublicAssetType_SingleAsset,
                          false);
    do_test_serialization(XfrType::ConfidentialAmount_ConfidentialAssetType_SingleAsset,
                          false);

    do_test_serialization(XfrType::ConfidentialAmount_PublicAssetType_SingleAsset,
                          true);
    do_test_serialization(XfrType::ConfidentialAmount_ConfidentialAssetType_SingleAsset,
                          true);
  }
}
