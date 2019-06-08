use crate::algebra::bls12_381::{BLSG1, BLSG2};
use crate::basic_crypto::elgamal::{ElGamalPublicKey, ElGamalCiphertext};
use crate::basic_crypto::hybrid_encryption::ZeiHybridCipher;
use crate::basic_crypto::signatures::{XfrMultiSig, XfrPublicKey};
use crate::crypto::anon_creds::ACIssuerPublicKey;
use crate::errors::ZeiError;
use crate::proofs::asset_mixer::AssetMixProof;
use crate::proofs::chaum_pedersen::ChaumPedersenProofX;
use crate::proofs::pedersen_elgamal::PedersenElGamalEqProof;
use crate::xfr::proofs::ConfIdReveal;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

use bulletproofs::RangeProof;

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};

pub type AssetType = [u8; 16];

/// I represent a transfer note
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct XfrNote {
    pub(crate) body: XfrBody,
    pub(crate) multisig: XfrMultiSig,
}

impl XfrNote {
    pub fn outputs_iter(&self) -> std::slice::Iter<BlindAssetRecord> {
        self.body.outputs.iter()
    }
}

/// I am the body of a transfer note
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct XfrBody {
    pub(crate) inputs: Vec<BlindAssetRecord>,
    pub(crate) outputs: Vec<BlindAssetRecord>,
    pub(crate) proofs: XfrProofs,
}

type EGPubKey = ElGamalPublicKey<RistrettoPoint>;
type EGPubKeyId = ElGamalPublicKey<BLSG1>;
type EGCText = ElGamalCiphertext<RistrettoPoint>;

/// I'm a bundle of public keys for the asset issuer
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AssetIssuerPubKeys {
    pub eg_ristretto_pub_key: EGPubKey,
    pub eg_blsg1_pub_key: EGPubKeyId,

}
/// I represent an Asset Record as presented in the public ledger.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct BlindAssetRecord {
    // amount is a 64 bit positive integer expressed in base 2^32 in confidential transaction
    // commitments and ciphertext
    pub(crate) issuer_public_key: Option<AssetIssuerPubKeys>, //None if issuer tracking is not required
    pub(crate) issuer_lock_amount: Option<(EGCText, EGCText)>, //None if issuer tracking not required or amount is not confidential
    pub(crate) issuer_lock_type: Option<EGCText>,
    pub(crate) amount_commitments: Option<(CompressedRistretto, CompressedRistretto)>, //None if not confidential transfer
    //pub(crate) issuer_lock_id: Option<(ElGamalCiphertext, ElGamalCiphertext)>, TODO
    pub(crate) amount: Option<u64>, // None if confidential transfers
    pub(crate) asset_type: Option<AssetType>, // None if confidential asset
    //#[serde(with = "serialization::zei_obj_serde")]
    pub(crate) public_key: XfrPublicKey, // ownership address
    //#[serde(with = "serialization::option_bytes")]
    pub(crate) asset_type_commitment: Option<CompressedRistretto>, //Noe if not confidential asset
    //#[serde(with = "serialization::zei_obj_serde")]
    pub(crate) blind_share: CompressedEdwardsY, // Used by pukey holder to derive blinding factors
    pub(crate) lock_amount: Option<ZeiHybridCipher>, // If confidential transfer lock the amount to the pubkey in asset_record
    pub(crate) lock_type: Option<ZeiHybridCipher>, // If confidential type lock the type to the public key in asset_record
}

/// I'm a BlindAssetRecors with revealed commitment openings.
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
pub struct AssetRecord {
    pub(crate) amount: u64,
    pub(crate) asset_type: AssetType,
    pub(crate) public_key: XfrPublicKey, // ownership address
}

impl AssetRecord {
    pub fn new(
        amount: u64,
        asset_type: AssetType,
        public_key: XfrPublicKey,
    ) -> Result<AssetRecord, ZeiError> {
        Ok(AssetRecord {
            amount,
            asset_type,
            public_key,
        })
    }
}


#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum AssetAmountProof{
    AssetMix(AssetMixProof), // multi-type fully confidential Xfr
    ConfAmount(XfrRangeProof), // single-type and public, confidental amount
    ConfAsset(ChaumPedersenProofX), // single-type confidential, public amount
    ConfAll((XfrRangeProof, ChaumPedersenProofX)), // fully confidential single type
    NoProof, // non-confidential transaction
}

/// I contain the proofs of a transfer note
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct XfrProofs {
    pub(crate) asset_amount_proof: AssetAmountProof,
    pub(crate) asset_tracking_proof: AssetTrackingProofs,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct XfrRangeProof {
    pub range_proof: RangeProof,
    pub xfr_diff_commitment_low: CompressedRistretto, //lower 32 bits transfer amount difference commitment
    pub xfr_diff_commitment_high: CompressedRistretto, //higher 32 bits transfer amount difference commitment
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AssetTrackingProof {
    pub(crate) amount_proof: Option<(PedersenElGamalEqProof, PedersenElGamalEqProof)>, // None if confidential amount flag is off. Otherwise, value proves that decryption of issuer_lock_amount yields the same as value committed in amount_commitment in BlindAssetRecord output
    pub(crate) asset_type_proof: Option<PedersenElGamalEqProof>, //None if confidential asset_type is off. Otherwise, value proves that decryption of issuer_lock_amount yields the same as value committed in amount_commitment in BlindAssetRecord output
    pub(crate) identity_proof: Option<ConfIdReveal> //None if asset policy does not require identity tracking. Otherwise, value proves that ElGamal ciphertexts encrypts encrypts attributes that satisfy an credential verification
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AssetTrackingProofs {
    pub(crate) aggregate_amount_asset_type_proof: Option<PedersenElGamalEqProof>, // None if confidential amount and confidential asset type flag are off. Otherwise, value proves that decryption of issuer_lock_amounts and/or asset type yield the same as values committed in amount_commitments in BlindAssetRecord outputs
    pub(crate) identity_proofs: Vec<Option<ConfIdReveal>> //None if asset policy does not require identity tracking. Otherwise, value proves that ElGamal ciphertexts encrypts encrypts attributes that satisfy an credential verification
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct IdRevealPolicy{
    pub cred_issuer_pub_key: ACIssuerPublicKey<BLSG1, BLSG2>,
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
mod test{
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use crate::xfr::lib::test::create_xfr;
    use serde::ser::{Serialize};
    use serde::de::{Deserialize};
    use rmp_serde::{Deserializer, Serializer};
    use crate::basic_crypto::signatures::XfrMultiSig;
    use super::{XfrBody,XfrProofs, XfrNote};

    fn do_test_serialization(
        confidential_amount: bool,
        confidential_asset: bool,
        asset_tracking: bool,
    ) {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let asset_type = [0u8; 16];
        let input_amount = [(10u64,asset_type), (20u64,asset_type)];
        let out_amount = [(1u64,asset_type), (2u64,asset_type), (1u64,asset_type), (10u64,asset_type), (16u64,asset_type)];

        let (xfr_note, _, _, _, _) = create_xfr(
            &mut prng,
            &input_amount,
            &out_amount,
            confidential_amount,
            confidential_asset,
            asset_tracking,
        );

        //serializing signatures
        let mut vec = vec![];
        assert_eq!(
            true,
            xfr_note
                .multisig
                .serialize(&mut Serializer::new(&mut vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&vec[..]);
        let multisig_de: XfrMultiSig = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(xfr_note.multisig, multisig_de);

        //serializing proofs
        let mut vec = vec![];
        assert_eq!(
            true,
            xfr_note
                .body
                .proofs
                .serialize(&mut Serializer::new(&mut vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&vec[..]);
        let proofs_de = XfrProofs::deserialize(&mut de).unwrap();
        assert_eq!(xfr_note.body.proofs, proofs_de);

        //serializing body
        let mut vec = vec![];
        assert_eq!(
            true,
            xfr_note
                .body
                .serialize(&mut Serializer::new(&mut vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&vec[..]);
        let body_de = XfrBody::deserialize(&mut de).unwrap();
        assert_eq!(xfr_note.body, body_de);

        //serializing whole Xfr
        let mut vec = vec![];
        assert_eq!(
            true,
            xfr_note.serialize(&mut Serializer::new(&mut vec)).is_ok()
        );
        let mut de = Deserializer::new(&vec[..]);
        let xfr_de = XfrNote::deserialize(&mut de).unwrap();
        assert_eq!(xfr_note, xfr_de);
    }

    #[test]
    fn test_serialization() {
        do_test_serialization(false, false, false);
        do_test_serialization(false, true, false);
        do_test_serialization(true, false, false);
        do_test_serialization(true, true, false);
        do_test_serialization(true, false, true);
        do_test_serialization(true, true, true);
    }
}