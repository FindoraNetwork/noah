use crate::anon_xfr::structs::AxfrOwnerMemo;
use crate::anon_xfr::{
    structs::{Nullifier, PayerWitness},
    AXfrAddressFoldingInstance, AXfrPlonkPf,
};
use crate::keys::KeyPair;
use crate::nextgen::structs::NabarAuditorMemo;
use crate::xfr::structs::BlindAssetRecord;
use noah_algebra::bls12_381::BLSScalar;
use noah_crypto::basic::anemoi_jive::AnemoiVLHTrace;

/// The traceable anonymous-to-transparent note.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TAbarToArNote {
    /// The body part of TABAR to AR.
    pub body: TAbarToArBody,
    /// The Plonk proof (assuming non-malleability).
    pub proof: AXfrPlonkPf,
    /// The address folding instance.
    pub folding_instance: AXfrAddressFoldingInstance,
}

/// The anonymous-to-transparent note without proof.
#[derive(Clone, Debug)]
pub struct TAbarToArPreNote {
    /// The body part of ABAR to AR.
    pub body: TAbarToArBody,
    /// Witness.
    pub witness: PayerWitness,
    /// The trace of the input commitment.
    pub input_commitment_trace: AnemoiVLHTrace<BLSScalar, 2, 12>,
    /// The trace of the nullifier.
    pub nullifier_trace: AnemoiVLHTrace<BLSScalar, 2, 12>,
    /// Input key pair.
    pub input_keypair: KeyPair,
}

/// The traceable anonymous-to-transparent body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TAbarToArBody {
    /// input ABAR being spent.
    pub input: Nullifier,
    /// The new AR to be created.
    pub output: BlindAssetRecord,
    /// The Merkle root hash.
    pub merkle_root: BLSScalar,
    /// The Merkle root version.
    pub merkle_root_version: u64,
    /// The owner memo.
    pub memo: Option<AxfrOwnerMemo>,
    /// The auditor memos.
    pub auditor_memos: NabarAuditorMemo,
}
