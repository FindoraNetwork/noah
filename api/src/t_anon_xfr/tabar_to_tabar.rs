use crate::anon_xfr::abar_to_abar::AXfrWitness;
use crate::anon_xfr::{
    structs::{AnonAssetRecord, AxfrOwnerMemo, Nullifier},
    AXfrAddressFoldingInstance, AXfrPlonkPf,
};
use crate::keys::KeyPair;
use noah_algebra::bls12_381::BLSScalar;
use noah_crypto::basic::anemoi_jive::AnemoiVLHTrace;

use super::structs::TAxfrAuditorMemo;

/// Traceable anonymous transfer note.
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct TAXfrNote {
    /// The traceable anonymous transfer body.
    pub body: TAXfrBody,
    /// The Plonk proof (assuming non-malleability).
    pub proof: AXfrPlonkPf,
    /// The address folding instance.
    pub folding_instance: AXfrAddressFoldingInstance,
}

/// Traceable anonymous transfer pre-note without proofs and signatures.
#[derive(Debug, Clone)]
pub struct TAXfrPreNote {
    /// The traceable anonymous transfer body.
    pub body: TAXfrBody,
    /// Witness.
    pub witness: AXfrWitness,
    /// The traces of the input commitments.
    pub input_commitments_traces: Vec<AnemoiVLHTrace<BLSScalar, 2, 12>>,
    /// The traces of the output commitments.
    pub output_commitments_traces: Vec<AnemoiVLHTrace<BLSScalar, 2, 12>>,
    /// The traces of the nullifiers.
    pub nullifiers_traces: Vec<AnemoiVLHTrace<BLSScalar, 2, 12>>,
    /// Input key pair.
    pub input_keypair: KeyPair,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
/// Traceable anonymous transfer body.
pub struct TAXfrBody {
    /// The inputs, in terms of nullifiers.
    pub inputs: Vec<Nullifier>,
    /// The outputs, in terms of new anonymous asset records.
    pub outputs: Vec<AnonAssetRecord>,
    /// The Merkle tree root.
    pub merkle_root: BLSScalar,
    /// An index of the Merkle tree root in the ledger.
    pub merkle_root_version: u64,
    /// The amount of fee.
    pub fee: u32,
    /// The owner memos.
    pub owner_memos: Vec<AxfrOwnerMemo>,
    /// The auditor memos.
    pub auditor_memos: Vec<TAxfrAuditorMemo>,
}
