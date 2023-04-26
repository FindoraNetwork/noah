use crate::{
    anon_xfr::{
        structs::{AnonAssetRecord, AxfrOwnerMemo},
        AXfrPlonkPf,
    },
    keys::Signature,
    xfr::structs::BlindAssetRecord,
};

use super::structs::TAxfrAuditorMemo;

/// The traceable transparent-to-anonymous note.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ArToNabarNote {
    /// The traceable transparent-to-anonymous body.
    pub body: ArToNabarBody,
    /// Signature of the sender.
    pub signature: Signature,
}

/// The traceable transparent-to-anonymous body.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ArToNabarBody {
    /// The input transparent asset note, requiring both amounts and asset types to be transparent.
    pub input: BlindAssetRecord,
    /// The output anonymous asset record.
    pub output: AnonAssetRecord,
    /// The proof that the output matches the input.
    pub proof: AXfrPlonkPf,
    /// memo to hold the blinding factor of commitment
    pub memo: AxfrOwnerMemo,
    /// The auditor memos.
    pub auditor_memos: Vec<TAxfrAuditorMemo>,
}
