use aes_gcm::aead::Aead;
use digest::{generic_array::GenericArray, Digest, KeyInit};
use noah_algebra::secp256k1::{SECP256K1Scalar, SECP256K1G1};
use noah_algebra::{
    collections::HashMap,
    prelude::*,
    ristretto::{CompressedRistretto, PedersenCommitmentRistretto, RistrettoScalar},
    traits::PedersenCommitment,
};
use noah_crypto::basic::hybrid_encryption::{
    hybrid_decrypt_with_ed25519_secret_key, hybrid_encrypt_ed25519, NoahHybridCiphertext,
};
use serde::ser::Serialize;

/// Module for asset mixing.
pub mod asset_mixer;
/// Module for asset records.
pub mod asset_record;
/// Module for asset tracing.
pub mod asset_tracer;
/// Module for zero-knowledge proofs.
pub mod proofs;
/// Module for shared structures.
pub mod structs;

#[cfg(feature = "xfr-tracing")]
#[cfg(test)]
pub(crate) mod tests;

use crate::anon_creds::{ACCommitment, Attr};
use crate::keys::{KeyPair, MultiSig, PublicKey, PublicKeyInner, SecretKey};
use crate::parameters::bulletproofs::BulletproofParams;

use self::{
    asset_mixer::{
        batch_verify_asset_mixing, prove_asset_mixing, AssetMixProof, AssetMixingInstance,
    },
    proofs::{
        asset_amount_tracing_proofs, asset_proof, batch_verify_confidential_amount,
        batch_verify_confidential_asset, batch_verify_tracer_tracing_proof, gen_range_proof,
    },
    structs::*,
};

const POW_2_32: u64 = 0xFFFF_FFFFu64 + 1;

#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
#[allow(clippy::enum_variant_names)]
pub(super) enum XfrType {
    /// All inputs and outputs are revealed and all have the same asset type
    NonConfidential_SingleAsset,
    /// At least one input or output has a confidential amount and all asset types are revealed
    ConfidentialAmount_NonConfidentialAssetType_SingleAsset,
    /// At least one asset type is confidential and all the amounts are revealed
    NonConfidentialAmount_ConfidentialAssetType_SingleAsset,
    /// At least one input or output has both confidential amount and asset type
    Confidential_SingleAsset,
    /// At least one input or output has confidential amount and asset type and involves multiple asset types
    Confidential_MultiAsset,
    /// All inputs and outputs reveal amounts and asset types
    NonConfidential_MultiAsset,
}

impl XfrType {
    pub(super) fn from_inputs_outputs(
        inputs_record: &[AssetRecord],
        outputs_record: &[AssetRecord],
    ) -> Self {
        let mut multi_asset = false;
        let mut confidential_amount_nonconfidential_asset_type = false;
        let mut confidential_asset_type_nonconfidential_amount = false;
        let mut confidential_all = false;

        let asset_type = inputs_record[0].open_asset_record.asset_type;
        for record in inputs_record.iter().chain(outputs_record) {
            if asset_type != record.open_asset_record.asset_type {
                multi_asset = true;
            }
            let confidential_amount = matches!(
                record.open_asset_record.blind_asset_record.amount,
                XfrAmount::Confidential(_)
            );
            let confidential_asset_type = matches!(
                record.open_asset_record.blind_asset_record.asset_type,
                XfrAssetType::Confidential(_)
            );

            if confidential_amount && confidential_asset_type {
                confidential_all = true;
            } else if confidential_amount {
                confidential_amount_nonconfidential_asset_type = true;
            } else if confidential_asset_type {
                confidential_asset_type_nonconfidential_amount = true;
            }
        }
        if multi_asset {
            if confidential_all
                || confidential_amount_nonconfidential_asset_type
                || confidential_asset_type_nonconfidential_amount
            {
                return XfrType::Confidential_MultiAsset;
            } else {
                return XfrType::NonConfidential_MultiAsset;
            }
        }
        if confidential_all
            || (confidential_amount_nonconfidential_asset_type
                && confidential_asset_type_nonconfidential_amount)
        {
            XfrType::Confidential_SingleAsset
        } else if confidential_amount_nonconfidential_asset_type {
            XfrType::ConfidentialAmount_NonConfidentialAssetType_SingleAsset
        } else if confidential_asset_type_nonconfidential_amount {
            XfrType::NonConfidentialAmount_ConfidentialAssetType_SingleAsset
        } else {
            XfrType::NonConfidential_SingleAsset
        }
    }
}

/// Generate a confidential transfer note.
/// # Example
/// ```
/// use rand_chacha::ChaChaRng;
/// use noah::keys::KeyPair;
/// use noah::xfr::structs::{AssetRecordTemplate, AssetRecord, AssetType};
/// use noah::xfr::asset_record::AssetRecordType;
/// use noah::xfr::{gen_xfr_note, verify_xfr_note, XfrNotePolicies};
/// use noah_algebra::prelude::*;
/// use ruc::err::*;
/// use noah::parameters::AddressFormat::SECP256K1;
/// use noah::parameters::bulletproofs::BulletproofParams;
///
/// let mut prng = ChaChaRng::from_seed([0u8; 32]);
/// let mut params = BulletproofParams::default();
/// let asset_type = AssetType::from_identical_byte(0u8);
/// let inputs_amounts = [(10u64, asset_type),
///                       (10u64, asset_type),
///                       (10u64, asset_type)];
/// let outputs_amounts = [(1u64, asset_type),
///                     (2u64, asset_type),
///                     (3u64, asset_type),
///                      (24u64, asset_type)];
///
/// let mut inputs = vec![];
/// let mut outputs = vec![];
///
/// let mut inkeys = vec![];
/// let mut in_asset_records = vec![];
///
/// let asset_record_type = AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType;
///
/// for x in inputs_amounts.iter() {
///   let keypair = KeyPair::sample(&mut prng, SECP256K1);
///   let asset_record = AssetRecordTemplate::with_no_asset_tracing( x.0,
///                                        x.1,
///                                        asset_record_type,
///                                        keypair.get_pk().clone());
///
///   inputs.push(AssetRecord::from_template_no_identity_tracing(&mut prng, &asset_record).unwrap());
///
///   in_asset_records.push(asset_record);
///   inkeys.push(keypair);
/// }
///
/// for x in outputs_amounts.iter() {
///     let keypair = KeyPair::sample(&mut prng, SECP256K1);
///
///     let ar = AssetRecordTemplate::with_no_asset_tracing(x.0, x.1, asset_record_type, keypair.get_pk().clone());
///     let output = AssetRecord::from_template_no_identity_tracing(&mut prng, &ar).unwrap();
///     outputs.push(output);
/// }
///
/// let xfr_note = gen_xfr_note( &mut prng,
///                              inputs.as_slice(),
///                              outputs.as_slice(),
///                              inkeys.iter().map(|x| x).collect_vec().as_slice()
///                ).unwrap();
/// let policies = XfrNotePolicies::empty_policies(inputs.len(), outputs.len());
/// pnk!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies.to_ref()));
/// ```
pub fn gen_xfr_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    inputs: &[AssetRecord],
    outputs: &[AssetRecord],
    input_key_pairs: &[&KeyPair],
) -> Result<XfrNote> {
    if inputs.is_empty() {
        return Err(eg!(NoahError::ParameterError));
    }

    check_keys(inputs, input_key_pairs).c(d!())?;

    let body = gen_xfr_body(prng, inputs, outputs).c(d!())?;
    let multisig = compute_transfer_multisig(&body, input_key_pairs).c(d!())?;

    Ok(XfrNote { body, multisig })
}

/// Generate the confidential transfer body.
/// # Example
/// ```
/// use rand_chacha::ChaChaRng;
/// use ruc::{*, err::*};
/// use rand_core::SeedableRng;
/// use noah::keys::KeyPair;
/// use noah::parameters::AddressFormat::SECP256K1;
/// use noah::xfr::structs::{AssetRecordTemplate, AssetRecord, AssetType};
/// use noah::xfr::asset_record::AssetRecordType;
/// use noah::xfr::{gen_xfr_body, verify_xfr_body, XfrNotePolicies, XfrNotePoliciesRef};
/// use noah::parameters::bulletproofs::BulletproofParams;
///
/// let mut prng = ChaChaRng::from_seed([0u8; 32]);
/// let mut params = BulletproofParams::default();
/// let asset_type = AssetType::from_identical_byte(0u8);
/// let inputs_amounts = [(10u64, asset_type),
///                       (10u64, asset_type),
///                       (10u64, asset_type)];
/// let outputs_amounts = [(1u64, asset_type),
///                     (2u64, asset_type),
///                     (3u64, asset_type),
///                      (24u64, asset_type)];
///
/// let mut inputs = vec![];
/// let mut outputs = vec![];
///
/// let asset_record_type = AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType;
///
/// for x in inputs_amounts.iter() {
///   let keypair = KeyPair::sample(&mut prng, SECP256K1);
///   let ar = AssetRecordTemplate::with_no_asset_tracing( x.0,
///                                        x.1,
///                                        asset_record_type,
///                                        keypair.get_pk().clone(),
///                                        );
///
///   inputs.push(AssetRecord::from_template_no_identity_tracing(&mut prng, &ar).unwrap());
/// }
/// for x in outputs_amounts.iter() {
///     let keypair = KeyPair::sample(&mut prng, SECP256K1);
///
///     let ar = AssetRecordTemplate::with_no_asset_tracing(x.0, x.1, asset_record_type, keypair.get_pk());
///     outputs.push(AssetRecord::from_template_no_identity_tracing(&mut prng, &ar).unwrap());
/// }
/// let body = gen_xfr_body(&mut prng, &inputs, &outputs).unwrap();
/// let policies = XfrNotePolicies::empty_policies(inputs.len(), outputs.len());
/// pnk!(verify_xfr_body(&mut prng, &mut params, &body, &policies.to_ref()));
/// ```
pub fn gen_xfr_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    inputs: &[AssetRecord],
    outputs: &[AssetRecord],
) -> Result<XfrBody> {
    if inputs.is_empty() {
        return Err(eg!(NoahError::ParameterError));
    }
    let xfr_type = XfrType::from_inputs_outputs(inputs, outputs);
    check_asset_amount(inputs, outputs).c(d!())?;

    let single_asset = !matches!(
        xfr_type,
        XfrType::NonConfidential_MultiAsset | XfrType::Confidential_MultiAsset
    );

    let open_inputs = inputs
        .iter()
        .map(|input| &input.open_asset_record)
        .collect_vec();
    let open_outputs = outputs
        .iter()
        .map(|output| &output.open_asset_record)
        .collect_vec();
    let asset_amount_proof = if single_asset {
        gen_xfr_proofs_single_asset(
            prng,
            open_inputs.as_slice(),
            open_outputs.as_slice(),
            xfr_type,
        )
        .c(d!())?
    } else {
        gen_xfr_proofs_multi_asset(open_inputs.as_slice(), open_outputs.as_slice(), xfr_type)
            .c(d!())?
    };

    let asset_type_amount_tracing_proof =
        asset_amount_tracing_proofs(prng, inputs, outputs).c(d!())?;
    let asset_tracing_proof = AssetTracingProofs {
        asset_type_and_amount_proofs: asset_type_amount_tracing_proof,
        inputs_identity_proofs: inputs
            .iter()
            .map(|input| input.identity_proofs.clone())
            .collect_vec(),
        outputs_identity_proofs: outputs
            .iter()
            .map(|output| output.identity_proofs.clone())
            .collect_vec(),
    };

    let proofs = XfrProofs {
        asset_type_and_amount_proof: asset_amount_proof,
        asset_tracing_proof,
    };

    let mut xfr_inputs = vec![];
    for x in open_inputs {
        xfr_inputs.push(x.blind_asset_record.clone())
    }

    let mut xfr_outputs = vec![];
    for x in open_outputs {
        xfr_outputs.push(x.blind_asset_record.clone())
    }

    let tracer_memos = inputs
        .iter()
        .chain(outputs)
        .map(|record_input| record_input.asset_tracers_memos.clone())
        .collect_vec();
    let owner_memos = outputs
        .iter()
        .map(|record_input| record_input.owner_memo.clone())
        .collect_vec();
    Ok(XfrBody {
        inputs: xfr_inputs,
        outputs: xfr_outputs,
        proofs,
        asset_tracing_memos: tracer_memos,
        owners_memos: owner_memos,
    })
}

fn check_keys(inputs: &[AssetRecord], input_key_pairs: &[&KeyPair]) -> Result<()> {
    if inputs.len() != input_key_pairs.len() {
        return Err(eg!(NoahError::ParameterError));
    }
    for (input, key) in inputs.iter().zip(input_key_pairs.iter()) {
        let inkey = &input.open_asset_record.blind_asset_record.public_key;
        if inkey != &key.pub_key {
            return Err(eg!(NoahError::ParameterError));
        }
    }
    Ok(())
}

fn gen_xfr_proofs_multi_asset(
    inputs: &[&OpenAssetRecord],
    outputs: &[&OpenAssetRecord],
    xfr_type: XfrType,
) -> Result<AssetTypeAndAmountProof> {
    let pow2_32 = RistrettoScalar::from(POW_2_32);

    let mut ins = vec![];

    for x in inputs.iter() {
        ins.push((
            x.amount,
            x.asset_type.as_scalar(),
            x.amount_blinds.0.add(&pow2_32.mul(&x.amount_blinds.1)),
            x.type_blind,
        ));
    }

    let mut out = vec![];
    for x in outputs.iter() {
        out.push((
            x.amount,
            x.asset_type.as_scalar(),
            x.amount_blinds.0.add(&pow2_32.mul(&x.amount_blinds.1)),
            x.type_blind,
        ));
    }

    match xfr_type {
        XfrType::Confidential_MultiAsset => {
            let mix_proof = prove_asset_mixing(ins.as_slice(), out.as_slice()).c(d!())?;
            Ok(AssetTypeAndAmountProof::AssetMix(mix_proof))
        }
        XfrType::NonConfidential_MultiAsset => Ok(AssetTypeAndAmountProof::NoProof),
        _ => Err(eg!(NoahError::XfrCreationAssetAmountError)),
    }
}

fn gen_xfr_proofs_single_asset<R: CryptoRng + RngCore>(
    prng: &mut R,
    inputs: &[&OpenAssetRecord],
    outputs: &[&OpenAssetRecord],
    xfr_type: XfrType,
) -> Result<AssetTypeAndAmountProof> {
    let pc_gens = PedersenCommitmentRistretto::default();

    match xfr_type {
        XfrType::NonConfidential_SingleAsset => Ok(AssetTypeAndAmountProof::NoProof),
        XfrType::ConfidentialAmount_NonConfidentialAssetType_SingleAsset => Ok(
            AssetTypeAndAmountProof::ConfAmount(gen_range_proof(inputs, outputs).c(d!())?),
        ),
        XfrType::NonConfidentialAmount_ConfidentialAssetType_SingleAsset => {
            Ok(AssetTypeAndAmountProof::ConfAsset(Box::new(
                asset_proof(prng, &pc_gens, inputs, outputs).c(d!())?,
            )))
        }
        XfrType::Confidential_SingleAsset => Ok(AssetTypeAndAmountProof::ConfAll(Box::new((
            gen_range_proof(inputs, outputs).c(d!())?,
            asset_proof(prng, &pc_gens, inputs, outputs).c(d!())?,
        )))),
        _ => Err(eg!(NoahError::XfrCreationAssetAmountError)), // Type cannot be multi asset
    }
}

/// Check that for each asset type total input amount == total output amount.
fn check_asset_amount(inputs: &[AssetRecord], outputs: &[AssetRecord]) -> Result<()> {
    let mut amounts = HashMap::new();

    for record in inputs.iter() {
        match amounts.get_mut(&(record.open_asset_record.asset_type)) {
            None => {
                amounts.insert(
                    record.open_asset_record.asset_type,
                    vec![i128::from(record.open_asset_record.amount)],
                );
            }
            Some(vec) => {
                vec.push(i128::from(record.open_asset_record.amount));
            }
        };
    }

    for record in outputs.iter() {
        match amounts.get_mut(&record.open_asset_record.asset_type) {
            None => {
                amounts.insert(
                    record.open_asset_record.asset_type,
                    vec![-i128::from(record.open_asset_record.amount)],
                );
            }
            Some(vec) => {
                vec.push(-i128::from(record.open_asset_record.amount));
            }
        };
    }

    for (_, a) in amounts.iter() {
        let sum = a.iter().sum::<i128>();
        if sum != 0i128 {
            return Err(eg!(NoahError::XfrCreationAssetAmountError));
        }
    }

    Ok(())
}

/// Compute a multisignature over the body.
pub(crate) fn compute_transfer_multisig(body: &XfrBody, keys: &[&KeyPair]) -> Result<MultiSig> {
    let mut bytes = vec![];
    body.serialize(&mut rmp_serde::Serializer::new(&mut bytes))
        .c(d!(NoahError::SerializationError))?;
    Ok(MultiSig::sign(&keys, &bytes)?)
}

/// Verify the multisignature over the body.
pub(crate) fn verify_transfer_multisig(xfr_note: &XfrNote) -> Result<()> {
    let mut bytes = vec![];
    xfr_note
        .body
        .serialize(&mut rmp_serde::Serializer::new(&mut bytes))
        .c(d!(NoahError::SerializationError))?;
    let pubkeys = xfr_note
        .body
        .inputs
        .iter()
        .map(|input| &input.public_key)
        .collect_vec();
    xfr_note.multisig.verify(&pubkeys, &bytes)
}

/// Verify a confidential transfer note.
pub fn verify_xfr_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &mut BulletproofParams,
    xfr_note: &XfrNote,
    policies: &XfrNotePoliciesRef<'_>,
) -> Result<()> {
    batch_verify_xfr_notes(prng, params, &[&xfr_note], &[&policies]).c(d!())
}

/// Batch-verify confidential transfer notes.
/// Note: in practice, the batch verification should only be used if the notes are assumed to be true.
pub fn batch_verify_xfr_notes<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &mut BulletproofParams,
    notes: &[&XfrNote],
    policies: &[&XfrNotePoliciesRef<'_>],
) -> Result<()> {
    // Check the memo size.
    for xfr_note in notes {
        if xfr_note.body.outputs.len() != xfr_note.body.owners_memos.len() {
            return Err(eg!(NoahError::AXfrVerifierParamsError));
        }
        #[cfg(not(feature = "xfr-tracing"))]
        if xfr_note
            .body
            .asset_tracing_memos
            .iter()
            .any(|x| !x.is_empty())
        {
            return Err(eg!(NoahError::AXfrVerificationError));
        }
        for (output, memo) in xfr_note
            .body
            .outputs
            .iter()
            .zip(xfr_note.body.owners_memos.iter())
        {
            check_memo_size(output, memo)?
        }
    }

    // Verify each note's multisignature, one by one.
    for xfr_note in notes {
        verify_transfer_multisig(xfr_note).c(d!())?;
    }

    let bodies = notes.iter().map(|note| &note.body).collect_vec();
    batch_verify_xfr_bodies(prng, params, &bodies, policies).c(d!())
}

pub(crate) fn batch_verify_xfr_body_asset_records<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &mut BulletproofParams,
    bodies: &[&XfrBody],
) -> Result<()> {
    let mut conf_amount_records = vec![];
    let mut conf_asset_type_records = vec![];
    let mut conf_asset_mix_bodies = vec![];

    for body in bodies {
        match &body.proofs.asset_type_and_amount_proof {
            AssetTypeAndAmountProof::ConfAll(x) => {
                let range_proof = &(*x).0;
                let asset_proof = &(*x).1;
                conf_amount_records.push((&body.inputs, &body.outputs, range_proof));
                conf_asset_type_records.push((&body.inputs, &body.outputs, asset_proof));
                // save for batching
            }
            AssetTypeAndAmountProof::ConfAmount(range_proof) => {
                conf_amount_records.push((&body.inputs, &body.outputs, range_proof)); // save for batching
                verify_plain_asset(body.inputs.as_slice(), body.outputs.as_slice()).c(d!())?;
                // no batching
            }
            AssetTypeAndAmountProof::ConfAsset(asset_proof) => {
                verify_plain_amounts(body.inputs.as_slice(), body.outputs.as_slice()).c(d!())?; // no batching
                conf_asset_type_records.push((&body.inputs, &body.outputs, asset_proof));
                // save for batch proof
            }
            AssetTypeAndAmountProof::NoProof => {
                verify_plain_asset_mix(body.inputs.as_slice(), body.outputs.as_slice()).c(d!())?;
                // no batching
            }
            AssetTypeAndAmountProof::AssetMix(asset_mix_proof) => {
                conf_asset_mix_bodies.push((
                    body.inputs.as_slice(),
                    body.outputs.as_slice(),
                    asset_mix_proof,
                ));
                // save for batch proof
            }
        }
    }

    // 1. Batch-verify confidential amounts.
    batch_verify_confidential_amount(prng, params, conf_amount_records.as_slice()).c(d!())?;

    // 2. Batch-verify confidential asset_types.
    batch_verify_confidential_asset(prng, &conf_asset_type_records).c(d!())?;

    // 3. Batch-verify confidential asset mix proofs.
    batch_verify_asset_mix(prng, params, conf_asset_mix_bodies.as_slice()).c(d!())
}

#[derive(Clone, Default)]
/// A reference of the policies.
pub struct XfrNotePoliciesRef<'b> {
    pub(crate) valid: bool,
    pub(crate) inputs_tracing_policies: Vec<&'b TracingPolicies>,
    pub(crate) inputs_sig_commitments: Vec<Option<&'b ACCommitment>>,
    pub(crate) outputs_tracing_policies: Vec<&'b TracingPolicies>,
    pub(crate) outputs_sig_commitments: Vec<Option<&'b ACCommitment>>,
}

impl<'b> XfrNotePoliciesRef<'b> {
    /// Create a new reference of the policies.
    pub fn new(
        inputs_tracing_policies: Vec<&'b TracingPolicies>,
        inputs_sig_commitments: Vec<Option<&'b ACCommitment>>,
        outputs_tracing_policies: Vec<&'b TracingPolicies>,
        outputs_sig_commitments: Vec<Option<&'b ACCommitment>>,
    ) -> XfrNotePoliciesRef<'b> {
        XfrNotePoliciesRef {
            valid: true,
            inputs_tracing_policies,
            inputs_sig_commitments,
            outputs_tracing_policies,
            outputs_sig_commitments,
        }
    }
}

pub(crate) fn if_some_closure(x: &Option<ACCommitment>) -> Option<&ACCommitment> {
    if (*x).is_some() {
        Some(x.as_ref().unwrap()) // safe unwrap()
    } else {
        None
    }
}

/// Tracing policies for an asset record.
#[derive(Clone, Default, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct XfrNotePolicies {
    /// Whether the structure is valid and has policies.
    pub valid: bool, // default to false
    /// The tracing policies
    pub inputs_tracing_policies: Vec<TracingPolicies>,
    /// The attribute commitments for each input.
    pub inputs_sig_commitments: Vec<Option<ACCommitment>>,
    /// The tracing policies for each output.
    pub outputs_tracing_policies: Vec<TracingPolicies>,
    /// The attribute commitments for each output.
    pub outputs_sig_commitments: Vec<Option<ACCommitment>>,
}

impl XfrNotePolicies {
    /// Create a structure of policies.
    pub fn new(
        inputs_tracing_policies: Vec<TracingPolicies>,
        inputs_sig_commitments: Vec<Option<ACCommitment>>,
        outputs_tracing_policies: Vec<TracingPolicies>,
        outputs_sig_commitments: Vec<Option<ACCommitment>>,
    ) -> XfrNotePolicies {
        XfrNotePolicies {
            valid: true,
            inputs_tracing_policies,
            inputs_sig_commitments,
            outputs_tracing_policies,
            outputs_sig_commitments,
        }
    }

    /// Return empty policies for the given numbers of inputs and outputs.
    pub fn empty_policies(num_inputs: usize, num_outputs: usize) -> XfrNotePolicies {
        XfrNotePolicies {
            valid: true,
            inputs_tracing_policies: vec![Default::default(); num_inputs],
            inputs_sig_commitments: vec![None; num_inputs],
            outputs_tracing_policies: vec![Default::default(); num_outputs],
            outputs_sig_commitments: vec![None; num_outputs],
        }
    }

    /// Obtain a reference of the policies.
    pub fn to_ref(&self) -> XfrNotePoliciesRef<'_> {
        if self.valid {
            XfrNotePoliciesRef::new(
                self.inputs_tracing_policies.iter().collect_vec(),
                self.inputs_sig_commitments
                    .iter()
                    .map(if_some_closure)
                    .collect_vec(),
                self.outputs_tracing_policies.iter().collect_vec(),
                self.outputs_sig_commitments
                    .iter()
                    .map(if_some_closure)
                    .collect_vec(),
            )
        } else {
            XfrNotePoliciesRef::default()
        }
    }
}

/// Verify the confidential transfer body with policies.
pub fn verify_xfr_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &mut BulletproofParams,
    body: &XfrBody,
    policies: &XfrNotePoliciesRef<'_>,
) -> Result<()> {
    batch_verify_xfr_bodies(prng, params, &[body], &[policies]).c(d!())
}

/// Batch-verify confidential transfer bodies with policies.
pub fn batch_verify_xfr_bodies<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &mut BulletproofParams,
    bodies: &[&XfrBody],
    policies: &[&XfrNotePoliciesRef<'_>],
) -> Result<()> {
    // 1. Verify amounts and asset types.
    batch_verify_xfr_body_asset_records(prng, params, bodies).c(d!())?;

    // 2. Verify tracing proofs.
    batch_verify_tracer_tracing_proof(prng, bodies, policies).c(d!())
}

/// Takes a vector of u64, converts each element to u128 and compute the sum of the new elements.
/// The goal is to avoid integer overflow when adding several u64 elements together.
fn safe_sum_u64(terms: &[u64]) -> u128 {
    terms.iter().map(|x| u128::from(*x)).sum()
}

fn verify_plain_amounts(inputs: &[BlindAssetRecord], outputs: &[BlindAssetRecord]) -> Result<()> {
    let in_amount: Result<Vec<u64>> = inputs
        .iter()
        .map(|x| x.amount.get_amount().c(d!(NoahError::ParameterError)))
        .collect();
    let out_amount: Result<Vec<u64>> = outputs
        .iter()
        .map(|x| x.amount.get_amount().c(d!(NoahError::ParameterError)))
        .collect();

    let sum_inputs = safe_sum_u64(in_amount.c(d!())?.as_slice());
    let sum_outputs = safe_sum_u64(out_amount.c(d!())?.as_slice());

    if sum_inputs != sum_outputs {
        return Err(eg!(NoahError::XfrVerifyAssetAmountError));
    }

    Ok(())
}

fn verify_plain_asset(inputs: &[BlindAssetRecord], outputs: &[BlindAssetRecord]) -> Result<()> {
    let mut list = vec![];
    for x in inputs.iter() {
        list.push(
            x.asset_type
                .get_asset_type()
                .c(d!(NoahError::ParameterError))?,
        );
    }
    for x in outputs.iter() {
        list.push(
            x.asset_type
                .get_asset_type()
                .c(d!(NoahError::ParameterError))?,
        );
    }
    if list.iter().all_equal() {
        Ok(())
    } else {
        Err(eg!(NoahError::XfrVerifyAssetAmountError))
    }
}

fn verify_plain_asset_mix(inputs: &[BlindAssetRecord], outputs: &[BlindAssetRecord]) -> Result<()> {
    let mut amounts = HashMap::new();

    for record in inputs.iter() {
        match amounts.get_mut(
            &record
                .asset_type
                .get_asset_type()
                .c(d!(NoahError::ParameterError))?,
        ) {
            None => {
                amounts.insert(
                    record
                        .asset_type
                        .get_asset_type()
                        .c(d!(NoahError::ParameterError))?,
                    vec![i128::from(
                        record
                            .amount
                            .get_amount()
                            .c(d!(NoahError::ParameterError))?,
                    )],
                );
            }
            Some(vec) => {
                vec.push(i128::from(
                    record
                        .amount
                        .get_amount()
                        .c(d!(NoahError::ParameterError))?,
                ));
            }
        };
    }

    for record in outputs.iter() {
        match amounts.get_mut(
            &record
                .asset_type
                .get_asset_type()
                .c(d!(NoahError::ParameterError))?,
        ) {
            None => {
                amounts.insert(
                    record
                        .asset_type
                        .get_asset_type()
                        .c(d!(NoahError::ParameterError))?,
                    vec![-i128::from(
                        record
                            .amount
                            .get_amount()
                            .c(d!(NoahError::ParameterError))?,
                    )],
                );
            }
            Some(vec) => {
                vec.push(-i128::from(
                    record
                        .amount
                        .get_amount()
                        .c(d!(NoahError::ParameterError))?,
                ));
            }
        };
    }

    for (_, a) in amounts.iter() {
        let sum = a.iter().sum::<i128>();
        if sum != 0i128 {
            return Err(eg!(NoahError::XfrVerifyAssetAmountError));
        }
    }
    Ok(())
}

fn batch_verify_asset_mix<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &mut BulletproofParams,
    bars_instances: &[(&[BlindAssetRecord], &[BlindAssetRecord], &AssetMixProof)],
) -> Result<()> {
    fn process_bars(
        bars: &[BlindAssetRecord],
    ) -> Result<Vec<(CompressedRistretto, CompressedRistretto)>> {
        let pow2_32 = RistrettoScalar::from(POW_2_32);
        bars.iter()
            .map(|x| {
                let (com_amount_low, com_amount_high) = match x.amount {
                    XfrAmount::Confidential((c1, c2)) => (
                        c1.decompress().c(d!(NoahError::DecompressElementError)),
                        c2.decompress().c(d!(NoahError::DecompressElementError)),
                    ),
                    XfrAmount::NonConfidential(amount) => {
                        let pc_gens = PedersenCommitmentRistretto::default();
                        let (low, high) = u64_to_u32_pair(amount);
                        (
                            Ok(pc_gens.commit(RistrettoScalar::from(low), RistrettoScalar::zero())),
                            Ok(pc_gens
                                .commit(RistrettoScalar::from(high), RistrettoScalar::zero())),
                        )
                    }
                };
                match (com_amount_low, com_amount_high) {
                    (Ok(com_amount_low), Ok(com_amount_high)) => {
                        let com_amount =
                            (com_amount_low.add(&com_amount_high.mul(&pow2_32))).compress();

                        let com_type = match x.asset_type {
                            XfrAssetType::Confidential(c) => c,
                            XfrAssetType::NonConfidential(asset_type) => {
                                let pc_gens = PedersenCommitmentRistretto::default();
                                pc_gens
                                    .commit(asset_type.as_scalar(), RistrettoScalar::zero())
                                    .compress()
                            }
                        };
                        Ok((com_amount, com_type))
                    }
                    _ => Err(eg!(NoahError::ParameterError)),
                }
            })
            .collect()
    }

    let mut asset_mix_instances = vec![];
    for instance in bars_instances {
        let in_coms = process_bars(instance.0).c(d!())?;
        let out_coms = process_bars(instance.1).c(d!())?;
        asset_mix_instances.push(AssetMixingInstance {
            inputs: in_coms,
            outputs: out_coms,
            proof: instance.2,
        });
    }

    batch_verify_asset_mixing(prng, params, &asset_mix_instances).c(d!())
}

/// Hybrid encryption
pub fn xfr_hybrid_encrypt<R: CryptoRng + RngCore>(
    pk: &PublicKey,
    prng: &mut R,
    msg: &[u8],
) -> Result<Vec<u8>> {
    match pk.0 {
        PublicKeyInner::Ed25519(pk) => Ok(hybrid_encrypt_ed25519(prng, &pk, msg).noah_to_bytes()),
        PublicKeyInner::Secp256k1(_) => {
            let pk = pk.to_secp256k1()?;

            let share_scalar = SECP256K1Scalar::random(prng);
            let share = SECP256K1G1::get_base().mul(&share_scalar);

            let mut bytes = share.to_compressed_bytes();

            let dh = pk.mul(&share_scalar);

            let mut hasher = sha2::Sha512::new();
            hasher.update(&dh.to_compressed_bytes());

            let mut key = [0u8; 32];
            key.copy_from_slice(&hasher.finalize().as_slice()[0..32]);

            let nonce = GenericArray::from_slice(&[0u8; 12]);

            let gcm = {
                let res = aes_gcm::Aes256Gcm::new_from_slice(key.as_slice());

                if res.is_err() {
                    return Err(eg!(NoahError::EncryptionError));
                }

                res.unwrap()
            };

            let mut ctext = {
                let res = gcm.encrypt(nonce, msg);

                if res.is_err() {
                    return Err(eg!(NoahError::EncryptionError));
                }

                res.unwrap()
            };
            bytes.append(&mut ctext);
            Ok(bytes)
        }
        PublicKeyInner::EthAddress(_) => panic!("EthAddress not supported"),
    }
}

/// Hybrid decryption
pub fn xfr_hybrid_decrypt(sk: &SecretKey, ctext: &[u8]) -> Result<Vec<u8>> {
    match sk {
        SecretKey::Ed25519(sk) => {
            let ctext = NoahHybridCiphertext::noah_from_bytes(ctext)?;
            Ok(hybrid_decrypt_with_ed25519_secret_key(&ctext, sk))
        }
        SecretKey::Secp256k1(_) => {
            let sk = sk.to_secp256k1()?;

            let share_len = SECP256K1G1::COMPRESSED_LEN;
            if ctext.len() < share_len {
                return Err(eg!(NoahError::DecryptionError));
            }
            let share = SECP256K1G1::from_compressed_bytes(&ctext[..share_len])?;
            let dh = share.mul(&sk);

            let mut hasher = sha2::Sha512::new();
            hasher.update(&dh.to_compressed_bytes());

            let mut key = [0u8; 32];
            key.copy_from_slice(&hasher.finalize().as_slice()[0..32]);

            let nonce = GenericArray::from_slice(&[0u8; 12]);

            let gcm = {
                let res = aes_gcm::Aes256Gcm::new_from_slice(key.as_slice());

                if res.is_err() {
                    return Err(eg!(NoahError::DecryptionError));
                }

                res.unwrap()
            };

            let res = {
                let res = gcm.decrypt(nonce, &ctext[share_len..]);

                if res.is_err() {
                    return Err(eg!(NoahError::DecryptionError));
                }

                res.unwrap()
            };
            Ok(res)
        }
    }
}

/// Find the tracer memo corresponding to the encryption keys.
pub fn find_tracing_memos<'a>(
    xfr_body: &'a XfrBody,
    pub_key: &AssetTracerEncKeys,
) -> Result<Vec<(&'a BlindAssetRecord, &'a TracerMemo)>> {
    let mut result = vec![];
    if xfr_body.inputs.len() + xfr_body.outputs.len() != xfr_body.asset_tracing_memos.len() {
        return Err(eg!(NoahError::InconsistentStructureError));
    }
    for (blind_asset_record, bar_memos) in xfr_body
        .inputs
        .iter()
        .chain(&xfr_body.outputs)
        .zip(&xfr_body.asset_tracing_memos)
    {
        for memo in bar_memos {
            if memo.enc_key == *pub_key {
                result.push((blind_asset_record, memo));
            }
        }
    }
    Ok(result)
}

/// The asset tracing result.
pub type RecordData = (u64, AssetType, Vec<Attr>, PublicKey);

/// Find and extract tracing information from confidential-transfer body.
pub fn trace_assets(
    xfr_body: &XfrBody,
    tracer_keypair: &AssetTracerKeyPair,
) -> Result<Vec<RecordData>> {
    let bars_memos = find_tracing_memos(xfr_body, &tracer_keypair.enc_key).c(d!())?;
    extract_tracing_info(bars_memos.as_slice(), &tracer_keypair.dec_key).c(d!())
}

/// Decrypt each memo with the decryption keys.
pub(crate) fn extract_tracing_info(
    memos: &[(&BlindAssetRecord, &TracerMemo)],
    dec_key: &AssetTracerDecKeys,
) -> Result<Vec<RecordData>> {
    let mut result = vec![];
    for (blind_asset_record, memo) in memos {
        let (amount_option, asset_type_option, attributes) = memo.decrypt(dec_key).c(d!())?; // return BogusAssetTracerMemo in case of error.
        let amount = match memo.lock_amount {
            None => blind_asset_record
                .amount
                .get_amount()
                .c(d!(NoahError::InconsistentStructureError))?,
            Some(_) => match amount_option {
                None => {
                    return Err(eg!(NoahError::InconsistentStructureError));
                }
                Some(amt) => amt,
            },
        };

        let asset_type = match memo.lock_asset_type {
            None => blind_asset_record
                .asset_type
                .get_asset_type()
                .c(d!(NoahError::InconsistentStructureError))?,
            Some(_) => match asset_type_option {
                None => {
                    return Err(eg!(NoahError::InconsistentStructureError));
                }
                Some(asset_type) => asset_type,
            },
        };

        result.push((
            amount,
            asset_type,
            attributes,
            blind_asset_record.public_key,
        ));
    }
    Ok(result)
}
