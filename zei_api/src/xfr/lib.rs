use crate::api::anon_creds::{ACCommitment, Attr};
use crate::setup::PublicParams;
use crate::xfr::asset_mixer::{
  batch_verify_asset_mixing, prove_asset_mixing, AssetMixProof, AssetMixingInstance,
};
use crate::xfr::proofs::{
  asset_amount_tracking_proofs, asset_proof, batch_verify_confidential_amount,
  batch_verify_confidential_asset, batch_verify_tracer_tracking_proof, range_proof,
};
use crate::xfr::sig::{sign_multisig, verify_multisig, XfrKeyPair, XfrMultiSig, XfrPublicKey};
use crate::xfr::structs::*;
use algebra::groups::{GroupArithmetic, Scalar as _, ScalarArithmetic};
use algebra::ristretto::{CompressedRistretto, RistrettoScalar as Scalar};
use crypto::ristretto_pedersen::RistrettoPedersenGens;
use itertools::Itertools;
use rand_core::{CryptoRng, RngCore};
use serde::ser::Serialize;
use std::collections::HashMap;
use utils::errors::ZeiError;
use utils::u64_to_u32_pair;

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
  pub(super) fn from_inputs_outputs(inputs_record: &[AssetRecord],
                                    outputs_record: &[AssetRecord])
                                    -> Self {
    let mut multi_asset = false;
    let mut confidential_amount_nonconfidential_asset_type = false;
    let mut confidential_asset_type_nonconfidential_amount = false;
    let mut confidential_all = false;

    let asset_type = inputs_record[0].open_asset_record.asset_type;
    for record in inputs_record.iter().chain(outputs_record) {
      if asset_type != record.open_asset_record.asset_type {
        multi_asset = true;
      }
      let confidential_amount = matches!(record.open_asset_record.blind_asset_record.amount,
                                         XfrAmount::Confidential(_));
      let confidential_asset_type =
        matches!(record.open_asset_record.blind_asset_record.asset_type,
                 XfrAssetType::Confidential(_));

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

/// I Create a XfrNote from list of opened asset records inputs and asset record outputs
/// * `prng` - pseudo-random number generator
/// * `inputs` - asset records containing amounts, assets, policies and memos
/// * `outputs` - asset records containing amounts, assets, policies and memos
/// * `input_keys`- keys needed to sign the inputs
/// * `returns` an error or an XfrNote
/// # Example
/// ```
/// use rand_chacha::ChaChaRng;
/// use rand_core::SeedableRng;
/// use zei::xfr::sig::XfrKeyPair;
/// use zei::xfr::structs::{AssetRecordTemplate, AssetRecord, AssetType};
/// use zei::xfr::asset_record::AssetRecordType;
/// use zei::xfr::lib::{gen_xfr_note, verify_xfr_note, XfrNotePolicies};
/// use itertools::Itertools;
/// use zei::setup::PublicParams;
///
/// let mut prng = ChaChaRng::from_seed([0u8; 32]);
/// let mut params = PublicParams::default();
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
///   let keypair = XfrKeyPair::generate(&mut prng);
///   let asset_record = AssetRecordTemplate::with_no_asset_tracking( x.0,
///                                        x.1,
///                                        asset_record_type,
///                                        keypair.pub_key.clone());
///
///   inputs.push(AssetRecord::from_template_no_identity_tracking(&mut prng, &asset_record).unwrap());
///
///   in_asset_records.push(asset_record);
///   inkeys.push(keypair);
/// }
///
/// for x in outputs_amounts.iter() {
///     let keypair = XfrKeyPair::generate(&mut prng);
///
///     let ar = AssetRecordTemplate::with_no_asset_tracking(x.0, x.1, asset_record_type, keypair.pub_key.clone());
///     let output = AssetRecord::from_template_no_identity_tracking(&mut prng, &ar).unwrap();
///     outputs.push(output);
/// }
///
/// let xfr_note = gen_xfr_note( &mut prng,
///                              inputs.as_slice(),
///                              outputs.as_slice(),
///                              inkeys.iter().map(|x| x).collect_vec().as_slice()
///                ).unwrap();
/// let policies = XfrNotePolicies::empty_policies(inputs.len(), outputs.len());
/// assert_eq!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies.to_ref()), Ok(()));
/// ```

pub fn gen_xfr_note<R: CryptoRng + RngCore>(prng: &mut R,
                                            inputs: &[AssetRecord],
                                            outputs: &[AssetRecord],
                                            input_key_pairs: &[&XfrKeyPair])
                                            -> Result<XfrNote, ZeiError> {
  if inputs.is_empty() {
    return Err(ZeiError::ParameterError);
  }

  check_keys(inputs, input_key_pairs)?;

  let body = gen_xfr_body(prng, inputs, outputs)?;

  let multisig = compute_transfer_multisig(&body, input_key_pairs)?;

  Ok(XfrNote { body, multisig })
}

/// I create the body of a xfr note. This body contains the data to be signed.
/// * `prng` - pseudo-random number generator
/// * `inputs` - asset records containing amounts, assets, policies and memos
/// * `outputs` - asset records containing amounts, assets, policies and memos
/// * `returns` - an XfrBody struct or an error
/// # Example
/// ```
/// use rand_chacha::ChaChaRng;
/// use rand_core::SeedableRng;
/// use zei::xfr::sig::XfrKeyPair;
/// use zei::xfr::structs::{AssetRecordTemplate, AssetRecord, AssetType};
/// use zei::xfr::asset_record::AssetRecordType;
/// use zei::xfr::lib::{gen_xfr_body, verify_xfr_body, XfrNotePolicies, XfrNotePoliciesRef};
/// use zei::setup::PublicParams;
///
/// let mut prng = ChaChaRng::from_seed([0u8; 32]);
/// let mut params = PublicParams::default();
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
///   let keypair = XfrKeyPair::generate(&mut prng);
///   let ar = AssetRecordTemplate::with_no_asset_tracking( x.0,
///                                        x.1,
///                                        asset_record_type,
///                                        keypair.pub_key.clone(),
///                                        );
///
///   inputs.push(AssetRecord::from_template_no_identity_tracking(&mut prng, &ar).unwrap());
/// }
/// for x in outputs_amounts.iter() {
///     let keypair = XfrKeyPair::generate(&mut prng);
///
///     let ar = AssetRecordTemplate::with_no_asset_tracking(x.0, x.1, asset_record_type, keypair.get_pk());
///     outputs.push(AssetRecord::from_template_no_identity_tracking(&mut prng, &ar).unwrap());
/// }
/// let body = gen_xfr_body(&mut prng, &inputs, &outputs).unwrap();
/// let policies = XfrNotePolicies::empty_policies(inputs.len(), outputs.len());
/// assert_eq!(verify_xfr_body(&mut prng, &mut params, &body, &policies.to_ref()), Ok(()));
/// ```
pub fn gen_xfr_body<R: CryptoRng + RngCore>(prng: &mut R,
                                            inputs: &[AssetRecord],
                                            outputs: &[AssetRecord])
                                            -> Result<XfrBody, ZeiError> {
  if inputs.is_empty() {
    return Err(ZeiError::ParameterError);
  }
  let xfr_type = XfrType::from_inputs_outputs(inputs, outputs);
  check_asset_amount(inputs, outputs)?;

  let single_asset = !matches!(xfr_type,
                               XfrType::NonConfidential_MultiAsset
                               | XfrType::Confidential_MultiAsset);

  let open_inputs = inputs.iter()
                          .map(|input| &input.open_asset_record)
                          .collect_vec();
  let open_outputs = outputs.iter()
                            .map(|output| &output.open_asset_record)
                            .collect_vec();
  let asset_amount_proof = if single_asset {
    gen_xfr_proofs_single_asset(prng,
                                open_inputs.as_slice(),
                                open_outputs.as_slice(),
                                xfr_type)?
  } else {
    gen_xfr_proofs_multi_asset(open_inputs.as_slice(), open_outputs.as_slice(), xfr_type)?
  };

  //do tracking proofs
  // TODO avoid clones below
  let asset_type_amount_tracking_proof = asset_amount_tracking_proofs(prng, inputs, outputs)?;
  let asset_tracking_proof =
    AssetTrackingProofs { asset_type_and_amount_proofs: asset_type_amount_tracking_proof,
                          inputs_identity_proofs: inputs.iter()
                                                        .map(|input| input.identity_proofs.clone())
                                                        .collect_vec(),
                          outputs_identity_proofs:
                            outputs.iter()
                                   .map(|output| output.identity_proofs.clone())
                                   .collect_vec() };

  let proofs = XfrProofs { asset_type_and_amount_proof: asset_amount_proof,
                           asset_tracking_proof };

  let mut xfr_inputs = vec![];
  for x in open_inputs {
    xfr_inputs.push(x.blind_asset_record.clone())
  }

  let mut xfr_outputs = vec![];
  for x in open_outputs {
    xfr_outputs.push(x.blind_asset_record.clone())
  }

  let tracer_memos = inputs.iter()
                           .chain(outputs)
                           .map(|record_input| {
                             record_input.asset_tracers_memos.clone() // Can I avoid this clone?
                           })
                           .collect_vec();
  let owner_memos = outputs.iter()
                           .map(|record_input| {
                             record_input.owner_memo.clone() // Can I avoid this clone?
                           })
                           .collect_vec();
  Ok(XfrBody { inputs: xfr_inputs,
               outputs: xfr_outputs,
               proofs,
               asset_tracing_memos: tracer_memos,
               owners_memos: owner_memos })
}

fn check_keys(inputs: &[AssetRecord], input_key_pairs: &[&XfrKeyPair]) -> Result<(), ZeiError> {
  if inputs.len() != input_key_pairs.len() {
    return Err(ZeiError::ParameterError);
  }
  for (input, key) in inputs.iter().zip(input_key_pairs.iter()) {
    let inkey = &input.open_asset_record.blind_asset_record.public_key;
    if inkey != &key.pub_key {
      return Err(ZeiError::ParameterError);
    }
  }
  Ok(())
}

fn gen_xfr_proofs_multi_asset(inputs: &[&OpenAssetRecord],
                              outputs: &[&OpenAssetRecord],
                              xfr_type: XfrType)
                              -> Result<AssetTypeAndAmountProof, ZeiError> {
  let pow2_32 = Scalar::from_u64(POW_2_32);

  let mut ins = vec![];

  for x in inputs.iter() {
    ins.push((x.amount,
              x.asset_type.as_scalar(),
              x.amount_blinds.0.add(&pow2_32.mul(&x.amount_blinds.1)),
              x.type_blind));
  }

  let mut out = vec![];
  for x in outputs.iter() {
    out.push((x.amount,
              x.asset_type.as_scalar(),
              x.amount_blinds.0.add(&pow2_32.mul(&x.amount_blinds.1)),
              x.type_blind));
  }

  match xfr_type {
    XfrType::Confidential_MultiAsset => {
      let mix_proof = prove_asset_mixing(ins.as_slice(), out.as_slice())?;
      Ok(AssetTypeAndAmountProof::AssetMix(mix_proof))
    }
    XfrType::NonConfidential_MultiAsset => Ok(AssetTypeAndAmountProof::NoProof),
    _ => Err(ZeiError::XfrCreationAssetAmountError),
  }
}

fn gen_xfr_proofs_single_asset<R: CryptoRng + RngCore>(
  prng: &mut R,
  inputs: &[&OpenAssetRecord],
  outputs: &[&OpenAssetRecord],
  xfr_type: XfrType)
  -> Result<AssetTypeAndAmountProof, ZeiError> {
  let pc_gens = RistrettoPedersenGens::default();

  match xfr_type {
    XfrType::NonConfidential_SingleAsset => Ok(AssetTypeAndAmountProof::NoProof),
    XfrType::ConfidentialAmount_NonConfidentialAssetType_SingleAsset => {
      Ok(AssetTypeAndAmountProof::ConfAmount(range_proof(inputs, outputs)?))
    }
    XfrType::NonConfidentialAmount_ConfidentialAssetType_SingleAsset => {
      Ok(AssetTypeAndAmountProof::ConfAsset(Box::new(asset_proof(prng, &pc_gens, inputs,
                                                                 outputs)?)))
    }
    XfrType::Confidential_SingleAsset => {
      Ok(AssetTypeAndAmountProof::ConfAll(Box::new((range_proof(inputs, outputs)?,
                                                    asset_proof(prng, &pc_gens, inputs,
                                                                outputs)?))))
    }
    _ => Err(ZeiError::XfrCreationAssetAmountError), // Type cannot be multi asset
  }
}

/// Check that for each asset type total input amount >= total output amount,
/// returns Err(ZeiError::XfrCreationAssetAmountError) otherwise.
/// Return Ok(true) if all inputs and outputs involve a single asset type. If multiple assets
/// are detected, then return Ok(false)
fn check_asset_amount(inputs: &[AssetRecord], outputs: &[AssetRecord]) -> Result<(), ZeiError> {
  let mut amounts = HashMap::new();

  for record in inputs.iter() {
    match amounts.get_mut(&(record.open_asset_record.asset_type)) {
      None => {
        amounts.insert(record.open_asset_record.asset_type,
                       vec![i128::from(record.open_asset_record.amount)]);
      }
      Some(vec) => {
        vec.push(i128::from(record.open_asset_record.amount));
      }
    };
  }

  for record in outputs.iter() {
    match amounts.get_mut(&record.open_asset_record.asset_type) {
      None => {
        amounts.insert(record.open_asset_record.asset_type,
                       vec![-i128::from(record.open_asset_record.amount)]);
      }
      Some(vec) => {
        vec.push(-i128::from(record.open_asset_record.amount));
      }
    };
  }

  for (_, a) in amounts.iter() {
    let sum = a.iter().sum::<i128>();
    if sum != 0i128 {
      return Err(ZeiError::XfrCreationAssetAmountError);
    }
  }

  Ok(())
}

/// I compute a multisignature over the transfer's body
pub(crate) fn compute_transfer_multisig(body: &XfrBody,
                                        keys: &[&XfrKeyPair])
                                        -> Result<XfrMultiSig, ZeiError> {
  let mut vec = vec![];
  body.serialize(&mut rmp_serde::Serializer::new(&mut vec))
      .map_err(|_| ZeiError::SerializationError)?;
  Ok(sign_multisig(keys, vec.as_slice()))
}

/// I verify the transfer multisignature over the its body
pub(crate) fn verify_transfer_multisig(xfr_note: &XfrNote) -> Result<(), ZeiError> {
  let mut vec = vec![];
  xfr_note.body
          .serialize(&mut rmp_serde::Serializer::new(&mut vec))
          .map_err(|_| ZeiError::SerializationError)?;
  let mut public_keys = vec![];
  for x in xfr_note.body.inputs.iter() {
    public_keys.push(x.public_key)
  }
  verify_multisig(public_keys.as_slice(), vec.as_slice(), &xfr_note.multisig)
}

/// XfrNote verification
/// * `prng` - pseudo-random number generator
/// * `xfr_note` - XfrNote struct to be verified
/// * `policies` - list of set of policies and associated information corresponding to each xfr_note-
/// * `returns` - () or an ZeiError in case of verification error
pub fn verify_xfr_note<R: CryptoRng + RngCore>(prng: &mut R,
                                               params: &mut PublicParams,
                                               xfr_note: &XfrNote,
                                               policies: &XfrNotePoliciesRef)
                                               -> Result<(), ZeiError> {
  batch_verify_xfr_notes(prng, params, &[&xfr_note], &[&policies])
}

/// XfrNote Batch verification
/// * `prng` - pseudo-random number generator
/// * `xfr_notes` - XfrNote structs to be verified
/// * `policies` - list of set of policies and associated information corresponding to each xfr_note
/// * `returns` - () or an ZeiError in case of verification error
pub fn batch_verify_xfr_notes<R: CryptoRng + RngCore>(prng: &mut R,
                                                      params: &mut PublicParams,
                                                      notes: &[&XfrNote],
                                                      policies: &[&XfrNotePoliciesRef])
                                                      -> Result<(), ZeiError> {
  // 1. verify signature
  for xfr_note in notes {
    verify_transfer_multisig(xfr_note)?;
  }

  let bodies = notes.iter().map(|note| &note.body).collect_vec();
  batch_verify_xfr_bodies(prng, params, &bodies, policies)
}

pub(crate) fn batch_verify_xfr_body_asset_records<R: CryptoRng + RngCore>(
  prng: &mut R,
  params: &mut PublicParams,
  bodies: &[&XfrBody])
  -> Result<(), ZeiError> {
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
        verify_plain_asset(body.inputs.as_slice(), body.outputs.as_slice())?; // no batching
      }
      AssetTypeAndAmountProof::ConfAsset(asset_proof) => {
        verify_plain_amounts(body.inputs.as_slice(), body.outputs.as_slice())?; // no batching
        conf_asset_type_records.push((&body.inputs, &body.outputs, asset_proof));
        // save for batch proof
      }
      AssetTypeAndAmountProof::NoProof => {
        verify_plain_asset_mix(body.inputs.as_slice(), body.outputs.as_slice())?;
        // no batching
      }
      AssetTypeAndAmountProof::AssetMix(asset_mix_proof) => {
        conf_asset_mix_bodies.push((body.inputs.as_slice(),
                                    body.outputs.as_slice(),
                                    asset_mix_proof));
        // save for batch proof
      }
    }
  }

  // 1. verify confidential amounts
  batch_verify_confidential_amount(prng, params, conf_amount_records.as_slice())?;

  // 2. verify confidential asset_types
  batch_verify_confidential_asset(prng, &params.pc_gens, &conf_asset_type_records)?;

  // 3. verify confidential asset mix proofs
  batch_verify_asset_mix(prng, params, conf_asset_mix_bodies.as_slice())
}

#[derive(Clone, Default)]
pub struct XfrNotePoliciesRef<'b> {
  pub(crate) valid: bool,
  pub(crate) inputs_tracking_policies: Vec<&'b AssetTracingPolicies>,
  pub(crate) inputs_sig_commitments: Vec<Option<&'b ACCommitment>>,
  pub(crate) outputs_tracking_policies: Vec<&'b AssetTracingPolicies>,
  pub(crate) outputs_sig_commitments: Vec<Option<&'b ACCommitment>>,
}

impl<'b> XfrNotePoliciesRef<'b> {
  pub fn new(inputs_tracking_policies: Vec<&'b AssetTracingPolicies>,
             inputs_sig_commitments: Vec<Option<&'b ACCommitment>>,
             outputs_tracking_policies: Vec<&'b AssetTracingPolicies>,
             outputs_sig_commitments: Vec<Option<&'b ACCommitment>>)
             -> XfrNotePoliciesRef<'b> {
    XfrNotePoliciesRef { valid: true,
                         inputs_tracking_policies,
                         inputs_sig_commitments,
                         outputs_tracking_policies,
                         outputs_sig_commitments }
  }
}

pub(crate) fn if_some_closure(x: &Option<ACCommitment>) -> Option<&ACCommitment> {
  if (*x).is_some() {
    Some(x.as_ref().unwrap()) // safe unwrap()
  } else {
    None
  }
}

#[derive(Clone, Default, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct XfrNotePolicies {
  pub valid: bool, // allows to implement Default, if false (as after Default), then use empty_policies to create a "valid" XfrNotePolicies struct with empty policies
  pub inputs_tracking_policies: Vec<AssetTracingPolicies>,
  pub inputs_sig_commitments: Vec<Option<ACCommitment>>,
  pub outputs_tracking_policies: Vec<AssetTracingPolicies>,
  pub outputs_sig_commitments: Vec<Option<ACCommitment>>,
}

impl XfrNotePolicies {
  pub fn new(inputs_tracking_policies: Vec<AssetTracingPolicies>,
             inputs_sig_commitments: Vec<Option<ACCommitment>>,
             outputs_tracking_policies: Vec<AssetTracingPolicies>,
             outputs_sig_commitments: Vec<Option<ACCommitment>>)
             -> XfrNotePolicies {
    XfrNotePolicies { valid: true,
                      inputs_tracking_policies,
                      inputs_sig_commitments,
                      outputs_tracking_policies,
                      outputs_sig_commitments }
  }
  pub fn empty_policies(num_inputs: usize, num_outputs: usize) -> XfrNotePolicies {
    XfrNotePolicies { valid: true,
                      inputs_tracking_policies: vec![Default::default(); num_inputs],
                      inputs_sig_commitments: vec![None; num_inputs],
                      outputs_tracking_policies: vec![Default::default(); num_outputs],
                      outputs_sig_commitments: vec![None; num_outputs] }
  }

  pub fn to_ref(&self) -> XfrNotePoliciesRef {
    if self.valid {
      XfrNotePoliciesRef::new(self.inputs_tracking_policies.iter().collect_vec(),
                              self.inputs_sig_commitments
                                  .iter()
                                  .map(|x| if_some_closure(x))
                                  .collect_vec(),
                              self.outputs_tracking_policies.iter().collect_vec(),
                              self.outputs_sig_commitments
                                  .iter()
                                  .map(|x| if_some_closure(x))
                                  .collect_vec())
    } else {
      XfrNotePoliciesRef::default()
    }
  }
}

/// XfrBody verification with tracking policies
/// * `prng` - pseudo-random number generator. Needed for verifying proofs in batch.
/// * `body` - XfrBody structure to be verified
/// * `policies` - list of set of policies and associated information corresponding to each xfr_note
/// * `returns` - () or an ZeiError in case of verification error
pub fn verify_xfr_body<R: CryptoRng + RngCore>(prng: &mut R,
                                               params: &mut PublicParams,
                                               body: &XfrBody,
                                               policies: &XfrNotePoliciesRef)
                                               -> Result<(), ZeiError> {
  batch_verify_xfr_bodies(prng, params, &[body], &[policies])
}

/// XfrBodys batch verification
/// * `prng` - pseudo-random number generator. Needed for verifying proofs in batch.
/// * `bodies` - XfrBody structures to be verified
/// * `policies` - list of set of policies and associated information corresponding to each xfr_note
/// * `returns` - () or an ZeiError in case of verification error
pub fn batch_verify_xfr_bodies<R: CryptoRng + RngCore>(prng: &mut R,
                                                       params: &mut PublicParams,
                                                       bodies: &[&XfrBody],
                                                       policies: &[&XfrNotePoliciesRef])
                                                       -> Result<(), ZeiError> {
  // 1. verify amounts and asset types
  batch_verify_xfr_body_asset_records(prng, params, bodies)?;

  // 2. verify tracing proofs
  batch_verify_tracer_tracking_proof(prng, &params.pc_gens, bodies, policies)
}

/// Takes a vector of u64, converts each element to u128 and compute the sum of the new elements.
/// The goal is to avoid integer overflow when adding several u64 elements together.
fn safe_sum_u64(terms: &[u64]) -> u128 {
  terms.iter().map(|x| u128::from(*x)).sum()
}

fn verify_plain_amounts(inputs: &[BlindAssetRecord],
                        outputs: &[BlindAssetRecord])
                        -> Result<(), ZeiError> {
  let in_amount: Result<Vec<u64>, ZeiError> =
    inputs.iter()
          .map(|x| x.amount.get_amount().ok_or(ZeiError::ParameterError))
          .collect();
  let out_amount: Result<Vec<u64>, ZeiError> =
    outputs.iter()
           .map(|x| x.amount.get_amount().ok_or(ZeiError::ParameterError))
           .collect();

  let sum_inputs = safe_sum_u64(in_amount?.as_slice());
  let sum_outputs = safe_sum_u64(out_amount?.as_slice());

  if sum_inputs < sum_outputs {
    return Err(ZeiError::XfrVerifyAssetAmountError);
  }

  Ok(())
}

fn verify_plain_asset(inputs: &[BlindAssetRecord],
                      outputs: &[BlindAssetRecord])
                      -> Result<(), ZeiError> {
  let mut list = vec![];
  for x in inputs.iter() {
    list.push(x.asset_type
               .get_asset_type()
               .ok_or(ZeiError::ParameterError)?);
  }
  for x in outputs.iter() {
    list.push(x.asset_type
               .get_asset_type()
               .ok_or(ZeiError::ParameterError)?);
  }
  if list.iter().all_equal() {
    Ok(())
  } else {
    Err(ZeiError::XfrVerifyAssetAmountError)
  }
}

fn verify_plain_asset_mix(inputs: &[BlindAssetRecord],
                          outputs: &[BlindAssetRecord])
                          -> Result<(), ZeiError> {
  let mut amounts = HashMap::new();

  for record in inputs.iter() {
    match amounts.get_mut(&record.asset_type
                                 .get_asset_type()
                                 .ok_or(ZeiError::ParameterError)?)
    {
      None => {
        amounts.insert(record.asset_type
                             .get_asset_type()
                             .ok_or(ZeiError::ParameterError)?,
                       vec![i128::from(record.amount
                                             .get_amount()
                                             .ok_or(ZeiError::ParameterError)?)]);
      }
      Some(vec) => {
        vec.push(i128::from(record.amount.get_amount().ok_or(ZeiError::ParameterError)?));
      }
    };
  }

  for record in outputs.iter() {
    match amounts.get_mut(&record.asset_type
                                 .get_asset_type()
                                 .ok_or(ZeiError::ParameterError)?)
    {
      None => {
        amounts.insert(record.asset_type
                             .get_asset_type()
                             .ok_or(ZeiError::ParameterError)?,
                       vec![-i128::from(record.amount
                                              .get_amount()
                                              .ok_or(ZeiError::ParameterError)?)]);
      }
      Some(vec) => {
        vec.push(-i128::from(record.amount.get_amount().ok_or(ZeiError::ParameterError)?));
      }
    };
  }

  for (_, a) in amounts.iter() {
    let sum = a.iter().sum::<i128>();
    if sum < 0i128 {
      return Err(ZeiError::XfrVerifyAssetAmountError);
    }
  }
  Ok(())
}

fn batch_verify_asset_mix<R: CryptoRng + RngCore>(prng: &mut R,
                                                  params: &mut PublicParams,
                                                  bars_instances: &[(&[BlindAssetRecord],
                                                     &[BlindAssetRecord],
                                                     &AssetMixProof)])
                                                  -> Result<(), ZeiError> {
  fn process_bars(bars: &[BlindAssetRecord])
                  -> Result<Vec<(CompressedRistretto, CompressedRistretto)>, ZeiError> {
    let pow2_32 = Scalar::from_u64(POW_2_32);
    bars.iter()
        .map(|x| {
          let (com_amount_low, com_amount_high) = match x.amount {
            XfrAmount::Confidential((c1, c2)) => {
              (c1.decompress().ok_or(ZeiError::DecompressElementError),
               c2.decompress().ok_or(ZeiError::DecompressElementError))
            }
            XfrAmount::NonConfidential(amount) => {
              let pc_gens = RistrettoPedersenGens::default();
              let (low, high) = u64_to_u32_pair(amount);
              (Ok(pc_gens.commit(Scalar::from_u32(low), Scalar::from_u32(0))),
               Ok(pc_gens.commit(Scalar::from_u32(high), Scalar::from_u32(0))))
            }
          };
          match (com_amount_low, com_amount_high) {
            (Ok(com_amount_low), Ok(com_amount_high)) => {
              let com_amount = (com_amount_low.add(&com_amount_high.mul(&pow2_32))).compress();

              let com_type = match x.asset_type {
                XfrAssetType::Confidential(c) => c,
                XfrAssetType::NonConfidential(asset_type) => {
                  let pc_gens = RistrettoPedersenGens::default();
                  pc_gens.commit(asset_type.as_scalar(), Scalar::from_u32(0))
                         .compress()
                }
              };
              Ok((com_amount, com_type))
            }
            _ => Err(ZeiError::ParameterError),
          }
        })
        .collect()
  }

  let mut asset_mix_instances = vec![];
  for instance in bars_instances {
    let in_coms = process_bars(instance.0)?;
    let out_coms = process_bars(instance.1)?;
    asset_mix_instances.push(AssetMixingInstance { inputs: in_coms,
                                                   outputs: out_coms,
                                                   proof: instance.2 });
  }
  batch_verify_asset_mixing(prng, params, &asset_mix_instances)
}

// ASSET TRACKING
pub fn find_tracing_memos<'a>(
  xfr_body: &'a XfrBody,
  pub_key: &AssetTracerEncKeys)
  -> Result<Vec<(&'a BlindAssetRecord, &'a AssetTracerMemo)>, ZeiError> {
  let mut result = vec![];
  if xfr_body.inputs.len() + xfr_body.outputs.len() != xfr_body.asset_tracing_memos.len() {
    return Err(ZeiError::InconsistentStructureError);
  }
  for (blind_asset_record, bar_memos) in xfr_body.inputs
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

/// amount, asset type, identity attribute, public key
pub type RecordData = (u64, AssetType, Vec<Attr>, XfrPublicKey);

/// Scan XfrBody transfers involving asset tracing for `tracer_keypair`
/// Return Vector of RecordData = (amount, asset_type, identity attributes, public key)
/// Returning ZeiError::BogusAssetTracerMemo in case a TracerMemo decrypts inconsistent information, and
/// ZeiError::InconsistentStructureError if amount or asset_type cannot be found.
pub fn trace_assets(xfr_body: &XfrBody,
                    tracer_keypair: &AssetTracerKeyPair)
                    -> Result<Vec<RecordData>, ZeiError> {
  let bars_memos = find_tracing_memos(xfr_body, &tracer_keypair.enc_key)?;
  extract_tracking_info(bars_memos.as_slice(), &tracer_keypair.dec_key)
}

/// Scan XfrBody transfers involving asset tracing memos intended for `tracer_keypair`.
/// It takes each AssetTracer memo, decrypt the ElGamalEncryption
/// and brute-force Dlog computation to retrieve amount and identity attributed.
/// Return Vector of RecordData = (amount, asset_type, identity attributes, public key)
/// Returning ZeiError::BogusAssetTracerMemo in case a TracerMemo decrypts inconsistent information, and
/// ZeiError::InconsistentStructureError if amount or asset_type cannot be found.
pub fn trace_assets_brute_force(xfr_body: &XfrBody,
                                tracer_keypair: &AssetTracerKeyPair,
                                candidate_asset_types: &[AssetType])
                                -> Result<Vec<RecordData>, ZeiError> {
  let bars_memos = find_tracing_memos(xfr_body, &tracer_keypair.enc_key)?;
  extract_tracking_info_brute_force(bars_memos.as_slice(),
                                    &tracer_keypair.dec_key,
                                    candidate_asset_types)
}

/// Scan list of (BlindAssetRecord, AssetTracerMemo) retrieved by find_tracing_memos
/// (e.i. intended for the same asset tracer). It takes each AssetTracer memo,
/// decrypts its lock_info field to retrieve amount, asset type and identity attributed.
/// ElGamal ciphertext are decrypted and verified agains the retrieved data from `memo.lock_info`
/// Returning ZeiError::BogusAssetTracerMemo in case a TracerMemo decrypts inconsistent information, and
/// ZeiError::InconsistentStructureError if amount or asset_type cannot be found.
/// Return Vector of RecordData = (amount, asset_type, identity attributes, public key)
pub(crate) fn extract_tracking_info(memos: &[(&BlindAssetRecord, &AssetTracerMemo)],
                                    dec_key: &AssetTracerDecKeys)
                                    -> Result<Vec<RecordData>, ZeiError> {
  let mut result = vec![];
  for bar_memo in memos {
    let blind_asset_record = bar_memo.0;
    let memo = bar_memo.1;
    let (amount_option, asset_type_option, attributes) = memo.decrypt(dec_key)?; // return BogusAssetTracerMemo in case of error.
    let amount = match memo.lock_amount {
      None => blind_asset_record.amount
                                .get_amount()
                                .ok_or(ZeiError::InconsistentStructureError)?,
      Some(_) => match amount_option {
        None => {
          return Err(ZeiError::InconsistentStructureError);
        }
        Some(amt) => amt,
      },
    };

    let asset_type = match memo.lock_asset_type {
      None => blind_asset_record.asset_type
                                .get_asset_type()
                                .ok_or(ZeiError::InconsistentStructureError)?,
      Some(_) => match asset_type_option {
        None => {
          return Err(ZeiError::InconsistentStructureError);
        }
        Some(asset_type) => asset_type,
      },
    };

    result.push((amount, asset_type, attributes, blind_asset_record.public_key));
  }
  Ok(result)
}

/// Scan list of (BlindAssetRecord, AssetTracerMemo) retrieved by find_tracing_memos
/// (e.i. intended for the same asset tracer). It takes each AssetTracer memo, decrypt the ElGamalEncryption
/// and brute-force Dlog computation to retrieve amount and identity attributed.
/// The asset type is verified agains a known list of possible asset types `candidate_asset_types`
/// Return Vector of RecordData = (amount, asset_type, identity attributes, public key)
/// Return Error in case data cannot be retrieved due to inconsistent structure.
/// Eg. amount is not in a BlindAssetRecord nor in the corresponding AssetTracerMemo
pub(crate) fn extract_tracking_info_brute_force(memos: &[(&BlindAssetRecord,
                                                   &AssetTracerMemo)],
                                                dec_key: &AssetTracerDecKeys,
                                                candidate_asset_types: &[AssetType])
                                                -> Result<Vec<RecordData>, ZeiError> {
  let mut result = vec![];
  for bar_memo in memos {
    let blind_asset_record = bar_memo.0;
    let memo = bar_memo.1;
    let amount = match memo.lock_amount {
      None => blind_asset_record.amount
                                .get_amount()
                                .ok_or(ZeiError::InconsistentStructureError)?,
      Some(_) => memo.extract_amount_brute_force(&dec_key.record_data_eg_dec_key)?,
    };

    let asset_type = match memo.lock_asset_type {
      None => blind_asset_record.asset_type
                                .get_asset_type()
                                .ok_or(ZeiError::InconsistentStructureError)?,
      Some(_) => memo.extract_asset_type(&dec_key.record_data_eg_dec_key, candidate_asset_types)?,
    };

    let attributes = memo.extract_identity_attributes_brute_force(&dec_key.attrs_dec_key)?;

    result.push((amount, asset_type, attributes, blind_asset_record.public_key));
  }
  Ok(result)
}

/*
pub(crate) fn verify_tracing_memos(memos: &[(&BlindAssetRecord, &AssetTracerMemo)],
                            dec_key: &AssetTracerDecKeys,
                            expected_data: &[RecordData])
                            -> Result<(), ZeiError> {
  if memos.len() != expected_data.len() {
    return Err(ZeiError::ParameterError);
  }
  for (bar_memo, expected) in memos.iter().zip(expected_data) {
    let blind_asset_record = bar_memo.0;
    let memo = bar_memo.1;
    match memo.lock_amount {
      None => {
        let bar_amount = blind_asset_record.amount
                                           .get_amount()
                                           .ok_or(ZeiError::InconsistentStructureError)?;
        if bar_amount != expected.0 {
          return Err(ZeiError::AssetTracingExtractionError);
        }
      }
      Some(_) => memo.verify_amount(&dec_key.record_data_eg_dec_key, expected.0)?,
    };

    match memo.lock_asset_type {
      None => {
        let asset_type = blind_asset_record.asset_type
                                           .get_asset_type()
                                           .ok_or(ZeiError::InconsistentStructureError)?;
        if asset_type != expected.1 {
          return Err(ZeiError::AssetTracingExtractionError);
        }
      }
      Some(_) => {
        memo.extract_asset_type(&dec_key.record_data_eg_dec_key, &[expected.1])?;
      }
    };

    let result = memo.verify_identity_attributes(&dec_key.attrs_dec_key, (expected.2).as_slice())?;
    if !result.iter().all(|current| *current) {
      return Err(ZeiError::IdentityTracingExtractionError);
    }
  }
  Ok(())
}

pub fn verify_tracing_ctexts(xfr_body: &XfrBody,
                             tracer_keypair: &AssetTracerKeyPair,
                             expected_data: &[RecordData])
                             -> Result<(), ZeiError> {
  let bars_memos = find_tracing_memos(xfr_body, &tracer_keypair.enc_key)?;
  verify_tracing_memos(bars_memos.as_slice(),
                       &tracer_keypair.dec_key,
                       expected_data)
}
*/
