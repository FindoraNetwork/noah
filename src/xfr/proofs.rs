use crate::api::anon_creds::ACCommitment;
use crate::api::anon_creds::{ac_confidential_verify, ACConfidentialRevealProof};
use crate::crypto::chaum_pedersen::{
  chaum_pedersen_batch_verify_multiple_eq, chaum_pedersen_prove_multiple_eq, ChaumPedersenProofX,
};
use crate::crypto::pedersen_elgamal::{
  pedersen_elgamal_aggregate_eq_proof, pedersen_elgamal_batch_aggregate_eq_verify,
  PedersenElGamalEqProof, PedersenElGamalProofInstance,
};
use crate::errors::ZeiError;

use crate::basic_crypto::elgamal::ElGamalCiphertext;
use crate::crypto::bp_range_proofs::{batch_verify_ranges, prove_ranges};
use crate::setup::{PublicParams, BULLET_PROOF_RANGE, MAX_PARTY_NUMBER};
use crate::utils::{min_greater_equal_power_of_two, u64_to_u32_pair, u8_bigendian_slice_to_u128};
use crate::xfr::asset_record::AssetRecordType;
use crate::xfr::asset_tracer::RecordDataEncKey;
use crate::xfr::lib::XfrNotePoliciesRef;
use crate::xfr::structs::{
  asset_type_to_scalar, AssetRecord, AssetTracerMemo, AssetTracingPolicies, BlindAssetRecord,
  OpenAssetRecord, XfrAmount, XfrAssetType, XfrBody, XfrRangeProof,
};
use bulletproofs::{PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use itertools::Itertools;
use linear_map::LinearMap;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

const POW_2_32: u64 = 0xFFFF_FFFFu64 + 1;

#[allow(clippy::or_fun_call)]
pub(crate) fn asset_amount_tracking_proofs<R: CryptoRng + RngCore>(
  prng: &mut R,
  inputs: &[AssetRecord],
  outputs: &[AssetRecord])
  -> Result<Vec<PedersenElGamalEqProof>, ZeiError> {
  let mut pks_map: LinearMap<RecordDataEncKey, Vec<(&AssetRecord, &AssetTracerMemo)>> =
    LinearMap::new(); // use linear map because of determinism  (rather than HashMap)

  // 1. group records by policies with same asset_tracer public keys
  // discard when there is no policy or policy asset tracking flag is off
  collect_records_and_memos_by_keys(&mut pks_map, inputs, outputs);

  // 2. do asset tracking for each tracer_key
  let mut proofs = vec![];
  for (tracer_pub_key, records_memos) in pks_map.iter() {
    let mut transcript = Transcript::new(b"AssetTrackingProofs");
    let proof = build_same_key_asset_type_amount_tracking_proof(prng,
                                                                &mut transcript,
                                                                &tracer_pub_key,
                                                                &records_memos)?;
    proofs.push(proof)
  }
  Ok(proofs)
}

fn build_same_key_asset_type_amount_tracking_proof<R: CryptoRng + RngCore>(
  prng: &mut R,
  transcript: &mut Transcript,
  pub_key: &RecordDataEncKey,
  records_memos: &[(&AssetRecord, &AssetTracerMemo)])
  -> Result<PedersenElGamalEqProof, ZeiError> {
  let mut m = vec![];
  let mut r = vec![];
  let mut ctexts = vec![];
  let mut commitments = vec![];

  for (record, memo) in records_memos {
    let open_record = &record.open_asset_record;
    let (low, high) = u64_to_u32_pair(open_record.amount);
    if let XfrAmount::Confidential((com_low, com_high)) = open_record.blind_asset_record.amount {
      let (lock_amount_low, lock_amount_high) = memo.lock_amount
                                                    .as_ref()
                                                    .ok_or(ZeiError::InconsistentStructureError)?;
      m.push(Scalar::from(low));
      r.push(open_record.amount_blinds.0);
      ctexts.push(lock_amount_low.clone()); // TODO avoid this clone
      commitments.push(com_low.decompress()
                              .ok_or(ZeiError::DecompressElementError)?);
      m.push(Scalar::from(high));
      r.push(open_record.amount_blinds.1);
      ctexts.push(lock_amount_high.clone()); // TODO avoid this clone
      commitments.push(com_high.decompress()
                               .ok_or(ZeiError::DecompressElementError)?);
    }
    if let XfrAssetType::Confidential(com) = open_record.blind_asset_record.asset_type {
      let lock_asset_type = memo.lock_asset_type
                                .as_ref()
                                .ok_or(ZeiError::InconsistentStructureError)?;
      m.push(asset_type_to_scalar(&open_record.asset_type));
      r.push(open_record.type_blind);
      ctexts.push(lock_asset_type.clone()); // TODO avoid this clone
      commitments.push(com.decompress().ok_or(ZeiError::DecompressElementError)?);
    }
  }
  Ok(pedersen_elgamal_aggregate_eq_proof(transcript,
                                         prng,
                                         m.as_slice(),
                                         r.as_slice(),
                                         &pub_key,
                                         ctexts.as_slice(),
                                         commitments.as_slice()))
}

fn collect_records_and_memos_by_keys<'a>(map: &mut LinearMap<RecordDataEncKey,
                                                        Vec<(&'a AssetRecord,
                                                             &'a AssetTracerMemo)>>,
                                         inputs: &'a [AssetRecord],
                                         outputs: &'a [AssetRecord]) {
  for record in inputs.iter().chain(outputs) {
    for (policy, memo) in record.tracking_policies
                                .get_policies()
                                .iter()
                                .zip(record.asset_tracers_memos.iter())
    {
      if policy.asset_tracking
         && record.open_asset_record
                  .blind_asset_record
                  .get_record_type()
            != AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
      {
        let tracer_pub_key = policy.enc_keys.record_data_enc_key.clone();
        map.entry(tracer_pub_key)
           .or_insert(vec![])
           .push((record, memo))
      }
    }
  }
}

fn collect_bars_and_memos_by_keys<'a>(map: &mut LinearMap<RecordDataEncKey, BarMemoVec<'a>>,
                                      reveal_policies: &[&AssetTracingPolicies],
                                      bars: &'a [BlindAssetRecord],
                                      memos: &'a [Vec<AssetTracerMemo>])
                                      -> Result<(), ZeiError> {
  if reveal_policies.len() != bars.len() || bars.len() != memos.len() {
    // TODO avoid this if and below zip by having a single structure for bar, policies and memo
    return Err(ZeiError::ParameterError);
  }
  for ((tracing_policies_i, bar_i), memos_i) in reveal_policies.iter().zip(bars.iter()).zip(memos) {
    // If the bar is non confidential skip memo and bar, since there is no tracing proof
    if bar_i.get_record_type() == AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType {
      continue;
    }

    let tracing_policies_i = tracing_policies_i.get_policies();
    for (j, policy_i_j) in tracing_policies_i.iter().enumerate() {
      // TODO avoid indexing by j
      if policy_i_j.asset_tracking {
        let key = policy_i_j.enc_keys.record_data_enc_key.clone();
        let memo_i_j = memos_i.get(j).ok_or(ZeiError::ParameterError)?;

        map.entry(key)
           .or_insert(Default::default())
           .push(bar_i, memo_i_j); // insert ith record with j-th memo
      }
    }
  }
  Ok(())
}

pub(crate) fn batch_verify_tracer_tracking_proof<R: CryptoRng + RngCore>(
  prng: &mut R,
  pc_gens: &PedersenGens,
  xfr_bodies: &[&XfrBody],
  instances_policies: &[&XfrNotePoliciesRef])
  -> Result<(), ZeiError> {
  if xfr_bodies.len() != instances_policies.len() {
    return Err(ZeiError::ParameterError);
  }

  // 1. batch asset_type and amount tracking
  let input_reveal_policies =
    instances_policies.iter()
                      .map(|policies| policies.inputs_tracking_policies.as_slice())
                      .collect_vec();
  let output_reveal_policies =
    instances_policies.iter()
                      .map(|policies| policies.outputs_tracking_policies.as_slice())
                      .collect_vec();
  batch_verify_asset_tracking_proofs(
    prng,
    pc_gens,
    xfr_bodies,
    &input_reveal_policies,
    &output_reveal_policies,
  ).map_err(|_| ZeiError::XfrVerifyAssetTracingAssetAmountError)?;

  // Identity proofs can be batched(?)
  for (xfr_body, policies) in xfr_bodies.iter().zip(instances_policies.iter()) {
    // 2. do identity tracking proof
    let inputs_len = xfr_body.inputs.len();
    verify_identity_proofs(&policies.inputs_tracking_policies,
                           &xfr_body.asset_tracing_memos[..inputs_len],
                           &xfr_body.proofs.asset_tracking_proof.inputs_identity_proofs,
                           &policies.inputs_sig_commitments)?;
    verify_identity_proofs(&policies.outputs_tracking_policies,
                           &xfr_body.asset_tracing_memos[inputs_len..],
                           &xfr_body.proofs.asset_tracking_proof.outputs_identity_proofs,
                           &policies.outputs_sig_commitments)?;
  }

  Ok(())
}

fn batch_verify_asset_tracking_proofs<R: CryptoRng + RngCore>(prng: &mut R,
                                                              pc_gens: &PedersenGens,
                                                              xfr_bodies: &[&XfrBody],
                                                              input_reveal_policies: &[&[&AssetTracingPolicies]],
                                                              output_reveal_policies: &[&[&AssetTracingPolicies]])
                                                              -> Result<(), ZeiError> {
  // Idea: collect all instances of perdersen_elgamal_equality proofs and call a single
  // batch verification for all of them.

  // Each asset record can be associated with several tracing policies.
  // Also, each tracing key in a policy can be associated with several records.
  // Proofs for same tracing key records can be aggregated into a single short proof in an XfrBody.

  // Strategy:
  // 1. For each XfrBody collect a mapping of tracing key <-> Vec<BlindAssetRecords, Memos>, and all the associated proofs.
  // 2. On each XfrBody: for each (key, Vec<BlindAssetRecord, Memo>, proof) tuple, build an instance of a pedersen_elgamal_aggregated verify proof
  // 3. Call a single batch verification proof for all the tuples collected in 2.
  let mut instances = vec![];
  let mut all_records_map = Vec::with_capacity(xfr_bodies.len());
  let mut all_proofs = Vec::with_capacity(xfr_bodies.len());
  for (xfr_body, (input_policies, output_policies)) in
    xfr_bodies.iter().zip(input_reveal_policies.iter()
                                               .zip(output_reveal_policies.iter()))
  {
    let records_map = collect_records_memos_by_key(xfr_body, input_policies, output_policies)?;
    let m = records_map.len();
    if m
       != xfr_body.proofs
                  .asset_tracking_proof
                  .asset_type_and_amount_proofs
                  .len()
    {
      return Err(ZeiError::XfrVerifyAssetTracingAssetAmountError);
    }
    all_records_map.push(records_map);
    all_proofs.push(&xfr_body.proofs
                             .asset_tracking_proof
                             .asset_type_and_amount_proofs);
  }

  for (records_map, proofs) in all_records_map.iter().zip(all_proofs.iter()) {
    for ((key, records_and_memos), proof) in records_map.iter().zip(proofs.iter()) {
      let (ctexts, commitments) = extract_ciphertext_and_commitments(&records_and_memos.0)?;
      let peg_eq_instance = PedersenElGamalProofInstance { public_key: key,
                                                           ctexts,
                                                           commitments,
                                                           proof };
      instances.push(peg_eq_instance);
    }
  }
  let mut transcript = Transcript::new(b"AssetTrackingProofs");
  pedersen_elgamal_batch_aggregate_eq_verify(&mut transcript, prng, pc_gens, &instances)
}

#[derive(Default)]
struct BarMemoVec<'a>(Vec<(&'a BlindAssetRecord, &'a AssetTracerMemo)>);

impl<'a> BarMemoVec<'a> {
  fn push(&mut self, record: &'a BlindAssetRecord, memo: &'a AssetTracerMemo) {
    self.0.push((record, memo))
  }
}

fn collect_records_memos_by_key<'a>(
  xfr_body: &'a XfrBody,
  input_reveal_policies: &'a [&AssetTracingPolicies],
  output_reveal_policies: &'a [&AssetTracingPolicies])
  -> Result<LinearMap<RecordDataEncKey, BarMemoVec<'a>>, ZeiError> {
  let mut map: LinearMap<RecordDataEncKey, BarMemoVec<'a>> = LinearMap::new();
  let inputs_len = xfr_body.inputs.len();
  collect_bars_and_memos_by_keys(
    &mut map,
    input_reveal_policies,
    &xfr_body.inputs,
    &xfr_body.asset_tracing_memos[..inputs_len] // only inputs
  ).map_err(|_| ZeiError::XfrVerifyAssetTracingIdentityError)?;
  collect_bars_and_memos_by_keys(
    &mut map,
    output_reveal_policies,
    &xfr_body.outputs,
    &xfr_body.asset_tracing_memos[inputs_len..] //only outputs
  ).map_err(|_| ZeiError::XfrVerifyAssetTracingIdentityError)?;
  Ok(map)
}

fn verify_identity_proofs(reveal_policies: &[&AssetTracingPolicies],
                          memos: &[Vec<AssetTracerMemo>],
                          proofs: &[Vec<Option<ACConfidentialRevealProof>>],
                          sig_commitments: &[Option<&ACCommitment>])
                          -> Result<(), ZeiError> {
  // 1. check for errors
  let n = reveal_policies.len();

  if memos.len() != proofs.len() || n != sig_commitments.len() {
    return Err(ZeiError::XfrVerifyAssetTracingIdentityError);
  }
  // if no policies, memos and proofs should be empty
  if n == 0 {
    // all memos must be empty
    if !memos.iter().all(|vec| vec.is_empty()) || !proofs.iter().all(|vec| vec.is_empty()) {
      return Err(ZeiError::XfrVerifyAssetTracingIdentityError);
    }
  } else if n != memos.len() {
    return Err(ZeiError::XfrVerifyAssetTracingIdentityError);
  }

  // 2. check proofs
  for (policies, (memos, (proofs, sig_commitment))) in
    reveal_policies.iter()
                   .zip(memos.iter().zip(proofs.iter().zip(sig_commitments.iter())))
  {
    let m = policies.len();
    if m != memos.len() || m != proofs.len() {
      return Err(ZeiError::XfrVerifyAssetTracingIdentityError);
    }
    // for each policy memo and proof
    let policies = policies.get_policies();
    for (policy, (memo, proof)) in policies.iter().zip(memos.iter().zip(proofs)) {
      let enc_keys = &policy.enc_keys.attrs_enc_key;
      match (&policy.identity_tracking, &memo.lock_attributes, proof) {
        (Some(policy), Some(attributes), Some(proof)) => {
          let sig_com = sig_commitment.ok_or(ZeiError::XfrVerifyAssetTracingIdentityError)?;
          ac_confidential_verify(&policy.cred_issuer_pub_key,
                                 enc_keys,
                                 &policy.reveal_map.as_slice(),
                                 sig_com,
                                 &attributes[..],
                                 proof,
                                 &[]).map_err(|_| ZeiError::XfrVerifyAssetTracingIdentityError)?
        }
        (None, None, None) => {}
        _ => {
          return Err(ZeiError::XfrVerifyAssetTracingIdentityError);
        }
      }
    }
  }
  Ok(())
}

fn extract_ciphertext_and_commitments(
  records_and_memos: &[(&BlindAssetRecord, &AssetTracerMemo)])
  -> Result<(Vec<ElGamalCiphertext<RistrettoPoint>>, Vec<RistrettoPoint>), ZeiError> {
  let mut ctexts = vec![];
  let mut coms = vec![];
  for record_and_memo in records_and_memos {
    let record = record_and_memo.0;
    let asset_tracer_memo = record_and_memo.1;
    // 1 amount
    if asset_tracer_memo.lock_amount.is_none() && record.amount.is_confidential() {
      return Err(ZeiError::InconsistentStructureError); // There should be a lock for the amount
    }
    if let Some(lock_amount) = &asset_tracer_memo.lock_amount {
      ctexts.push(lock_amount.0.clone());
      ctexts.push(lock_amount.1.clone());
      let commitments = record.amount
                              .get_commitments()
                              .ok_or(ZeiError::InconsistentStructureError)?;
      coms.push((commitments.0).decompress()
                               .ok_or(ZeiError::DecompressElementError)?);
      coms.push((commitments.1).decompress()
                               .ok_or(ZeiError::DecompressElementError)?);
    }

    // 2 asset type
    if asset_tracer_memo.lock_asset_type.is_none() && record.asset_type.is_confidential() {
      return Err(ZeiError::InconsistentStructureError); // There should be a lock for the asset type
    }
    if let Some(lock_type) = &asset_tracer_memo.lock_asset_type {
      ctexts.push(lock_type.clone());
      coms.push(record.asset_type
                      .get_commitment()
                      .ok_or(ZeiError::InconsistentStructureError)?
                      .decompress()
                      .ok_or(ZeiError::DecompressElementError)?);
    }
  }
  Ok((ctexts, coms))
}

/**** Range Proofs *****/

/// I compute a range proof for confidential amount transfers.
/// The proof guarantees that output amounts and difference between total input
/// and total output are in the range [0,2^{64} - 1]
pub(crate) fn range_proof(inputs: &[&OpenAssetRecord],
                          outputs: &[&OpenAssetRecord])
                          -> Result<XfrRangeProof, ZeiError> {
  let num_output = outputs.len();
  let upper_power2 = min_greater_equal_power_of_two((2 * (num_output + 1)) as u32) as usize;
  if upper_power2 > MAX_PARTY_NUMBER {
    return Err(ZeiError::RangeProofProveError);
  }

  let params = PublicParams::new();

  //build values vector (out amounts + amount difference)
  let in_total = inputs.iter().fold(0u64, |accum, x| accum + x.amount);
  let out_amounts: Vec<u64> = outputs.iter().map(|x| x.amount).collect();
  let out_total = out_amounts.iter().sum::<u64>();
  let xfr_diff = if in_total >= out_total {
    in_total - out_total
  } else {
    return Err(ZeiError::RangeProofProveError);
  };
  let mut values = Vec::with_capacity(out_amounts.len() + 1);
  for x in out_amounts {
    let (lower, higher) = u64_to_u32_pair(x);
    values.push(lower as u64);
    values.push(higher as u64);
  }
  let (diff_low, diff_high) = u64_to_u32_pair(xfr_diff);
  values.push(diff_low as u64);
  values.push(diff_high as u64);
  for _ in values.len()..upper_power2 {
    values.push(0u64);
  }

  //build blinding vectors (out blindings + blindings difference)
  let (total_blind_input_low, total_blind_input_high) = add_blindings(inputs);
  let (total_blind_output_low, total_blind_output_high) = add_blindings(outputs);

  let xfr_blind_diff_low = total_blind_input_low - total_blind_output_low;
  let xfr_blind_diff_high = total_blind_input_high - total_blind_output_high;

  let mut range_proof_blinds = Vec::with_capacity(upper_power2);
  for output in outputs.iter() {
    range_proof_blinds.push(output.amount_blinds.0); // low
    range_proof_blinds.push(output.amount_blinds.1); // high
  }
  range_proof_blinds.push(xfr_blind_diff_low);
  range_proof_blinds.push(xfr_blind_diff_high);
  for _ in range_proof_blinds.len()..upper_power2 {
    range_proof_blinds.push(Scalar::default());
  }

  let mut transcript = Transcript::new(b"Zei Range Proof");
  let (range_proof, coms) =
    prove_ranges(&params,
                 &mut transcript,
                 values.as_slice(),
                 range_proof_blinds.as_slice(),
                 BULLET_PROOF_RANGE).map_err(|_| ZeiError::RangeProofProveError)?;

  let diff_com_low = coms[2 * num_output];
  let diff_com_high = coms[2 * num_output + 1];
  Ok(XfrRangeProof { range_proof,
                     xfr_diff_commitment_low: diff_com_low,
                     xfr_diff_commitment_high: diff_com_high })
}
fn add_blindings(oar: &[&OpenAssetRecord]) -> (Scalar, Scalar) {
  oar.iter()
     .fold((Scalar::from(0u8), Scalar::from(0u8)), |(low, high), x| {
       (low + x.amount_blinds.0, high + x.amount_blinds.1)
     })
}

pub(crate) fn batch_verify_confidential_amount<R: CryptoRng + RngCore>(prng: &mut R,
                                                                       params: &PublicParams,
                                                                       instances: &[(&Vec<BlindAssetRecord>, &Vec<BlindAssetRecord>, &XfrRangeProof)])
                                                                       -> Result<(), ZeiError> {
  let mut transcripts = vec![Transcript::new(b"Zei Range Proof"); instances.len()];
  let proofs: Vec<&RangeProof> = instances.iter().map(|(_, _, pf)| &pf.range_proof).collect();
  let mut commitments = vec![];
  for (input, output, proof) in instances {
    commitments.push(extract_value_commitments(input.as_slice(), output.as_slice(), proof)?);
  }
  let value_commitments = commitments.iter().map(|c| c.as_slice()).collect_vec();
  batch_verify_ranges(prng,
                      params,
                      proofs.as_slice(),
                      &mut transcripts,
                      &value_commitments,
                      BULLET_PROOF_RANGE).map_err(|_| ZeiError::XfrVerifyConfidentialAmountError)
}

fn extract_value_commitments(inputs: &[BlindAssetRecord],
                             outputs: &[BlindAssetRecord],
                             proof: &XfrRangeProof)
                             -> Result<Vec<CompressedRistretto>, ZeiError> {
  let num_output = outputs.len();
  let upper_power2 = min_greater_equal_power_of_two((2 * num_output + 2) as u32) as usize;
  let pow2_32 = Scalar::from(POW_2_32);

  let mut commitments = Vec::with_capacity(upper_power2);
  // 1. verify proof commitment to transfer's input - output amounts match proof commitments
  let mut total_input_com_low = RistrettoPoint::identity();
  let mut total_input_com_high = RistrettoPoint::identity();
  for input in inputs.iter() {
    let (com_low, com_high) = match input.amount {
      XfrAmount::Confidential((com_low, com_high)) => {
        (com_low.decompress()
                .ok_or(ZeiError::XfrVerifyConfidentialAmountError)?,
         com_high.decompress()
                 .ok_or(ZeiError::XfrVerifyConfidentialAmountError)?)
      }
      XfrAmount::NonConfidential(amount) => {
        let (low, high) = u64_to_u32_pair(amount);
        let com_low = PedersenGens::default().commit(Scalar::from(low), Scalar::zero());
        let com_high = PedersenGens::default().commit(Scalar::from(high), Scalar::zero());
        (com_low, com_high)
      }
    };
    total_input_com_low += com_low;
    total_input_com_high += com_high;
  }
  let mut total_output_com_low = RistrettoPoint::identity();
  let mut total_output_com_high = RistrettoPoint::identity();
  for output in outputs.iter() {
    let (com_low, com_high) = match output.amount {
      XfrAmount::Confidential((com_low, com_high)) => {
        (com_low.decompress().unwrap(), com_high.decompress().unwrap())
      }
      XfrAmount::NonConfidential(amount) => {
        let (low, high) = u64_to_u32_pair(amount);
        let com_low = PedersenGens::default().commit(Scalar::from(low), Scalar::zero());
        let com_high = PedersenGens::default().commit(Scalar::from(high), Scalar::zero());
        (com_low, com_high)
      }
    };
    total_output_com_low += com_low;
    total_output_com_high += com_high;

    commitments.push(com_low.compress());
    commitments.push(com_high.compress());
    //output_com.push(com_low + com_high * Scalar::from(0xFFFFFFFF as u64 + 1));
  }

  // 3. derive input - output commitment, compare with proof struct low anc high commitments
  let derived_xfr_diff_com = total_input_com_low - total_output_com_low
                             + (total_input_com_high - total_output_com_high) * pow2_32;
  let proof_xfr_com_low = proof.xfr_diff_commitment_low
                               .decompress()
                               .ok_or(ZeiError::DecompressElementError)?;
  let proof_xfr_com_high = proof.xfr_diff_commitment_high
                                .decompress()
                                .ok_or(ZeiError::DecompressElementError)?;
  let proof_xfr_com_diff = proof_xfr_com_low + proof_xfr_com_high * pow2_32;

  if derived_xfr_diff_com.compress() != proof_xfr_com_diff.compress() {
    return Err(ZeiError::XfrVerifyConfidentialAmountError);
  }

  // 4. Push diff commitments
  commitments.push(proof.xfr_diff_commitment_low);
  commitments.push(proof.xfr_diff_commitment_high);

  // 5. padd with commitments to 0
  for _ in commitments.len()..upper_power2 {
    commitments.push(CompressedRistretto::identity());
  }

  Ok(commitments)
}
/**** Asset Equality Proofs *****/

/// I compute asset equality proof for confidential asset transfers
pub(crate) fn asset_proof<R: CryptoRng + RngCore>(prng: &mut R,
                                                  pc_gens: &PedersenGens,
                                                  open_inputs: &[&OpenAssetRecord],
                                                  open_outputs: &[&OpenAssetRecord])
                                                  -> Result<ChaumPedersenProofX, ZeiError> {
  let asset = open_inputs[0].asset_type;
  let asset_scalar = Scalar::from(u8_bigendian_slice_to_u128(&asset[..]));

  let mut asset_coms = vec![];
  let mut asset_blinds = vec![];

  for x in open_inputs.iter().chain(open_outputs) {
    let commitment = match x.blind_asset_record.asset_type {
      XfrAssetType::Confidential(com) => com.decompress().unwrap(),
      XfrAssetType::NonConfidential(asset_type) => {
        pc_gens.commit(asset_type_to_scalar(&asset_type), x.type_blind)
      }
    };
    asset_coms.push(commitment);
    asset_blinds.push(x.type_blind);
  }
  let mut transcript = Transcript::new(b"AssetEquality");
  let proof = chaum_pedersen_prove_multiple_eq(&mut transcript,
                                               prng,
                                               pc_gens,
                                               &asset_scalar,
                                               asset_coms.as_slice(),
                                               asset_blinds.as_slice())?;

  Ok(proof)
}

pub(crate) fn batch_verify_confidential_asset<R: CryptoRng + RngCore>(prng: &mut R,
                                                                      pc_gens: &PedersenGens,
                                                                      instances: &[(&Vec<BlindAssetRecord>, &Vec<BlindAssetRecord>, &ChaumPedersenProofX)])
                                                                      -> Result<(), ZeiError> {
  let mut transcript = Transcript::new(b"AssetEquality");
  let mut proof_instances = Vec::with_capacity(instances.len());
  for (inputs, outputs, proof) in instances {
    let instance_commitments: Vec<RistrettoPoint> =
      inputs.iter()
            .chain(outputs.iter())
            .map(|x| match x.asset_type {
              XfrAssetType::Confidential(com) => com.decompress().unwrap(),
              XfrAssetType::NonConfidential(asset_type) => {
                pc_gens.commit(asset_type_to_scalar(&asset_type), Scalar::zero())
              }
            })
            .collect();
    proof_instances.push((instance_commitments, *proof));
  }
  chaum_pedersen_batch_verify_multiple_eq(&mut transcript, prng, &pc_gens, &proof_instances)
    .map_err(|_| ZeiError::XfrVerifyConfidentialAssetError)
}

#[cfg(test)]
mod tests {
  use crate::algebra::bls12_381::BLSG1;
  use crate::algebra::groups::Group;
  use crate::api::anon_creds::ACSignature;
  use crate::errors::ZeiError;
  use crate::xfr::asset_tracer::gen_asset_tracer_keypair;
  use crate::xfr::proofs::verify_identity_proofs;
  use crate::xfr::structs::{AssetTracerMemo, AssetTracingPolicies, AssetTracingPolicy};
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn verify_identity_proofs_structure() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);

    // Case where the number of asset tracing policies is 0
    let reveal_policies = vec![];
    let memos = vec![];
    let proofs = vec![];
    let sig_commitments = vec![];

    // 1. no policies => correct verification
    let res = verify_identity_proofs(reveal_policies.as_slice(),
                                     memos.as_slice(),
                                     proofs.as_slice(),
                                     sig_commitments.as_slice());
    assert_eq!(res, Ok(()));

    // fake sig commitment
    let sig_commitment =
      crate::api::anon_creds::ACCommitment { 0: ACSignature { sigma1: BLSG1::get_identity(),
                                                              sigma2: BLSG1::get_identity() } };

    // 2. sig commitments length doesn't match memos length
    let sig_commitments = vec![Some(&sig_commitment)];
    let res = verify_identity_proofs(reveal_policies.as_slice(),
                                     memos.as_slice(),
                                     proofs.as_slice(),
                                     sig_commitments.as_slice());

    assert_eq!(res, Err(ZeiError::XfrVerifyAssetTracingIdentityError));

    // 2. if policy, then there must be memos and proofs
    let policy = AssetTracingPolicy{
      enc_keys: gen_asset_tracer_keypair(&mut prng).enc_key,
      asset_tracking: true, // do asset tracing
      identity_tracking: None // do not trace identity
    };

    let asset_tracing_policies = AssetTracingPolicies(vec![policy]);
    let reveal_policies = vec![&asset_tracing_policies];

    let res = verify_identity_proofs(reveal_policies.as_slice(),
                                     memos.as_slice(),
                                     proofs.as_slice(),
                                     sig_commitments.as_slice());

    assert_eq!(res, Err(ZeiError::XfrVerifyAssetTracingIdentityError));

    // fake memo
    let memos = vec![vec![AssetTracerMemo { enc_key:
                                              gen_asset_tracer_keypair(&mut prng).enc_key,
                                            lock_amount: None,
                                            lock_asset_type: None,
                                            lock_attributes: None }]];
    let reveal_policies = vec![&asset_tracing_policies];

    let res = verify_identity_proofs(reveal_policies.as_slice(),
                                     memos.as_slice(),
                                     proofs.as_slice(),
                                     sig_commitments.as_slice());

    assert_eq!(res, Err(ZeiError::XfrVerifyAssetTracingIdentityError));
  }
}
