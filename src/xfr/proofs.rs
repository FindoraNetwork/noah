use crate::api::anon_creds::ACCommitment;
use crate::api::anon_creds::{ac_confidential_verify, ACConfidentialRevealProof};
use crate::crypto::chaum_pedersen::{
  chaum_pedersen_prove_multiple_eq, chaum_pedersen_verify_multiple_eq, ChaumPedersenProofX,
};
use crate::crypto::pedersen_elgamal::{
  pedersen_elgamal_aggregate_eq_proof, pedersen_elgamal_aggregate_eq_verify, PedersenElGamalEqProof,
};
use crate::errors::ZeiError;

use crate::setup::{PublicParams, BULLET_PROOF_RANGE, MAX_PARTY_NUMBER};
use crate::utils::{min_greater_equal_power_of_two, u64_to_u32_pair, u8_bigendian_slice_to_u128};
use crate::xfr::asset_record::AssetRecordType;
use crate::xfr::asset_tracer::RecordDataEncKey;
use crate::xfr::structs::{
  asset_type_to_scalar, AssetRecord, AssetTracerMemo, AssetTracingPolicies, BlindAssetRecord,
  OpenAssetRecord, XfrAmount, XfrAssetType, XfrBody, XfrRangeProof,
};
use bulletproofs::{PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
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
  let mut transcript = Transcript::new(b"AssetTrackingProofs");
  let mut proofs = vec![];
  for (tracer_pub_key, records_memos) in pks_map {
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

fn collect_bars_and_memos_by_keys<'a>(map: &mut LinearMap<RecordDataEncKey,
                                                     Vec<(&'a BlindAssetRecord,
                                                          &'a AssetTracerMemo)>>,
                                      reveal_policies: &[&AssetTracingPolicies],
                                      bars: &'a [BlindAssetRecord],
                                      memos: &'a [Vec<AssetTracerMemo>])
                                      -> Result<(), ZeiError> {
  for (i, tracing_policies_i) in reveal_policies.iter().enumerate() {
    let memos_i = memos.get(i).ok_or(ZeiError::ParameterError)?;
    let tracing_policies_i = tracing_policies_i.get_policies();
    for (j, policy_i_j) in tracing_policies_i.iter().enumerate() {
      if policy_i_j.asset_tracking {
        let key = policy_i_j.enc_keys.record_data_enc_key.clone();
        let memo_i_j = memos_i.get(j).ok_or(ZeiError::ParameterError)?;

        map.entry(key).or_insert(vec![]).push((&bars[i], memo_i_j)); // insert ith record with j-th memo
      }
    }
  }
  Ok(())
}

#[allow(clippy::or_fun_call)]
pub(crate) fn verify_tracer_tracking_proof<R: CryptoRng + RngCore>(prng: &mut R,
                                                                   xfr_body: &XfrBody,
                                                                   input_reveal_policies: &[&AssetTracingPolicies],
                                                                   input_sig_commitments: &[Option<&ACCommitment>],
                                                                   output_reveal_policies: &[&AssetTracingPolicies],
                                                                   output_sig_commitments: &[Option<&ACCommitment>])
                                                                   -> Result<(), ZeiError> {
  // 1. asset_type and amount tracking
  verify_asset_tracking_proofs(prng,
                               xfr_body,
                               input_reveal_policies,
                               output_reveal_policies)?;
  // 2. do identity tracking proof
  let inputs_len = xfr_body.inputs.len();
  verify_identity_proofs(input_reveal_policies,
                         &xfr_body.asset_tracing_memos[..inputs_len],
                         &xfr_body.proofs.asset_tracking_proof.inputs_identity_proofs,
                         input_sig_commitments)?;
  verify_identity_proofs(output_reveal_policies,
                         &xfr_body.asset_tracing_memos[inputs_len..],
                         &xfr_body.proofs.asset_tracking_proof.outputs_identity_proofs,
                         output_sig_commitments)
}

fn verify_asset_tracking_proofs<R: CryptoRng + RngCore>(prng: &mut R,
                                                        xfr_body: &XfrBody,
                                                        input_reveal_policies: &[&AssetTracingPolicies],
                                                        output_reveal_policies: &[&AssetTracingPolicies])
                                                        -> Result<(), ZeiError> {
  let mut records_map: LinearMap<RecordDataEncKey, Vec<(&BlindAssetRecord, &AssetTracerMemo)>> =
    LinearMap::new();
  let inputs_len = xfr_body.inputs.len();
  collect_bars_and_memos_by_keys(
    &mut records_map,
    input_reveal_policies,
    &xfr_body.inputs,
    &xfr_body.asset_tracing_memos[..inputs_len] // only inputs
  ).map_err(|_| ZeiError::XfrVerifyAssetTracingIdentityError)?;
  collect_bars_and_memos_by_keys(
    &mut records_map,
    output_reveal_policies,
    &xfr_body.outputs,
    &xfr_body.asset_tracing_memos[inputs_len..] //only outputs
  ).map_err(|_| ZeiError::XfrVerifyAssetTracingIdentityError)?;

  let mut transcript = Transcript::new(b"AssetTrackingProofs");

  let m = records_map.len();
  if m
     != xfr_body.proofs
                .asset_tracking_proof
                .asset_type_and_amount_proofs
                .len()
  {
    return Err(ZeiError::XfrVerifyAssetTracingAssetAmountError);
  }

  for ((key, records_and_memos), proof) in records_map.iter()
                                                      .zip(xfr_body.proofs
                                                                   .asset_tracking_proof
                                                                   .asset_type_and_amount_proofs
                                                                   .iter())
  {
    verify_amount_and_asset_type_tracking_proof(&mut transcript,
                                                prng,
                                                key,
                                                proof,
                                                records_and_memos.as_slice())?;
  }
  Ok(())
}
fn verify_identity_proofs(reveal_policies: &[&AssetTracingPolicies],
                          memos: &[Vec<AssetTracerMemo>],
                          proofs: &[Vec<Option<ACConfidentialRevealProof>>],
                          sig_commitments: &[Option<&ACCommitment>])
                          -> Result<(), ZeiError> {
  // for each entry (with potentially many policies
  let n = reveal_policies.len();
  if n != memos.len() || n != proofs.len() || n != sig_commitments.len() {
    return Err(ZeiError::XfrVerifyAssetTracingIdentityError);
  }
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

fn verify_amount_and_asset_type_tracking_proof<R: CryptoRng + RngCore>(transcript: &mut Transcript,
                                                                       prng: &mut R,
                                                                       tracer_enc_key: &RecordDataEncKey,
                                                                       proof: &PedersenElGamalEqProof,
                                                                       records_and_memos: &[(&BlindAssetRecord, &AssetTracerMemo)])
                                                                       -> Result<(), ZeiError> {
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
      coms.push((commitments.0).decompress().unwrap());
      coms.push((commitments.1).decompress().unwrap());
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
                      .unwrap());
    }
  }
  pedersen_elgamal_aggregate_eq_verify(transcript,
                                       prng,
                                       tracer_enc_key,
                                       ctexts.as_slice(),
                                       coms.as_slice(),
                                       proof).map_err(|_| {
                                               ZeiError::XfrVerifyAssetTracingAssetAmountError
                                             })
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

  let mut params = PublicParams::new();

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

  let (range_proof, coms) =
    RangeProof::prove_multiple(&params.bp_gens,
                               &params.pc_gens,
                               &mut params.transcript,
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

pub(crate) fn verify_confidential_amount(inputs: &[BlindAssetRecord],
                                         outputs: &[BlindAssetRecord],
                                         range_proof: &XfrRangeProof)
                                         -> Result<(), ZeiError> {
  let num_output = outputs.len();
  let upper_power2 = min_greater_equal_power_of_two((2 * num_output + 2) as u32) as usize;
  if upper_power2 > MAX_PARTY_NUMBER {
    return Err(ZeiError::XfrVerifyConfidentialAmountError);
  }
  let pow2_32 = Scalar::from(POW_2_32);
  let params = PublicParams::new();
  let mut transcript = Transcript::new(b"Zei Range Proof");

  // 1. verify proof commitment to transfer's input - output amounts match proof commitments
  let mut total_input_com = RistrettoPoint::identity();
  for input in inputs.iter() {
    let (com_low, com_high) = match input.amount {
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
    total_input_com += com_low + com_high * pow2_32;
  }

  let mut total_output_com = RistrettoPoint::identity();
  let mut range_coms: Vec<CompressedRistretto> = Vec::with_capacity(2 * num_output + 2);
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
    total_output_com += com_low + com_high * pow2_32;

    range_coms.push(com_low.compress());
    range_coms.push(com_high.compress());
    //output_com.push(com_low + com_high * Scalar::from(0xFFFFFFFF as u64 + 1));
  }
  let derived_xfr_diff_com = total_input_com - total_output_com;

  let proof_xfr_com_low = range_proof.xfr_diff_commitment_low
                                     .decompress()
                                     .ok_or(ZeiError::DecompressElementError)?;
  let proof_xfr_com_high = range_proof.xfr_diff_commitment_high
                                      .decompress()
                                      .ok_or(ZeiError::DecompressElementError)?;
  let proof_xfr_com_diff = proof_xfr_com_low + proof_xfr_com_high * pow2_32;

  if derived_xfr_diff_com.compress() != proof_xfr_com_diff.compress() {
    return Err(ZeiError::XfrVerifyConfidentialAmountError);
  }

  //2 verify range proof
  range_coms.push(range_proof.xfr_diff_commitment_low);
  range_coms.push(range_proof.xfr_diff_commitment_high);

  for _ in range_coms.len()..upper_power2 {
    range_coms.push(CompressedRistretto::identity());
  }

  range_proof.range_proof
             .verify_multiple(&params.bp_gens,
                              &params.pc_gens,
                              &mut transcript,
                              range_coms.as_slice(),
                              BULLET_PROOF_RANGE)
             .map_err(|_| ZeiError::XfrVerifyConfidentialAmountError)
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

pub(crate) fn verify_confidential_asset<R: CryptoRng + RngCore>(prng: &mut R,
                                                                inputs: &[BlindAssetRecord],
                                                                outputs: &[BlindAssetRecord],
                                                                asset_proof: &ChaumPedersenProofX)
                                                                -> Result<(), ZeiError> {
  let pc_gens = PedersenGens::default();
  let mut asset_commitments: Vec<RistrettoPoint> =
    inputs.iter()
          .map(|x| match x.asset_type {
            XfrAssetType::Confidential(com) => com.decompress().unwrap(),
            XfrAssetType::NonConfidential(asset_type) => {
              pc_gens.commit(asset_type_to_scalar(&asset_type), Scalar::zero())
            }
          })
          .collect();

  let out_asset_commitments: Vec<RistrettoPoint> =
    outputs.iter()
           .map(|x| match x.asset_type {
             XfrAssetType::Confidential(com) => com.decompress().unwrap(),
             XfrAssetType::NonConfidential(asset_type) => {
               pc_gens.commit(asset_type_to_scalar(&asset_type), Scalar::zero())
             }
           })
           .collect();

  asset_commitments.extend(out_asset_commitments.iter());

  let mut transcript = Transcript::new(b"AssetEquality");
  chaum_pedersen_verify_multiple_eq(&mut transcript,
                                    prng,
                                    &pc_gens,
                                    asset_commitments.as_slice(),
                                    asset_proof).map_err(|_| {
                                                  ZeiError::XfrVerifyConfidentialAssetError
                                                })
}
