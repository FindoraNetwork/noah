use crate::api::anon_creds::ACCommitment;
use crate::api::anon_creds::{ac_confidential_verify, ACConfidentialRevealProof};
use crate::crypto::chaum_pedersen::{
  chaum_pedersen_prove_multiple_eq, chaum_pedersen_verify_multiple_eq, ChaumPedersenProofX,
};
use crate::crypto::pedersen_elgamal::{
  pedersen_elgamal_aggregate_eq_proof, pedersen_elgamal_aggregate_eq_verify, PedersenElGamalEqProof,
};
use crate::errors::ZeiError;

use crate::errors::ZeiError::XfrVerifyAssetTracingEmptyProofError;
use crate::setup::{PublicParams, BULLET_PROOF_RANGE, MAX_PARTY_NUMBER};
use crate::utils::{min_greater_equal_power_of_two, u64_to_u32_pair, u8_bigendian_slice_to_u128};
use crate::xfr::asset_record::AssetRecordType;
use crate::xfr::asset_tracer::RecordDataEncKey;
use crate::xfr::structs::{
  asset_type_to_scalar, AssetRecord, AssetTracerMemo, AssetTracingPolicy, BlindAssetRecord,
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
  let mut proofs = vec![];
  let mut pks_map: LinearMap<RecordDataEncKey, Vec<&AssetRecord>> = LinearMap::new(); // use linear map because of determinism  (rather than HashMap)

  // 1. group records by policies with same asset_tracer public keys
  // discard when there is no policy or policy asset tracking flag is off
  for record in inputs.iter().chain(outputs) {
    if let Some(policy) = &record.tracking_policy {
      if policy.asset_tracking
         && record.open_asset_record
                  .blind_asset_record
                  .get_record_type()
            != AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
      {
        let tracer_pub_key = policy.enc_keys.record_data_enc_key.clone();
        pks_map.entry(tracer_pub_key)
               .or_insert(vec![])
               .push(&record)
      }
    }
  }

  // 2. do asset tracking for each tracer_key
  let mut transcript = Transcript::new(b"AssetTrackingProofs");
  for (tracer_pub_key, record_inputs) in pks_map {
    let mut m = vec![];
    let mut r = vec![];
    let mut ctexts = vec![];
    let mut commitments = vec![];
    for record in record_inputs {
      let open_record = &record.open_asset_record;
      if let XfrAmount::Confidential((com_low, com_high)) = open_record.blind_asset_record.amount {
        let (low, high) = u64_to_u32_pair(open_record.amount);
        let (lock_amount_low, lock_amount_high) =
          record.asset_tracer_memo
                .as_ref()
                .ok_or(ZeiError::InconsistentStructureError)?
                .lock_amount
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
        let lock_asset_type = record.asset_tracer_memo
                                    .as_ref()
                                    .ok_or(ZeiError::InconsistentStructureError)?
                                    .lock_asset_type
                                    .as_ref()
                                    .ok_or(ZeiError::InconsistentStructureError)?;
        m.push(asset_type_to_scalar(&open_record.asset_type));
        r.push(open_record.type_blind);
        ctexts.push(lock_asset_type.clone()); // TODO avoid this clone
        commitments.push(com.decompress().ok_or(ZeiError::DecompressElementError)?);
      }
    }
    proofs.push(pedersen_elgamal_aggregate_eq_proof(&mut transcript,
                                                    prng,
                                                    m.as_slice(),
                                                    r.as_slice(),
                                                    &tracer_pub_key,
                                                    ctexts.as_slice(),
                                                    commitments.as_slice()));
  }
  Ok(proofs)
}

#[allow(clippy::or_fun_call)]
pub(crate) fn verify_tracer_tracking_proof<R: CryptoRng + RngCore>(prng: &mut R,
                                                                   xfr_body: &XfrBody,
                                                                   input_reveal_policies: &[Option<&AssetTracingPolicy>],
                                                                   input_sig_commitments: &[Option<&ACCommitment>],
                                                                   output_reveal_policies: &[Option<&AssetTracingPolicy>],
                                                                   output_sig_commitments: &[Option<&ACCommitment>],
                                                                   msg: &[u8])
                                                                   -> Result<(), ZeiError> {
  // 1. asset_type and amount tracking
  let mut records_map: LinearMap<RecordDataEncKey, Vec<(&BlindAssetRecord, &AssetTracerMemo)>> =
    LinearMap::new();
  for (i, tracking_policy_option) in input_reveal_policies.iter().enumerate() {
    if let Some(policy) = tracking_policy_option {
      if policy.asset_tracking {
        let key = policy.enc_keys.record_data_enc_key.clone();
        let asset_tracer_memo =
          xfr_body.asset_tracing_memos[i].as_ref()
                                         .ok_or(ZeiError::InconsistentStructureError)?;
        records_map.entry(key)
                   .or_insert(vec![])
                   .push((&xfr_body.inputs[i], asset_tracer_memo));
      }
    }
  }

  let n = xfr_body.inputs.len();
  for (i, tracking_policy_option) in output_reveal_policies.iter().enumerate() {
    if let Some(policy) = tracking_policy_option {
      if policy.asset_tracking {
        let key = policy.enc_keys.record_data_enc_key.clone();
        let asset_tracer_memo =
          xfr_body.asset_tracing_memos[n + i].as_ref()
                                             .ok_or(ZeiError::InconsistentStructureError)?;
        records_map.entry(key)
                   .or_insert(vec![])
                   .push((&xfr_body.outputs[i], asset_tracer_memo));
      }
    }
  }
  let mut transcript = Transcript::new(b"AssetTrackingProofs");

  // TODO this section needs more testing: with different asset tracer
  let number_of_proofs = xfr_body.proofs
                                 .asset_tracking_proof
                                 .asset_type_and_amount_proofs
                                 .len();

  let number_of_asset_tracer_pub_keys = records_map.keys().len();

  if number_of_asset_tracer_pub_keys != number_of_proofs {
    return Err(XfrVerifyAssetTracingEmptyProofError);
  }

  for ((key, records_and_memos), proof) in records_map.iter()
                                                      .zip(xfr_body.proofs
                                                                   .asset_tracking_proof
                                                                   .asset_type_and_amount_proofs
                                                                   .iter())
  {
    check_amount_and_asset_type_proof(&mut transcript,
                                      prng,
                                      key,
                                      proof,
                                      records_and_memos.as_slice())?;
  }

  // 2. do identity tracking proof
  let inputs_identity_proofs = &xfr_body.proofs.asset_tracking_proof.inputs_identity_proofs;
  let inputs_identity_ctexts =
    &xfr_body.asset_tracing_memos[..xfr_body.inputs.len()].iter()
                                                          .map(|memo_option| match memo_option {
                                                            None => None,
                                                            Some(memo) => {
                                                              memo.lock_attributes.as_ref()
                                                            }
                                                          })
                                                          .collect_vec();
  check_identity_proofs(inputs_identity_proofs.as_slice(),
                        inputs_identity_ctexts.as_slice(),
                        input_reveal_policies,
                        input_sig_commitments,
                        msg)?;
  let outputs_identity_proofs = &xfr_body.proofs.asset_tracking_proof.outputs_identity_proofs;
  let outputs_identity_ctexts =
    &xfr_body.asset_tracing_memos[xfr_body.inputs.len()..].iter()
                                                          .map(|memo_option| match memo_option {
                                                            None => None,
                                                            Some(memo) => {
                                                              memo.lock_attributes.as_ref()
                                                            }
                                                          })
                                                          .collect_vec();
  check_identity_proofs(outputs_identity_proofs.as_slice(),
                        outputs_identity_ctexts.as_slice(),
                        output_reveal_policies,
                        output_sig_commitments,
                        msg)
}

fn check_amount_and_asset_type_proof<R: CryptoRng + RngCore>(transcript: &mut Transcript,
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

fn check_identity_proofs(identity_proofs: &[Option<ACConfidentialRevealProof>],
                         identity_ctexts: &[Option<&Vec<crate::api::anon_creds::AttributeCiphertext>>],
                         reveal_policies: &[Option<&AssetTracingPolicy>],
                         sig_commitments: &[Option<&ACCommitment>],
                         msg: &[u8])
                         -> Result<(), ZeiError> {
  let n = identity_proofs.len();
  if n != reveal_policies.len() || n != sig_commitments.len() {
    return Err(ZeiError::ParameterError);
  }
  for (((confidential_ac_proof, id_reveal_policy), sig_commitment), id_ctexts) in
    identity_proofs.iter()
                   .zip(reveal_policies.iter())
                   .zip(sig_commitments.iter())
                   .zip(identity_ctexts)
  {
    match (confidential_ac_proof, id_reveal_policy, sig_commitment, id_ctexts) {
      (None, None, None, None) => {} // no policy to verify,
      (Some(proof), Some(policy), Some(sig_com), Some(ctexts)) => {
        match &policy.identity_tracking {
          None => {
            // there is proof in xfr_body but there is no policy
            return Err(ZeiError::InconsistentStructureError);
          }
          Some(identity_tracking_policy) => {
            ac_confidential_verify(&identity_tracking_policy.cred_issuer_pub_key,
                                   &policy.enc_keys.attrs_enc_key,
                                   &identity_tracking_policy.reveal_map.as_slice(),
                                   sig_com,
                                   ctexts,
                                   proof,
                                   msg).map_err(|_| ZeiError::XfrVerifyAssetTracingIdentityError)?
          }
        }
      }
      (_, Some(policy), _, _) => match policy.identity_tracking {
        None => {} // ok, no proof to check
        _ => {
          // there is an identity tracking policy with no proof, or commmitment or ctext
          return Err(ZeiError::XfrVerifyAssetTracingIdentityError);
        }
      },
      _ => {
        // there is sig commitment, but no proof to verify against
        // or there is a proof, but no sig commitment or no policy
        return Err(ZeiError::ParameterError);
      }
    }
  }
  Ok(())
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
