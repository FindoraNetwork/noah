use crate::basic_crypto::signatures::{sign_multisig, verify_multisig, XfrKeyPair, XfrMultiSig};
use crate::errors::ZeiError;
use crate::utils::u8_bigendian_slice_to_u128;
use crate::xfr::asset_mixer::{asset_mixer_proof, asset_mixer_verify, AssetMixProof};
use crate::xfr::asset_record::build_open_asset_record;
use crate::xfr::proofs::{
  asset_proof, range_proof, tracking_proofs, verify_confidential_amount, verify_confidential_asset,
  verify_issuer_tracking_proof, ConfIdReveal,
};
use crate::xfr::structs::*;
use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::ser::Serialize;
use std::collections::HashMap;

const POW_2_32: u64 = 0xFFFFFFFFu64 + 1;

/// I Create a XfrNote from list of opened asset records inputs and asset record outputs
pub fn gen_xfr_note<R: CryptoRng + Rng>(prng: &mut R,
                                        inputs: &[OpenAssetRecord],
                                        outputs: &[AssetRecord],
                                        input_keys: &[XfrKeyPair],
                                        identity_proofs: &[Option<ConfIdReveal>])
                                        -> Result<XfrNote, ZeiError> {
  let confidential_amount = inputs[0].asset_record.amount.is_none();
  let confidential_asset = inputs[0].asset_record.asset_type.is_none();
  let issuer_pk = &inputs[0].asset_record.issuer_public_key;
  let pc_gens = PedersenGens::default();

  let single_asset = check_asset_amount(inputs, outputs)?;

  let open_outputs: Vec<OpenAssetRecord> = outputs.iter()
                                                  .map(|asset_record| {
                                                    build_open_asset_record(prng,
                                                                            &pc_gens,
                                                                            asset_record,
                                                                            confidential_amount,
                                                                            confidential_asset,
                                                                            issuer_pk)
                                                  })
                                                  .collect();

  let asset_amount_proof = match single_asset {
    true => gen_xfr_proofs_single_asset(prng,
                                        inputs,
                                        open_outputs.as_slice(),
                                        confidential_amount,
                                        confidential_asset)?,
    false => gen_xfr_proofs_multi_asset(inputs,
                                        open_outputs.as_slice(),
                                        confidential_amount,
                                        confidential_asset)?,
  };

  //do tracking proofs
  let asset_tracking_proof = AssetTrackingProofs { aggregate_amount_asset_type_proof:
                                                     tracking_proofs(prng, open_outputs.as_slice())?,
                                                   identity_proofs: identity_proofs.to_vec() };

  let proofs = XfrProofs { asset_amount_proof,
                           asset_tracking_proof };

  let mut xfr_inputs = vec![];
  for x in inputs {
    xfr_inputs.push(x.asset_record.clone())
  }

  let mut xfr_outputs = vec![];
  for x in open_outputs {
    xfr_outputs.push(x.asset_record.clone())
  }

  let body = XfrBody { inputs: xfr_inputs,
                       outputs: xfr_outputs,
                       proofs };

  let multisig = compute_transfer_multisig(&body, input_keys)?;

  Ok(XfrNote { body, multisig })
}

fn gen_xfr_proofs_multi_asset(//prng: &mut R,
                              inputs: &[OpenAssetRecord],
                              outputs: &[OpenAssetRecord],
                              confidential_amount: bool,
                              confidential_asset: bool)
                              -> Result<AssetAmountProof, ZeiError> {
  let pow2_32 = Scalar::from(POW_2_32);

  let mut ins = vec![];

  for x in inputs.iter() {
    let type_as_u128 = u8_bigendian_slice_to_u128(&x.asset_type[..]);
    let type_scalar = Scalar::from(type_as_u128);
    ins.push((x.amount,
              type_scalar,
              x.amount_blinds.0 + pow2_32 * x.amount_blinds.1,
              x.type_blind));
  }

  let mut out = vec![];
  for x in outputs.iter() {
    let type_as_u128 = u8_bigendian_slice_to_u128(&x.asset_type[..]);
    let type_scalar = Scalar::from(type_as_u128);
    out.push((x.amount,
              type_scalar,
              x.amount_blinds.0 + pow2_32 * x.amount_blinds.1,
              x.type_blind));
  }

  if confidential_asset && confidential_amount {
    let mix_proof = asset_mixer_proof(ins.as_slice(), out.as_slice())?;
    return Ok(AssetAmountProof::AssetMix(mix_proof));
  }
  if !confidential_asset && !confidential_amount {
    return Ok(AssetAmountProof::NoProof);
  }
  Err(ZeiError::XfrCreationAssetAmountError)
}
fn gen_xfr_proofs_single_asset<R: CryptoRng + Rng>(prng: &mut R,
                                                   inputs: &[OpenAssetRecord],
                                                   outputs: &[OpenAssetRecord],
                                                   confidential_amount: bool,
                                                   confidential_asset: bool)
                                                   -> Result<AssetAmountProof, ZeiError> {
  let pc_gens = PedersenGens::default();

  let xfr_range_proof = match confidential_amount {
    true => Some(range_proof(inputs, outputs)?),
    false => None,
  };

  let xfr_asset_proof = match confidential_asset {
    true => Some(asset_proof(prng, &pc_gens, inputs, outputs)?),
    false => None,
  };

  if xfr_range_proof.is_none() && xfr_asset_proof.is_none() {
    return Ok(AssetAmountProof::NoProof);
  }
  if xfr_range_proof.is_none() {
    return Ok(AssetAmountProof::ConfAsset(xfr_asset_proof.unwrap()));
  }
  if xfr_asset_proof.is_none() {
    return Ok(AssetAmountProof::ConfAmount(xfr_range_proof.unwrap()));
  }

  Ok(AssetAmountProof::ConfAll((xfr_range_proof.unwrap(), xfr_asset_proof.unwrap())))
}

fn check_asset_amount(inputs: &[OpenAssetRecord],
                      outputs: &[AssetRecord])
                      -> Result<bool, ZeiError> {
  let mut amounts = HashMap::new();

  for record in inputs.iter() {
    match amounts.get_mut(&record.asset_type) {
      None => {
        amounts.insert(record.asset_type, vec![i128::from(record.amount)]);
      }
      Some(vec) => {
        vec.push(i128::from(record.amount));
      }
    };
  }

  for record in outputs.iter() {
    match amounts.get_mut(&record.asset_type) {
      None => {
        amounts.insert(record.asset_type, vec![-i128::from(record.amount)]);
      }
      Some(vec) => {
        vec.push(-i128::from(record.amount));
      }
    };
  }

  for (_, a) in amounts.iter() {
    let sum = a.iter().sum::<i128>();
    if sum != 0i128 {
      return Err(ZeiError::XfrCreationAssetAmountError);
    }
  }

  Ok(amounts.len() == 1)
}

/// I compute a multisignature over the transfer's body
fn compute_transfer_multisig(body: &XfrBody, keys: &[XfrKeyPair]) -> Result<XfrMultiSig, ZeiError> {
  let mut vec = vec![];
  body.serialize(&mut rmp_serde::Serializer::new(&mut vec))?;
  Ok(sign_multisig(keys, vec.as_slice()))
}

/// I verify the transfer multisignature over the its body
fn verify_transfer_multisig(xfr_note: &XfrNote) -> Result<(), ZeiError> {
  let mut vec = vec![];
  xfr_note.body
          .serialize(&mut rmp_serde::Serializer::new(&mut vec))?;
  let mut public_keys = vec![];
  for x in xfr_note.body.inputs.iter() {
    public_keys.push(x.public_key)
  }
  verify_multisig(public_keys.as_slice(), vec.as_slice(), &xfr_note.multisig)
}

/// I verify a transfer note
pub fn verify_xfr_note<R: CryptoRng + Rng>(prng: &mut R,
                                           xfr_note: &XfrNote,
                                           id_reveal_policies: &[Option<IdRevealPolicy>])
                                           -> Result<(), ZeiError> {
  // 1. verify signature
  verify_transfer_multisig(&xfr_note)?;

  // 2. verify amounts and asset types
  match &xfr_note.body.proofs.asset_amount_proof {
    AssetAmountProof::ConfAll((range_proof, asset_proof)) => {
      verify_confidential_amount(&xfr_note.body.inputs, &xfr_note.body.outputs, range_proof)?;
      verify_confidential_asset(prng,
                                &xfr_note.body.inputs,
                                &xfr_note.body.outputs,
                                asset_proof)?;
    }
    AssetAmountProof::ConfAmount(range_proof) => {
      verify_confidential_amount(&xfr_note.body.inputs, &xfr_note.body.outputs, range_proof)?;
      verify_plain_asset(&xfr_note.body.inputs, &xfr_note.body.outputs)?;
    }
    AssetAmountProof::ConfAsset(asset_proof) => {
      verify_plain_amounts(&xfr_note.body.inputs, &xfr_note.body.outputs)?;
      verify_confidential_asset(prng,
                                &xfr_note.body.inputs,
                                &xfr_note.body.outputs,
                                asset_proof)?;
    }
    AssetAmountProof::NoProof => {
      verify_plain_asset_mix(&xfr_note.body.inputs, &xfr_note.body.outputs)?;
    }
    AssetAmountProof::AssetMix(asset_mix_proof) => {
      verify_asset_mix(&xfr_note.body.inputs,
                       &xfr_note.body.outputs,
                       asset_mix_proof)?;
    }
  };
  // 3 verify tracking proofs
  verify_issuer_tracking_proof(prng, &xfr_note.body, id_reveal_policies)
}

fn verify_plain_amounts(inputs: &[BlindAssetRecord],
                        outputs: &[BlindAssetRecord])
                        -> Result<(), ZeiError> {
  let in_amount: Vec<u64> = inputs.iter().map(|x| x.amount.unwrap()).collect();
  let out_amount: Vec<u64> = outputs.iter().map(|x| x.amount.unwrap()).collect();
  if in_amount.into_iter().sum::<u64>() < out_amount.into_iter().sum::<u64>() {
    return Err(ZeiError::XfrVerifyAssetAmountError);
  }

  Ok(())
}

fn verify_plain_asset(inputs: &[BlindAssetRecord],
                      outputs: &[BlindAssetRecord])
                      -> Result<(), ZeiError> {
  let mut list = vec![];
  for x in inputs.iter() {
    list.push(x.asset_type.unwrap());
  }
  for x in outputs.iter() {
    list.push(x.asset_type.unwrap());
  }

  match list.iter().all_equal() {
    true => Ok(()),
    false => Err(ZeiError::XfrVerifyAssetAmountError),
  }
}

fn verify_plain_asset_mix(inputs: &[BlindAssetRecord],
                          outputs: &[BlindAssetRecord])
                          -> Result<(), ZeiError> {
  let mut amounts = HashMap::new();

  for record in inputs.iter() {
    match amounts.get_mut(&record.asset_type.unwrap()) {
      None => {
        amounts.insert(record.asset_type.unwrap(),
                       vec![i128::from(record.amount.unwrap())]);
      }
      Some(vec) => {
        vec.push(i128::from(record.amount.unwrap()));
      }
    };
  }

  for record in outputs.iter() {
    match amounts.get_mut(&record.asset_type.unwrap()) {
      None => {
        amounts.insert(record.asset_type.unwrap(),
                       vec![-i128::from(record.amount.unwrap())]);
      }
      Some(vec) => {
        vec.push(-i128::from(record.amount.unwrap()));
      }
    };
  }

  for (_, a) in amounts.iter() {
    let sum = a.iter().sum::<i128>();
    if sum != 0i128 {
      return Err(ZeiError::XfrVerifyAssetAmountError);
    }
  }
  Ok(())
}

fn verify_asset_mix(inputs: &[BlindAssetRecord],
                    outputs: &[BlindAssetRecord],
                    proof: &AssetMixProof)
                    -> Result<(), ZeiError> {
  let pow2_32 = Scalar::from(POW_2_32);

  let mut in_coms = vec![];
  for x in inputs.iter() {
    let com_amount_low = x.amount_commitments.unwrap().0.decompress().unwrap();
    let com_amount_high = x.amount_commitments.unwrap().1.decompress().unwrap();
    let com_amount = (com_amount_low + pow2_32 * com_amount_high).compress();
    let com_type = x.asset_type_commitment.unwrap();
    in_coms.push((com_amount, com_type));
  }

  let mut out_coms = vec![];
  for x in outputs.iter() {
    let com_amount_low = x.amount_commitments.unwrap().0.decompress().unwrap();
    let com_amount_high = x.amount_commitments.unwrap().1.decompress().unwrap();
    let com_amount = (com_amount_low + pow2_32 * com_amount_high).compress();
    let com_type = x.asset_type_commitment.unwrap();
    out_coms.push((com_amount, com_type));
  }
  asset_mixer_verify(in_coms.as_slice(), out_coms.as_slice(), proof)
}

#[cfg(test)]
pub(crate) mod tests {
  use super::*;
  use crate::algebra::bls12_381::{BLSGt, BLSScalar, BLSG1};
  use crate::algebra::groups::Group;
  use crate::algebra::groups::Scalar as ScalarTrait;
  use crate::basic_crypto::elgamal::{
    elgamal_derive_public_key, elgamal_generate_secret_key, ElGamalCiphertext,
  };
  use crate::basic_crypto::signatures::XfrKeyPair;
  use crate::crypto::anon_creds;
  use crate::errors::ZeiError::{
    XfrCreationAssetAmountError, XfrVerifyAssetAmountError, XfrVerifyConfidentialAmountError,
    XfrVerifyConfidentialAssetError, XfrVerifyIssuerTrackingAssetAmountError,
    XfrVerifyIssuerTrackingIdentityError,
  };
  use crate::utils::u64_to_u32_pair;
  use crate::xfr::proofs::create_conf_id_reveal;
  use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
  use rand::SeedableRng;
  use rand_chacha::ChaChaRng;
  use rmp_serde::{Deserializer, Serializer};
  use serde::de::Deserialize;
  use serde::ser::Serialize;

  pub(crate) fn create_xfr(
    prng: &mut ChaChaRng,
    input_amounts: &[(u64, AssetType)],
    output_amounts: &[(u64, AssetType)],
    confidential_amount: bool,
    confidential_asset: bool,
    asset_tracking: bool)
    -> (XfrNote, Vec<XfrKeyPair>, Vec<OpenAssetRecord>, Vec<AssetRecord>, Vec<XfrKeyPair>) {
    let pc_gens = PedersenGens::default();
    let issuer_public_key = match asset_tracking {
      true => {
        let sk = elgamal_generate_secret_key::<_, Scalar>(prng);
        let xfr_pub_key = elgamal_derive_public_key(&pc_gens.B, &sk);
        let sk = elgamal_generate_secret_key::<_, BLSScalar>(prng);
        let id_reveal_pub_key = elgamal_derive_public_key(&BLSG1::get_base(), &sk);

        Some(AssetIssuerPubKeys { eg_ristretto_pub_key: xfr_pub_key,
                                  eg_blsg1_pub_key: id_reveal_pub_key })
      }
      false => None,
    };

    let mut inputs = vec![];
    let mut outputs = vec![];

    let mut outkeys = vec![];
    let mut inkeys = vec![];
    let mut in_asset_records = vec![];

    for x in input_amounts.iter() {
      let keypair = XfrKeyPair::generate(prng);
      let asset_record = AssetRecord { amount: x.0,
                                       asset_type: x.1,
                                       public_key: keypair.get_pk_ref().clone() };

      inputs.push(build_open_asset_record(prng,
                                          &pc_gens,
                                          &asset_record,
                                          confidential_amount,
                                          confidential_asset,
                                          &issuer_public_key));

      in_asset_records.push(asset_record);
      inkeys.push(keypair);
    }

    let mut identity_proofs = vec![];
    for x in output_amounts.iter() {
      let keypair = XfrKeyPair::generate(prng);

      outputs.push(AssetRecord { amount: x.0,
                                 asset_type: x.1,
                                 public_key: keypair.get_pk_ref().clone() });
      outkeys.push(keypair);

      identity_proofs.push(None);
    }

    let xfr_note = gen_xfr_note(prng,
                                inputs.as_slice(),
                                outputs.as_slice(),
                                inkeys.as_slice(),
                                identity_proofs.as_slice()).unwrap();

    (xfr_note, inkeys, inputs, outputs, outkeys)
  }

  fn do_transfer_tests(confidential_amount: bool, confidential_asset: bool, asset_tracking: bool) {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let asset_type = [0u8; 16];
    let pc_gens = PedersenGens::default();
    let input_amount = [(10u64, asset_type),
                        (10u64, asset_type),
                        (10u64, asset_type)];
    let out_amount = [(1u64, asset_type),
                      (2u64, asset_type),
                      (3u64, asset_type),
                      (24u64, asset_type)];

    let tuple = create_xfr(&mut prng,
                           &input_amount,
                           &out_amount,
                           confidential_amount,
                           confidential_asset,
                           asset_tracking);

    let xfr_note = tuple.0;
    let inkeys = tuple.1;
    let mut inputs = tuple.2;
    let mut outputs = tuple.3;
    let mut null_policies = vec![];
    let mut id_proofs = vec![];
    null_policies.push(None);
    null_policies.push(None);
    null_policies.push(None);
    null_policies.push(None);
    id_proofs.push(None);
    id_proofs.push(None);
    id_proofs.push(None);
    id_proofs.push(None);

    // test 1: simple transfer
    assert_eq!(Ok(()),
               verify_xfr_note(&mut prng, &xfr_note, &null_policies),
               "Simple transaction should verify ok");

    //test 2: overflow transfer
    outputs[3] = AssetRecord { amount: 0xFFFFFFFFFF,
                               asset_type,
                               public_key: outputs[3].public_key };
    let xfr_note = gen_xfr_note(&mut prng,
                                inputs.as_slice(),
                                outputs.as_slice(),
                                inkeys.as_slice(),
                                &id_proofs);
    assert_eq!(true,
               xfr_note.is_err(),
               "Xfr cannot be build if output total amount is greater than input amounts");
    assert_eq!(XfrCreationAssetAmountError,
               xfr_note.err().unwrap(),
               "Xfr cannot be build if output total amount is greater than input amounts");
    //output 3 back to original
    outputs[3] = AssetRecord { amount: 24,
                               asset_type,
                               public_key: outputs[3].public_key };
    let mut xfr_note = gen_xfr_note(&mut prng,
                                    inputs.as_slice(),
                                    outputs.as_slice(),
                                    inkeys.as_slice(),
                                    &id_proofs).unwrap();
    let error;
    if confidential_amount {
      let (low, high) = u64_to_u32_pair(0xFFFFFFFFFF);
      let commitment_low = pc_gens.commit(Scalar::from(low), Scalar::random(&mut prng))
                                  .compress();
      let commitment_high = pc_gens.commit(Scalar::from(high), Scalar::random(&mut prng))
                                   .compress();
      xfr_note.body.outputs[3].amount_commitments = Some((commitment_low, commitment_high));
      error = XfrVerifyConfidentialAmountError;
    } else {
      xfr_note.body.outputs[3].amount = Some(0xFFFFFFFFFF);
      error = XfrVerifyAssetAmountError;
    }
    xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
    assert_eq!(Err(error),
               verify_xfr_note(&mut prng, &xfr_note, &null_policies),
               "Confidential transfer with invalid amounts should fail verification");

    //test 3: exact amount transfer
    outputs[3] = AssetRecord { amount: 24u64,
                               asset_type,
                               public_key: outputs[3].public_key };
    let xfr_note = gen_xfr_note(&mut prng,
                                inputs.as_slice(),
                                outputs.as_slice(),
                                inkeys.as_slice(),
                                &id_proofs).unwrap();
    assert_eq!(Ok(()),
               verify_xfr_note(&mut prng, &xfr_note, &null_policies),
               "Not confidential tx with exact input and output should pass");

    //test 4: one output asset different from rest
    outputs[3] = AssetRecord { amount: 24u64,
                               asset_type: [1u8; 16],
                               public_key: outputs[3].public_key };
    let xfr_note = gen_xfr_note(&mut prng,
                                inputs.as_slice(),
                                outputs.as_slice(),
                                inkeys.as_slice(),
                                &id_proofs);
    assert_eq!(true,
               xfr_note.is_err(),
               "Xfr cannot be build if output asset types are different");
    assert_eq!(XfrCreationAssetAmountError,
               xfr_note.err().unwrap(),
               "Xfr cannot be build if output asset types are different");
    outputs[3] = AssetRecord { amount: 24u64,
                               asset_type: [0u8; 16],
                               public_key: outputs[3].public_key };
    let mut xfr_note = gen_xfr_note(&mut prng,
                                    inputs.as_slice(),
                                    outputs.as_slice(),
                                    inkeys.as_slice(),
                                    &id_proofs).unwrap();
    // modify xfr_note asset on an output
    let error;
    if confidential_asset {
      xfr_note.body.outputs[1].asset_type_commitment = Some(CompressedRistretto::default());
      error = XfrVerifyConfidentialAssetError;
    } else {
      xfr_note.body.outputs[1].asset_type = Some([1u8; 16]);
      error = XfrVerifyAssetAmountError;
    }
    xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
    assert_eq!(Err(error),
               verify_xfr_note(&mut prng, &xfr_note, &null_policies),
               "Transfer with different asset types should fail verification");

    //test 4:  one input asset different from rest
    let ar = AssetRecord { amount: 10u64,
                           asset_type: [1u8; 16],
                           public_key: inputs[1].asset_record.public_key };
    inputs[1] = build_open_asset_record(&mut prng,
                                        &pc_gens,
                                        &ar,
                                        confidential_amount,
                                        confidential_asset,
                                        &None);
    let xfr_note = gen_xfr_note(&mut prng,
                                inputs.as_slice(),
                                outputs.as_slice(),
                                inkeys.as_slice(),
                                &id_proofs);
    assert_eq!(true,
               xfr_note.is_err(),
               "Xfr cannot be build if output asset types are different");
    assert_eq!(XfrCreationAssetAmountError,
               xfr_note.err().unwrap(),
               "Xfr cannot be build if output asset types are different");
    //inputs[1] back to normal
    let ar = AssetRecord { amount: 10u64,
                           asset_type: [0u8; 16],
                           public_key: inputs[1].asset_record.public_key };
    inputs[1] = build_open_asset_record(&mut prng,
                                        &pc_gens,
                                        &ar,
                                        confidential_amount,
                                        confidential_asset,
                                        &None);
    let mut xfr_note = gen_xfr_note(&mut prng,
                                    inputs.as_slice(),
                                    outputs.as_slice(),
                                    inkeys.as_slice(),
                                    &id_proofs).unwrap();
    let old_asset_com = xfr_note.body.inputs[1].asset_type_commitment.clone();
    let old_asset_type = xfr_note.body.inputs[1].asset_type.clone();
    // modify xfr_note asset on an input
    let error;
    if confidential_asset {
      xfr_note.body.inputs[1].asset_type_commitment = Some(CompressedRistretto::default());
      error = XfrVerifyConfidentialAssetError;
    } else {
      xfr_note.body.inputs[1].asset_type = Some([1u8; 16]);
      error = XfrVerifyAssetAmountError;
    }
    xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
    assert_eq!(Err(error),
               verify_xfr_note(&mut prng, &xfr_note, &null_policies),
               "Confidential transfer with different asset types should fail verification ok");

    //test 5 asset tracing
    xfr_note.body.inputs[1].asset_type_commitment = old_asset_com;
    xfr_note.body.inputs[1].asset_type = old_asset_type;
    xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
    assert_eq!(Ok(()),
               verify_xfr_note(&mut prng, &xfr_note, &null_policies),
               "Transfer is ok at this point");

    /* TODO REBUILD THIS PART OF THE TEST
    for (proof, bar) in xfr_note
        .body
        .proofs
        .asset_tracking_proof
        .iter()
        .zip(xfr_note.body.outputs.iter())
    {
        assert_eq!(asset_tracking, proof.is_some());
        assert_eq!(
            asset_tracking && confidential_asset,
            proof.is_some() && proof.as_ref().unwrap().asset_type_proof.is_some()
        );
        assert_eq!(
            asset_tracking && confidential_asset,
            bar.issuer_lock_type.is_some(),
            "Issuer lock type contain value only when asset tracing and confidential asset"
        );
        assert_eq!(
            asset_tracking && confidential_amount,
            proof.is_some() && proof.as_ref().unwrap().amount_proof.is_some()
        );
        assert_eq!(
            asset_tracking && confidential_amount,
            bar.issuer_lock_amount.is_some(),
            "Issuer lock amount contain value only when asset tracing and confidential asset"
        );
        //TODO check identity proof
    }
    */

    // test bad asset tracking
    if asset_tracking && confidential_asset {
      let old_enc = xfr_note.body.outputs[0].issuer_lock_type
                                            .as_ref()
                                            .unwrap()
                                            .clone();
      let new_enc = old_enc.e2 + pc_gens.B; //adding 1 to the exponent
      xfr_note.body.outputs[0].issuer_lock_type = Some(ElGamalCiphertext { e1: old_enc.e1,
                                                                           e2: new_enc });
      xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
      assert_eq!(Err(XfrVerifyIssuerTrackingAssetAmountError),
                 verify_xfr_note(&mut prng, &xfr_note, &null_policies),
                 "Transfer verification should fail due to error in AssetTracing verification");

      //restore
      xfr_note.body.outputs[0].issuer_lock_type = Some(old_enc);
      xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
      assert_eq!(Ok(()),
                 verify_xfr_note(&mut prng, &xfr_note, &null_policies),
                 "Transfer is ok");
    }
    // test bad amount tracking
    if asset_tracking && confidential_amount {
      let old_enc = xfr_note.body.outputs[0].issuer_lock_amount
                                            .as_ref()
                                            .unwrap();
      let new_enc = old_enc.0.e2 + pc_gens.B; //adding 1 to the exponent
      xfr_note.body.outputs[0].issuer_lock_amount = Some((ElGamalCiphertext { e1: old_enc.0.e1,
                                                                              e2: new_enc },
                                                          ElGamalCiphertext { e1: old_enc.1.e1,
                                                                              e2: old_enc.1.e2 }));
      xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
      assert_eq!(Err(XfrVerifyIssuerTrackingAssetAmountError),
                 verify_xfr_note(&mut prng, &xfr_note, &null_policies),
                 "Transfer verification should fail due to error in AssetTracing verification");
    }
  }

  #[test]
  fn test_transfer_not_confidential() {
    /*! I test non confidential transfers*/
    do_transfer_tests(false, false, false);
    do_transfer_tests(false, false, true);
  }

  #[test]
  fn test_transfer_confidential_amount_plain_asset() {
    /*! I test confidential amount transfers*/
    do_transfer_tests(true, false, false);
    do_transfer_tests(true, false, true);
  }

  #[test]
  fn test_transfer_confidential_asset_plain_amount() {
    /*! I test confidential asset transfers*/
    do_transfer_tests(false, true, false);
    do_transfer_tests(false, true, true);
  }

  #[test]
  fn test_transfer_confidential() {
    /*! I test confidential amount and confidential asset transfers*/
    do_transfer_tests(true, true, false);
    do_transfer_tests(true, true, true);
  }

  fn do_test_transfer_multisig(confidential_amount: bool,
                               confidential_asset: bool,
                               asset_tracking: bool) {
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
                                            confidential_amount,
                                            confidential_asset,
                                            asset_tracking);
    assert_eq!(Ok(()), verify_transfer_multisig(&xfr_note));
  }

  #[test]
  fn test_transfer_multisig() {
    do_test_transfer_multisig(false, false, false);
    do_test_transfer_multisig(false, true, false);
    do_test_transfer_multisig(true, false, false);
    do_test_transfer_multisig(true, true, false);
    do_test_transfer_multisig(false, false, true);
    do_test_transfer_multisig(false, true, true);
    do_test_transfer_multisig(true, false, true);
    do_test_transfer_multisig(true, true, true);
  }

  #[test]
  fn test_xfr_with_identity_tracking() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);

    let pc_gens = PedersenGens::default();
    let asset_issuer_sec_key = elgamal_generate_secret_key::<_, Scalar>(&mut prng);
    let asset_issuer_pub_key =
      elgamal_derive_public_key(&RistrettoPoint::get_base(), &asset_issuer_sec_key);
    let asset_issuer_id_sec_key = elgamal_generate_secret_key::<_, BLSScalar>(&mut prng);
    let asset_issuer_id_pub_key =
      elgamal_derive_public_key(&BLSG1::get_base(), &asset_issuer_id_sec_key);
    let asset_issuer_public_key =
      Some(AssetIssuerPubKeys { eg_ristretto_pub_key: asset_issuer_pub_key,
                                eg_blsg1_pub_key: asset_issuer_id_pub_key });

    let input_keypair = XfrKeyPair::generate(&mut prng);
    let asset_record = AssetRecord { amount: 10,
                                     asset_type: [0; 16],
                                     public_key: input_keypair.get_pk_ref().clone() };
    let input = build_open_asset_record(&mut prng,
                                        &pc_gens,
                                        &asset_record,
                                        true,
                                        true,
                                        &asset_issuer_public_key);

    let output = AssetRecord { amount: 10,
                               asset_type: [0; 16],
                               public_key: input_keypair.get_pk_ref().clone() };

    let attrs = [BLSScalar::random_scalar(&mut prng),
                 BLSScalar::random_scalar(&mut prng),
                 BLSScalar::random_scalar(&mut prng),
                 BLSScalar::random_scalar(&mut prng)];
    let cred_issuer_keys = anon_creds::ac_keygen_issuer::<_, BLSScalar, BLSGt>(&mut prng, 4);
    let receiver_ac_keys =
      anon_creds::ac_keygen_user::<_, BLSScalar, BLSGt>(&mut prng, &cred_issuer_keys.0);

    let ac_signature = anon_creds::ac_sign::<_, BLSScalar, BLSGt>(&mut prng,
                                                                  &cred_issuer_keys.1,
                                                                  &receiver_ac_keys.0,
                                                                  &attrs);
    let id_tracking_policy = IdRevealPolicy { cred_issuer_pub_key: cred_issuer_keys.0.clone(),
                                              bitmap: vec![false, true, false, true] };
    let proof = anon_creds::ac_reveal::<_, BLSScalar, BLSGt>(&mut prng,
                                                             &receiver_ac_keys.1,
                                                             &cred_issuer_keys.0,
                                                             &ac_signature,
                                                             &attrs,
                                                             &id_tracking_policy.bitmap).unwrap();
    let identity_proof =
      create_conf_id_reveal(&mut prng,
                            &attrs,
                            &id_tracking_policy,
                            &proof,
                            &asset_issuer_public_key.unwrap().eg_blsg1_pub_key).unwrap();

    let xfr_note = gen_xfr_note(&mut prng,
                                &[input],
                                &[output],
                                &[input_keypair],
                                &[Some(identity_proof)]).unwrap();

    assert_eq!(Ok(()),
               verify_xfr_note(&mut prng, &xfr_note, &[Some(id_tracking_policy)]));

    let id_tracking_policy = IdRevealPolicy { cred_issuer_pub_key: cred_issuer_keys.0.clone(),
                                              bitmap: vec![false, true, true, true] };
    assert_eq!(Err(XfrVerifyIssuerTrackingIdentityError),
               verify_xfr_note(&mut prng, &xfr_note, &[Some(id_tracking_policy)]));

    //test serialization
    //to msg pack whole Xfr
    let mut vec = vec![];
    assert_eq!(true,
               xfr_note.serialize(&mut Serializer::new(&mut vec)).is_ok());
    let mut de = Deserializer::new(&vec[..]);
    let xfr_de = XfrNote::deserialize(&mut de).unwrap();
    assert_eq!(xfr_note, xfr_de);
  }

  #[test]
  fn do_multiasset_transfer_tests() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let asset_type0 = [0u8; 16];
    let asset_type1 = [1u8; 16];
    let asset_type2 = [2u8; 16];
    let input_amount = [(10u64, asset_type0),
                        (10u64, asset_type1),
                        (10u64, asset_type0),
                        (10u64, asset_type1),
                        (10u64, asset_type1),
                        (10u64, asset_type2)];
    let out_amount = [(30u64, asset_type1),
                      (5u64, asset_type2),
                      (1u64, asset_type2),
                      (4u64, asset_type2),
                      (0u64, asset_type0),
                      (20u64, asset_type0)];

    let (xfr_note, _, _, _, _) =
      create_xfr(&mut prng, &input_amount, &out_amount, true, true, false);

    let mut null_policies = vec![];
    //let mut id_proofs = vec![];
    null_policies.push(None);
    null_policies.push(None);
    null_policies.push(None);
    null_policies.push(None);
    null_policies.push(None);
    null_policies.push(None);

    // test 1: simple transfer using confidential asset mixer
    assert_eq!(Ok(()),
               verify_xfr_note(&mut prng, &xfr_note, &null_policies),
               "Multi asset transfer confidential");

    //test 2: non confidential
    let (mut xfr_note, inkeys, _, _, _) =
      create_xfr(&mut prng, &input_amount, &out_amount, false, false, false);

    assert_eq!(Ok(()),
               verify_xfr_note(&mut prng, &xfr_note, &null_policies),
               "Multi asset transfer non confidential");

    xfr_note.body.inputs[0].amount = Some(8u64);

    xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();

    assert_eq!(Err(ZeiError::XfrVerifyAssetAmountError),
               verify_xfr_note(&mut prng, &xfr_note, &null_policies),
               "Multi asset transfer non confidential");
  }
}
