use crate::anon_xfr::circuits::{AMultiXfrPubInputs, AMultiXfrWitness, PayeeSecret, PayerSecret};
use crate::anon_xfr::keys::AXfrKeyPair;
use crate::anon_xfr::proofs::{prove_xfr, verify_xfr};
use crate::anon_xfr::structs::{
  AXfrBody, AXfrProof, AnonBlindAssetRecord, OpenAnonBlindAssetRecord,
};
use crate::setup::{NodeParams, UserParams};
use crate::xfr::structs::{AssetType, OwnerMemo, ASSET_TYPE_LENGTH};
use algebra::bls12_381::{BLSScalar, BLS_SCALAR_LEN};
use algebra::groups::{Scalar, ScalarArithmetic};
use algebra::jubjub::{JubjubScalar, JUBJUB_SCALAR_LEN};
use crypto::basics::hybrid_encryption::{
  hybrid_decrypt_with_x25519_secret_key,
  //hybrid_encrypt_with_x25519_key,
  XSecretKey,
};
use crypto::basics::prf::PRF;
use itertools::Itertools;
use rand_core::{CryptoRng, RngCore};
use std::collections::HashMap;
use utils::errors::ZeiError;

pub mod bar_to_from_abar;
pub(crate) mod circuits;
pub mod keys;
pub(crate) mod proofs;
pub mod structs;

/// Build a anonymous transfer structure AXfrBody. It also returns randomized signature keys to sign the transfer,
/// * `rng` - pseudo-random generator.
/// * `params` - User parameters
/// * `inputs` - Open source asset records
/// * `outputs` - Description of output asset records.
pub fn gen_anon_xfr_body<R: CryptoRng + RngCore>(
  prng: &mut R,
  params: &UserParams,
  inputs: &[OpenAnonBlindAssetRecord],
  outputs: &[OpenAnonBlindAssetRecord],
  input_keypairs: &[AXfrKeyPair])
  -> Result<(AXfrBody, Vec<AXfrKeyPair>), ZeiError> {
  // 1. check input correctness
  if inputs.is_empty() || outputs.is_empty() {
    return Err(ZeiError::AXfrProverParamsError);
  }
  check_inputs(inputs, input_keypairs)?;
  check_asset_amount(inputs, outputs)?;
  check_roots(inputs)?;

  // 2. randomize input key pair with open_abar rand key
  let rand_input_keypairs = inputs.iter()
                                  .zip(input_keypairs.iter())
                                  .map(|(input, keypair)| keypair.randomize(&input.key_rand_factor))
                                  .collect_vec();

  // 3. build input witness infos
  let diversifiers: Vec<JubjubScalar> = inputs.iter().map(|_| JubjubScalar::random(prng)).collect();
  let nullifiers_and_signing_keys =
    inputs.iter()
          .zip(rand_input_keypairs.iter())
          .zip(diversifiers.iter())
          .map(|((input, keypair), diversifier)| {
            let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();
            (nullifier(&keypair, input.amount, &input.asset_type, mt_leaf_info.uid),
             keypair.pub_key().randomize(diversifier))
          })
          .collect();

  // 4. build proof
  let payers_secrets = inputs.iter()
                             .zip(rand_input_keypairs.iter())
                             .zip(diversifiers.iter())
                             .map(|((input, keypair), &diversifier)| {
                               let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();
                               PayerSecret { sec_key: keypair.get_secret_scalar(),
                                             diversifier,
                                             uid: mt_leaf_info.uid,
                                             amount: input.amount,
                                             asset_type: input.asset_type.as_scalar(),
                                             path: mt_leaf_info.path.clone(),
                                             blind: input.blind }
                             })
                             .collect();
  let payees_secrets =
    outputs.iter()
           .map(|output| PayeeSecret { amount: output.amount,
                                       blind: output.blind,
                                       asset_type: output.asset_type.as_scalar() })
           .collect();

  let secret_inputs = AMultiXfrWitness { payers_secrets,
                                         payees_secrets };
  let proof = prove_xfr(prng, params, secret_inputs)?;

  let diversified_key_pairs =
    rand_input_keypairs.iter()
                       .zip(diversifiers.iter())
                       .map(|(keypair, diversifier)| keypair.randomize(diversifier))
                       .collect();

  let out_abars = outputs.iter()
                         .map(|output| AnonBlindAssetRecord::from_oabar(output))
                         .collect_vec();
  let out_memos: Result<Vec<OwnerMemo>, ZeiError> =
    outputs.iter()
           .map(|output| output.owner_memo.clone().ok_or(ZeiError::ParameterError))
           .collect();

  Ok((AXfrBody { inputs: nullifiers_and_signing_keys,
                 outputs: out_abars,
                 proof: AXfrProof { snark_proof: proof,
                                    merkle_root: inputs[0].mt_leaf_info
                                                          .as_ref()
                                                          .unwrap()
                                                          .root },
                 owner_memos: out_memos? },
      diversified_key_pairs))
}

/// Verifies an anonymous transfer structure AXfrBody.
/// * `params` - Verifier parameters
/// * `body` - Transfer structure to verify
/// * `accumulator` - candidate state of the accumulator. It must match body.proof.merkle_root, otherwise it returns ZeiError::AXfrVerification Error.
pub fn verify_anon_xfr_body(params: &NodeParams,
                            body: &AXfrBody,
                            merkle_root: &BLSScalar)
                            -> Result<(), ZeiError> {
  if *merkle_root != body.proof.merkle_root {
    return Err(ZeiError::AXfrVerificationError);
  }
  let payees_commitments = body.outputs
                               .iter()
                               .map(|output| output.amount_type_commitment)
                               .collect();
  let pub_inputs = AMultiXfrPubInputs { payers_inputs: body.inputs.clone(),
                                        payees_commitments,
                                        merkle_root: *merkle_root };
  verify_xfr(params, &pub_inputs, &body.proof.snark_proof).map_err(|_| {
                                                            ZeiError::AXfrVerificationError
                                                          })
}

/// Check that inputs have mt witness and keypair matched pubkey
fn check_inputs(inputs: &[OpenAnonBlindAssetRecord],
                keypairs: &[AXfrKeyPair])
                -> Result<(), ZeiError> {
  if inputs.len() != keypairs.len() {
    return Err(ZeiError::ParameterError);
  }
  for (input, keypair) in inputs.iter().zip(keypairs.iter()) {
    if input.mt_leaf_info.is_none() || keypair.pub_key() != input.pub_key {
      return Err(ZeiError::ParameterError);
    }
  }
  Ok(())
}
/// Check that for each asset type total input amount == total output amount
fn check_asset_amount(inputs: &[OpenAnonBlindAssetRecord],
                      outputs: &[OpenAnonBlindAssetRecord])
                      -> Result<(), ZeiError> {
  let mut balances = HashMap::new();

  for record in inputs.iter() {
    if let Some(x) = balances.get_mut(&record.asset_type) {
      *x += record.amount as i128;
    } else {
      balances.insert(record.asset_type, record.amount as i128);
    }
  }

  for record in outputs.iter() {
    if let Some(x) = balances.get_mut(&record.asset_type) {
      *x -= record.amount as i128;
    } else {
      balances.insert(record.asset_type, -(record.amount as i128));
    }
  }

  for (_, &sum) in balances.iter() {
    if sum != 0i128 {
      return Err(ZeiError::XfrCreationAssetAmountError);
    }
  }

  Ok(())
}

/// Check that the merkle roots in input asset records are consistent
/// `inputs` is guaranteed to have at least one asset record
fn check_roots(inputs: &[OpenAnonBlindAssetRecord]) -> Result<(), ZeiError> {
  let root = inputs[0].mt_leaf_info
                      .as_ref()
                      .ok_or(ZeiError::ParameterError)?
                      .root;
  for input in inputs.iter().skip(1) {
    if input.mt_leaf_info
            .as_ref()
            .ok_or(ZeiError::ParameterError)?
            .root
       != root
    {
      return Err(ZeiError::AXfrVerificationError);
    }
  }
  Ok(())
}

/// Decrypts the owner memo
/// * `memo` - Owner memo to decrypt
/// * `dec_key` - Decryption key
/// * `abar` - Associated anonymous blind asset record to check memo info against.
/// Return Error if memo info does not match abar's commitment or public key
/// Return Ok(amount, asset_type, blinding) otherwise
pub fn decrypt_memo(memo: &OwnerMemo,
                    dec_key: &XSecretKey,
                    key_pair: &AXfrKeyPair,
                    abar: &AnonBlindAssetRecord)
                    -> Result<(u64, AssetType, BLSScalar, JubjubScalar), ZeiError> {
  let plaintext = hybrid_decrypt_with_x25519_secret_key(&memo.lock, dec_key);
  if plaintext.len() != 8 + ASSET_TYPE_LENGTH + BLS_SCALAR_LEN + JUBJUB_SCALAR_LEN {
    return Err(ZeiError::ParameterError);
  }
  let amount = utils::u8_le_slice_to_u64(&plaintext[0..8]);
  let mut i = 8;
  let mut asset_type_array = [0u8; ASSET_TYPE_LENGTH];
  asset_type_array.copy_from_slice(&plaintext[i..i + ASSET_TYPE_LENGTH]);
  let asset_type = AssetType(asset_type_array);
  i += ASSET_TYPE_LENGTH;
  let blind =
    BLSScalar::from_bytes(&plaintext[i..i + BLS_SCALAR_LEN]).map_err(|_| ZeiError::ParameterError)?;
  i += BLS_SCALAR_LEN;
  let rand =
    JubjubScalar::from_bytes(&plaintext[i..i + JUBJUB_SCALAR_LEN]).map_err(|_| {
                                                                    ZeiError::ParameterError
                                                                  })?;
  // verify abar's commitment
  crypto::basics::commitments::rescue::HashCommitment::new().verify(&[BLSScalar::from_u64(amount),
                                                         asset_type.as_scalar()],
                                                                    &blind,
                                                                    &abar.amount_type_commitment)?;
  // verify abar's public key
  if key_pair.randomize(&rand).pub_key() != abar.public_key {
    return Err(ZeiError::InconsistentStructureError);
  }

  Ok((amount, asset_type, blind, rand))
}

fn nullifier(key_pair: &AXfrKeyPair, amount: u64, asset_type: &AssetType, uid: u64) -> BLSScalar {
  let pub_key = key_pair.pub_key();
  let pub_key_point = pub_key.as_jubjub_point();
  let pub_key_x = pub_key_point.get_x();
  let pub_key_y = pub_key_point.get_y();

  // TODO From<u128> for ZeiScalar and do let uid_amount = BLSScalar::from(amount as u128 + ((uid as u128) << 64));
  let pow_2_64 = BLSScalar::from_u64(u64::max_value()).add(&BLSScalar::from_u32(1));
  let uid_shifted = BLSScalar::from_u64(uid).mul(&pow_2_64);
  let uid_amount = uid_shifted.add(&BLSScalar::from_u64(amount));
  PRF::new().eval(&BLSScalar::from(&key_pair.get_secret_scalar()),
                  &[uid_amount, asset_type.as_scalar(), pub_key_x, pub_key_y])
}

#[cfg(test)]
mod tests {
  use crate::anon_xfr::keys::AXfrKeyPair;
  use crate::anon_xfr::structs::{
    AnonBlindAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonBlindAssetRecord,
    OpenAnonBlindAssetRecordBuilder,
  };
  use crate::anon_xfr::{gen_anon_xfr_body, verify_anon_xfr_body};
  use crate::setup::{NodeParams, UserParams, DEFAULT_BP_NUM_GENS};
  use crate::xfr::structs::AssetType;
  use algebra::bls12_381::BLSScalar;
  use algebra::groups::{One, Scalar, ScalarArithmetic, Zero};
  use crypto::basics::hash::rescue::RescueInstance;
  use crypto::basics::hybrid_encryption::{XPublicKey, XSecretKey};
  use itertools::Itertools;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
  use rand_core::{CryptoRng, RngCore};
  use utils::errors::ZeiError;

  #[test]
  fn test_anon_xfr() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);

    let user_params =
      UserParams::from_file_if_exists(1, 1, Some(1), DEFAULT_BP_NUM_GENS, None).unwrap();

    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let two = one.add(&one);

    let amount = 10u64;
    let asset_type = AssetType::from_identical_byte(0);

    // simulate input abar
    let (oabar, keypair_in, dec_key_in, _) = gen_oabar_and_keys(&mut prng, amount, asset_type);
    let abar = AnonBlindAssetRecord::from_oabar(&oabar);
    assert_eq!(keypair_in.pub_key(), *oabar.pub_key_ref());
    let rand_keypair_in = keypair_in.randomize(&oabar.get_key_rand_factor());
    assert_eq!(rand_keypair_in.pub_key(), abar.public_key);

    let owner_memo = oabar.get_owner_memo().unwrap();

    // simulate merklee tree state
    let rand_pk_in = rand_keypair_in.pub_key();
    let node = MTNode { siblings1: one,
                        siblings2: two,
                        is_left_child: 0u8,
                        is_right_child: 1u8 };
    let hash = RescueInstance::new();
    let rand_pk_in_jj = rand_pk_in.as_jubjub_point();
    let pk_in_hash =
      hash.rescue_hash(&[rand_pk_in_jj.get_x(), rand_pk_in_jj.get_y(), zero, zero])[0];
    let leaf = hash.rescue_hash(&[/*uid=*/ two,
                                  oabar.compute_commitment(),
                                  pk_in_hash,
                                  zero])[0];
    let merkle_root = hash.rescue_hash(&[/*sib1[0]=*/ one, /*sib2[0]=*/ two, leaf, zero])[0];
    let mt_leaf_info = MTLeafInfo { path: MTPath { nodes: vec![node] },
                                    root: merkle_root,
                                    uid: 2 };

    // output keys
    let keypair_out = AXfrKeyPair::generate(&mut prng);
    let dec_key_out = XSecretKey::new(&mut prng);
    let enc_key_out = XPublicKey::from(&dec_key_out);

    let (body, merkle_root) = {
      // prover scope
      // 1. open abar
      let oabar_in =
        OpenAnonBlindAssetRecordBuilder::from_abar(&abar,
                                                   owner_memo,
                                                   &keypair_in,
                                                   &dec_key_in)
          .unwrap()
          .mt_leaf_info(mt_leaf_info)
          .build()
          .unwrap();
      assert_eq!(amount, oabar_in.get_amount());
      assert_eq!(asset_type, oabar_in.get_asset_type());
      assert_eq!(keypair_in.pub_key(), oabar_in.pub_key);

      let oabar_out = OpenAnonBlindAssetRecordBuilder::new().amount(amount)
                                                            .asset_type(asset_type)
                                                            .pub_key(keypair_out.pub_key())
                                                            .finalize(&mut prng, &enc_key_out)
                                                            .unwrap()
                                                            .build()
                                                            .unwrap();

      let (body, _) = gen_anon_xfr_body(&mut prng,
                                        &user_params,
                                        &[oabar_in],
                                        &[oabar_out],
                                        &[keypair_in]).unwrap();
      (body, merkle_root)
    };
    {
      // owner scope
      let oabar = OpenAnonBlindAssetRecordBuilder::from_abar(&body.outputs[0],
                                                             body.owner_memos[0].clone(),
                                                             &keypair_out,
                                                             &dec_key_out).unwrap()
                                                                          .build()
                                                                          .unwrap();
      let rand_pk = keypair_out.pub_key()
                               .randomize(&oabar.get_key_rand_factor());
      assert_eq!(amount, oabar.get_amount());
      assert_eq!(asset_type, oabar.get_asset_type());
      assert_eq!(rand_pk, body.outputs[0].public_key);
    }
    {
      // verifier scope
      let verifier_params = NodeParams::from(user_params);
      assert!(verify_anon_xfr_body(&verifier_params, &body, &merkle_root).is_ok())
    }
  }

  #[test]
  fn test_anon_xfr_multi_assets() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let n_payers = 3;
    let n_payees = 3;
    let user_params = UserParams::from_file_if_exists(n_payers,
                                                      n_payees,
                                                      Some(1),
                                                      DEFAULT_BP_NUM_GENS,
                                                      None).unwrap();

    let zero = BLSScalar::zero();
    let one = BLSScalar::one();

    // simulate input abars
    let amounts_in = vec![10u64, 20u64, 30u64];
    let asset_types_in = vec![AssetType::from_identical_byte(0),
                              AssetType::from_identical_byte(1),
                              AssetType::from_identical_byte(0)];
    let mut in_abars = vec![];
    let mut in_keypairs = vec![];
    let mut in_dec_keys = vec![];
    let mut in_owner_memos = vec![];
    for i in 0..n_payers {
      let (oabar, keypair, dec_key, _) =
        gen_oabar_and_keys(&mut prng, amounts_in[i], asset_types_in[i]);
      let abar = AnonBlindAssetRecord::from_oabar(&oabar);
      let owner_memo = oabar.get_owner_memo().unwrap();
      in_abars.push(abar);
      in_keypairs.push(keypair);
      in_dec_keys.push(dec_key);
      in_owner_memos.push(owner_memo);
    }
    // simulate merklee tree state
    let hash = RescueInstance::new();
    let leafs: Vec<BLSScalar> =
      in_abars.iter()
              .enumerate()
              .map(|(uid, in_abar)| {
                let rand_pk_in_jj = in_abar.public_key.as_jubjub_point();
                let pk_in_hash =
                  hash.rescue_hash(&[rand_pk_in_jj.get_x(), rand_pk_in_jj.get_y(), zero, zero])[0];
                hash.rescue_hash(&[BLSScalar::from_u32(uid as u32),
                                   in_abar.amount_type_commitment,
                                   pk_in_hash,
                                   zero])[0]
              })
              .collect();
    let node0 = MTNode { siblings1: leafs[1],
                         siblings2: leafs[2],
                         is_left_child: 1u8,
                         is_right_child: 0u8 };
    let node1 = MTNode { siblings1: leafs[0],
                         siblings2: leafs[2],
                         is_left_child: 0u8,
                         is_right_child: 0u8 };
    let node2 = MTNode { siblings1: leafs[0],
                         siblings2: leafs[1],
                         is_left_child: 0u8,
                         is_right_child: 1u8 };
    let nodes = vec![node0, node1, node2];
    let merkle_root = hash.rescue_hash(&[leafs[0], leafs[1], leafs[2], zero])[0];

    // output keys, amounts, asset_types
    let (keypairs_out, dec_keys_out, enc_keys_out) = gen_keys(&mut prng, n_payees);
    let amounts_out = vec![7u64, 40u64, 13u64];
    let asset_types_out = vec![AssetType::from_identical_byte(1),
                               AssetType::from_identical_byte(0),
                               AssetType::from_identical_byte(1)];
    let mut outputs = vec![];
    for i in 0..n_payees {
      outputs.push(OpenAnonBlindAssetRecordBuilder::new().amount(amounts_out[i])
                                                         .asset_type(asset_types_out[i])
                                                         .pub_key(keypairs_out[i].pub_key())
                                                         .finalize(&mut prng, &enc_keys_out[i])
                                                         .unwrap()
                                                         .build()
                                                         .unwrap());
    }

    let (body, merkle_root) = {
      // prover scope
      let mut open_abars_in: Vec<OpenAnonBlindAssetRecord> =
        (0..n_payers).map(|uid| {
                       let mt_leaf_info = MTLeafInfo { path: MTPath { nodes:
                                                                        vec![nodes[uid].clone()] },
                                                       root: merkle_root,
                                                       uid: uid as u64 };
                       let open_abar_in = OpenAnonBlindAssetRecordBuilder::from_abar(
            &in_abars[uid],
            in_owner_memos[uid].clone(),
            &in_keypairs[uid],
            &in_dec_keys[uid],
            ).unwrap().mt_leaf_info(mt_leaf_info).build().unwrap();
                       assert_eq!(amounts_in[uid], open_abar_in.amount);
                       assert_eq!(asset_types_in[uid], open_abar_in.asset_type);
                       open_abar_in
                     })
                     .collect();

      let open_abars_out = (0..n_payees).map(|i| {
                                          OpenAnonBlindAssetRecordBuilder::new()
          .amount(amounts_out[i])
          .asset_type(asset_types_out[i])
          .pub_key(keypairs_out[i].pub_key())
          .finalize(&mut prng, &enc_keys_out[i]).unwrap().build().unwrap()
                                        })
                                        .collect_vec();

      // empty inputs/outputs
      assert_eq!(gen_anon_xfr_body(&mut prng, &user_params, &[], &open_abars_out, &[]),
                 Err(ZeiError::AXfrProverParamsError));
      assert_eq!(gen_anon_xfr_body(&mut prng, &user_params, &open_abars_in, &[], &in_keypairs),
                 Err(ZeiError::AXfrProverParamsError));
      // invalid inputs/outputs
      open_abars_in[0].amount += 1;
      assert!(gen_anon_xfr_body(&mut prng,
                                &user_params,
                                &open_abars_in,
                                &open_abars_out,
                                &in_keypairs).is_err());
      open_abars_in[0].amount -= 1;
      // inconsistent roots
      let mut mt_info = open_abars_in[0].mt_leaf_info.clone().unwrap();
      mt_info.root.add_assign(&one);
      open_abars_in[0].mt_leaf_info = Some(mt_info);
      assert!(gen_anon_xfr_body(&mut prng,
                                &user_params,
                                &open_abars_in,
                                &open_abars_out,
                                &in_keypairs).is_err());
      let mut mt_info = open_abars_in[0].mt_leaf_info.clone().unwrap();
      mt_info.root.sub_assign(&one);
      open_abars_in[0].mt_leaf_info = Some(mt_info);

      let (body, _) = gen_anon_xfr_body(&mut prng,
                                        &user_params,
                                        &open_abars_in,
                                        &open_abars_out,
                                        &in_keypairs).unwrap();
      (body, merkle_root)
    };
    {
      // owner scope
      for i in 0..n_payees {
        let oabar_out = OpenAnonBlindAssetRecordBuilder::from_abar(&body.outputs[i],
                                                                   body.owner_memos[i].clone(),
                                                                   &keypairs_out[i],
                                                                   &dec_keys_out[i]).unwrap()
                                                                                    .build()
                                                                                    .unwrap();
        let rand_pk = keypairs_out[i].pub_key()
                                     .randomize(&oabar_out.key_rand_factor);
        assert_eq!(amounts_out[i], oabar_out.amount);
        assert_eq!(asset_types_out[i], oabar_out.asset_type);
        assert_eq!(rand_pk, body.outputs[i].public_key);
      }
    }
    {
      // verifier scope
      let verifier_params = NodeParams::from(user_params);
      // inconsistent merkle roots
      assert!(verify_anon_xfr_body(&verifier_params, &body, &zero).is_err());
      assert!(verify_anon_xfr_body(&verifier_params, &body, &merkle_root).is_ok());
    }
  }

  fn gen_keys<R: CryptoRng + RngCore>(prng: &mut R,
                                      n: usize)
                                      -> (Vec<AXfrKeyPair>, Vec<XSecretKey>, Vec<XPublicKey>) {
    let keypairs_in: Vec<AXfrKeyPair> = (0..n).map(|_| AXfrKeyPair::generate(prng)).collect();

    let dec_keys_in: Vec<XSecretKey> = (0..n).map(|_| XSecretKey::new(prng)).collect();
    let enc_keys_in: Vec<XPublicKey> = dec_keys_in.iter()
                                                  .map(|dec_key| XPublicKey::from(dec_key))
                                                  .collect();
    (keypairs_in, dec_keys_in, enc_keys_in)
  }

  fn gen_oabar_and_keys<R: CryptoRng + RngCore>(
    prng: &mut R,
    amount: u64,
    asset_type: AssetType)
    -> (OpenAnonBlindAssetRecord, AXfrKeyPair, XSecretKey, XPublicKey) {
    let keypair = AXfrKeyPair::generate(prng);
    let dec_key = XSecretKey::new(prng);
    let enc_key = XPublicKey::from(&dec_key);
    let oabar = OpenAnonBlindAssetRecordBuilder::new().amount(amount)
                                                      .asset_type(asset_type)
                                                      .pub_key(keypair.pub_key())
                                                      .finalize(prng, &enc_key)
                                                      .unwrap()
                                                      .build()
                                                      .unwrap();
    (oabar, keypair, dec_key, enc_key)
  }
}
