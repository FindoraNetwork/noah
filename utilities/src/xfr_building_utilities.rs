use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use crate::xfr_bench::bench_utils::{ASSET_TYPE_1, ASSET_TYPE_2};
use crypto::ristretto_pedersen::RistrettoPedersenGens;
use itertools::Itertools;
use zei::api::anon_creds;
use zei::api::anon_creds::{
  ac_commit, ac_sign, ACCommitment, ACCommitmentKey, ACUserSecretKey, Credential,
};
use zei::xfr::asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType};
use zei::xfr::asset_tracer::gen_asset_tracer_keypair;
use zei::xfr::lib::XfrNotePolicies;
use zei::xfr::sig::{XfrKeyPair, XfrPublicKey};
use zei::xfr::structs::{
  AssetRecord, AssetRecordTemplate, AssetTracingPolicies, AssetTracingPolicy, AssetType,
  BlindAssetRecord, IdentityRevealPolicy, OwnerMemo, XfrAmount, XfrAssetType,
};

// Simulate getting a BlindAssetRecord from Ledger
#[allow(clippy::clone_on_copy)]
pub fn non_conf_blind_asset_record_from_ledger(key: &XfrPublicKey,
                                               amount: u64,
                                               asset_type: AssetType)
                                               -> BlindAssetRecord {
  BlindAssetRecord { amount: XfrAmount::NonConfidential(amount),
                     asset_type: XfrAssetType::NonConfidential(asset_type),
                     public_key: key.clone() }
}

/// Simulate getting a BlindAssetRecord from Ledger
#[allow(clippy::clone_on_copy)]
#[allow(clippy::blacklisted_name)]
pub fn conf_blind_asset_record_from_ledger(key: &XfrPublicKey,
                                           amount: u64,
                                           asset_type: AssetType)
                                           -> (BlindAssetRecord, OwnerMemo) {
  let mut prng = ChaChaRng::from_seed([1u8; 32]);
  let template = AssetRecordTemplate { amount,
                                       asset_type,
                                       public_key: key.clone(),
                                       asset_record_type:
                                         AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                                       asset_tracing_policies: Default::default() };
  let (bar, _, owner) = build_blind_asset_record(&mut prng,
                                                 &RistrettoPedersenGens::default(),
                                                 &template,
                                                 vec![]);

  (bar, owner.unwrap())
}

#[allow(clippy::type_complexity)]
pub fn setup_with_policies(
  n: usize)
  -> (Vec<XfrKeyPair>,
      Vec<ACUserSecretKey>,
      Vec<Credential>,
      Vec<ACCommitmentKey>,
      AssetTracingPolicy,
      Vec<ACCommitment>) {
  let mut prng = ChaChaRng::from_seed([0u8; 32]);

  const ATTR_SIZE: usize = 4;

  let (sender_key_pairs, _) = multiple_key_gen(n);

  // credential keys
  let (cred_issuer_pk, cred_issuer_sk) = anon_creds::ac_keygen_issuer(&mut prng, ATTR_SIZE);
  // asset tracing keys
  let asset_tracing_key = gen_asset_tracer_keypair(&mut prng);

  // All AC keys are the same
  let mut user_ac_pks = vec![];
  let mut user_ac_sks = vec![];
  let mut credentials = vec![];
  let mut ac_commitments = vec![];
  let mut ac_commitment_keys = vec![];
  let mut ac_proofs = vec![];

  let user_attrs = vec![0u32, 1, 2, 3];

  #[allow(clippy::needless_range_loop)]
  for i in 0..n {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let (user_ac_pk, user_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    user_ac_pks.push(user_ac_pk.clone());
    user_ac_sks.push(user_ac_sk.clone());
    let credential_user = Credential { signature: ac_sign(&mut prng,
                                                          &cred_issuer_sk,
                                                          &user_ac_pk,
                                                          user_attrs.as_slice()).unwrap(),
                                       attributes: user_attrs.clone(),
                                       issuer_pub_key: cred_issuer_pk.clone() };
    credentials.push(credential_user.clone());

    let user_key_pair = &sender_key_pairs[i];

    let output = ac_commit(&mut prng,
                           &user_ac_sk,
                           &credential_user.clone(),
                           user_key_pair.get_pk_ref().as_bytes()).unwrap();
    ac_commitment_keys.push(output.key.unwrap());
    ac_commitments.push(output.commitment);
    ac_proofs.push(output.pok);
  }

  let id_tracking_policy = IdentityRevealPolicy { cred_issuer_pub_key: cred_issuer_pk,
                                                  reveal_map: vec![false, true, false, true] };

  let asset_tracing_policy_asset_input =
    AssetTracingPolicy { enc_keys: asset_tracing_key.enc_key,
                         asset_tracking: true,
                         identity_tracking: Some(id_tracking_policy) };

  (sender_key_pairs,
   user_ac_sks,
   credentials,
   ac_commitment_keys,
   asset_tracing_policy_asset_input,
   ac_commitments)
}

// All the key pairs generated are the same
pub fn multiple_key_gen(n: usize) -> (Vec<XfrKeyPair>, XfrPublicKey) {
  let mut sender_key_pairs = vec![];

  for _i in 0..n {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let sender_keypair = XfrKeyPair::generate(&mut prng);
    sender_key_pairs.push(sender_keypair);
  }

  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  let recv_keypair = XfrKeyPair::generate(&mut prng);
  let recv_pub_key = recv_keypair.get_pk();
  (sender_key_pairs, recv_pub_key)
}

pub fn prepare_inputs_and_outputs_with_policies(sender_key_pairs: &[&XfrKeyPair],
                                                user_ac_sks: Vec<ACUserSecretKey>,
                                                credentials: Vec<Credential>,
                                                ac_commitment_keys: Vec<ACCommitmentKey>,
                                                asset_tracing_policy_input: Option<AssetTracingPolicy>,
                                                asset_types: &[AssetType],
                                                n: usize)
                                                -> (Vec<AssetRecord>, Vec<AssetRecord>) {
  let mut prng = ChaChaRng::from_seed([0u8; 32]);

  let amount = 10;

  // Prepare inputs
  let mut ar_ins = vec![];

  for i in 0..n {
    let user_key_pair = &sender_key_pairs[i];

    let l = asset_types.len();
    let asset_type = asset_types[i % l];

    let (bar_user_addr, memo) =
      conf_blind_asset_record_from_ledger(user_key_pair.get_pk_ref(), amount, asset_type);

    let oar_user_addr =
      open_blind_asset_record(&bar_user_addr, &Some(memo), user_key_pair.get_sk_ref()).unwrap();

    let credential_user = credentials[i].clone();

    let user_ac_sk = user_ac_sks[i].clone();
    let ac_commitment_key = ac_commitment_keys[i].clone();

    let policies = match asset_tracing_policy_input.clone() {
      Some(p) => AssetTracingPolicies::from_policy(p),
      None => AssetTracingPolicies::new(),
    };

    let ar_in =
      AssetRecord::from_open_asset_record_with_identity_tracking(&mut prng,
                                                                 oar_user_addr,
                                                                 policies,
                                                                 &user_ac_sk,
                                                                 &credential_user,
                                                                 &ac_commitment_key).unwrap();

    ar_ins.push(ar_in);
  }

  // Prepare outputs
  let mut output_asset_records = vec![];
  for i in 0..n {
    let user_key_pair = &sender_key_pairs[i];

    let l = asset_types.len();
    let asset_type = asset_types[i % l];

    let template = AssetRecordTemplate::with_no_asset_tracking(
      amount, asset_type, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, user_key_pair.get_pk());

    let output_asset_record =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template).unwrap();

    output_asset_records.push(output_asset_record);
  }

  (ar_ins, output_asset_records)
}

pub(crate) fn prepare_inputs_and_outputs_without_policies_single_asset(
  sender_key_pairs: &[&XfrKeyPair],
  n: usize)
  -> (Vec<AssetRecord>, Vec<AssetRecord>) {
  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  let amount = 100;

  // Prepare inputs
  let mut ar_ins = vec![];

  #[allow(clippy::needless_range_loop)]
  for i in 0..n {
    let user_key_pair = &sender_key_pairs[i];

    let (bar_user_addr, memo) =
      conf_blind_asset_record_from_ledger(user_key_pair.get_pk_ref(), amount, ASSET_TYPE_1);

    let oar_user_addr =
      open_blind_asset_record(&bar_user_addr, &Some(memo), user_key_pair.get_sk_ref()).unwrap();

    let ar_in = AssetRecord::from_open_asset_record_no_asset_tracking(oar_user_addr);

    ar_ins.push(ar_in);
  }

  // Prepare outputs
  let mut output_asset_records = vec![];
  for user_key_pair in sender_key_pairs.iter().take(n) {
    let template = AssetRecordTemplate::with_no_asset_tracking(
      amount, ASSET_TYPE_1, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, user_key_pair.get_pk());

    let output_asset_record =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template).unwrap();

    output_asset_records.push(output_asset_record);
  }

  (ar_ins, output_asset_records)
}

pub fn prepare_inputs_and_outputs_with_policies_single_asset(
  sender_key_pairs: &[&XfrKeyPair],
  user_ac_sks: Vec<ACUserSecretKey>,
  credentials: Vec<Credential>,
  ac_commitment_keys: Vec<ACCommitmentKey>,
  asset_tracing_policy_input: Option<AssetTracingPolicy>,
  n: usize)
  -> (Vec<AssetRecord>, Vec<AssetRecord>) {
  prepare_inputs_and_outputs_with_policies(sender_key_pairs,
                                           user_ac_sks,
                                           credentials,
                                           ac_commitment_keys,
                                           asset_tracing_policy_input,
                                           &[ASSET_TYPE_1],
                                           n)
}

pub(crate) fn prepare_inputs_and_outputs_with_policies_multiple_assets(
  sender_key_pairs: &[&XfrKeyPair],
  user_ac_sks: Vec<ACUserSecretKey>,
  credentials: Vec<Credential>,
  ac_commitment_keys: Vec<ACCommitmentKey>,
  asset_tracing_policy_input: Option<AssetTracingPolicy>,
  n: usize)
  -> (Vec<AssetRecord>, Vec<AssetRecord>) {
  prepare_inputs_and_outputs_with_policies(sender_key_pairs,
                                           user_ac_sks,
                                           credentials,
                                           ac_commitment_keys,
                                           asset_tracing_policy_input,
                                           &[ASSET_TYPE_1, ASSET_TYPE_2],
                                           n)
}

pub(crate) fn gen_policies_with_id_tracking(ac_commitments: &[ACCommitment],
                                            asset_tracing_policy_input: AssetTracingPolicy,
                                            n: usize)
                                            -> XfrNotePolicies {
  let inputs_sig_commitments = ac_commitments.iter().map(|x| Some(x.clone())).collect_vec();
  let outputs_tracking_policies = vec![AssetTracingPolicies::new(); n];
  let outputs_sig_commitments = vec![None; n];
  let policies = AssetTracingPolicies::from_policy(asset_tracing_policy_input);
  let inputs_tracking_policies = vec![policies; n];

  XfrNotePolicies::new(inputs_tracking_policies,
                       inputs_sig_commitments,
                       outputs_tracking_policies,
                       outputs_sig_commitments)
}

pub(crate) fn gen_policies_no_id_tracking(n: usize) -> XfrNotePolicies {
  let inputs_sig_commitments = vec![None; n];
  let outputs_tracking_policies = vec![AssetTracingPolicies::new(); n];
  let outputs_sig_commitments = vec![None; n];
  let inputs_tracking_policies = vec![AssetTracingPolicies::new(); n];

  XfrNotePolicies::new(inputs_tracking_policies,
                       inputs_sig_commitments,
                       outputs_tracking_policies,
                       outputs_sig_commitments)
}
