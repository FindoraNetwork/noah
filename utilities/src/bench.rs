use criterion::measurement::Measurement;
use itertools::Itertools;

use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use crate::examples::conf_blind_asset_record_from_ledger;
use criterion::{BenchmarkGroup, Criterion};
use zei::api::anon_creds;
use zei::api::anon_creds::{
  ac_commit, ac_sign, ACCommitment, ACCommitmentKey, ACUserSecretKey, Credential,
};
use zei::xfr::asset_record::{open_blind_asset_record, AssetRecordType};
use zei::xfr::asset_tracer::gen_asset_tracer_keypair;
use zei::xfr::lib::{
  gen_xfr_body, gen_xfr_note, verify_xfr_body, verify_xfr_note, XfrNotePolicies,
};
use zei::xfr::sig::{XfrKeyPair, XfrPublicKey};
use zei::xfr::structs::{
  AssetRecord, AssetRecordTemplate, AssetTracingPolicies, AssetTracingPolicy, AssetType,
  IdentityRevealPolicy, XfrBody, XfrNote,
};

pub const ASSET_TYPE: AssetType = [0u8; 16];

// All the key pairs generated are the same
fn multiple_key_gen(n: usize) -> (Vec<XfrKeyPair>, XfrPublicKey) {
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

fn run_verify_xfr_note(xfr_note: &XfrNote, policies: &XfrNotePolicies) {
  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  assert!(verify_xfr_note(&mut prng, xfr_note, policies).is_ok());
}

fn run_verify_xfr_body(xfr_body: &XfrBody, policies: &XfrNotePolicies) {
  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  assert!(verify_xfr_body(&mut prng, xfr_body, policies).is_ok());
}

fn prepare_inputs_and_outputs(sender_key_pairs: &[&XfrKeyPair],
                              user_ac_sks: Vec<ACUserSecretKey>,
                              credentials: Vec<Credential>,
                              ac_commitment_keys: Vec<ACCommitmentKey>,
                              asset_tracing_policy_asset_input: AssetTracingPolicy,
                              n: usize)
                              -> (Vec<AssetRecord>, Vec<AssetRecord>) {
  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  let amount = 100;

  // Prepare inputs
  let mut ar_ins = vec![];

  for i in 0..n {
    let user_key_pair = &sender_key_pairs[i];

    let (bar_user_addr, memo) =
      conf_blind_asset_record_from_ledger(user_key_pair.get_pk_ref(), amount, ASSET_TYPE);

    let oar_user_addr =
      open_blind_asset_record(&bar_user_addr, &Some(memo), user_key_pair.get_sk_ref()).unwrap();

    let credential_user = credentials[i].clone();

    let user_ac_sk = user_ac_sks[i].clone();
    let ac_commitment_key = ac_commitment_keys[i].clone();
    let policies = AssetTracingPolicies::from_policy(asset_tracing_policy_asset_input.clone());
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
  for user_key_pair in sender_key_pairs.iter().take(n) {
    let template = AssetRecordTemplate::with_no_asset_tracking(
      amount, ASSET_TYPE, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, user_key_pair.get_pk());

    let output_asset_record =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template).unwrap();

    output_asset_records.push(output_asset_record);
  }

  (ar_ins, output_asset_records)
}

/// Create a complex transaction with n inputs and outputs, asset and identity tracking.
fn run_complex_xfr_note_create(sender_key_pairs: &[&XfrKeyPair],
                               user_ac_sks: Vec<ACUserSecretKey>,
                               credentials: Vec<Credential>,
                               ac_commitment_keys: Vec<ACCommitmentKey>,
                               asset_tracing_policy_asset_input: AssetTracingPolicy,
                               n: usize)
                               -> XfrNote {
  let (ar_ins, output_asset_records) = prepare_inputs_and_outputs(sender_key_pairs,
                                                                  user_ac_sks,
                                                                  credentials,
                                                                  ac_commitment_keys,
                                                                  asset_tracing_policy_asset_input,
                                                                  n);

  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  gen_xfr_note(&mut prng,
               ar_ins.as_slice(),
               output_asset_records.as_slice(),
               sender_key_pairs).unwrap()
}

fn run_complex_xfr_body_create(sender_key_pairs: &[&XfrKeyPair],
                               user_ac_sks: Vec<ACUserSecretKey>,
                               credentials: Vec<Credential>,
                               ac_commitment_keys: Vec<ACCommitmentKey>,
                               asset_tracing_policy_asset_input: AssetTracingPolicy,
                               n: usize)
                               -> XfrBody {
  let (ar_ins, output_asset_records) = prepare_inputs_and_outputs(sender_key_pairs,
                                                                  user_ac_sks,
                                                                  credentials,
                                                                  ac_commitment_keys,
                                                                  asset_tracing_policy_asset_input,
                                                                  n);

  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  gen_xfr_body(&mut prng,
               ar_ins.as_slice(),
               output_asset_records.as_slice()).unwrap()
}

pub fn setup(
  sender_key_pairs: &[&XfrKeyPair],
  n: usize)
  -> (Vec<ACUserSecretKey>,
      Vec<Credential>,
      Vec<ACCommitmentKey>,
      AssetTracingPolicy,
      Vec<ACCommitment>) {
  let mut prng = ChaChaRng::from_seed([0u8; 32]);

  const ATTR_SIZE: usize = 4;

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

    let (commitment_user_addr, proof, ac_commitment_key) =
      ac_commit(&mut prng,
                &user_ac_sk,
                &credential_user.clone(),
                user_key_pair.get_pk_ref().as_bytes()).unwrap();
    ac_commitment_keys.push(ac_commitment_key);
    ac_commitments.push(commitment_user_addr);
    ac_proofs.push(proof);
  }

  let id_tracking_policy = IdentityRevealPolicy { cred_issuer_pub_key: cred_issuer_pk,
                                                  reveal_map: vec![false, true, false, true] };

  let asset_tracing_policy_asset_input =
    AssetTracingPolicy { enc_keys: asset_tracing_key.enc_key,
                         asset_tracking: true,
                         identity_tracking: Some(id_tracking_policy) };

  (user_ac_sks, credentials, ac_commitment_keys, asset_tracing_policy_asset_input, ac_commitments)
}

pub fn run_benchmark_create_complex_xfr_note<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                             n: usize) {
  let title = format!("Complex XfrNote creation n={}", n);

  let (sender_key_pairs, _) = multiple_key_gen(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();
  let (user_ac_sks,
       credentials,
       ac_commitment_keys,
       asset_tracing_policy_asset_input,
       _ac_commitments) = setup(sender_key_pairs_ref.as_slice(), n);

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| {
                      run_complex_xfr_note_create(sender_key_pairs_ref.as_slice(),
                                                  user_ac_sks.clone(),
                                                  credentials.clone(),
                                                  ac_commitment_keys.clone(),
                                                  asset_tracing_policy_asset_input.clone(),
                                                  n)
                    })
                 });
}

pub fn run_benchmark_create_complex_xfr_body<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                             n: usize) {
  let title = format!("Complex XfrBody creation n={}", n);

  let (sender_key_pairs, _) = multiple_key_gen(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();
  let (user_ac_sks, credentials, ac_commitment_keys, asset_tracing_policy, _) =
    setup(sender_key_pairs_ref.as_slice(), n);

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| {
                      run_complex_xfr_body_create(sender_key_pairs_ref.as_slice(),
                                                  user_ac_sks.clone(),
                                                  credentials.clone(),
                                                  ac_commitment_keys.clone(),
                                                  asset_tracing_policy.clone(),
                                                  n)
                    })
                 });
}

pub fn run_benchmark_verify_complex_xfr_note<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                             n: usize) {
  let title = format!("Complex XfrNote verification n={}", n);

  let (sender_key_pairs, _) = multiple_key_gen(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();
  let (user_ac_sks,
       credentials,
       ac_commitment_keys,
       asset_tracing_policy_asset_input,
       ac_commitments) = setup(sender_key_pairs_ref.as_slice(), n);

  let xfr_note = run_complex_xfr_note_create(sender_key_pairs_ref.as_slice(),
                                             user_ac_sks,
                                             credentials,
                                             ac_commitment_keys,
                                             asset_tracing_policy_asset_input.clone(),
                                             n);

  let inputs_sig_commitments = ac_commitments.iter().map(Some).collect_vec();
  let no_policies = AssetTracingPolicies::new();
  let outputs_tracking_policies = vec![&no_policies; n];
  let outputs_sig_commitments = vec![None; n];
  let policies = AssetTracingPolicies::from_policy(asset_tracing_policy_asset_input);
  let inputs_tracking_policies = vec![&policies; n];

  let policies = XfrNotePolicies::new(inputs_tracking_policies,
                                      inputs_sig_commitments,
                                      outputs_tracking_policies,
                                      outputs_sig_commitments);

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| run_verify_xfr_note(&xfr_note, &policies))
                 });
}

pub fn run_benchmark_verify_complex_xfr_body<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                             n: usize) {
  let title = format!("Complex XfrBody verification n={}", n);

  let (sender_key_pairs, _) = multiple_key_gen(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();
  let (user_ac_sks,
       credentials,
       ac_commitment_keys,
       asset_tracing_policy_asset_input,
       ac_commitments) = setup(sender_key_pairs_ref.as_slice(), n);

  let xfr_body = run_complex_xfr_body_create(sender_key_pairs_ref.as_slice(),
                                             user_ac_sks,
                                             credentials,
                                             ac_commitment_keys,
                                             asset_tracing_policy_asset_input.clone(),
                                             n);
  let no_policies = AssetTracingPolicies::new();
  let policies = AssetTracingPolicies::from_policy(asset_tracing_policy_asset_input);

  let policies = XfrNotePolicies::new(vec![&policies; n],
                                      ac_commitments.iter().map(Some).collect_vec(),
                                      vec![&no_policies; n],
                                      vec![None; n]);

  benchmark_group.bench_function(title, |b| {
                   b.iter(|| run_verify_xfr_body(&xfr_body, &policies))
                 });
}

pub fn bench_xfr_note<B: Measurement>(c: &mut Criterion<B>) {
  // Configure the benchmark
  let mut benchmark_group = c.benchmark_group("xfr");
  benchmark_group.sample_size(10);

  run_benchmark_create_complex_xfr_note::<B>(&mut benchmark_group, 1);
  run_benchmark_verify_complex_xfr_note::<B>(&mut benchmark_group, 1);

  run_benchmark_create_complex_xfr_note::<B>(&mut benchmark_group, 4);
  run_benchmark_verify_complex_xfr_note::<B>(&mut benchmark_group, 4);

  run_benchmark_create_complex_xfr_note::<B>(&mut benchmark_group, 10);
  run_benchmark_verify_complex_xfr_note::<B>(&mut benchmark_group, 10);
}

pub fn bench_xfr_body<B: Measurement>(c: &mut Criterion<B>) {
  // Configure the benchmark
  let mut benchmark_group = c.benchmark_group("xfr");
  benchmark_group.sample_size(10);

  run_benchmark_create_complex_xfr_body::<B>(&mut benchmark_group, 1);
  run_benchmark_verify_complex_xfr_body::<B>(&mut benchmark_group, 1);

  run_benchmark_create_complex_xfr_body::<B>(&mut benchmark_group, 4);
  run_benchmark_verify_complex_xfr_body::<B>(&mut benchmark_group, 4);

  run_benchmark_create_complex_xfr_body::<B>(&mut benchmark_group, 10);
  run_benchmark_verify_complex_xfr_body::<B>(&mut benchmark_group, 10);
}
