use criterion::measurement::Measurement;
use itertools::Itertools;

use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use criterion::{BenchmarkGroup, Criterion};

use zei::api::anon_creds::{ACCommitmentKey, ACUserSecretKey, Credential};
use zei::setup::PublicParams;
use zei::xfr::lib::{
  batch_verify_xfr_notes, gen_xfr_body, gen_xfr_note, verify_xfr_note, XfrNotePolicies,
  XfrNotePoliciesNoRef,
};
use zei::xfr::sig::XfrKeyPair;
use zei::xfr::structs::{AssetTracingPolicy, XfrBody, XfrNote};

pub mod bench_utils;

use crate::xfr_bench::bench_utils::{
  get_string_measurement_type, make_title, run_verify_xfr_body, run_verify_xfr_note, XFR_NOTE_SIZES,
};
use crate::xfr_building_utilities::{
  gen_policies_no_id_tracking, gen_policies_with_id_tracking, multiple_key_gen,
  prepare_inputs_and_outputs_with_policies_multiple_assets,
  prepare_inputs_and_outputs_with_policies_single_asset,
  prepare_inputs_and_outputs_without_policies_single_asset, setup_with_policies,
};

fn run_simple_xfr_note_create(sender_key_pairs: &[&XfrKeyPair], n: usize) -> XfrNote {
  let (ar_ins, output_asset_records) =
    prepare_inputs_and_outputs_without_policies_single_asset(sender_key_pairs, n);

  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  let xfr_note = gen_xfr_note(&mut prng,
                              ar_ins.as_slice(),
                              output_asset_records.as_slice(),
                              sender_key_pairs);
  xfr_note.unwrap()
}

fn run_complex_xfr_note_create(sender_key_pairs: &[&XfrKeyPair],
                               user_ac_sks: Vec<ACUserSecretKey>,
                               credentials: Vec<Credential>,
                               ac_commitment_keys: Vec<ACCommitmentKey>,
                               asset_tracing_policy_asset_input: AssetTracingPolicy,
                               n: usize)
                               -> XfrNote {
  let (ar_ins, output_asset_records) =
    prepare_inputs_and_outputs_with_policies_single_asset(sender_key_pairs,
                                                          user_ac_sks,
                                                          credentials,
                                                          ac_commitment_keys,
                                                          Some(asset_tracing_policy_asset_input),
                                                          n);

  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  gen_xfr_note(&mut prng,
               ar_ins.as_slice(),
               output_asset_records.as_slice(),
               sender_key_pairs).unwrap()
}

fn run_xfr_note_with_identity_tracking_create(sender_key_pairs: &[&XfrKeyPair],
                                              user_ac_sks: Vec<ACUserSecretKey>,
                                              credentials: Vec<Credential>,
                                              ac_commitment_keys: Vec<ACCommitmentKey>,
                                              n: usize)
                                              -> XfrNote {
  let (ar_ins, output_asset_records) =
    prepare_inputs_and_outputs_with_policies_single_asset(sender_key_pairs,
                                                          user_ac_sks,
                                                          credentials,
                                                          ac_commitment_keys,
                                                          None,
                                                          n);

  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  gen_xfr_note(&mut prng,
               ar_ins.as_slice(),
               output_asset_records.as_slice(),
               sender_key_pairs).unwrap()
}

pub fn run_complex_xfr_note_multiple_assets_create(sender_key_pairs: &[&XfrKeyPair],
                                                   user_ac_sks: Vec<ACUserSecretKey>,
                                                   credentials: Vec<Credential>,
                                                   ac_commitment_keys: Vec<ACCommitmentKey>,
                                                   asset_tracing_policy_asset_input: AssetTracingPolicy,
                                                   n: usize)
                                                   -> XfrNote {
  let (ar_ins, output_asset_records) =
    prepare_inputs_and_outputs_with_policies_multiple_assets(sender_key_pairs,
                                             user_ac_sks,
                                             credentials,
                                             ac_commitment_keys,
                                             Some(asset_tracing_policy_asset_input),
                                             n);

  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  gen_xfr_note(&mut prng,
               ar_ins.as_slice(),
               output_asset_records.as_slice(),
               sender_key_pairs).unwrap()
}

fn run_simple_xfr_note_verify(xfr_note: XfrNote, policies: XfrNotePoliciesNoRef) {
  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  let mut params = PublicParams::new();

  let policies_with_ref: XfrNotePolicies = XfrNotePolicies::from_policies_no_ref(&policies);
  let res = verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies_with_ref);
  assert!(res.is_ok());
}

fn run_batch_xfr_note_verify(xfr_notes: &[XfrNote], xfr_notes_policies: &[XfrNotePoliciesNoRef]) {
  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  let mut params = PublicParams::new();

  let xfr_notes_vec = xfr_notes.iter().map(|x| x).collect_vec();
  let xfr_notes_ref = xfr_notes_vec.as_slice();

  let mut xfr_notes_policies_ref = vec![];
  for policies in xfr_notes_policies {
    let policies_with_ref: XfrNotePolicies = XfrNotePolicies::from_policies_no_ref(policies);

    xfr_notes_policies_ref.push(policies_with_ref);
  }

  let res = batch_verify_xfr_notes(&mut prng,
                                   &mut params,
                                   xfr_notes_ref,
                                   xfr_notes_policies_ref.iter()
                                                         .map(|x| x)
                                                         .collect_vec()
                                                         .as_slice());
  assert!(res.is_ok());
}

fn run_complex_xfr_body_create(sender_key_pairs: &[&XfrKeyPair],
                               user_ac_sks: Vec<ACUserSecretKey>,
                               credentials: Vec<Credential>,
                               ac_commitment_keys: Vec<ACCommitmentKey>,
                               asset_tracing_policy_asset_input: AssetTracingPolicy,
                               n: usize)
                               -> XfrBody {
  let (ar_ins, output_asset_records) =
    prepare_inputs_and_outputs_with_policies_single_asset(sender_key_pairs,
                                                          user_ac_sks,
                                                          credentials,
                                                          ac_commitment_keys,
                                                          Some(asset_tracing_policy_asset_input),
                                                          n);

  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  gen_xfr_body(&mut prng,
               ar_ins.as_slice(),
               output_asset_records.as_slice()).unwrap()
}

pub fn run_benchmark_create_complex_xfr_note<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                             n: usize) {
  let title = make_title::<B>("Complex XfrNote creation", n);

  let (sender_key_pairs,
       user_ac_sks,
       credentials,
       ac_commitment_keys,
       asset_tracing_policy_asset_input,
       _ac_commitments) = setup_with_policies(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

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

pub fn run_benchmark_create_xfr_note_identity_tracking<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                                       n: usize) {
  let title = make_title::<B>("XfrNote with identity tracking creation", n);

  let (sender_key_pairs, user_ac_sks, credentials, ac_commitment_keys, _, _ac_commitments) =
    setup_with_policies(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| {
                      run_xfr_note_with_identity_tracking_create(sender_key_pairs_ref.as_slice(),
                                                                 user_ac_sks.clone(),
                                                                 credentials.clone(),
                                                                 ac_commitment_keys.clone(),
                                                                 n)
                    })
                 });
}

pub fn run_benchmark_create_complex_xfr_note_multiple_assets<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                                             n: usize) {
  let title = make_title::<B>("Complex XfrNote creation with multiple assets", n);

  let (sender_key_pairs,
       user_ac_sks,
       credentials,
       ac_commitment_keys,
       asset_tracing_policy_asset_input,
       _ac_commitments) = setup_with_policies(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| {
                      run_complex_xfr_note_multiple_assets_create(sender_key_pairs_ref.as_slice(),
                                                   user_ac_sks.clone(),
                                                   credentials.clone(),
                                                   ac_commitment_keys.clone(),
                                                   asset_tracing_policy_asset_input.clone(),
                                                   n)
                    })
                 });
}

pub fn run_benchmark_create_simple_xfr_note<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                            n: usize) {
  let title = make_title::<B>("Simple XfrNote creation", n);

  let (sender_key_pairs, _) = multiple_key_gen(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| run_simple_xfr_note_create(sender_key_pairs_ref.as_slice(), n))
                 });
}

pub fn run_benchmark_verify_simple_xfr_note<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                            n: usize) {
  let title = make_title::<B>("Simple XfrNote verification", n);

  let (sender_key_pairs, _) = multiple_key_gen(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

  let xfr_note = run_simple_xfr_note_create(sender_key_pairs_ref.as_slice(), n);

  let xfr_policies = gen_policies_no_id_tracking(n);

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| run_simple_xfr_note_verify(xfr_note.clone(), xfr_policies.clone()))
                 });
}

pub fn run_benchmark_verify_batch_xfr<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                      n: usize,
                                                      k: usize) {
  let title = format!("Batch XfrNote verification n={n}, k={k} ({b_type})",
                      n = n,
                      k = k,
                      b_type = std::any::type_name::<B>());

  let mut xfr_notes = vec![];
  let mut xfr_policies = vec![];

  for _i in 0..k {
    let (sender_key_pairs, _) = multiple_key_gen(n);
    let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

    let (ar_ins, output_asset_records) =
      prepare_inputs_and_outputs_without_policies_single_asset(sender_key_pairs_ref.as_slice(), n);

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let xfr_note = gen_xfr_note(&mut prng,
                                ar_ins.as_slice(),
                                output_asset_records.as_slice(),
                                sender_key_pairs_ref.as_slice());
    xfr_notes.push(xfr_note.unwrap().clone());

    let policies = gen_policies_no_id_tracking(n);
    xfr_policies.push(policies);
  }

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| {
                      run_batch_xfr_note_verify(xfr_notes.clone().as_slice(),
                                                xfr_policies.as_slice())
                    })
                 });
}

pub fn run_benchmark_create_complex_xfr_body<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                             n: usize) {
  let title = make_title::<B>("Complex XfrBody creation", n);

  let (sender_key_pairs,
       user_ac_sks,
       credentials,
       ac_commitment_keys,
       asset_tracing_policy_asset_input,
       _ac_commitments) = setup_with_policies(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| {
                      run_complex_xfr_body_create(sender_key_pairs_ref.as_slice(),
                                                  user_ac_sks.clone(),
                                                  credentials.clone(),
                                                  ac_commitment_keys.clone(),
                                                  asset_tracing_policy_asset_input.clone(),
                                                  n)
                    })
                 });
}

pub fn run_benchmark_verify_complex_xfr_note<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                             n: usize) {
  let title = make_title::<B>("Complex XfrNote verification", n);

  let (sender_key_pairs,
       user_ac_sks,
       credentials,
       ac_commitment_keys,
       asset_tracing_policy_input,
       ac_commitments) = setup_with_policies(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

  let xfr_note = run_complex_xfr_note_create(sender_key_pairs_ref.as_slice(),
                                             user_ac_sks,
                                             credentials,
                                             ac_commitment_keys,
                                             asset_tracing_policy_input.clone(),
                                             n);

  let policies_no_ref =
    gen_policies_with_id_tracking(ac_commitments.as_slice(), asset_tracing_policy_input, n);
  let policies = XfrNotePolicies::from_policies_no_ref(&policies_no_ref);

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| run_verify_xfr_note(&xfr_note, &policies))
                 });
}

pub fn run_benchmark_verify_xfr_note_identity_tracking<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                                       n: usize) {
  let title = make_title::<B>("XfrNote with identity tracking verification", n);

  let (sender_key_pairs,
       user_ac_sks,
       credentials,
       ac_commitment_keys,
       asset_tracing_policy_input,
       ac_commitments) = setup_with_policies(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

  let xfr_note = run_complex_xfr_note_create(sender_key_pairs_ref.as_slice(),
                                             user_ac_sks,
                                             credentials,
                                             ac_commitment_keys,
                                             asset_tracing_policy_input.clone(),
                                             n);

  let policies_no_ref =
    gen_policies_with_id_tracking(ac_commitments.as_slice(), asset_tracing_policy_input, n);
  let policies = XfrNotePolicies::from_policies_no_ref(&policies_no_ref);

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| run_verify_xfr_note(&xfr_note, &policies))
                 });
}

pub fn run_benchmark_verify_complex_xfr_note_many_assets<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                                         n: usize) {
  let title = make_title::<B>("Complex XfrNote verification with many assets", n);

  let (sender_key_pairs,
       user_ac_sks,
       credentials,
       ac_commitment_keys,
       asset_tracing_policy_input,
       ac_commitments) = setup_with_policies(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

  let xfr_note = run_complex_xfr_note_multiple_assets_create(sender_key_pairs_ref.as_slice(),
                                                             user_ac_sks,
                                                             credentials,
                                                             ac_commitment_keys,
                                                             asset_tracing_policy_input.clone(),
                                                             n);

  let policies_no_ref =
    gen_policies_with_id_tracking(ac_commitments.as_slice(), asset_tracing_policy_input, n);
  let policies = XfrNotePolicies::from_policies_no_ref(&policies_no_ref);

  benchmark_group.bench_function(title, move |b| {
                   b.iter(|| run_verify_xfr_note(&xfr_note, &policies))
                 });
}

pub fn run_benchmark_verify_complex_xfr_body<B: Measurement>(benchmark_group: &mut BenchmarkGroup<B>,
                                                             n: usize) {
  let title = make_title::<B>("Complex XfrBody verification", n);

  let (sender_key_pairs,
       user_ac_sks,
       credentials,
       ac_commitment_keys,
       asset_tracing_policy_input,
       ac_commitments) = setup_with_policies(n);
  let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

  let xfr_body = run_complex_xfr_body_create(sender_key_pairs_ref.as_slice(),
                                             user_ac_sks,
                                             credentials,
                                             ac_commitment_keys,
                                             asset_tracing_policy_input.clone(),
                                             n);

  let policies_no_ref =
    gen_policies_with_id_tracking(ac_commitments.as_slice(), asset_tracing_policy_input, n);
  let policies = XfrNotePolicies::from_policies_no_ref(&policies_no_ref);

  benchmark_group.bench_function(title, |b| {
                   b.iter(|| run_verify_xfr_body(&xfr_body, &policies))
                 });
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//// Bench main functions //////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

pub fn xfr_note_noidtracking_noassettracking_singleasset<B: Measurement>(c: &mut Criterion<B>) {
  // Configure the benchmark
  let mut benchmark_group =
    c.benchmark_group(format!("xfr_note_noidtracking_noassettracking_singleasset_{}",
                              get_string_measurement_type::<B>()));
  benchmark_group.sample_size(10);

  for xfr_note_size in XFR_NOTE_SIZES.iter() {
    run_benchmark_create_simple_xfr_note::<B>(&mut benchmark_group, *xfr_note_size);
    run_benchmark_verify_simple_xfr_note::<B>(&mut benchmark_group, *xfr_note_size);
  }
}

pub fn xfr_note_idtracking_assettracking_singleasset<B: Measurement>(c: &mut Criterion<B>) {
  let mut benchmark_group =
    c.benchmark_group(format!("xfr_note_idtracking_assettracking_singleasset_{}",
                              get_string_measurement_type::<B>()));
  benchmark_group.sample_size(10);

  for xfr_note_size in XFR_NOTE_SIZES.iter() {
    run_benchmark_create_complex_xfr_note::<B>(&mut benchmark_group, *xfr_note_size);
    run_benchmark_verify_complex_xfr_note::<B>(&mut benchmark_group, *xfr_note_size);
  }
}

pub fn xfr_note_idtracking_noassettracking_singleasset<B: Measurement>(c: &mut Criterion<B>) {
  let mut benchmark_group =
    c.benchmark_group(format!("xfr_note_idtracking_noassettracking_singleasset_{}",
                              get_string_measurement_type::<B>()));
  benchmark_group.sample_size(10);

  for xfr_note_size in XFR_NOTE_SIZES.iter() {
    run_benchmark_create_xfr_note_identity_tracking::<B>(&mut benchmark_group, *xfr_note_size);
    run_benchmark_verify_xfr_note_identity_tracking::<B>(&mut benchmark_group, *xfr_note_size);
  }
}

pub fn xfr_note_idtracking_assettracking_multiasset<B: Measurement>(c: &mut Criterion<B>) {
  let mut benchmark_group =
    c.benchmark_group(format!("xfr_note_idtracking_assettracking_multiasset_{}",
                              std::any::type_name::<B>()));
  benchmark_group.sample_size(10);

  for xfr_note_size in XFR_NOTE_SIZES.iter() {
    run_benchmark_create_complex_xfr_note_multiple_assets::<B>(&mut benchmark_group,
                                                               *xfr_note_size);
    run_benchmark_verify_complex_xfr_note_many_assets::<B>(&mut benchmark_group, *xfr_note_size);
  }
}

pub fn xfr_body_idtracking_assettracking_singleasset<B: Measurement>(c: &mut Criterion<B>) {
  let mut benchmark_group =
    c.benchmark_group(format!("xfr_body_idtracking_assettracking_singleasset_{}",
                              get_string_measurement_type::<B>()));
  benchmark_group.sample_size(10);

  for xfr_note_size in XFR_NOTE_SIZES.iter() {
    run_benchmark_create_complex_xfr_body::<B>(&mut benchmark_group, *xfr_note_size);
    run_benchmark_verify_complex_xfr_body::<B>(&mut benchmark_group, *xfr_note_size);
  }
}

pub fn xfr_note_batch<B: Measurement>(c: &mut Criterion<B>) {
  let mut benchmark_group =
    c.benchmark_group(format!("xfr_note_batch_{}", get_string_measurement_type::<B>()));
  benchmark_group.sample_size(10);

  const K_VALUES: [usize; 3] = [1, 10, 100];

  for xfr_note_size in XFR_NOTE_SIZES.iter() {
    for k_value in K_VALUES.iter() {
      run_benchmark_verify_batch_xfr::<B>(&mut benchmark_group, *xfr_note_size, *k_value);
    }
  }
}
