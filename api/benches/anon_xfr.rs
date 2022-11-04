use criterion::{criterion_group, criterion_main, Criterion};
use digest::Digest;
use mem_db::MemoryDB;
use noah::{
    anon_xfr::{
        abar_to_abar::*,
        abar_to_ar::*,
        abar_to_bar::*,
        ar_to_abar::*,
        bar_to_abar::*,
        keys::AXfrKeyPair,
        structs::{
            AnonAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonAssetRecord,
            OpenAnonAssetRecordBuilder,
        },
        FEE_TYPE, TREE_DEPTH,
    },
    setup::{ProverParams, VerifierParams},
    xfr::{
        asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType},
        sig::XfrKeyPair,
        structs::{AssetRecordTemplate, AssetType, ASSET_TYPE_LENGTH},
    },
};
use noah_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
use noah_algebra::{bls12_381::BLSScalar, prelude::*};
use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381};
use noah_crypto::basic::pedersen_comm::PedersenCommitmentRistretto;
use parking_lot::RwLock;
use sha2::Sha512;
use std::sync::Arc;
use storage::{
    state::{ChainState, State},
    store::PrefixedStore,
};

const AMOUNT: u64 = 10u64;
const ASSET: AssetType = AssetType([1u8; ASSET_TYPE_LENGTH]);
#[cfg(feature = "parallel")]
const BATCHSIZE: [usize; 7] = [1, 2, 3, 6, 10, 20, 30];

// Measurement of the verification time and batch verification time of `abar_to_abar`.
fn bench_abar_to_abar(c: &mut Criterion) {
    let outputs = vec![(5, FEE_TYPE), (15, FEE_TYPE), (30, ASSET)];
    let inputs = vec![(20 + 13 as u64, FEE_TYPE), (30, ASSET)];
    abar_to_abar(c, inputs, outputs, 13);
}

// Measurement of the verification time and batch verification time of `abar_to_bar`.
fn bench_abar_to_bar(c: &mut Criterion) {
    abar_to_bar(c);
}

// Measurement of the verification time and batch verification time of `abar_to_ar`.
fn bench_abar_to_ar(c: &mut Criterion) {
    abar_to_ar(c);
}

// Measurement of the verification time and batch verification time of `bar_to_abar`.
fn bench_bar_to_abar(c: &mut Criterion) {
    bar_to_abar(c);
}

// Measurement of the verification time and batch verification time of `ar_to_abar`.
fn bench_ar_to_abar(c: &mut Criterion) {
    ar_to_abar(c);
}

criterion_group!(
    benches,
    bench_abar_to_abar,
    bench_abar_to_bar,
    bench_abar_to_ar,
    bench_bar_to_abar,
    bench_ar_to_abar
);
criterion_main!(benches);

fn abar_to_abar(
    c: &mut Criterion,
    inputs: Vec<(u64, AssetType)>,
    outputs: Vec<(u64, AssetType)>,
    fee: u32,
) {
    let mut prng = test_rng();
    let params = ProverParams::new(inputs.len(), outputs.len(), None).unwrap();
    let verifier_params = VerifierParams::load(inputs.len(), outputs.len()).unwrap();

    let sender = AXfrKeyPair::generate(&mut prng);
    let receivers: Vec<AXfrKeyPair> = (0..outputs.len())
        .map(|_| AXfrKeyPair::generate(&mut prng))
        .collect();

    let mut oabars: Vec<OpenAnonAssetRecord> = inputs
        .iter()
        .map(|input| build_oabar(&mut prng, input.0, input.1, &sender))
        .collect();
    let abars: Vec<_> = oabars.iter().map(AnonAssetRecord::from_oabar).collect();

    let fdb = MemoryDB::new();
    let cs = Arc::new(RwLock::new(ChainState::new(fdb, "my_store".to_string(), 0)));
    let mut state = State::new(cs, false);
    let store = PrefixedStore::new("my_store", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();
    let mut uids = vec![];
    for i in 0..abars.len() {
        let abar_comm = hash_abar(mt.entry_count(), &abars[i]);
        uids.push(mt.add_commitment_hash(abar_comm).unwrap());
    }
    mt.commit().unwrap();
    let root = mt.get_root().unwrap();
    for (i, uid) in uids.iter().enumerate() {
        let proof = mt.generate_proof(*uid).unwrap();
        oabars[i].update_mt_leaf_info(build_mt_leaf_info_from_proof(proof, *uid));
    }

    let oabars_out: Vec<OpenAnonAssetRecord> = outputs
        .iter()
        .enumerate()
        .map(|(i, output)| build_oabar(&mut prng, output.0, output.1, &receivers[i]))
        .collect();

    let pre_note = init_anon_xfr_note(&oabars, &oabars_out, fee, &sender).unwrap();
    let hash = random_hasher(&mut prng);
    let note = finish_anon_xfr_note(&mut prng, &params, pre_note, hash.clone()).unwrap();

    let mut single_group = c.benchmark_group("abar_to_abar");
    single_group.sample_size(10);
    single_group.bench_function("non batch verify".to_string(), |b| {
        b.iter(|| {
            assert!(verify_anon_xfr_note(&verifier_params, &note, &root, hash.clone()).is_ok())
        });
    });
    single_group.finish();

    #[cfg(feature = "parallel")]
    {
        for batch_size in BATCHSIZE {
            let verifiers_params = vec![&verifier_params; batch_size];
            let notes = vec![&note; batch_size];
            let merkle_roots = vec![&root; batch_size];
            let hashes = vec![hash.clone(); batch_size];
            let mut batch_group = c.benchmark_group("abar_to_abar");
            batch_group.sample_size(10);
            batch_group.bench_function(format!("batch verify of {}", batch_size), |b| {
                b.iter(|| {
                    assert!(batch_verify_anon_xfr_note(
                        &verifiers_params,
                        &notes,
                        &merkle_roots,
                        hashes.clone()
                    )
                    .is_ok())
                });
            });
            batch_group.finish();
        }
    }
}

fn abar_to_ar(c: &mut Criterion) {
    let mut prng = test_rng();
    let params = ProverParams::abar_to_ar_params(TREE_DEPTH).unwrap();
    let verify_params = VerifierParams::abar_to_ar_params().unwrap();

    let sender = AXfrKeyPair::generate(&mut prng);
    let receiver = XfrKeyPair::generate(&mut prng);

    let fdb = MemoryDB::new();
    let cs = Arc::new(RwLock::new(ChainState::new(fdb, "abar_ar".to_owned(), 0)));
    let mut state = State::new(cs, false);
    let store = PrefixedStore::new("my_store", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();

    let mut oabar = build_oabar(&mut prng, AMOUNT, ASSET, &sender);
    let abar = AnonAssetRecord::from_oabar(&oabar);
    mt.add_commitment_hash(hash_abar(0, &abar)).unwrap();
    mt.commit().unwrap();
    let proof = mt.generate_proof(0).unwrap();
    oabar.update_mt_leaf_info(build_mt_leaf_info_from_proof(proof.clone(), 0));

    let pre_note = init_abar_to_ar_note(&mut prng, &oabar, &sender, &receiver.pub_key).unwrap();
    let hash = random_hasher(&mut prng);
    let note = finish_abar_to_ar_note(&mut prng, &params, pre_note, hash.clone()).unwrap();

    let mut single_group = c.benchmark_group("abar_to_ar");
    single_group.sample_size(10);
    single_group.bench_function("non batch verify".to_string(), |b| {
        b.iter(|| {
            assert!(
                verify_abar_to_ar_note(&verify_params, &note, &proof.root, hash.clone()).is_ok()
            )
        });
    });
    single_group.finish();

    #[cfg(feature = "parallel")]
    {
        for batch_size in BATCHSIZE {
            let notes = vec![&note; batch_size];
            let merkle_roots = vec![&proof.root; batch_size];
            let hashes = vec![hash.clone(); batch_size];

            let mut batch_group = c.benchmark_group("abar_to_abar");
            batch_group.sample_size(10);
            batch_group.bench_function(format!("batch verify of {}", batch_size), |b| {
                b.iter(|| {
                    assert!(batch_verify_abar_to_ar_note(
                        &verify_params,
                        &notes,
                        &merkle_roots,
                        hashes.clone()
                    )
                    .is_ok())
                });
            });
            batch_group.finish();
        }
    }
}

fn abar_to_bar(c: &mut Criterion) {
    let mut prng = test_rng();
    let params = ProverParams::abar_to_bar_params(TREE_DEPTH).unwrap();
    let verify_params = VerifierParams::abar_to_bar_params().unwrap();

    let sender = AXfrKeyPair::generate(&mut prng);
    let receiver = XfrKeyPair::generate(&mut prng);

    let fdb = MemoryDB::new();
    let cs = Arc::new(RwLock::new(ChainState::new(fdb, "abar_bar".to_owned(), 0)));
    let mut state = State::new(cs, false);
    let store = PrefixedStore::new("my_store", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();

    let mut oabar = build_oabar(&mut prng, AMOUNT, ASSET, &sender);
    let abar = AnonAssetRecord::from_oabar(&oabar);
    mt.add_commitment_hash(hash_abar(0, &abar)).unwrap();
    mt.add_commitment_hash(hash_abar(1, &abar)).unwrap();
    mt.commit().unwrap();
    let proof = mt.generate_proof(1).unwrap();
    oabar.update_mt_leaf_info(build_mt_leaf_info_from_proof(proof.clone(), 1));

    let pre_note = init_abar_to_bar_note(
        &mut prng,
        &oabar,
        &sender,
        &receiver.pub_key,
        AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
    )
    .unwrap();
    let hash = random_hasher(&mut prng);
    let note = finish_abar_to_bar_note(&mut prng, &params, pre_note, hash.clone()).unwrap();

    let mut single_group = c.benchmark_group("abar_to_bar");
    single_group.bench_function("non batch verify".to_string(), |b| {
        b.iter(|| {
            assert!(
                verify_abar_to_bar_note(&verify_params, &note, &proof.root, hash.clone()).is_ok()
            )
        });
    });
    single_group.finish();

    #[cfg(feature = "parallel")]
    {
        for batch_size in BATCHSIZE {
            let notes = vec![&note; batch_size];
            let merkle_roots = vec![&proof.root; batch_size];
            let hashes = vec![hash.clone(); batch_size];

            let mut batch_group = c.benchmark_group("abar_to_bar");
            batch_group.sample_size(10);
            batch_group.bench_function(format!("batch verify of {}", batch_size), |b| {
                b.iter(|| {
                    assert!(batch_verify_abar_to_bar_note(
                        &verify_params,
                        &notes,
                        &merkle_roots,
                        hashes.clone()
                    )
                    .is_ok())
                });
            });
            batch_group.finish();
        }
    }
}

fn ar_to_abar(c: &mut Criterion) {
    let mut prng = test_rng();
    let pc_gens = PedersenCommitmentRistretto::default();
    let params = ProverParams::ar_to_abar_params().unwrap();
    let verify_params = VerifierParams::ar_to_abar_params().unwrap();

    let sender = XfrKeyPair::generate(&mut prng);
    let receiver = AXfrKeyPair::generate(&mut prng);

    let (bar, memo) = {
        let ar = AssetRecordTemplate::with_no_asset_tracing(
            AMOUNT,
            ASSET,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            sender.pub_key,
        );
        let (bar, _, memo) = build_blind_asset_record(&mut prng, &pc_gens, &ar, vec![]);
        (bar, memo)
    };

    let obar = open_blind_asset_record(&bar, &memo, &sender).unwrap();

    let note = gen_ar_to_abar_note(
        &mut prng,
        &params,
        &obar,
        &sender,
        &receiver.get_public_key(),
    )
    .unwrap();

    let mut single_group = c.benchmark_group("ar_to_abar");
    single_group.sample_size(10);
    single_group.bench_function("non batch verify".to_string(), |b| {
        b.iter(|| assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok()));
    });
    single_group.finish();

    #[cfg(feature = "parallel")]
    {
        for batch_size in BATCHSIZE {
            let notes = vec![&note; batch_size];

            let mut batch_group = c.benchmark_group("ar_to_abar");
            batch_group.sample_size(10);
            batch_group.bench_function(format!("batch verify of {}", batch_size), |b| {
                b.iter(|| assert!(batch_verify_ar_to_abar_note(&verify_params, &notes).is_ok()));
            });
            batch_group.finish();
        }
    }
}

fn bar_to_abar(c: &mut Criterion) {
    let mut prng = test_rng();
    let pc_gens = PedersenCommitmentRistretto::default();
    let params = ProverParams::bar_to_abar_params().unwrap();
    let verify_params = VerifierParams::bar_to_abar_params().unwrap();

    let sender = XfrKeyPair::generate(&mut prng);
    let receiver = AXfrKeyPair::generate(&mut prng);

    let (bar, memo) = {
        let ar = AssetRecordTemplate::with_no_asset_tracing(
            AMOUNT,
            ASSET,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            sender.pub_key,
        );
        let (bar, _, memo) = build_blind_asset_record(&mut prng, &pc_gens, &ar, vec![]);
        (bar, memo)
    };
    let obar = open_blind_asset_record(&bar, &memo, &sender).unwrap();

    let note = gen_bar_to_abar_note(
        &mut prng,
        &params,
        &obar,
        &sender,
        &receiver.get_public_key(),
    )
    .unwrap();
    assert!(verify_bar_to_abar_note(&verify_params, &note, &sender.pub_key).is_ok());

    let mut single_group = c.benchmark_group("bar_to_abar");
    single_group.sample_size(10);
    single_group.bench_function("non batch verify".to_string(), |b| {
        b.iter(|| assert!(verify_bar_to_abar_note(&verify_params, &note, &sender.pub_key).is_ok()));
    });
    single_group.finish();

    #[cfg(feature = "parallel")]
    {
        for batch_size in BATCHSIZE {
            let notes = vec![&note; batch_size];
            let pub_keys = vec![&sender.pub_key; batch_size];

            let mut batch_group = c.benchmark_group("bar_to_abar");
            batch_group.sample_size(10);
            batch_group.bench_function(format!("batch verify of {}", batch_size), |b| {
                b.iter(|| {
                    assert!(
                        batch_verify_bar_to_abar_note(&verify_params, &notes, &pub_keys).is_ok()
                    )
                });
            });
            batch_group.finish();
        }
    }
}

fn build_oabar<R: CryptoRng + RngCore>(
    prng: &mut R,
    amount: u64,
    asset_type: AssetType,
    keypair: &AXfrKeyPair,
) -> OpenAnonAssetRecord {
    OpenAnonAssetRecordBuilder::new()
        .amount(amount)
        .asset_type(asset_type)
        .pub_key(&keypair.get_public_key())
        .finalize(prng)
        .unwrap()
        .build()
        .unwrap()
}

fn hash_abar(uid: u64, abar: &AnonAssetRecord) -> BLSScalar {
    AnemoiJive381::eval_variable_length_hash(&[BLSScalar::from(uid), abar.commitment])
}

fn build_mt_leaf_info_from_proof(proof: Proof, uid: u64) -> MTLeafInfo {
    return MTLeafInfo {
        path: MTPath {
            nodes: proof
                .nodes
                .iter()
                .map(|e| MTNode {
                    left: e.left,
                    mid: e.mid,
                    right: e.right,
                    is_left_child: (e.path == TreePath::Left) as u8,
                    is_mid_child: (e.path == TreePath::Middle) as u8,
                    is_right_child: (e.path == TreePath::Right) as u8,
                })
                .collect(),
        },
        root: proof.root,
        root_version: proof.root_version,
        uid,
    };
}

fn random_hasher<R: CryptoRng + RngCore>(prng: &mut R) -> Sha512 {
    let mut hasher = Sha512::new();
    let mut random_bytes = [0u8; 32];
    prng.fill_bytes(&mut random_bytes);
    hasher.update(&random_bytes);
    hasher
}
