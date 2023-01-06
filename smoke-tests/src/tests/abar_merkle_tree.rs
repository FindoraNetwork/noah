use mem_db::MemoryDB;
use noah_api::anon_xfr::structs::AccElemVars;
use noah_api::anon_xfr::{
    add_merkle_path_variables, compute_merkle_root_variables,
    structs::{AnonAssetRecord, MTNode, MTPath, OpenAnonAssetRecord},
};
use noah_accumulators::merkle_tree::{PersistentMerkleTree, TreePath};
use noah_algebra::{bls12_381::BLSScalar, prelude::*};
use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381, ANEMOI_JIVE_381_SALTS};
use noah_plonk::plonk::constraint_system::TurboCS;
use parking_lot::RwLock;
use std::env::temp_dir;
use std::sync::Arc;
use std::time::SystemTime;
use storage::{
    state::{ChainState, State},
    store::PrefixedStore,
};

#[test]
fn test_persistent_merkle_tree() {
    let fdb = MemoryDB::new();
    let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
    let mut state = State::new(cs, false);
    let store = PrefixedStore::new("mystore", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();

    assert_eq!(mt.get_root().unwrap(), BLSScalar::zero(),);

    let abar = AnonAssetRecord::from_oabar(&OpenAnonAssetRecord::default());
    assert!(mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
        .is_ok());

    assert_ne!(
        mt.get_root().unwrap(),
        AnemoiJive381::eval_jive(
            &[BLSScalar::zero(), BLSScalar::zero()],
            &[BLSScalar::zero(), ANEMOI_JIVE_381_SALTS[0]]
        )
    );

    assert!(mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
        .is_ok());

    assert!(mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
        .is_ok());

    assert!(mt.generate_proof(0).is_ok());
    assert!(mt.generate_proof(1).is_ok());
    assert!(mt.generate_proof(2).is_ok());

    assert!(mt.generate_proof(3).is_err());
    assert!(mt.generate_proof(4).is_err());
    assert!(mt.generate_proof(11234).is_err());
}

#[test]
fn test_persistent_merkle_tree_proof_commitment() {
    let fdb = MemoryDB::new();
    let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
    let mut state = State::new(cs, false);
    let store = PrefixedStore::new("mystore", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();

    let mut prng = test_rng();

    let abar = AnonAssetRecord {
        commitment: BLSScalar::random(&mut prng),
    };
    assert!(mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
        .is_ok());

    let proof = mt.generate_proof(0).unwrap();

    let mut cs = TurboCS::new();
    cs.load_anemoi_jive_parameters::<AnemoiJive381>();

    let uid_var = cs.new_variable(BLSScalar::from(0u32));
    let comm_var = cs.new_variable(abar.commitment);
    let elem = AccElemVars {
        uid: uid_var,
        commitment: comm_var,
    };

    let path_vars = add_merkle_path_variables(
        &mut cs,
        MTPath {
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
    );

    let mut path_traces = Vec::new();
    let leaf_trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[
        BLSScalar::from(0u32),
        abar.commitment,
    ]);
    for (i, mt_node) in proof.nodes.iter().enumerate() {
        let trace = AnemoiJive381::eval_jive_with_trace(
            &[mt_node.left, mt_node.mid],
            &[mt_node.right, ANEMOI_JIVE_381_SALTS[i]],
        );
        path_traces.push(trace);
    }
    let root_var =
        compute_merkle_root_variables(&mut cs, elem, &path_vars, &leaf_trace, &path_traces);

    // Check Merkle root correctness
    let witness = cs.get_and_clear_witness();
    assert!(cs.verify_witness(&witness, &[]).is_ok());
    assert_eq!(witness[root_var], mt.get_root().unwrap());

    let _ = mt.commit();
}

#[test]
fn test_persistent_merkle_tree_recovery() {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut path = temp_dir();
    path.push(format!("temp-memorydb–{}", time));

    let fdb = MemoryDB::open(path.clone()).unwrap();
    let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
    let mut state = State::new(cs, false);
    let store = PrefixedStore::new("mystore", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();

    let mut prng = test_rng();

    let mut abar = AnonAssetRecord {
        commitment: BLSScalar::random(&mut prng),
    };
    assert!(mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
        .is_ok());
    mt.commit().unwrap();

    abar = AnonAssetRecord {
        commitment: BLSScalar::random(&mut prng),
    };
    assert!(mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
        .is_ok());
    mt.commit().unwrap();

    abar = AnonAssetRecord {
        commitment: BLSScalar::random(&mut prng),
    };
    assert!(mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
        .is_ok());
    mt.commit().unwrap();

    abar = AnonAssetRecord {
        commitment: BLSScalar::random(&mut prng),
    };
    assert!(mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
        .is_ok());
    mt.commit().unwrap();

    // test recovery
    let fdb2 = MemoryDB::open(path).unwrap();
    let cs2 = Arc::new(RwLock::new(ChainState::new(fdb2, "test_db".to_string(), 0)));
    let mut state2 = State::new(cs2, false);
    let store2 = PrefixedStore::new("mystore", &mut state2);
    let mt2 = PersistentMerkleTree::new(store2).unwrap();

    assert_eq!(mt2.version(), 4);
    assert_eq!(mt2.entry_count(), 4);
}

#[test]
fn test_init_tree() {
    let fdb = MemoryDB::new();
    let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
    let mut state = State::new(cs, false);

    build_tree(&mut state);
    build_tree(&mut state);
}

#[allow(dead_code)]
fn build_tree(state: &mut State<MemoryDB>) {
    let store = PrefixedStore::new("mystore", state);
    let _mt = PersistentMerkleTree::new(store).unwrap();
}

#[test]
pub fn test_merkle_proofs() {
    let fdb = MemoryDB::new();
    let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
    let mut state = State::new(cs, false);

    let store = PrefixedStore::new("mystore", &mut state);
    let mut pmt = PersistentMerkleTree::new(store).unwrap();

    let mut prng = test_rng();
    let abar0 = AnonAssetRecord {
        commitment: BLSScalar::random(&mut prng),
    };
    let abar1 = AnonAssetRecord {
        commitment: BLSScalar::random(&mut prng),
    };
    let abar2 = AnonAssetRecord {
        commitment: BLSScalar::random(&mut prng),
    };

    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
        .unwrap();
    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
        .unwrap();
    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
        .unwrap();
    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
        .unwrap();
    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
        .unwrap();
    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
        .unwrap();
    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
        .unwrap();
    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
        .unwrap();
    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
        .unwrap();
    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
        .unwrap();
    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
        .unwrap();
    pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
        .unwrap();
    pmt.commit().unwrap();
}

fn hash_abar(uid: u64, abar: &AnonAssetRecord) -> BLSScalar {
    AnemoiJive381::eval_variable_length_hash(&[BLSScalar::from(uid), abar.commitment])
}
