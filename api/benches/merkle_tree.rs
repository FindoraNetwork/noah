use ark_std::test_rng;
use criterion::{criterion_group, criterion_main, Criterion};
use mem_db::MemoryDB;
use merlin::Transcript;
use noah::anon_xfr::add_merkle_path_variables;
use noah::anon_xfr::structs::{AccElemVars, MTLeafInfo, MTNode, MTPath, MerklePathVars};
use noah_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
use noah_algebra::bls12_381::BLSFr;
use noah_crypto::basic::anemoi_jive::{
    AnemoiJive, AnemoiJive381, AnemoiVLHTrace, JiveTrace, ANEMOI_JIVE_381_SALTS,
};
use noah_plonk::plonk::constraint_system::{TurboCS, VarIndex};
use noah_plonk::plonk::indexer::indexer;
use noah_plonk::plonk::prover::prover;
use noah_plonk::poly_commit::kzg_poly_com::KZGCommitmentScheme;
use num_traits::One;
use parking_lot::RwLock;
use std::ops::Neg;
use std::sync::Arc;
use storage::state::{ChainState, State};
use storage::store::PrefixedStore;

fn merkle_tree_proof_bench(c: &mut Criterion) {
    let fdb = MemoryDB::new();
    let cs = Arc::new(RwLock::new(ChainState::new(
        fdb,
        "merkle_tree".to_owned(),
        0,
    )));
    let mut state = State::new(cs, false);
    let store = PrefixedStore::new("my_store", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();
    let uid = mt
        .add_commitment_hash(AnemoiJive381::eval_variable_length_hash(&[
            BLSFr::from(mt.entry_count()),
            BLSFr::one(),
        ]))
        .unwrap();
    mt.commit().unwrap();

    let proof = mt.generate_proof(uid).unwrap();

    let mut cs = TurboCS::new();
    cs.load_anemoi_jive_parameters::<AnemoiJive381>();

    let uid_var = cs.new_variable(BLSFr::from(uid));
    let commitment_var = cs.new_variable(BLSFr::one());

    // Merkle path authentication.

    let mut path_traces = Vec::new();

    let leaf_trace =
        AnemoiJive381::eval_variable_length_hash_with_trace(&[BLSFr::from(uid), BLSFr::one()]);
    for (i, mt_node) in proof.nodes.iter().enumerate() {
        let trace = AnemoiJive381::eval_jive_with_trace(
            &[mt_node.left, mt_node.mid],
            &[mt_node.right, ANEMOI_JIVE_381_SALTS[i]],
        );
        path_traces.push(trace);
    }
    let info = build_mt_leaf_info_from_proof(proof, uid);
    let path_var = add_merkle_path_variables(&mut cs, info.path);
    for _ in 0..70 {
        let acc_elem = AccElemVars {
            uid: uid_var,
            commitment: commitment_var,
        };
        let _ = compute_merkle_root_variables_2_20(
            &mut cs,
            acc_elem,
            &path_var,
            &leaf_trace,
            &path_traces,
        );
    }
    cs.pad();
    let witness = cs.get_and_clear_witness();

    let mut prng = test_rng();
    let pcs = KZGCommitmentScheme::new(16400, &mut prng);

    let prover_params = indexer(&cs, &pcs).unwrap();

    let mut transcript = Transcript::new(b"TestTurboPlonk");

    let mut single_group = c.benchmark_group("merkle_tree");
    single_group.sample_size(10);
    single_group.bench_function("batch of 70".to_string(), |b| {
        b.iter(|| {
            prover(
                &mut prng,
                &mut transcript,
                &pcs,
                &cs,
                &prover_params,
                &witness,
            )
            .unwrap()
        });
    });
    single_group.finish();
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

pub fn compute_merkle_root_variables_2_20(
    cs: &mut TurboPlonkCS,
    elem: AccElemVars,
    path_vars: &MerklePathVars,
    leaf_trace: &AnemoiVLHTrace<BLSFr, 2, 12>,
    traces: &Vec<JiveTrace<BLSFr, 2, 12>>,
) -> VarIndex {
    let (uid, commitment) = (elem.uid, elem.commitment);

    let mut node_var = cs.new_variable(leaf_trace.output);
    cs.anemoi_variable_length_hash(leaf_trace, &[uid, commitment], node_var);
    for (idx, (path_node, trace)) in path_vars
        .nodes
        .iter()
        .zip(traces.iter())
        .enumerate()
        .take(12)
    {
        let input_var = parse_merkle_tree_path(
            cs,
            node_var,
            path_node.mid,
            path_node.right,
            path_node.is_left_child,
            path_node.is_right_child,
        );
        node_var = cs.jive_crh(trace, &input_var, ANEMOI_JIVE_381_SALTS[idx]);
    }
    node_var
}

pub(crate) type TurboPlonkCS = TurboCS<BLSFr>;

fn parse_merkle_tree_path(
    cs: &mut TurboPlonkCS,
    node: VarIndex,
    sib1: VarIndex,
    sib2: VarIndex,
    is_left_child: VarIndex,
    is_right_child: VarIndex,
) -> [VarIndex; 3] {
    let left = cs.select(sib1, node, is_left_child);
    let right = cs.select(sib2, node, is_right_child);
    let sum_left_right = cs.add(left, right);
    let one = BLSFr::one();
    let mid = cs.linear_combine(
        &[node, sib1, sib2, sum_left_right],
        one,
        one,
        one,
        one.neg(),
    );
    [left, mid, right]
}

criterion_group!(benches, merkle_tree_proof_bench);
criterion_main!(benches);
