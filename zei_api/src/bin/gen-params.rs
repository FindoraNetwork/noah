#![allow(clippy::upper_case_acronyms)]

use bulletproofs::BulletproofGens;
use poly_iops::commitments::kzg_poly_com::KZGCommitmentSchemeBLS;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::collections::HashMap;
use std::path::PathBuf;
use structopt::StructOpt;
use utils::save_to_file;
use zei::anon_xfr::TREE_DEPTH;
use zei::setup::{NodeParams, PublicParams, UserParams, PRECOMPUTED_PARTY_NUMBER};

use rayon::prelude::*;

#[derive(StructOpt, Debug)]
#[structopt(
    about = "Zei tool to handle public zkp-parameters.",
    rename_all = "kebab-case"
)]
enum Actions {
    User {
        n_payers: usize,
        n_payees: usize,
        tree_depth: usize,
        out_filename: PathBuf,
    },

    Node {
        n_payers: usize,
        n_payees: usize,
        tree_depth: usize,
        out_filename: PathBuf,
    },

    VK {
        directory: PathBuf,
    },

    BP {
        gens_capacity: usize,
        party_capacity: usize,
        out_filename: PathBuf,
    },

    KZG {
        size: usize,
        out_filename: PathBuf,
    },

    PublicParams {
        out_filename: PathBuf,
    },
}

// cargo run --release --features="parallel" --bin gen-params
#[allow(dead_code)]
fn main() {
    use Actions::*;
    let action = Actions::from_args();
    match action {
        User {
            n_payers,
            n_payees,
            tree_depth,
            out_filename,
        } => {
            gen_user_params(n_payers, n_payees, tree_depth, out_filename);
        }
        Node {
            n_payers,
            n_payees,
            tree_depth,
            out_filename,
        } => {
            gen_node_params(n_payers, n_payees, tree_depth, out_filename);
        }
        VK { directory } => {
            gen_vk(directory);
        }
        BP {
            gens_capacity,
            party_capacity,
            out_filename,
        } => {
            gen_params_bp(gens_capacity, party_capacity, out_filename);
        }
        KZG { size, out_filename } => {
            gen_params_kzg(size, out_filename);
        }
        PublicParams { out_filename } => gen_public_params(out_filename),
    };
}

fn gen_user_params(
    n_payers: usize,
    n_payees: usize,
    tree_depth: usize,
    out_filename: PathBuf,
) {
    println!(
        "Generating 'User Parameters' for {} payers, {} payees and with tree depth={}...",
        n_payers, n_payees, tree_depth
    );

    let tree_dept_option = if tree_depth == 0 {
        None
    } else {
        Some(tree_depth)
    };

    let user_params = UserParams::new(n_payers, n_payees, tree_dept_option).unwrap();
    let user_params_ser = bincode::serialize(&user_params).unwrap();
    save_to_file(&user_params_ser, out_filename);
}

fn gen_node_params(
    n_payers: usize,
    n_payees: usize,
    tree_depth: usize,
    out_filename: PathBuf,
) {
    println!(
        "Generating 'Node Parameters' for {} payers, {} payees and with tree depth={}...",
        n_payers, n_payees, tree_depth
    );

    let tree_dept_option = if tree_depth == 0 {
        None
    } else {
        Some(tree_depth)
    };

    let node_params = NodeParams::create(n_payers, n_payees, tree_dept_option).unwrap();
    let node_params_ser = bincode::serialize(&node_params).unwrap();
    save_to_file(&node_params_ser, out_filename);
}

// cargo run --release --features="parallel" --bin gen-params vk "./parameters"
fn gen_vk(directory: PathBuf) {
    println!(
        "Generating 'Node Compressed Parameters' for 1..{} payers, 1..{} payees ...",
        PRECOMPUTED_PARTY_NUMBER, PRECOMPUTED_PARTY_NUMBER
    );

    //let mut specials = vec![];
    let node_params = NodeParams::create(1, 1, Some(TREE_DEPTH)).unwrap();
    let (common, _) = node_params.split().unwrap();
    let common_ser = bincode::serialize(&common).unwrap();
    let mut common_path = directory.clone();
    common_path.push("vk-common.bin");
    save_to_file(&common_ser, common_path);

    //let mut need_common = true;
    let is: Vec<usize> = (1..=PRECOMPUTED_PARTY_NUMBER).map(|i| i).collect();
    let mut bytes: HashMap<usize, Vec<Vec<u8>>> = is
        .par_iter()
        .map(|i| {
            let js: Vec<usize> = (1..=PRECOMPUTED_PARTY_NUMBER).map(|j| j).collect();
            let mut bytes: HashMap<usize, Vec<u8>> = js
                .par_iter()
                .map(|j| {
                    println!("generateing {} payers & {} payees", i, j);
                    let node_params =
                        NodeParams::create(*i, *j, Some(TREE_DEPTH)).unwrap();
                    let (_, special) = node_params.split().unwrap();
                    (*j, bincode::serialize(&special).unwrap())
                })
                .collect();
            let mut ordered = vec![];
            for i in 1..=PRECOMPUTED_PARTY_NUMBER {
                ordered.push(bytes.remove(&i).unwrap())
            }
            (*i, ordered)
        })
        .collect();

    let mut specials = vec![];
    for i in 1..=PRECOMPUTED_PARTY_NUMBER {
        specials.push(bytes.remove(&i).unwrap())
    }

    let specials_ser = bincode::serialize(&specials).unwrap();
    let mut specials_path = directory.clone();
    specials_path.push("vk-specials.bin");
    save_to_file(&specials_ser, specials_path);
}

fn gen_params_bp(gens_capacity: usize, party_capacity: usize, out_filename: PathBuf) {
    println!("Generating BP parameters of size {} ...", gens_capacity);
    let bpgens = BulletproofGens::new(gens_capacity, party_capacity);
    let bpgens_ser = bincode::serialize(&bpgens).unwrap();
    save_to_file(&bpgens_ser, out_filename);
}

fn gen_params_kzg(size: usize, out_filename: PathBuf) {
    println!("Warning: The KZG parameters should come from a setup ceremony instead of generated here.");
    println!("Generating KZG parameters of size {} ...", size);
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let pcs = KZGCommitmentSchemeBLS::new(size, &mut prng);
    let params_ser = bincode::serialize(&pcs).unwrap();
    save_to_file(&params_ser, out_filename);
}

fn gen_public_params(out_filename: PathBuf) {
    println!("Generating Public Parameters ...");
    let pp = PublicParams::default();
    let pp_ser = bincode::serialize(&pp).unwrap();
    save_to_file(&pp_ser, out_filename);
}
