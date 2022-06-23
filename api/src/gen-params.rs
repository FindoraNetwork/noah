#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]
#![cfg_attr(
    any(feature = "no_urs", feature = "no_srs", feature = "no_vk"),
    allow(unused)
)]

use bulletproofs::BulletproofGens;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::{collections::HashMap, path::PathBuf};
use structopt::StructOpt;
use zei::{
    anon_xfr::TREE_DEPTH,
    setup::{BulletproofParams, ProverParams, VerifierParams, PRECOMPUTED_PARTY_NUMBER},
};
use zei_algebra::utils::save_to_file;
use zei_plonk::poly_commit::kzg_poly_com::KZGCommitmentSchemeBLS;

use rayon::prelude::*;

#[derive(StructOpt, Debug)]
#[structopt(
    about = "Zei tool to generate necessary zero-knowledge proof parameters.",
    rename_all = "kebab-case"
)]
enum Actions {
    /// Generates the verifying key for anonymous transfer
    TRANSFER { directory: PathBuf },

    /// Generates the verifying key for ABAR to BAR transform
    ABAR_TO_BAR { directory: PathBuf },

    /// Generates the verifying key for BAR to ABAR transform
    BAR_TO_ABAR { directory: PathBuf },

    /// Generates the verifying key for AR to ABAR transform
    AR_TO_ABAR { directory: PathBuf },

    /// Generates the verifying key for ABAR to AR transform
    ABAR_TO_AR { directory: PathBuf },

    /// Generates the uniform reference string for Bulletproof
    BULLETPROOF { directory: PathBuf },
}

// cargo run --release --features="gen no_urs no_srs no_vk" --bin gen-params
#[allow(dead_code)]
fn main() {
    use Actions::*;
    let action = Actions::from_args();
    match action {
        TRANSFER { directory } => {
            gen_transfer_vk(directory);
        }

        ABAR_TO_BAR { directory } => {
            gen_abar_to_bar_vk(directory);
        }

        BAR_TO_ABAR { directory } => {
            gen_bar_to_abar_vk(directory);
        }

        AR_TO_ABAR { directory } => {
            gen_ar_to_abar_vk(directory);
        }

        ABAR_TO_AR { directory } => {
            gen_abar_to_ar_vk(directory);
        }

        BULLETPROOF { directory } => gen_bulletproof_urs(directory),
    };
}

// cargo run --release --features="gen no_vk" --bin gen-params transfer "./parameters"
fn gen_transfer_vk(directory: PathBuf) {
    println!(
        "Generating verifying keys for anonymous transfer for 1..{} payers, 1..{} payees ...",
        PRECOMPUTED_PARTY_NUMBER, PRECOMPUTED_PARTY_NUMBER
    );

    let transfer_params = VerifierParams::create(1, 1, Some(TREE_DEPTH)).unwrap();
    let (common, _) = transfer_params.split().unwrap();
    let common_ser = bincode::serialize(&common).unwrap();

    let mut common_path = directory.clone();
    common_path.push("transfer-vk-common.bin");
    save_to_file(&common_ser, common_path);

    let is: Vec<usize> = (1..=PRECOMPUTED_PARTY_NUMBER).map(|i| i).collect();
    let mut bytes: HashMap<usize, Vec<Vec<u8>>> = is
        .par_iter()
        .map(|i| {
            let js: Vec<usize> = (1..=PRECOMPUTED_PARTY_NUMBER).map(|j| j).collect();
            let mut bytes: HashMap<usize, Vec<u8>> = js
                .par_iter()
                .map(|j| {
                    println!("generating {} payers & {} payees", i, j);
                    let node_params = VerifierParams::create(*i, *j, Some(TREE_DEPTH)).unwrap();
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
    specials_path.push("transfer-vk-specials.bin");
    save_to_file(&specials_ser, specials_path);
}

// cargo run --release --features="gen no_vk" --bin gen-params abar-to-bar "./parameters"
fn gen_abar_to_bar_vk(mut path: PathBuf) {
    println!("Generating the verifying key for ABAR TO BAR ...");

    let user_params = ProverParams::abar_to_bar_params(TREE_DEPTH).unwrap();
    let node_params = VerifierParams::from(user_params).shrink().unwrap();
    let bytes = bincode::serialize(&node_params).unwrap();
    path.push("abar-to-bar-vk.bin");
    save_to_file(&bytes, path);

    let start = std::time::Instant::now();
    let _n: VerifierParams = bincode::deserialize(&bytes).unwrap();
    let elapsed = start.elapsed();
    println!("Deserialize time: {:.2?}", elapsed);
}

// cargo run --release --features="gen no_vk" --bin gen-params bar-to-abar "./parameters"
fn gen_bar_to_abar_vk(mut path: PathBuf) {
    println!("Generating the verifying key for BAR TO ABAR ...");

    let user_params = ProverParams::bar_to_abar_params().unwrap();
    let node_params = VerifierParams::from(user_params).shrink().unwrap();
    let bytes = bincode::serialize(&node_params).unwrap();
    path.push("bar-to-abar-vk.bin");
    save_to_file(&bytes, path);

    let start = std::time::Instant::now();
    let _n: VerifierParams = bincode::deserialize(&bytes).unwrap();
    let elapsed = start.elapsed();
    println!("Deserialize time: {:.2?}", elapsed);
}

// cargo run --release --features="gen no_vk" --bin gen-params ar-to-abar "./parameters"
fn gen_ar_to_abar_vk(mut path: PathBuf) {
    println!("Generating the verifying key for AR TO ABAR ...");

    let user_params = ProverParams::ar_to_abar_params().unwrap();
    let node_params = VerifierParams::from(user_params).shrink().unwrap();
    let bytes = bincode::serialize(&node_params).unwrap();
    path.push("ar-to-abar-vk.bin");
    save_to_file(&bytes, path);

    let start = std::time::Instant::now();
    let _n: VerifierParams = bincode::deserialize(&bytes).unwrap();
    let elapsed = start.elapsed();
    println!("Deserialize time: {:.2?}", elapsed);
}

// cargo run --release --features="gen no_vk" --bin gen-params abar-to-ar "./parameters"
fn gen_abar_to_ar_vk(mut path: PathBuf) {
    println!("Generating the verifying key for ABAR TO AR ...");

    let user_params = ProverParams::abar_to_ar_params(TREE_DEPTH).unwrap();
    let node_params = VerifierParams::from(user_params).shrink().unwrap();
    let bytes = bincode::serialize(&node_params).unwrap();
    path.push("abar-to-ar-vk.bin");
    save_to_file(&bytes, path);

    let start = std::time::Instant::now();
    let _n: VerifierParams = bincode::deserialize(&bytes).unwrap();
    let elapsed = start.elapsed();
    println!("Deserialize time: {:.2?}", elapsed);
}

// cargo run --release --features="gen no_urs no_srs no_vk" --bin gen-params bulletproof "./parameters"
fn gen_bulletproof_urs(mut path: PathBuf) {
    println!("Generating Bulletproof uniform reference string ...");

    let pp = BulletproofParams::default();
    let bytes = bincode::serialize(&pp).unwrap();
    path.push("bulletproof-urs.bin");
    save_to_file(&bytes, path);

    let start = std::time::Instant::now();
    let _n: BulletproofParams = bincode::deserialize(&bytes).unwrap();
    let elapsed = start.elapsed();
    println!("Deserialize time: {:.2?}", elapsed);
}
