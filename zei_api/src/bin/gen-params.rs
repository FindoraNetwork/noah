use bulletproofs::BulletproofGens;
use poly_iops::commitments::kzg_poly_com::KZGCommitmentSchemeBLS;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::path::PathBuf;
use structopt::StructOpt;
use utils::errors::ZeiError;
use utils::save_to_file;
use zei::setup::{PublicParams, UserParams};

#[derive(StructOpt, Debug)]
#[structopt(about = "Zei tool to handle public zkp-parameters.",
            rename_all = "kebab-case")]
enum Actions {
  User {
    tree_depth: usize,
    kzg_degree: usize,
    bp_num_gens: usize,
    out_filename: PathBuf,
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

#[allow(dead_code)]
fn main() {
  use Actions::*;
  let action = Actions::from_args();
  match action {
    User { tree_depth,
           kzg_degree,
           bp_num_gens,
           out_filename, } => {
      gen_user_params(tree_depth, kzg_degree, bp_num_gens, out_filename).unwrap();
    }
    BP { gens_capacity,
         party_capacity,
         out_filename, } => {
      gen_params_bp(gens_capacity, party_capacity, out_filename);
    }
    KZG { size, out_filename } => {
      gen_params_kzg(size, out_filename);
    }

    PublicParams { out_filename } => gen_public_params(out_filename),
  };
}

fn gen_user_params(tree_depth: usize,
                   kzg_degree: usize,
                   bp_num_gens: usize,
                   out_filename: PathBuf)
                   -> Result<(), ZeiError> {
  println!("Generating 'User Parameters' with tree depth={} and KZG degree={} ...",
           tree_depth, kzg_degree);

  let tree_dept_option = if tree_depth == 0 {
    None
  } else {
    Some(tree_depth)
  };

  let user_params = UserParams::new(tree_dept_option, kzg_degree, bp_num_gens)?;
  let user_params_ser = bincode::serialize(&user_params).unwrap();
  save_to_file(&user_params_ser, out_filename);
  Ok(())
}

fn gen_params_bp(gens_capacity: usize, party_capacity: usize, out_filename: PathBuf) {
  println!("Generating BP parameters of size {} ...", gens_capacity);
  let bpgens = BulletproofGens::new(gens_capacity, party_capacity);
  let bpgens_ser = bincode::serialize(&bpgens).unwrap();
  save_to_file(&bpgens_ser, out_filename);
}

fn gen_params_kzg(size: usize, out_filename: PathBuf) {
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
