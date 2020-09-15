//The Public Setup needed for Proofs
use crate::anon_xfr::circuits::{build_single_spend_cs, AXfrWitness, TurboPlonkCS, TREE_DEPTH};
use crate::anon_xfr::structs::AXfrSecKey;
use algebra::groups::Scalar;
use algebra::jubjub::JubjubScalar;
use bulletproofs::BulletproofGens;
use crypto::ristretto_pedersen::RistrettoPedersenGens;
use poly_iops::commitments::kzg_poly_com::{KZGCommitmentScheme, KZGCommitmentSchemeBLS};
use poly_iops::plonk::plonk_setup::{preprocess_prover, ProverParams, VerifierParams};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

//Shared by all members of the ledger
pub struct PublicParams {
  pub bp_gens: BulletproofGens,
  pub bp_circuit_gens: BulletproofGens,
  pub pc_gens: RistrettoPedersenGens,
  pub range_proof_bits: usize,
}

pub struct UserParams {
  pub bp_params: PublicParams,
  pub pcs: KZGCommitmentSchemeBLS,
  pub cs: TurboPlonkCS,
  pub prover_params: ProverParams<KZGCommitmentSchemeBLS>,
}

pub struct NodeParams {
  pub bp_params: PublicParams,
  pub pcs: KZGCommitmentSchemeBLS,
  pub cs: TurboPlonkCS,
  pub verifier_params: VerifierParams<KZGCommitmentSchemeBLS>,
}

pub const BULLET_PROOF_RANGE: usize = 32;

pub const MAX_PARTY_NUMBER: usize = 128;

const COMMON_SEED: [u8; 32] = [0u8; 32];

#[allow(clippy::new_without_default)]
impl PublicParams {
  pub fn new() -> PublicParams {
    //Create a new BulletproofGens generators
    let range_generators = BulletproofGens::new(BULLET_PROOF_RANGE, MAX_PARTY_NUMBER);
    let circuit_generators = BulletproofGens::new(256, 1);
    // Pedersen commitment parameters
    let pc_gens = RistrettoPedersenGens::default();

    PublicParams { bp_gens: range_generators,
                   bp_circuit_gens: circuit_generators,
                   pc_gens,
                   range_proof_bits: BULLET_PROOF_RANGE }
  }

  /// Has no effect if new_size.next_power_of_two() is less or equal than current capacity
  pub fn increase_circuit_gens(&mut self, new_size: usize) {
    self.bp_circuit_gens
        .increase_capacity(new_size.next_power_of_two());
  }
}

impl Default for PublicParams {
  fn default() -> Self {
    PublicParams::new()
  }
}

impl UserParams {
  pub fn new(tree_depth: Option<usize>, kzg_degree: usize) -> UserParams {
    let fake_key = AXfrSecKey(JubjubScalar::from_u32(0));
    let cs = match tree_depth {
      Some(depth) => build_single_spend_cs(AXfrWitness::fake(&fake_key, depth)),
      None => build_single_spend_cs(AXfrWitness::fake(&fake_key, TREE_DEPTH)),
    };
    let pcs = KZGCommitmentScheme::new(kzg_degree, &mut ChaChaRng::from_seed([0u8; 32]));
    let prover_params = preprocess_prover(&cs, &pcs, COMMON_SEED).unwrap();
    UserParams { bp_params: PublicParams::new(),
                 pcs,
                 cs,
                 prover_params }
  }
}

impl Default for UserParams {
  fn default() -> Self {
    Self::new(None, TREE_DEPTH)
  }
}

impl NodeParams {
  pub fn new(tree_depth: Option<usize>, kzg_degree: usize) -> NodeParams {
    let user_params = UserParams::new(tree_depth, kzg_degree);
    Self::from(user_params)
  }
}

impl From<UserParams> for NodeParams {
  fn from(params: UserParams) -> Self {
    NodeParams { bp_params: params.bp_params,
                 pcs: params.pcs,
                 cs: params.cs,
                 verifier_params: params.prover_params.get_verifier_params() }
  }
}
