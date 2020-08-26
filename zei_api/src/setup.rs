//The Public Setup needed for Proofs
use bulletproofs::{BulletproofGens, PedersenGens};

//Shared by all members of the ledger
pub struct PublicParams {
  pub bp_gens: BulletproofGens,
  pub bp_circuit_gens: BulletproofGens,
  pub pc_gens: PedersenGens,
  pub range_proof_bits: usize,
}

pub const BULLET_PROOF_RANGE: usize = 32;

pub const MAX_PARTY_NUMBER: usize = 128;

#[allow(clippy::new_without_default)]
impl PublicParams {
  pub fn new() -> PublicParams {
    //Create a new BulletproofGens generators
    let range_generators = BulletproofGens::new(BULLET_PROOF_RANGE, MAX_PARTY_NUMBER);
    let circuit_generators = BulletproofGens::new(256, 1);
    // Pedersen commitment parameters
    let pc_gens = PedersenGens::default();

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
