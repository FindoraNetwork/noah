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

//gens_capacity ->
//The maximum number of usable generators for each party.
//Is the number of generators to precompute for each party.
//For rangeproofs, it is sufficient to pass 64, the maximum bitsize of the rangeproofs.
// bitsize: BULLET_PROOF_RANGE-bit (0, 2^BULLET_PROOF_RANGE-1)
//
//party_capacity ->
//Number of values or parties
//is the maximum number of parties that can produce an aggregated proof.
#[allow(clippy::new_without_default)]
impl PublicParams {
  //helper function todo public setup
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

  pub fn set_circuit_gens(&mut self, size: usize) {
    self.bp_circuit_gens = BulletproofGens::new(size.next_power_of_two(), 1);
  }
}
