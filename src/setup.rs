//The Public Setup needed for Proofs

use bulletproofs::{PedersenGens, BulletproofGens};
use merlin::Transcript;

//Shared by all members of the ledger
pub struct PublicParams {
    pub bp_gens: BulletproofGens,
    pub pc_gens: PedersenGens,
    pub range_proof_bits: usize,
    pub transcript: Transcript,
}

pub const BULLET_PROOF_RANGE: usize = 32;
pub const MAX_PARTY_NUMBER: usize = 32;
pub const BULLET_PROOF_CLOAK_GENS: usize = 1000;

//gens_capacity ->
//The maximum number of usable generators for each party.
//Is the number of generators to precompute for each party.
//For rangeproofs, it is sufficient to pass 64, the maximum bitsize of the rangeproofs.
// bitsize: BULLET_PROOF_RANGE-bit (0, 2^BULLET_PROOF_RANGE-1)
//
//party_capacity ->
//Number of values or parties
//is the maximum number of parties that can produce an aggregated proof.

impl PublicParams {
    //helper function todo public setup
    pub fn new() -> PublicParams {
        //public params with default BULLET_PROOF_RANGE bit range and also n provers
        //Create a new BulletproofGens object
        let generators = BulletproofGens::new(BULLET_PROOF_RANGE, 32);
        //def pederson from lib with Common Reference String
        let pc_gens = PedersenGens::default();
        //Common Reference String
        let transcript = Transcript::new(b"Zei Range Proof");


        PublicParams {
            bp_gens: generators,
            pc_gens,
            range_proof_bits: BULLET_PROOF_RANGE,
            transcript
        }
    }
}
