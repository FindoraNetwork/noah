//The Public Setup needed for Proofs

use bulletproofs::BulletproofGens;

//Shared by all members of the ledger
pub struct PublicParams {
    bp_gens: BulletproofGens,
    range_proof_bits: usize,
}


//gens_capacity -> 
//The maximum number of usable generators for each party.
//Is the number of generators to precompute for each party. 
//For rangeproofs, it is sufficient to pass 64, the maximum bitsize of the rangeproofs.
// bitsize: 32-bit (0, 2^32-1)
//
//party_capacity ->
//Number of values or parties
//is the maximum number of parties that can produce an aggregated proof.

//helper function todo public setup
pub fn setup(gens_capacity: usize, party_capacity: usize) -> PublicParams {
    //Create a new BulletproofGens object
    let generators = BulletproofGens::new(gens_capacity, party_capacity);

    return PublicParams {
        bp_gens: generators,
        range_proof_bits: gens_capacity
    };
}