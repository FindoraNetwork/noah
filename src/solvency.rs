//Proof of Solvency

/*
Take two list of accounts, one is accounts that hold assets & the other is the liabilities
Each Account has associated pedersen commitment that is blinding the account balance and the randomness (i.e secret key) that authorizes spending.
We must create a proof of solvency showing that the assets amount is greater or equal to the liabilities. This proof is a rangeproof. 
To create our range proof we need a commitment (Cr), an amount (Ar), and a blinding scalar (Br).
The rangeproof that acts as our proof of solvency is derived such that:

	5a. Ar = total sum of balance in assets accounts (plaintext) minus liabilities accounts (plaintext)    

	5b. Br = 


	Assumptions:

*/

// use account::Account;
// use bulletproofs::RangeProof;


// pub fn proove_solvency(assets: Vec<Account>, liabilities: Vec<Account>) -> RangeProof {
//     // Create a 32-bit rangeproof.
//     // let (proof, committed_value) = RangeProof::prove_single(
//     //     &bp_gens,
//     //     &pc_gens,
//     //     &mut prover_transcript,
//     //     secret_value,
//     //     &blinding,
//     //     32,
//     // ).expect("A real program could handle errors");


// }