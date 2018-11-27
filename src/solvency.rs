//Proof of Solvency

use crate::account::Account;
use curve25519_dalek::ristretto::RistrettoPoint;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use curve25519_dalek::traits::Identity;

pub fn proove_solvency(assets: Vec<Account>, liabilities: Vec<Account>) -> RangeProof {
	//Common Reference String
    let mut transcript = Transcript::new(b"Zei Range Proof");
    //def pederson from lib with Common Reference String
    let pc_gens = PedersenGens::default();
    //32bit range for now & one prover
    let bp_gens = BulletproofGens::new(32, 1);

	//Calculate Amount
	let mut assets_ammount : u32 = 0;
	let mut assets_blind : Scalar = Scalar::zero();

	for a in assets {
		assets_ammount += a.balance;
		assets_blind += a.opening;
	}

	//Calculate Liabilities
	let mut liabilities_ammount : u32 = 0;
	let mut liabilities_blind : Scalar = Scalar::zero();

	for a in liabilities {
		liabilities_ammount += a.balance;
		liabilities_blind += a.opening;
	}

	let proof_balance = assets_ammount - liabilities_ammount;
	let proof_blind = assets_blind - liabilities_blind;
	
    // Create a 32-bit rangeproof.
    let (proof, _) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        proof_balance as u64,
        &proof_blind,
        32,
    ).expect("A real program could handle errors");

	return proof;

}

pub fn verify_solvency(commitments_assets: Vec<RistrettoPoint>, commitments_liabilities: Vec<RistrettoPoint>, proof: RangeProof) -> bool {

	let mut assets_total_comm: RistrettoPoint = RistrettoPoint::identity();

	for c in commitments_assets {
		assets_total_comm += c;
	}

	let mut liabilities_total_comm: RistrettoPoint = RistrettoPoint::identity(); 

	for c in commitments_liabilities {
		liabilities_total_comm += c;
	}

	let proof_comm: RistrettoPoint = assets_total_comm - liabilities_total_comm;

	//Common Reference String
    let mut transcript = Transcript::new(b"Zei Range Proof");
    //def pederson from lib with Common Reference String
    let pc_gens = PedersenGens::default();
    //32bit range for now & one prover
    let bp_gens = BulletproofGens::new(32, 1);

	let veriy_t = RangeProof::verify_single(
		&proof,
		&bp_gens,
        &pc_gens,
        &mut transcript,
		&proof_comm.compress(),
		32
	);

	//check rangeproof
    if veriy_t.is_ok() {
        return true;
    } else {
        return false;
    }


}



#[cfg(test)]
mod test {


}