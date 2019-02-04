//Proof of Solvency

use crate::account::Account;
use curve25519_dalek::ristretto::RistrettoPoint;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use curve25519_dalek::traits::Identity;
use crate::setup::BULLET_PROOF_RANGE;

pub fn prove_solvency(assets: Vec<Account>, liabilities: Vec<Account>, asset_id: &str) -> RangeProof {
	// Common Reference String
    let mut transcript = Transcript::new(b"Zei Range Proof");
    // def pederson from lib with Common Reference String
    let pc_gens = PedersenGens::default();
    // 32bit range for now & one prover
    let bp_gens = BulletproofGens::new(BULLET_PROOF_RANGE, 1);

	// Calculate Amount
	let mut assets_amount : u64 = 0;
	let mut assets_blind : Scalar = Scalar::zero();

	for a in assets {
		assets_amount += a.balances[asset_id].balance;
		assets_blind += a.balances[asset_id].balance_blinding;
	}

	// Calculate liabilities
	let mut liabilities_amount : u64 = 0;
	let mut liabilities_blind : Scalar = Scalar::zero();

	for a in liabilities {
		liabilities_amount += a.balances[asset_id].balance;
		liabilities_blind += a.balances[asset_id].balance_blinding;
	}

	let proof_balance = assets_amount - liabilities_amount;
	let proof_blind = assets_blind - liabilities_blind;

    // Create a 32-bit rangeproof.
    let (proof, _) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        u64::from(proof_balance),
        &proof_blind,
		BULLET_PROOF_RANGE,
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
    let bp_gens = BulletproofGens::new(BULLET_PROOF_RANGE, 1);

	let verify_t = RangeProof::verify_single(
		&proof,
		&bp_gens,
        &pc_gens,
        &mut transcript,
		&proof_comm.compress(),
		BULLET_PROOF_RANGE
	);

	//check rangeproof
    return verify_t.is_ok()
}



#[cfg(test)]
mod test {

}
