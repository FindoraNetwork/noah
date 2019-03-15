//Proof of Solvency
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use bulletproofs::{RangeProof};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use curve25519_dalek::traits::Identity;
use crate::setup::BULLET_PROOF_RANGE;
use crate::errors::ZeiError;

pub fn prove_solvency(
	assets: Vec<(u64, Scalar)>,
	liabilities: Vec<(u64, Scalar)>) -> Result<RangeProof, ZeiError>
{
	// Common Reference String
    let mut transcript = Transcript::new(b"Zei Range Proof");
	let params = crate::setup::PublicParams::new();
    //let pc_gens = PedersenGens::default();
    //let bp_gens = BulletproofGens::new(BULLET_PROOF_RANGE, 1);

	// Calculate Amount
	let mut assets_amount : u64 = 0;
	let mut assets_blind : Scalar = Scalar::zero();

	for record in assets {
		assets_amount += record.0;
		assets_blind += record.1;
	}

	// Calculate liabilities
	let mut liabilities_amount : u64 = 0;
	let mut liabilities_blind : Scalar = Scalar::zero();

	for records in liabilities {
		liabilities_amount += records.0;
		liabilities_blind += records.1;
	}

	let proof_balance = assets_amount - liabilities_amount;
	let proof_blind = assets_blind - liabilities_blind;

    // Create a 32-bit rangeproof.
    let (proof,_) = RangeProof::prove_single(
        &params.bp_gens,
        &params.pc_gens,
        &mut transcript,
        u64::from(proof_balance),
        &proof_blind,
		BULLET_PROOF_RANGE).map_err(|_| ZeiError::RangeProofProveError)?;

	Ok(proof)
}

pub fn verify_solvency(
	blind_assets: Vec<CompressedRistretto>,
	blind_liabilities: Vec<CompressedRistretto>,
	proof: RangeProof) -> Result<(), ZeiError> {

	//Common Reference String
	let mut transcript = Transcript::new(b"Zei Range Proof");
	let params = crate::setup::PublicParams::new();
	let mut assets_total_comm: RistrettoPoint = RistrettoPoint::identity();

	for c in blind_assets.iter() {
		assets_total_comm += c.decompress().ok_or(ZeiError::DecompressElementError)?;
	}

	let mut liabilities_total_comm: RistrettoPoint = RistrettoPoint::identity();

	for c in blind_liabilities {
		liabilities_total_comm += c.decompress().ok_or(ZeiError::DecompressElementError)?;
	}

	let proof_comm: RistrettoPoint = assets_total_comm - liabilities_total_comm;

	RangeProof::verify_single(
		&proof,
		&params.bp_gens,
        &params.pc_gens,
        &mut transcript,
		&proof_comm.compress(),
		BULLET_PROOF_RANGE
	).map_err(|_| ZeiError::RangeProofVerifyError)
}



#[cfg(test)]
mod test {

}
