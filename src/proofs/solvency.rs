//Proof of Solvency
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use bulletproofs::{RangeProof};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use curve25519_dalek::traits::Identity;
use crate::setup::BULLET_PROOF_RANGE;
use crate::errors::ZeiError;

pub fn prove_solvency(
	assets_openings: &[(u64, Scalar)],
	liabilities_openings: &[(u64, Scalar)]) -> Result<RangeProof, ZeiError>
{
	// Common Reference String
    let mut transcript = Transcript::new(b"Zei Range Proof");
	let params = crate::setup::PublicParams::new();
    //let pc_gens = PedersenGens::default();
    //let bp_gens = BulletproofGens::new(BULLET_PROOF_RANGE, 1);

	// Calculate Amount
	let mut assets_amount : u64 = 0;
	let mut assets_blind : Scalar = Scalar::zero();

	for record in assets_openings {
		assets_amount += record.0;
		assets_blind += record.1;
	}

	// Calculate liabilities
	let mut liabilities_amount : u64 = 0;
	let mut liabilities_blind : Scalar = Scalar::zero();

	for records in liabilities_openings {
		liabilities_amount += records.0;
		liabilities_blind += records.1;
	}

	if assets_amount < liabilities_amount {
		return Err(ZeiError::RangeProofProveError);
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
	assets_commitments: &[CompressedRistretto],
	liabilities_commitments: &[CompressedRistretto],
	proof: RangeProof) -> Result<(), ZeiError> {

	//Common Reference String
	let mut transcript = Transcript::new(b"Zei Range Proof");
	let params = crate::setup::PublicParams::new();
	let mut assets_total_comm: RistrettoPoint = RistrettoPoint::identity();

	for c in assets_commitments.iter() {
		assets_total_comm += c.decompress().ok_or(ZeiError::DecompressElementError)?;
	}

	let mut liabilities_total_comm: RistrettoPoint = RistrettoPoint::identity();

	for c in liabilities_commitments {
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
	use bulletproofs::PedersenGens;
	use curve25519_dalek::scalar::Scalar;
	use rand_chacha::ChaChaRng;
	use rand::SeedableRng;
	use crate::errors::ZeiError;
	use curve25519_dalek::ristretto::CompressedRistretto;

	#[test]
	fn solvency(){
		let mut prng = ChaChaRng::from_seed([10u8;32]);
		let pc_gens = PedersenGens::default();
		let asset1 = 10u64;
		let lia1=10u64;

		let b1 = Scalar::random(&mut prng);
		let b2 = Scalar::random(&mut prng);

		let asset_com = pc_gens.commit(Scalar::from(asset1), b1);
		let lia1_com = pc_gens.commit(Scalar::from(lia1), b2);

		let proof = super::prove_solvency(
			&[(asset1, b1)],
			&[(lia1, b2)]).unwrap();

		assert_eq!(Ok(()), super::verify_solvency(
			&[asset_com.compress()],
			&[lia1_com.compress()],
			proof));

		let lia2=1u64;
		let b3 = Scalar::random(&mut prng);
		let lia2_com = pc_gens.commit(Scalar::from(lia2), b3);


		let proof = super::prove_solvency(
			&[(asset1, b1)],
			&[(lia1, b2)]).unwrap();

		assert_eq!(Err(ZeiError::RangeProofVerifyError), super::verify_solvency(
			&[asset_com.compress()],
			&[lia1_com.compress(), lia2_com.compress()],
			proof));

		assert_eq!(ZeiError::RangeProofProveError,
				   super::prove_solvency(
					   &[(asset1, b1)],
					   &[(lia1, b2), (lia2, b3)]).err().unwrap());

		let assets = [10u64, 10u64, 10u64, 10u64, 10u64];
		let lia = [1u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 5u64, 10u64];

		let asset_openings: Vec<(u64, Scalar)> = assets.iter().map(|x| (*x, Scalar::random(&mut prng))).collect();
		let lia_openings: Vec<(u64, Scalar)> = lia.iter().map(|x| (*x, Scalar::random(&mut prng))).collect();

		let proof = super::prove_solvency(
			asset_openings.as_slice(),
			lia_openings.as_slice()).unwrap();

		let asset_com: Vec<CompressedRistretto> = asset_openings.iter().
			map(|(x,binding)| pc_gens.commit(
				Scalar::from(*x),
				*binding).compress()).collect();

		let lia_com: Vec<CompressedRistretto> = lia_openings.iter().
			map(|(x,binding)| pc_gens.commit(
				Scalar::from(*x),
				*binding).compress()).collect();

		assert_eq!(Ok(()), super::verify_solvency(
			asset_com.as_slice(),
			lia_com.as_slice(),
			proof));

	}
}
