use bulletproofs_yoloproof::r1cs::{R1CSProof, Prover, Verifier, Variable, ConstraintSystem};
use bulletproofs_yoloproof::{PedersenGens, BulletproofGens};
use crate::crypto::bp_circuits;
use crate::errors::ZeiError;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use std::collections::HashMap;
use curve25519_dalek::ristretto::CompressedRistretto;


pub fn prove_solvency(
	hidden_assets: &[(Scalar, Scalar)],
	assets_blinds: &[(Scalar, Scalar)],
	public_assets: &[(Scalar, Scalar)],
	hidden_liabilities: &[(Scalar, Scalar)],
	liabilities_blinds: &[(Scalar, Scalar)],
	public_liabilities: &[(Scalar, Scalar)],
	rates_table: &HashMap<[u8;32], Scalar>,
) -> Result<R1CSProof, ZeiError>
{
	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(1000, 1);
	let mut transcript = Transcript::new(b"SolvencyProof");
	let mut prover = Prover::new(&pc_gens, &mut transcript);

	let mut asset_vars = Vec::with_capacity(hidden_assets.len());
	for (asset, blind) in hidden_assets.iter().zip(assets_blinds){
		let (_, asset_amount_var) = prover.commit(asset.0, blind.0); //amount
		let (_, asset_type_var) = prover.commit(asset.1, blind.1); //asset type

		asset_vars.push((asset_amount_var, asset_type_var));
	}

	let mut liabilities_vars = Vec::with_capacity(hidden_liabilities.len());
	for (lia, blind) in hidden_liabilities.iter().zip(liabilities_blinds){
		let (_, lia_amount_var) = prover.commit(lia.0, blind.0); //amount
		let (_, lia_type_var) = prover.commit(lia.1, blind.1); //asset type

		liabilities_vars.push((lia_amount_var, lia_type_var));
	}

	let mut public_asset_sum = Scalar::zero();
	for (amount, asset_type) in public_assets{
		let rate = rates_table.get(asset_type.as_bytes()).ok_or(ZeiError::SolvencyProveError)?;
		public_asset_sum = public_asset_sum + rate * amount;
	}

	let mut public_liability_sum = Scalar::zero();
	for (amount, asset_type) in public_liabilities{
		let rate = rates_table.get(asset_type.as_bytes()).ok_or(ZeiError::SolvencyProveError)?;
		public_liability_sum = public_liability_sum + rate * amount;
	}

	bp_circuits::solvency::solvency(
		&mut prover,
		&asset_vars[..],
		Some(hidden_assets),
		public_asset_sum,
		&liabilities_vars[..],
		Some(hidden_liabilities),
		public_liability_sum,
		rates_table,
	).map_err(|_| ZeiError::SolvencyProveError)?;

	prover.prove(&bp_gens).map_err(|_| ZeiError::SolvencyProveError)
}

pub fn verify_solvency(
	hidden_assets: &[(CompressedRistretto, CompressedRistretto)],
	public_assets: &[(Scalar, Scalar)],
	hidden_liabilities: &[(CompressedRistretto, CompressedRistretto)],
	public_liabilities: &[(Scalar, Scalar)],
	rates_table: &HashMap<[u8;32], Scalar>,
	proof: &R1CSProof
) -> Result<(), ZeiError>{
	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(1000, 1);

	let mut transcript = Transcript::new(b"SolvencyProof");
	let mut verifier = Verifier::new(&mut transcript);

	let mut asset_vars: Vec<(Variable, Variable)> = hidden_assets.iter().map(
		|(a,t)|{
			(verifier.commit(*a), verifier.commit(*t))
		}).collect();

	for (amount, asset_type) in public_assets{
		let amount_var = verifier.allocate(Some(*amount)).map_err(|_| ZeiError::SolvencyVerificationError)?;
		let asset_type_var = verifier.allocate(Some(*asset_type)).map_err(|_| ZeiError::SolvencyProveError)?;
		asset_vars.push((amount_var, asset_type_var));
	}

	let mut liabilities_vars: Vec<(Variable, Variable)> = hidden_liabilities.iter().map(
		|(a,t)|{
			(verifier.commit(*a), verifier.commit(*t))
		}).collect();

	for (amount, asset_type) in public_liabilities{
		let amount_var = verifier.allocate(Some(*amount)).map_err(|_| ZeiError::SolvencyProveError)?;
		let asset_type_var = verifier.allocate(Some(*asset_type)).map_err(|_| ZeiError::SolvencyProveError)?;
		liabilities_vars.push((amount_var, asset_type_var));
	}

	let mut public_asset_sum = Scalar::zero();
	for (amount, asset_type) in public_assets{
		let rate = rates_table.get(asset_type.as_bytes()).ok_or(ZeiError::SolvencyProveError)?;
		public_asset_sum = public_asset_sum + rate * amount;
	}

	let mut public_liability_sum = Scalar::zero();
	for (amount, asset_type) in public_liabilities{
		let rate = rates_table.get(asset_type.as_bytes()).ok_or(ZeiError::SolvencyProveError)?;
		public_liability_sum = public_liability_sum + rate * amount;
	}

	bp_circuits::solvency::solvency(
		&mut verifier,
		&asset_vars[..],
		None,
		public_asset_sum,
		&liabilities_vars[..],
		None,
		public_liability_sum,
		rates_table,
	).map_err(|_| ZeiError::SolvencyVerificationError)?;

	verifier.verify(proof, &pc_gens, &bp_gens).map_err(|_| ZeiError::SolvencyVerificationError)
}
