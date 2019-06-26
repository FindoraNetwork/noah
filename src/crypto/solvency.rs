use bulletproofs_yoloproof::r1cs::{R1CSProof, Prover, Verifier, Variable};
use bulletproofs_yoloproof::{PedersenGens, BulletproofGens};
use crate::crypto::bp_circuits;
use crate::errors::ZeiError;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use std::collections::HashMap;
use curve25519_dalek::ristretto::CompressedRistretto;


pub fn prove_solvency(
	assets: &[(Scalar, Scalar)],
	assets_blinds: &[(Scalar, Scalar)],
	liabilities: &[(Scalar, Scalar)],
	liabilities_blinds: &[(Scalar, Scalar)],
	rates_table: &HashMap<[u8;32], Scalar>,
) -> Result<R1CSProof, ZeiError>
{
	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(1000, 1);
	let mut transcript = Transcript::new(b"SolvencyProof");
	let mut prover = Prover::new(&pc_gens, &mut transcript);

	let mut asset_vars = Vec::with_capacity(assets.len());
	for (asset, blind) in assets.iter().zip(assets_blinds){
		let (_, asset_amount_var) = prover.commit(asset.0, blind.0); //amount
		let (_, asset_type_var) = prover.commit(asset.1, blind.1); //asset type

		asset_vars.push((asset_amount_var, asset_type_var));
	}

	let mut liabilities_vars = Vec::with_capacity(liabilities.len());
	for (lia, blind) in liabilities.iter().zip(liabilities_blinds){
		let (_, lia_amount_var) = prover.commit(lia.0, blind.0); //amount
		let (_, lia_type_var) = prover.commit(lia.1, blind.1); //asset type

		liabilities_vars.push((lia_amount_var, lia_type_var));
	}

	bp_circuits::solvency::solvency(
		&mut prover,
		&asset_vars[..],
		Some(assets),
		&liabilities_vars[..],
		Some(liabilities),
		rates_table,
	).map_err(|_| ZeiError::SolvencyProveError)?;

	prover.prove(&bp_gens).map_err(|_| ZeiError::SolvencyProveError)
}

pub fn verify_solvency(
	assets: &[(CompressedRistretto, CompressedRistretto)],
	liabilities: &[(CompressedRistretto, CompressedRistretto)],
	rates_table: &HashMap<[u8;32], Scalar>,
	proof: &R1CSProof
) -> Result<(), ZeiError>{
	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(1000, 1);

	let mut transcript = Transcript::new(b"SolvencyProof");
	let mut verifier = Verifier::new(&mut transcript);

	let asset_vars: Vec<(Variable, Variable)> = assets.iter().map(
		|(a,t)|{
			(verifier.commit(*a), verifier.commit(*t))
		}).collect();

	let liabilities_vars: Vec<(Variable, Variable)> = liabilities.iter().map(
		|(a,t)|{
			(verifier.commit(*a), verifier.commit(*t))
		}).collect();

	bp_circuits::solvency::solvency(
		&mut verifier,
		&asset_vars[..],
		None,
		&liabilities_vars[..],
		None,
		rates_table,
	).map_err(|_| ZeiError::SolvencyVerificationError)?;

	verifier.verify(proof, &pc_gens, &bp_gens).map_err(|_| ZeiError::SolvencyVerificationError)
}
