use crate::crypto::bp_circuits;
use crate::errors::ZeiError;
use bulletproofs_yoloproof::r1cs::{
  ConstraintSystem, Prover, R1CSError, R1CSProof, Variable, Verifier,
};
use bulletproofs_yoloproof::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use linear_map::LinearMap;
use merlin::Transcript;

/// I produce a proof of solvency for a set of assets vs liabilities for potentially different
/// asset types using a conversion table to a common type.
/// Values are given as pairs (amount, asset_type).
/// Values can be hidden or public to the verifier. For hidden values, prover needs to provide
/// blinding factors for the corresponding Pedersen commitments.
/// Asset type cannot be `Scalar::zero()`
/// Returns proof in case of success and ZeiError::SolvencyProveError in case proof cannot be
/// computed.
/// # Example
/// ```
/// use bulletproofs_yoloproof::{BulletproofGens, PedersenGens};
/// use rand_chacha::ChaChaRng;
/// use rand::SeedableRng;
/// use curve25519_dalek::scalar::Scalar;
/// use zei::crypto::solvency::{prove_solvency,verify_solvency};
/// let pc_gens = PedersenGens::default();
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// use linear_map::LinearMap;
/// use zei::errors::ZeiError;
///
/// let mut rates = LinearMap::new();
///    rates.insert(Scalar::from(1u8), Scalar::from(1u8));
///    rates.insert(Scalar::from(2u8), Scalar::from(2u8));
///    rates.insert(Scalar::from(3u8), Scalar::from(3u8));
///
/// let hidden_liability_set = [
///			(Scalar::from(10u8), Scalar::from(1u8)), // 10
///			(Scalar::from(20u8), Scalar::from(2u8)), // 40
///		];
///
/// let hidden_asset_set = [
///			(Scalar::from(10u8), Scalar::from(1u8)), // 10
///			(Scalar::from(20u8), Scalar::from(2u8)), // 40
///			(Scalar::from(30u8), Scalar::from(2u8)), // 60
///		];
///
/// let mut assets_blinds = vec![
///         (Scalar::random(&mut prng), Scalar::random(&mut prng)),
///         (Scalar::random(&mut prng), Scalar::random(&mut prng)),
///         (Scalar::random(&mut prng), Scalar::random(&mut prng))];
///
///
/// let hidden_asset_set = hidden_asset_set;
/// let hidden_liability_set = hidden_liability_set;
/// let mut liabilities_blinds = vec![
///         (Scalar::random(&mut prng), Scalar::random(&mut prng)),
///         (Scalar::random(&mut prng), Scalar::random(&mut prng))];
///
/// let proof = prove_solvency(   &hidden_asset_set,
///                               assets_blinds.as_slice(),
///                               &[],
///                               &hidden_liability_set,
///                               liabilities_blinds.as_slice(),
///                               &[],
///                               &rates);
///
/// ```

pub fn prove_solvency(hidden_asset_set: &[(Scalar, Scalar)], // amount and type of hidden assets
                      asset_set_blinds: &[(Scalar, Scalar)], // blindings for amount and type of hidden assets
                      public_asset_set: &[(Scalar, Scalar)], // amount and type of public/known assets
                      hidden_liability_set: &[(Scalar, Scalar)], // amount and type of hidden liabilities
                      liability_set_blinds: &[(Scalar, Scalar)], // blindings for amount and type in hidden liabilities
                      public_liability_set: &[(Scalar, Scalar)], // amount and type of public/known assets
                      conversion_rates: &LinearMap<Scalar, Scalar>  // exchange rates for asset types
) -> Result<R1CSProof, ZeiError> {
  let pc_gens = PedersenGens::default();
  let mut transcript = Transcript::new(b"SolvencyProof");
  let mut prover = Prover::new(&pc_gens, &mut transcript);

  // compute assets circuit variables
  let mut asset_vars = Vec::with_capacity(hidden_asset_set.len());
  for (asset, blind) in hidden_asset_set.iter().zip(asset_set_blinds) {
    let (_, asset_amount_var) = prover.commit(asset.0, blind.0); //amount
    let (_, asset_type_var) = prover.commit(asset.1, blind.1); //asset type
    asset_vars.push((asset_amount_var, asset_type_var));
  }

  // compute liabilities circuit variables
  let mut liabilities_vars = Vec::with_capacity(hidden_liability_set.len());
  for (lia, blind) in hidden_liability_set.iter().zip(liability_set_blinds) {
    let (_, lia_amount_var) = prover.commit(lia.0, blind.0); //amount
    let (_, lia_type_var) = prover.commit(lia.1, blind.1); //asset type

    liabilities_vars.push((lia_amount_var, lia_type_var));
  }

  // compute public asset total
  let mut public_asset_sum = Scalar::zero();
  for (amount, asset_type) in public_asset_set {
    let rate = conversion_rates.get(asset_type)
                               .ok_or(ZeiError::SolvencyProveError)?;
    public_asset_sum = public_asset_sum + rate * amount;
  }

  // compute public liabilities total
  let mut public_liability_sum = Scalar::zero();
  for (amount, asset_type) in public_liability_set {
    let rate = conversion_rates.get(asset_type)
                               .ok_or(ZeiError::SolvencyProveError)?;
    public_liability_sum = public_liability_sum + rate * amount;
  }

  // padding:
  let mut types = vec![];
  for (t, _) in conversion_rates {
    types.push(*t);
  }
  let mut padded_hidden_assets = hidden_asset_set.to_vec();
  let mut padded_hidden_liabilities = hidden_liability_set.to_vec();
  padd_vars(&mut prover, &mut asset_vars, types.as_slice()).map_err(|_| {
                                                             ZeiError::SolvencyProveError
                                                           })?;
  padd_values(&mut padded_hidden_assets, types.as_slice());
  padd_vars(&mut prover, &mut liabilities_vars, types.as_slice()).map_err(|_| {
                                                                   ZeiError::SolvencyProveError
                                                                 })?;
  padd_values(&mut padded_hidden_liabilities, types.as_slice());

  let num_left_wires =
    bp_circuits::solvency::solvency(&mut prover,
                                    &asset_vars[..],
                                    Some(padded_hidden_assets.as_slice()),
                                    public_asset_sum,
                                    &liabilities_vars[..],
                                    Some(padded_hidden_liabilities.as_slice()),
                                    public_liability_sum,
                                    conversion_rates).map_err(|_| ZeiError::SolvencyProveError)?;

  let bp_gens = BulletproofGens::new(num_left_wires.next_power_of_two(), 1);
  prover.prove(&bp_gens)
        .map_err(|_| ZeiError::SolvencyProveError)
}

/// I verify a proof of solvency for a set of assets vs liabilities for potentially different
/// asset types using a conversion table to a common type.
/// Values are given as pairs (amount, asset_type).
/// Values can be hidden or public. Hidden values are given as perdersen commitments.
/// Returns `Ok(())` in case of success and ZeiError::SolvencyVerificationError in case proof is
/// wrong for the given input or other error occurs in the verification process (Eg: asset type of
/// a public value is not a key in the conversion table).
/// # Example
/// ```
/// use bulletproofs_yoloproof::{BulletproofGens, PedersenGens};
/// use rand_chacha::ChaChaRng;
/// use rand::SeedableRng;
/// use curve25519_dalek::scalar::Scalar;
/// use zei::crypto::solvency::{prove_solvency,verify_solvency};
/// let pc_gens = PedersenGens::default();
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// use linear_map::LinearMap;
/// use zei::errors::ZeiError;
///
/// let mut rates = LinearMap::new();
///    rates.insert(Scalar::from(1u8), Scalar::from(1u8));
///    rates.insert(Scalar::from(2u8), Scalar::from(2u8));
///    rates.insert(Scalar::from(3u8), Scalar::from(3u8));
///
/// let hidden_liability_set = [
///			(Scalar::from(10u8), Scalar::from(1u8)), // 10
///			(Scalar::from(20u8), Scalar::from(2u8)), // 40
///		];
///
/// let hidden_asset_set = [
///			(Scalar::from(10u8), Scalar::from(1u8)), // 10
///			(Scalar::from(20u8), Scalar::from(2u8)), // 40
///			(Scalar::from(30u8), Scalar::from(2u8)), // 60
///		];
///
/// let mut assets_blinds = vec![
///         (Scalar::random(&mut prng), Scalar::random(&mut prng)),
///         (Scalar::random(&mut prng), Scalar::random(&mut prng)),
///         (Scalar::random(&mut prng), Scalar::random(&mut prng))];
///
///
/// let hidden_asset_set = hidden_asset_set;
/// let hidden_liability_set = hidden_liability_set;
/// let mut liabilities_blinds = vec![
///         (Scalar::random(&mut prng), Scalar::random(&mut prng)),
///         (Scalar::random(&mut prng), Scalar::random(&mut prng))];
///
/// let proof = prove_solvency(   &hidden_asset_set,
///                               assets_blinds.as_slice(),
///                               &[],
///                               &hidden_liability_set,
///                               liabilities_blinds.as_slice(),
///                               &[],
///                               &rates);
///
/// let mut hidden_assets_coms = vec![];
/// for ((a, t), (ba, bt)) in hidden_asset_set.iter().zip(assets_blinds.iter()) {
///     let com_a = pc_gens.commit(*a, *ba).compress();
///     let com_t = pc_gens.commit(*t, *bt).compress();
///     hidden_assets_coms.push((com_a, com_t));
/// }
/// let mut hidden_liabilities_coms = vec![];
/// for ((a, t), (ba, bt)) in hidden_liability_set.iter().zip(liabilities_blinds.iter()) {
///     let com_a = pc_gens.commit(*a, *ba).compress();
///     let com_t = pc_gens.commit(*t, *bt).compress();
///     hidden_liabilities_coms.push((com_a, com_t));
/// }
/// let vrfy = verify_solvency(
///                 hidden_assets_coms.as_slice(),
///                 &[],
///                 hidden_liabilities_coms.as_slice(),
///                 &[],
///                 &rates,
///                 &proof.unwrap());
/// assert!(vrfy.is_ok());
/// ```

pub fn verify_solvency(hidden_asset_set: &[(CompressedRistretto, CompressedRistretto)], //commitments to assets
                       public_asset_set: &[(Scalar, Scalar)],
                       hidden_liability_set: &[(CompressedRistretto, CompressedRistretto)], //commitments to liabilities
                       public_liability_set: &[(Scalar, Scalar)],
                       conversion_rates: &LinearMap<Scalar, Scalar>, // exchange rate for asset types
                       proof: &R1CSProof)
                       -> Result<(), ZeiError> {
  let pc_gens = PedersenGens::default();

  let mut transcript = Transcript::new(b"SolvencyProof");
  let mut verifier = Verifier::new(&mut transcript);

  let mut asset_vars: Vec<(Variable, Variable)> =
    hidden_asset_set.iter()
                    .map(|(a, t)| (verifier.commit(*a), verifier.commit(*t)))
                    .collect();

  let mut liabilities_vars: Vec<(Variable, Variable)> =
    hidden_liability_set.iter()
                        .map(|(a, t)| (verifier.commit(*a), verifier.commit(*t)))
                        .collect();

  let mut public_asset_sum = Scalar::zero();
  for (amount, asset_type) in public_asset_set {
    let rate = conversion_rates.get(asset_type)
                               .ok_or(ZeiError::SolvencyProveError)?;
    public_asset_sum = public_asset_sum + rate * amount;
  }

  let mut public_liability_sum = Scalar::zero();
  for (amount, asset_type) in public_liability_set {
    let rate = conversion_rates.get(asset_type)
                               .ok_or(ZeiError::SolvencyProveError)?;
    public_liability_sum = public_liability_sum + rate * amount;
  }

  // padding:
  let mut types = vec![];
  for (t, _) in conversion_rates {
    types.push(*t);
  }
  padd_vars(&mut verifier, &mut asset_vars, types.as_slice()).map_err(|_| {
                                                               ZeiError::SolvencyVerificationError
                                                             })?;
  padd_vars(&mut verifier, &mut liabilities_vars, types.as_slice()).map_err(|_| ZeiError::SolvencyVerificationError)?;

  let num_left_wires =
    bp_circuits::solvency::solvency(&mut verifier,
                                    &asset_vars[..],
                                    None,
                                    public_asset_sum,
                                    &liabilities_vars[..],
                                    None,
                                    public_liability_sum,
                                    conversion_rates).map_err(|_| {
                                                       ZeiError::SolvencyVerificationError
                                                     })?;

  let bp_gens = BulletproofGens::new(num_left_wires.next_power_of_two(), 1);
  verifier.verify(proof, &pc_gens, &bp_gens)
          .map_err(|_| ZeiError::SolvencyVerificationError)
}

fn padd_vars<CS: ConstraintSystem>(cs: &mut CS,
                                   vars: &mut Vec<(Variable, Variable)>,
                                   types: &[Scalar])
                                   -> Result<(), R1CSError> {
  for t in types {
    let zero_var = cs.allocate(Some(Scalar::zero()))?;
    let t_var = cs.allocate(Some(*t))?;
    vars.push((zero_var, t_var));
  }
  Ok(())
}

fn padd_values(values: &mut Vec<(Scalar, Scalar)>, types: &[Scalar]) {
  for t in types {
    values.push((Scalar::zero(), *t));
  }
}

#[cfg(test)]
mod test {
  use bulletproofs_yoloproof::PedersenGens;
  use curve25519_dalek::scalar::Scalar;
  use linear_map::LinearMap;
  use rand::SeedableRng;
  use rand_chacha::ChaChaRng;

  fn do_test_solvency(hidden_asset_set: &[(Scalar, Scalar)],
                      public_asset_set: &[(Scalar, Scalar)],
                      hidden_liability_set: &[(Scalar, Scalar)],
                      public_liability_set: &[(Scalar, Scalar)],
                      conversion_rates: &LinearMap<Scalar, Scalar>,
                      pass: bool) {
    let pc_gens = PedersenGens::default();
    let mut prng = ChaChaRng::from_seed([1u8; 32]);
    let mut assets_blinds = vec![];
    for _ in 0..hidden_asset_set.len() {
      assets_blinds.push((Scalar::random(&mut prng), Scalar::random(&mut prng)));
    }

    let mut liabilities_blinds = vec![];
    for _ in 0..hidden_liability_set.len() {
      liabilities_blinds.push((Scalar::random(&mut prng), Scalar::random(&mut prng)));
    }

    let proof = super::prove_solvency(hidden_asset_set,
                                      assets_blinds.as_slice(),
                                      public_asset_set,
                                      hidden_liability_set,
                                      liabilities_blinds.as_slice(),
                                      public_liability_set,
                                      &conversion_rates).unwrap();

    let mut hidden_assets_coms = vec![];
    for ((a, t), (ba, bt)) in hidden_asset_set.iter().zip(assets_blinds.iter()) {
      let com_a = pc_gens.commit(*a, *ba).compress();
      let com_t = pc_gens.commit(*t, *bt).compress();
      hidden_assets_coms.push((com_a, com_t));
    }
    let mut hidden_liabilities_coms = vec![];
    for ((a, t), (ba, bt)) in hidden_liability_set.iter().zip(liabilities_blinds.iter()) {
      let com_a = pc_gens.commit(*a, *ba).compress();
      let com_t = pc_gens.commit(*t, *bt).compress();
      hidden_liabilities_coms.push((com_a, com_t));
    }

    let vrfy = super::verify_solvency(hidden_assets_coms.as_slice(),
                                      public_asset_set,
                                      hidden_liabilities_coms.as_slice(),
                                      public_liability_set,
                                      &conversion_rates,
                                      &proof);
    assert_eq!(pass, vrfy.is_ok());
  }

  fn create_values_and_do_test(hidden_asset: bool, hidden_lia: bool, pass: bool) {
    let mut rates = LinearMap::new();
    rates.insert(Scalar::from(1u8), Scalar::from(1u8));
    rates.insert(Scalar::from(2u8), Scalar::from(2u8));
    rates.insert(Scalar::from(3u8), Scalar::from(3u8));

    let smaller = [
			(Scalar::from(10u8), Scalar::from(1u8)), // 10
			(Scalar::from(20u8), Scalar::from(2u8)), // 40
			(Scalar::from(30u8), Scalar::from(2u8)), // 60
			(Scalar::from(40u8), Scalar::from(3u8)), // 120
			(Scalar::from(50u8), Scalar::from(2u8)), // 100, total 330
		];

    let greater = [
			(Scalar::from(10u8), Scalar::from(1u8)), // 10
			(Scalar::from(20u8), Scalar::from(2u8)), // 40
			(Scalar::from(30u8), Scalar::from(2u8)), // 60
			(Scalar::from(40u8), Scalar::from(1u8)), // 40
			(Scalar::from(50u8), Scalar::from(3u8)), // 150
			(Scalar::from(60u8), Scalar::from(2u8)), // 120
			(Scalar::from(70u8), Scalar::from(3u8)), // 210, total 630
		];
    match (hidden_asset, hidden_lia, pass) {
      (false, false, false) => do_test_solvency(&[], &smaller, &[], &greater, &rates, pass),
      (false, false, true) => do_test_solvency(&[], &greater, &[], &smaller, &rates, pass),
      (false, true, false) => do_test_solvency(&[], &smaller, &greater, &[], &rates, pass),
      (false, true, true) => do_test_solvency(&[], &greater, &smaller, &[], &rates, pass),
      (true, false, false) => do_test_solvency(&smaller, &[], &[], &greater, &rates, pass),
      (true, false, true) => do_test_solvency(&greater, &[], &[], &smaller, &rates, pass),
      (true, true, false) => do_test_solvency(&smaller, &[], &greater, &[], &rates, pass),
      (true, true, true) => do_test_solvency(&greater, &[], &smaller, &[], &rates, pass),
    }
  }

  #[test]
  fn test_solvency_all_hidden_fail() {
    create_values_and_do_test(false, false, false);
  }

  #[test]
  fn test_solvency_all_hidden_pass() {
    create_values_and_do_test(false, false, true);
  }

  #[test]
  fn test_solvency_liabilities_hidden_fail() {
    create_values_and_do_test(false, true, false);
  }

  #[test]
  fn test_solvency_liabilities_hidden_pass() {
    create_values_and_do_test(false, true, true);
  }

  #[test]
  fn test_solvency_assets_hidden_fail() {
    create_values_and_do_test(true, false, false);
  }

  #[test]
  fn test_solvency_assets_hidden_pass() {
    create_values_and_do_test(true, false, true);
  }

  #[test]
  fn test_solvency_all_public_fail() {
    create_values_and_do_test(true, true, false);
  }

  #[test]
  fn test_solvency_all_public_pass() {
    create_values_and_do_test(true, true, true);
  }

  #[test]
  fn test_solvency_mixed() {
    let mut rates = LinearMap::new();
    rates.insert(Scalar::from(1u8), Scalar::from(1u8));
    rates.insert(Scalar::from(2u8), Scalar::from(2u8));
    rates.insert(Scalar::from(3u8), Scalar::from(3u8));

    let lia_hidden = [
			(Scalar::from(40u8), Scalar::from(1u8)), // 40
			(Scalar::from(10u8), Scalar::from(2u8)), // 20
			(Scalar::from(20u8), Scalar::from(3u8)), // 60
			(Scalar::from(80u8), Scalar::from(1u8)), // 80, total 200

		];
    let greater = [
			(Scalar::from(100u8), Scalar::from(2u8)), // 200
			(Scalar::from(100u8), Scalar::from(3u8)), // 300, total 500
		];

    let asset_hidden = [
			(Scalar::from(10u8), Scalar::from(1u8)), // 10
			(Scalar::from(20u8), Scalar::from(2u8)), // 40
			(Scalar::from(20u8), Scalar::from(3u8)), // 60
			(Scalar::from(40u8), Scalar::from(2u8)), // 80
			(Scalar::from(10u8), Scalar::from(1u8)), // 10, total 200
		];
    let smaller = [
			(Scalar::from(499u16), Scalar::from(1u8)), // 499
		];

    do_test_solvency(&asset_hidden,
                     &smaller,
                     &lia_hidden,
                     &greater,
                     &rates,
                     false);
    do_test_solvency(&asset_hidden, &greater, &lia_hidden, &smaller, &rates, true);

    // test with incomplete hidden asset list
    do_test_solvency(&smaller,
                     &asset_hidden,
                     &greater,
                     &lia_hidden,
                     &rates,
                     false);
    do_test_solvency(&greater, &asset_hidden, &smaller, &lia_hidden, &rates, true);
  }
}
