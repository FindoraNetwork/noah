use crate::bp_circuits::cloak::{CloakCommitment, CloakValue, CloakVariable};
use crate::bp_circuits::solvency::solvency;
use bulletproofs::r1cs::{ConstraintSystem, Prover, R1CSError, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use linear_map::LinearMap;
use merlin::Transcript;
use utils::errors::ZeiError;

/// I produce a proof of solvency for a set of assets vs liabilities for potentially different
/// asset types using a conversion table to a common type.
/// Values are given as pairs (amount, asset_type).
/// Values can be hidden or public to the verifier. For hidden values, prover needs to provide
/// blinding factors for the corresponding Pedersen commitments.
/// Asset type cannot be `Scalar::zero()`
/// Returns Ok(proof) in case of success and Err(ZeiError::SolvencyProveError) in case proof cannot be
/// computed.
/// # Example
/// ```
/// use rand_chacha::ChaChaRng;
/// use rand_core::SeedableRng;
/// use curve25519_dalek::scalar::Scalar;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// use linear_map::LinearMap;
/// use utils::errors::ZeiError;
/// use curve25519_dalek::ristretto::CompressedRistretto;
/// use crypto::bp_circuits::cloak::{CloakValue, CloakCommitment};
/// use crypto::solvency::{verify_solvency, prove_solvency};
/// use bulletproofs::{PedersenGens, BulletproofGens};
///
/// // asset types
/// let type1 = Scalar::from(1u8);
/// let type2 = Scalar::from(2u8);
/// let type3 = Scalar::from(3u8);
///
///  // exchange rate table
/// let mut rates = LinearMap::new();
///   rates.insert(type1, Scalar::from(1u8));
///   rates.insert(type2, Scalar::from(2u8));
///   rates.insert(type3, Scalar::from(3u8));
///
/// // liabilities
/// let hidden_liability_set = [
///   CloakValue::new(Scalar::from(10u8), type1), // 10
///   CloakValue::new(Scalar::from(20u8), type2), // 40
/// ];
///
/// //assets
/// let hidden_asset_set = [
///   CloakValue::new(Scalar::from(10u8), type1), // 10
///   CloakValue::new(Scalar::from(20u8), type2), // 40
///   CloakValue::new(Scalar::from(30u8), type3), // 60
/// ];
///
/// // blinding factors
/// let mut assets_blinds = vec![CloakValue::new(Scalar::random(&mut prng), Scalar::random(&mut prng)); 3];
/// let mut liabilities_blinds = vec![CloakValue::new(Scalar::random(&mut prng), Scalar::random(&mut prng)); 2];
///
/// let pc_gens = PedersenGens::default();
/// let bp_gens = BulletproofGens::new(256, 1);
/// let proof = prove_solvency(&bp_gens,
///                            &pc_gens,
///                            &hidden_asset_set,
///                            assets_blinds.as_slice(),
///                            &[], // no public asset
///                            &hidden_liability_set,
///                            liabilities_blinds.as_slice(),
///                            &[], // no public liabilities
///                            &rates);
///
/// let hidden_assets_coms: Vec<CloakCommitment> = hidden_asset_set.
///   iter().
///   zip(assets_blinds.iter()).
///   map(|(asset, blind)| {
///     asset.commit(&pc_gens, blind)
///   }).collect();
///
/// let hidden_liabilities_coms: Vec<CloakCommitment> = hidden_liability_set.
///   iter().
///   zip(liabilities_blinds.iter()).
///   map(|(lia,blind)| {
///     lia.commit(&pc_gens, blind)
///   }).collect();
///
/// let vrfy = verify_solvency(
///                 &bp_gens,
///                 &pc_gens,
///                 hidden_assets_coms.as_slice(),
///                 &[],
///                 hidden_liabilities_coms.as_slice(),
///                 &[],
///                 &rates,
///                 &proof.unwrap());
/// assert!(vrfy.is_ok());
/// ```
#[allow(clippy::too_many_arguments)] // TODO (fernando) simplify this signature
pub fn prove_solvency(bp_gens: &BulletproofGens,
                      pc_gens: &PedersenGens,
                      hidden_asset_set: &[CloakValue], // amount and type of hidden assets
                      asset_set_blinds: &[CloakValue], // blindings for amount and type of hidden assets
                      public_asset_set: &[CloakValue], // amount and type of public/known assets
                      hidden_liability_set: &[CloakValue], // amount and type of hidden liabilities
                      liability_set_blinds: &[CloakValue], // blindings for amount and type in hidden liabilities
                      public_liability_set: &[CloakValue], // amount and type of public/known assets
                      conversion_rates: &LinearMap<Scalar, Scalar>  // exchange rates for asset types
) -> Result<R1CSProof, ZeiError> {
  let mut transcript = Transcript::new(b"SolvencyProof");
  let mut prover = Prover::new(pc_gens, &mut transcript);

  // compute assets circuit variables
  let mut asset_vars = Vec::with_capacity(hidden_asset_set.len());
  for (asset, blinds) in hidden_asset_set.iter().zip(asset_set_blinds) {
    let (_, var) = asset.commit_prover(&mut prover, blinds);
    asset_vars.push(var);
  }

  // compute liabilities circuit variables
  let mut liabilities_vars = Vec::with_capacity(hidden_liability_set.len());
  for (lia, blinds) in hidden_liability_set.iter().zip(liability_set_blinds) {
    let (_, var) = lia.commit_prover(&mut prover, blinds);
    liabilities_vars.push(var);
  }

  // compute public asset total
  let mut public_asset_sum = Scalar::zero();
  for public_asset in public_asset_set {
    let rate = conversion_rates.get(&public_asset.asset_type)
                               .ok_or(ZeiError::SolvencyProveError)?;
    public_asset_sum += rate * public_asset.amount;
  }

  // compute public liabilities total
  let mut public_liability_sum = Scalar::zero();
  for public_lia in public_liability_set {
    let rate = conversion_rates.get(&public_lia.asset_type)
                               .ok_or(ZeiError::SolvencyProveError)?;
    public_liability_sum += rate * public_lia.amount;
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

  let _num_gates = solvency(&mut prover,
                            &asset_vars[..],
                            Some(padded_hidden_assets.as_slice()),
                            public_asset_sum,
                            &liabilities_vars[..],
                            Some(padded_hidden_liabilities.as_slice()),
                            public_liability_sum,
                            conversion_rates).map_err(|_| ZeiError::SolvencyProveError)?;
  prover.prove(bp_gens)
        .map_err(|_| ZeiError::SolvencyProveError)
}

/// Verify a proof of solvency for a set of assets vs liabilities for potentially different
/// asset types using a conversion table to a common type.
/// Values are given as pairs (amount, asset_type).
/// Values can be hidden or public. Hidden values are given as perdersen commitments.
/// Returns `Ok(())` in case of success and ZeiError::SolvencyVerificationError in case proof is
/// wrong for the given input or other error occurs in the verification process (Eg: asset type of
/// a public value is not a key in the conversion table).
/// bp_gens should have enough generators.
/// # Example
/// ```
/// // See zei::crypto::solvency::prove_solvency
/// ```
#[allow(clippy::too_many_arguments)] // TODO (fernando) simplify this signature
pub fn verify_solvency(bp_gens: &BulletproofGens,
                       pc_gens: &PedersenGens,
                       hidden_asset_set: &[CloakCommitment], //commitments to assets
                       public_asset_set: &[CloakValue],
                       hidden_liability_set: &[CloakCommitment], //commitments to liabilities
                       public_liability_set: &[CloakValue],
                       conversion_rates: &LinearMap<Scalar, Scalar>, // exchange rate for asset types
                       proof: &R1CSProof)
                       -> Result<(), ZeiError> {
  let mut transcript = Transcript::new(b"SolvencyProof");
  let mut verifier = Verifier::new(&mut transcript);

  let mut asset_vars: Vec<CloakVariable> =
    hidden_asset_set.iter()
                    .map(|com| com.commit_verifier(&mut verifier))
                    .collect();

  let mut liabilities_vars: Vec<CloakVariable> =
    hidden_liability_set.iter()
                        .map(|com| com.commit_verifier(&mut verifier))
                        .collect();

  let mut public_asset_sum = Scalar::zero();
  for public_asset in public_asset_set {
    let rate = conversion_rates.get(&public_asset.asset_type)
                               .ok_or(ZeiError::SolvencyProveError)?;
    public_asset_sum += rate * public_asset.amount;
  }

  let mut public_liability_sum = Scalar::zero();
  for public_lia in public_liability_set {
    let rate = conversion_rates.get(&public_lia.asset_type)
                               .ok_or(ZeiError::SolvencyProveError)?;
    public_liability_sum += rate * public_lia.amount;
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

  let _num_gates = solvency(&mut verifier,
                            &asset_vars[..],
                            None,
                            public_asset_sum,
                            &liabilities_vars[..],
                            None,
                            public_liability_sum,
                            conversion_rates).map_err(|_| ZeiError::SolvencyVerificationError)?;

  verifier.verify(proof, pc_gens, bp_gens)
          .map_err(|_| ZeiError::SolvencyVerificationError)
}

fn padd_vars<CS: ConstraintSystem>(cs: &mut CS,
                                   vars: &mut Vec<CloakVariable>,
                                   types: &[Scalar])
                                   -> Result<(), R1CSError> {
  for t in types {
    vars.push(CloakVariable { amount: cs.allocate(Some(Scalar::zero()))?,
                              asset_type: cs.allocate(Some(*t))? });
  }
  Ok(())
}

fn padd_values(values: &mut Vec<CloakValue>, types: &[Scalar]) {
  for t in types {
    values.push(CloakValue::new(Scalar::zero(), *t));
  }
}

#[cfg(test)]
mod test {
  use crate::bp_circuits::cloak::CloakValue;
  use bulletproofs::{BulletproofGens, PedersenGens};
  use curve25519_dalek::scalar::Scalar;
  use linear_map::LinearMap;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  fn do_test_solvency(bp_gens: &BulletproofGens,
                      pc_gens: &PedersenGens,
                      hidden_asset_set: &[CloakValue],
                      public_asset_set: &[CloakValue],
                      hidden_liability_set: &[CloakValue],
                      public_liability_set: &[CloakValue],
                      conversion_rates: &LinearMap<Scalar, Scalar>,
                      pass: bool) {
    let mut prng = ChaChaRng::from_seed([1u8; 32]);
    let mut assets_blinds = vec![];
    for _ in 0..hidden_asset_set.len() {
      assets_blinds.push(CloakValue::new(Scalar::random(&mut prng), Scalar::random(&mut prng)));
    }

    let mut liabilities_blinds = vec![];
    for _ in 0..hidden_liability_set.len() {
      liabilities_blinds.push(CloakValue::new(Scalar::random(&mut prng),
                                              Scalar::random(&mut prng)));
    }

    let proof = super::prove_solvency(bp_gens,
                                      pc_gens,
                                      hidden_asset_set,
                                      assets_blinds.as_slice(),
                                      public_asset_set,
                                      hidden_liability_set,
                                      liabilities_blinds.as_slice(),
                                      public_liability_set,
                                      &conversion_rates).unwrap();

    let mut hidden_assets_coms = vec![];
    for (asset, blinds) in hidden_asset_set.iter().zip(assets_blinds.iter()) {
      hidden_assets_coms.push(asset.commit(pc_gens, blinds));
    }
    let mut hidden_liabilities_coms = vec![];
    for (liability, blinds) in hidden_liability_set.iter().zip(liabilities_blinds.iter()) {
      hidden_liabilities_coms.push(liability.commit(pc_gens, blinds));
    }

    let vrfy = super::verify_solvency(bp_gens,
                                      pc_gens,
                                      hidden_assets_coms.as_slice(),
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
			CloakValue::new(Scalar::from(10u8), Scalar::from(1u8)), // 10
      CloakValue::new(Scalar::from(20u8), Scalar::from(2u8)), // 40
      CloakValue::new(Scalar::from(30u8), Scalar::from(2u8)), // 60
      CloakValue::new(Scalar::from(40u8), Scalar::from(3u8)), // 120
      CloakValue::new(Scalar::from(50u8), Scalar::from(2u8)), // 100, total 330
		];

    let greater = [
      CloakValue::new(Scalar::from(10u8), Scalar::from(1u8)), // 10
      CloakValue::new(Scalar::from(20u8), Scalar::from(2u8)), // 40
      CloakValue::new(Scalar::from(30u8), Scalar::from(2u8)), // 60
      CloakValue::new(Scalar::from(40u8), Scalar::from(1u8)), // 40
      CloakValue::new(Scalar::from(50u8), Scalar::from(3u8)), // 150
      CloakValue::new(Scalar::from(60u8), Scalar::from(2u8)), // 120
      CloakValue::new(Scalar::from(70u8), Scalar::from(3u8)), // 210, total 630
		];
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(512, 1);
    match (hidden_asset, hidden_lia, pass) {
      (false, false, false) => do_test_solvency(&bp_gens,
                                                &pc_gens,
                                                &[],
                                                &smaller,
                                                &[],
                                                &greater,
                                                &rates,
                                                pass),
      (false, false, true) => do_test_solvency(&bp_gens,
                                               &pc_gens,
                                               &[],
                                               &greater,
                                               &[],
                                               &smaller,
                                               &rates,
                                               pass),
      (false, true, false) => do_test_solvency(&bp_gens,
                                               &pc_gens,
                                               &[],
                                               &smaller,
                                               &greater,
                                               &[],
                                               &rates,
                                               pass),
      (false, true, true) => do_test_solvency(&bp_gens,
                                              &pc_gens,
                                              &[],
                                              &greater,
                                              &smaller,
                                              &[],
                                              &rates,
                                              pass),
      (true, false, false) => do_test_solvency(&bp_gens,
                                               &pc_gens,
                                               &smaller,
                                               &[],
                                               &[],
                                               &greater,
                                               &rates,
                                               pass),
      (true, false, true) => do_test_solvency(&bp_gens,
                                              &pc_gens,
                                              &greater,
                                              &[],
                                              &[],
                                              &smaller,
                                              &rates,
                                              pass),
      (true, true, false) => do_test_solvency(&bp_gens,
                                              &pc_gens,
                                              &smaller,
                                              &[],
                                              &greater,
                                              &[],
                                              &rates,
                                              pass),
      (true, true, true) => do_test_solvency(&bp_gens,
                                             &pc_gens,
                                             &greater,
                                             &[],
                                             &smaller,
                                             &[],
                                             &rates,
                                             pass),
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
			CloakValue::new(Scalar::from(40u8), Scalar::from(1u8)), // 40
      CloakValue::new(Scalar::from(10u8), Scalar::from(2u8)), // 20
      CloakValue::new(Scalar::from(20u8), Scalar::from(3u8)), // 60
      CloakValue::new(Scalar::from(80u8), Scalar::from(1u8)), // 80, total 200

		];
    let greater = [
      CloakValue::new(Scalar::from(100u8), Scalar::from(2u8)), // 200
      CloakValue::new(Scalar::from(100u8), Scalar::from(3u8)), // 300, total 500
		];

    let asset_hidden = [
      CloakValue::new(Scalar::from(10u8), Scalar::from(1u8)), // 10
      CloakValue::new(Scalar::from(20u8), Scalar::from(2u8)), // 40
      CloakValue::new(Scalar::from(20u8), Scalar::from(3u8)), // 60
      CloakValue::new(Scalar::from(40u8), Scalar::from(2u8)), // 80
      CloakValue::new(Scalar::from(10u8), Scalar::from(1u8)), // 10, total 200
		];
    let smaller = [
      CloakValue::new(Scalar::from(499u16), Scalar::from(1u8)), // 499
		];

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(256, 1);

    do_test_solvency(&bp_gens,
                     &pc_gens,
                     &asset_hidden,
                     &smaller,
                     &lia_hidden,
                     &greater,
                     &rates,
                     false);
    do_test_solvency(&bp_gens,
                     &pc_gens,
                     &asset_hidden,
                     &greater,
                     &lia_hidden,
                     &smaller,
                     &rates,
                     true);

    // test with incomplete hidden asset list
    do_test_solvency(&bp_gens,
                     &pc_gens,
                     &smaller,
                     &asset_hidden,
                     &greater,
                     &lia_hidden,
                     &rates,
                     false);
    do_test_solvency(&bp_gens,
                     &pc_gens,
                     &greater,
                     &asset_hidden,
                     &smaller,
                     &lia_hidden,
                     &rates,
                     true);
  }
}
