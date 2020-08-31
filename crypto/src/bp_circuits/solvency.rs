/*
 * This file implements proof of solvency resembling the cloak protocol in https://github.com/stellar/slingshot/tree/main/spacesuit.
 * 1) Values are first sorted by order of appearance of type in a rate conversion table
 * 2) Values of same type are added, invalidating zeroed values
 * 3) Values are shuffled so that zeored values are placed at the end of the list
 * 4) Conversion table is applied to added values
 * 5) Values are added
 * 5) Apply range proof for total_asset - total_liabilities
*/

use crate::bp_circuits::cloak::{allocate_cloak_vector, CloakValue, CloakVariable};
use algebra::groups::Scalar as _;
use algebra::ristretto::RistrettoScalar as Scalar;
use bulletproofs::r1cs::{LinearCombination, RandomizableConstraintSystem};
use linear_map::LinearMap;
use utils::errors::ZeiError;

/// I implement a proof of solvency bulletproof protocol
/// The prover needs to provide asset and liabilities plaintain
/// Input values are represented as a pair where the first coordinate
/// corresponds to amount, and second coordinate to the type
/// The rate table is hash map of Scalar to Scalar.
// TODO rewrite this function so that it has less arguments
#[allow(clippy::too_many_arguments)]
pub(crate) fn solvency<CS: RandomizableConstraintSystem>(cs: &mut CS,
                                                         asset_set_vars: &[CloakVariable],
                                                         asset_set_values: Option<&[CloakValue]>,
                                                         public_asset_sum: Scalar,
                                                         liability_set_vars: &[CloakVariable],
                                                         liability_set_values: Option<&[CloakValue]>,
                                                         public_liability_sum: Scalar,
                                                         conversion_rates: &LinearMap<Scalar,
                                                                    Scalar>)
                                                         -> Result<usize, ZeiError> {
  let mut rate_types = vec![];
  let mut rate_values = vec![];
  for (k, v) in conversion_rates {
    rate_types.push(*k);
    rate_values.push(*v);
  }

  let (mut total_assets_var, num_gates_asset) = match asset_set_vars.len() {
    0 => (LinearCombination::default(), 0),
    _ => aggregate(cs,
                   asset_set_vars,
                   asset_set_values,
                   &rate_types[..],
                   &rate_values[..])?,
  };
  let (mut total_lia_var, num_gates_lia) = match liability_set_vars.len() {
    0 => (LinearCombination::default(), 0),
    _ => aggregate(cs,
                   liability_set_vars,
                   liability_set_values,
                   &rate_types[..],
                   &rate_values[..])?,
  };

  total_assets_var = total_assets_var + public_asset_sum.0;
  total_lia_var = total_lia_var + public_liability_sum.0;

  let diff_var = total_assets_var - total_lia_var;
  let diff_value = match asset_set_values {
    Some(values) => {
      let converted_asset: Vec<Scalar> = values.iter()
                                               .map(|v| v.amount.mul(conversion_rates.get(&v.asset_type).unwrap())) // TODO remove this unwrap
                                               .collect();

      //let total_asset = converted_asset.iter().sum::<Scalar>() + public_asset_sum;
      let total_asset = converted_asset.iter()
                                       .fold(Scalar::from_u32(0), |acc, b| acc.add(b))
                                       .add(&public_asset_sum);

      let converted_lia: Vec<Scalar> =
        liability_set_values.unwrap() // safe unwrap
                            .iter()
                            .map(|v| v.amount.mul(conversion_rates.get(&v.asset_type).unwrap())) // TODO remove this unwrap
                            .collect();
      //let total_lia = converted_lia.iter().sum::<Scalar>().add(&public_liability_sum);
      let total_lia = converted_lia.iter()
                                   .fold(Scalar::from_u32(0), |acc, b| acc.add(b))
                                   .add(&public_liability_sum);

      Some(total_asset.sub(&total_lia))
    }
    None => None,
  };

  let num_gates_range_proof =
    super::gadgets::range_proof_64(cs, diff_var, diff_value).map_err(|_| ZeiError::R1CSProofError)?;

  Ok(num_gates_asset + num_gates_lia + num_gates_range_proof)
}

/// I aggregate a list of values using a rate conversion version table.
fn aggregate<CS: RandomizableConstraintSystem>(cs: &mut CS,
                                               vars: &[CloakVariable],
                                               values: Option<&[CloakValue]>,
                                               rate_types: &[Scalar],
                                               rate_values: &[Scalar])
                                               -> Result<(LinearCombination, usize), ZeiError> {
  let l = vars.len();
  if l <= 1 {
    return Ok((LinearCombination::default(), 0));
  }

  let (sorted_vars, mid_vars, added_vars, trimmed_vars) = match values {
    Some(values) => {
      //prover allocate variables
      let sorted_values = sort_by_rate_type(values, &rate_types[..]);
      let (mid_values, added_values) = super::cloak::merge(&sorted_values[..]);
      let trimmed_values = trim(&added_values[..]);

      (allocate_cloak_vector(cs, Some(&sorted_values), l)?,
       allocate_cloak_vector(cs, Some(&mid_values), l - 2)?,
       allocate_cloak_vector(cs, Some(&added_values), l)?,
       allocate_cloak_vector(cs, Some(&trimmed_values), l)?)
    }
    None => (allocate_cloak_vector(cs, None, l)?,
             allocate_cloak_vector(cs, None, l - 2)?,
             allocate_cloak_vector(cs, None, l)?,
             allocate_cloak_vector(cs, None, l)?),
  };

  let mut total = LinearCombination::default();
  for i in 0..rate_values.len() {
    let value = trimmed_vars[i].amount;
    let value_type = trimmed_vars[i].asset_type;
    let rate = rate_values[i];
    let rate_type = rate_types[i];
    let (_, _, out) = cs.multiply(value.into(), rate.0.into());
    cs.constrain(value_type - rate_type.0);
    total = total + out;
  }
  // prove addition of same flavor
  let n_mix = super::gadgets::cloak_merge_gadget(cs,
                                                 &sorted_vars[..],
                                                 &mid_vars[..],
                                                 &added_vars[..]).map_err(|_| {
                                                                   ZeiError::R1CSProofError
                                                                 })?;
  // prove first shuffle
  let n_shuffle1 =
    super::gadgets::cloak_shuffle_gadget(cs, vars.to_vec(), sorted_vars).map_err(|_| {
                                                                          ZeiError::R1CSProofError
                                                                        })?;
  // prove second shiffled (zeroed values places at the end of the list)
  let n_shuffle2 =
    super::gadgets::cloak_shuffle_gadget(cs, added_vars, trimmed_vars).map_err(|_| {
                                                                        ZeiError::R1CSProofError
                                                                      })?;
  Ok((total, 6 * l + 2 * (l - 2) + rate_values.len() + n_mix + n_shuffle1 + n_shuffle2))
}

/// Sort the pairs in values by the order asset_type appears in type_list
fn sort_by_rate_type(values: &[CloakValue], type_list: &[Scalar]) -> Vec<CloakValue> {
  let mut sorted = vec![];
  for key in type_list.iter() {
    for value in values {
      if &value.asset_type == key {
        sorted.push(*value);
      }
    }
  }
  sorted
}

/*
/// Given a sorted by type list, I add the amounts of same type pairs in the list,
/// zeroing out values and types already aggregated into another value
#[allow(clippy::type_complexity)]
fn add(list: &[CloakValue]) -> (Vec<CloakValue>, Vec<CloakValue>) {
  let l = list.len();
  if l == 0 {
    return (vec![], vec![]);
  }
  let mut agg_values = Vec::with_capacity(l);
  let mut mid_values: Vec<(Scalar, Scalar)> = Vec::with_capacity(l - 1);
  let mut in1 = (list[0].0, list[0].1);

  for item in list.iter().take(l).skip(1) {
    let in2 = *item;
    if in1.1 == in2.1 {
      agg_values.push((Scalar::zero(), Scalar::zero()));
      mid_values.push((in1.0 + in2.0, in1.1));
      in1 = (in1.0 + in2.0, in1.1); // in1 becomes the current mid value
    } else {
      //maintain values
      agg_values.push((in1.0, in1.1));
      mid_values.push((in2.0, in2.1));
      in1 = (in2.0, in2.1); // in1 becomes the current mid value
    }
  }
  agg_values.push(mid_values.pop().unwrap()); // last mid value is actually an output
  (mid_values, agg_values)
}
*/

/// Shuffle values to that zeroed values are placed in the tail of the list
/// while maintaining the order of the non-zero type elements
fn trim(values: &[CloakValue]) -> Vec<CloakValue> {
  let l = values.len();
  let mut trimmed = Vec::with_capacity(l);
  let mut rest = vec![];

  for value in &values[0..l] {
    if value.asset_type != Scalar::from_u32(0) {
      trimmed.push(*value);
    } else {
      rest.push(CloakValue::default());
    }
  }
  trimmed.append(&mut rest);
  trimmed
}

#[cfg(test)]
mod test {
  use crate::bp_circuits::cloak::{CloakCommitment, CloakValue, CloakVariable};
  use algebra::groups::Scalar;
  use algebra::ristretto::RistrettoScalar;
  use bulletproofs::r1cs::{Prover, Verifier};
  use bulletproofs::{BulletproofGens, PedersenGens};
  use linear_map::LinearMap;
  use merlin::Transcript;

  #[test]
  fn sort() {
    let values = vec![CloakValue::new(RistrettoScalar::from_u32(30), RistrettoScalar::from_u32(3)),
                      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1)),
                      CloakValue::new(RistrettoScalar::from_u32(20), RistrettoScalar::from_u32(2)),
                      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1)),
                      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1)),
                      CloakValue::new(RistrettoScalar::from_u32(30), RistrettoScalar::from_u32(3)),
                      CloakValue::new(RistrettoScalar::from_u32(30), RistrettoScalar::from_u32(3))];

    let t = [RistrettoScalar::from_u32(3),
             RistrettoScalar::from_u32(2),
             RistrettoScalar::from_u32(1)];

    let sorted = super::sort_by_rate_type(&values, &t);
    let expected =
      vec![CloakValue::new(RistrettoScalar::from_u32(30), RistrettoScalar::from_u32(3)),
           CloakValue::new(RistrettoScalar::from_u32(30), RistrettoScalar::from_u32(3)),
           CloakValue::new(RistrettoScalar::from_u32(30), RistrettoScalar::from_u32(3)),
           CloakValue::new(RistrettoScalar::from_u32(20), RistrettoScalar::from_u32(2)),
           CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1)),
           CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1)),
           CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1))];
    assert_eq!(&sorted[..], &expected[..]);
  }

  #[test]
  fn trim() {
    let values = [CloakValue::new(RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(0)),
                  CloakValue::new(RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(0)),
                  CloakValue::new(RistrettoScalar::from_u32(90), RistrettoScalar::from_u32(3)),
                  CloakValue::new(RistrettoScalar::from_u32(20), RistrettoScalar::from_u32(2)),
                  CloakValue::new(RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(0)),
                  CloakValue::new(RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(0)),
                  CloakValue::new(RistrettoScalar::from_u32(30), RistrettoScalar::from_u32(1))];

    let trimmed = super::trim(&values);
    let expected = [CloakValue::new(RistrettoScalar::from_u32(90), RistrettoScalar::from_u32(3)),
                    CloakValue::new(RistrettoScalar::from_u32(20), RistrettoScalar::from_u32(2)),
                    CloakValue::new(RistrettoScalar::from_u32(30), RistrettoScalar::from_u32(1)),
                    CloakValue::new(RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(0)),
                    CloakValue::new(RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(0)),
                    CloakValue::new(RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(0)),
                    CloakValue::new(RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(0))];

    assert_eq!(&trimmed[..], &expected[..]);
  }

  #[test]
  fn test_solvency() {
    let pc_gens = PedersenGens::default();
    let mut rates = LinearMap::new();
    rates.insert(RistrettoScalar::from_u32(1), RistrettoScalar::from_u32(1));
    rates.insert(RistrettoScalar::from_u32(2), RistrettoScalar::from_u32(2));
    rates.insert(RistrettoScalar::from_u32(3), RistrettoScalar::from_u32(3));
    let asset_set = vec![
      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1)), //total 10
      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(2)), //total 20
      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(2)), //total 20
      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1)), //total 10
      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(3)), //total 30
      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1)), //total 10
      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1)), //total 10, total asset worth = 100
        ];

    let liability_set = vec![
      CloakValue::new(RistrettoScalar::from_u32(2), RistrettoScalar::from_u32(2)), // total 4
      CloakValue::new(RistrettoScalar::from_u32(8), RistrettoScalar::from_u32(2)),  // total 16
      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1)), // total 10
      CloakValue::new(RistrettoScalar::from_u32(20), RistrettoScalar::from_u32(3)), // total 60
      CloakValue::new(RistrettoScalar::from_u32(10), RistrettoScalar::from_u32(1)), // total 10
        ];
    let mut prover_transcript = Transcript::new(b"test");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    let asset_com_vars: Vec<(CloakCommitment, CloakVariable)> =
      asset_set.iter()
               .map(|value| {
                 value.commit_prover(&mut prover,
                                     &CloakValue::new(RistrettoScalar::from_u32(1),
                                                      RistrettoScalar::from_u32(2)))
               })
               .collect();
    let asset_com: Vec<CloakCommitment> = asset_com_vars.iter().map(|(com, _)| *com).collect();
    let asset_var: Vec<CloakVariable> = asset_com_vars.iter().map(|(_, var)| *var).collect();

    let lia_com_vars: Vec<(CloakCommitment, CloakVariable)> =
      liability_set.iter()
                   .map(|value| {
                     value.commit_prover(&mut prover,
                                         &CloakValue::new(RistrettoScalar::from_u32(3),
                                                          RistrettoScalar::from_u32(4)))
                   })
                   .collect();
    let lia_com: Vec<CloakCommitment> = lia_com_vars.iter().map(|(com, _)| *com).collect();
    let lia_var: Vec<CloakVariable> = lia_com_vars.iter().map(|(_, var)| *var).collect();

    let num_left_wires = super::solvency(&mut prover,
                                         &asset_var[..],
                                         Some(&asset_set),
                                         Scalar::from_u64(0),
                                         &lia_var[..],
                                         Some(&liability_set),
                                         Scalar::from_u64(0),
                                         &rates).unwrap();
    let bp_gens = BulletproofGens::new(num_left_wires.next_power_of_two(), 1);
    let proof = prover.prove(&bp_gens).unwrap();

    let mut verifier_transcript = Transcript::new(b"test");
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let asset_var: Vec<CloakVariable> = asset_com.iter()
                                                 .map(|var| var.commit_verifier(&mut verifier))
                                                 .collect();

    let lia_var: Vec<CloakVariable> = lia_com.iter()
                                             .map(|var| var.commit_verifier(&mut verifier))
                                             .collect();

    super::solvency(&mut verifier,
                    &asset_var[..],
                    None,
                    RistrettoScalar::from_u64(0),
                    &lia_var[..],
                    None,
                    RistrettoScalar::from_u64(0),
                    &rates).unwrap();
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
  }
}
