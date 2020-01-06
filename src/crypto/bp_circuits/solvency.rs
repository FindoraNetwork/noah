/*
 * This file implements proof of solvency resembling the cloak protocol in https://github.com/stellar/slingshot/tree/main/spacesuit.
 * 1) Values are first sorted by order of appearance of type in a rate conversion table
 * 2) Values of same type are added, invalidating zeroed values
 * 3) Values are shuffled so that zeored values are placed at the end of the list
 * 4) Conversion table is applied to added values
 * 5) Values are added
 * 5) Apply range proof for total_asset - total_liabilities
*/

use bulletproofs::r1cs::{
  LinearCombination, R1CSError, RandomizableConstraintSystem, Variable,
};
use curve25519_dalek::scalar::Scalar;
use linear_map::LinearMap;

/// I implement a proof of solvency bulletproof protocol
/// The prover needs to provide asset and liabilities plaintain
/// Input values are represented as a pair where the first coordinate
/// corresponds to amount, and second coordinate to the type
/// The rate table is hash map of Scalar to Scalar.
// TODO rewrite this function so that it has less arguments
#[allow(clippy::too_many_arguments)]
pub(crate) fn solvency<CS: RandomizableConstraintSystem>(cs: &mut CS,
                                                         asset_set_vars: &[(Variable,
                                                            Variable)],
                                                         asset_set_values: Option<&[(Scalar,
                                                                   Scalar)]>,
                                                         public_asset_sum: Scalar,
                                                         liability_set_vars: &[(Variable,
                                                            Variable)],
                                                         liability_set_values: Option<&[(Scalar, Scalar)]>,
                                                         public_liability_sum: Scalar,
                                                         conversion_rates: &LinearMap<Scalar,
                                                                    Scalar>)
                                                         -> Result<usize, R1CSError> {
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

  total_assets_var = total_assets_var + public_asset_sum;
  total_lia_var = total_lia_var + public_liability_sum;

  let diff_var = total_assets_var - total_lia_var;
  let diff_value = match asset_set_values {
    Some(values) => {
      let converted_asset: Vec<Scalar> = values.iter()
                                               .map(|(a, t)| a * conversion_rates.get(t).unwrap())
                                               .collect();

      let total_asset = converted_asset.iter().sum::<Scalar>() + public_asset_sum;

      let converted_lia: Vec<Scalar> =
        liability_set_values.unwrap()
                            .iter()
                            .map(|(a, t)| a * conversion_rates.get(t).unwrap())
                            .collect();
      let total_lia = converted_lia.iter().sum::<Scalar>() + public_liability_sum;

      Some(total_asset - total_lia)
    }
    None => None,
  };

  let num_gates_range_proof = super::gadgets::range_proof(cs, diff_var, diff_value)?;

  Ok(num_gates_asset + num_gates_lia + num_gates_range_proof)
}

/// I aggregate a list of values using a rate conversion version table.
fn aggregate<CS: RandomizableConstraintSystem>(cs: &mut CS,
                                               vars: &[(Variable, Variable)],
                                               values: Option<&[(Scalar, Scalar)]>,
                                               rate_types: &[Scalar],
                                               rate_values: &[Scalar])
                                               -> Result<(LinearCombination, usize), R1CSError> {
  let l = vars.len();
  if l <= 1 {
    return Ok((LinearCombination::default(), 0));
  }

  let (sorted_vars, mid_vars, added_vars, trimmed_vars) = match values {
    Some(values) => {
      //prover allocate variables
      let sorted_values = sort(values, &rate_types[..]);
      let (mid_values, added_values) = add(&sorted_values[..]);
      let trimmed_values = trim(&added_values[..]);

      (allocate_vector(cs, &sorted_values),
       allocate_vector(cs, &mid_values),
       allocate_vector(cs, &added_values),
       allocate_vector(cs, &trimmed_values))
    }
    None => {
      //verifier creates variables
      ((0..l).map(|_| (cs.allocate(None).unwrap(), cs.allocate(None).unwrap()))
             .collect(),
       (0..l - 2).map(|_| (cs.allocate(None).unwrap(), cs.allocate(None).unwrap()))
                 .collect(),
       (0..l).map(|_| (cs.allocate(None).unwrap(), cs.allocate(None).unwrap()))
             .collect(),
       (0..l).map(|_| (cs.allocate(None).unwrap(), cs.allocate(None).unwrap()))
             .collect())
    }
  };

  let mut total = LinearCombination::default();
  for i in 0..rate_values.len() {
    let value = trimmed_vars[i].0;
    let value_type = trimmed_vars[i].1;
    let rate = rate_values[i];
    let rate_type = rate_types[i];
    let (_, _, out) = cs.multiply(value.into(), rate.into());
    cs.constrain(value_type - rate_type);
    total = total + out;
  }
  // prove addition of same flavor
  let n_mix = super::gadgets::list_mix(cs, &sorted_vars[..], &mid_vars[..], &added_vars[..])?;
  // prove first shuffle
  let n_shuffle1 = super::gadgets::pair_list_shuffle(cs, vars.to_vec(), sorted_vars)?;
  // prove second shiffled (zeroed values places at the end of the list)
  let n_shuffle2 = super::gadgets::pair_list_shuffle(cs, added_vars, trimmed_vars)?;
  Ok((total, 6 * l + 2 * (l - 2) + rate_values.len() + n_mix + n_shuffle1 + n_shuffle2))
}

/// I sort the pairs in values by the order the second coordinate appears in type_list
#[allow(clippy::type_complexity)]
fn sort(values: &[(Scalar, Scalar)], type_list: &[Scalar]) -> Vec<(Scalar, Scalar)> {
  let mut sorted = vec![];
  for key in type_list.iter() {
    for (a, t) in values {
      if t == key {
        sorted.push((*a, *t));
      }
    }
  }
  sorted
}

/// Given a sorted by type list, I add the amounts of same type pairs in the list,
/// zeroing out values and types already aggregated into another value
#[allow(clippy::type_complexity)]
fn add(list: &[(Scalar, Scalar)]) -> (Vec<(Scalar, Scalar)>, Vec<(Scalar, Scalar)>) {
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

/// I shuffle values to that zeroed values are placed in the tail of the list
/// while maintaining the order of the non-zero type elements
fn trim(values: &[(Scalar, Scalar)]) -> Vec<(Scalar, Scalar)> {
  let l = values.len();
  let mut trimmed = Vec::with_capacity(l);
  let mut rest = vec![];

  for (amount, asset_type) in &values[0..l] {
    if *asset_type != Scalar::zero() {
      trimmed.push((*amount, *asset_type));
    } else {
      rest.push((Scalar::zero(), Scalar::zero()));
    }
  }
  trimmed.append(&mut rest);
  trimmed
}

pub(super) fn allocate_vector<CS: RandomizableConstraintSystem>(cs: &mut CS,
                                                                list: &[(Scalar, Scalar)])
                                                                -> Vec<(Variable, Variable)> {
  let mut list_var = Vec::with_capacity(list.len());
  for (amount, asset_type) in list {
    let amount_var = cs.allocate(Some(*amount)).unwrap();
    let asset_var = cs.allocate(Some(*asset_type)).unwrap();
    list_var.push((amount_var, asset_var));
  }
  list_var
}

#[cfg(test)]
mod test {
  use bulletproofs::r1cs::{Prover, Variable, Verifier};
  use bulletproofs::{BulletproofGens, PedersenGens};
  use curve25519_dalek::ristretto::CompressedRistretto;
  use curve25519_dalek::scalar::Scalar;
  use linear_map::LinearMap;
  use merlin::Transcript;

  #[test]
  fn sort() {
    let values = [(Scalar::from(30u8), Scalar::from(3u8)),
                  (Scalar::from(10u8), Scalar::from(1u8)),
                  (Scalar::from(20u8), Scalar::from(2u8)),
                  (Scalar::from(10u8), Scalar::from(1u8)),
                  (Scalar::from(10u8), Scalar::from(1u8)),
                  (Scalar::from(30u8), Scalar::from(3u8)),
                  (Scalar::from(30u8), Scalar::from(3u8))];

    let t = [Scalar::from(3u8), Scalar::from(2u8), Scalar::from(1u8)];

    let sorted = super::sort(&values, &t);
    let expected = [(Scalar::from(30u8), Scalar::from(3u8)),
                    (Scalar::from(30u8), Scalar::from(3u8)),
                    (Scalar::from(30u8), Scalar::from(3u8)),
                    (Scalar::from(20u8), Scalar::from(2u8)),
                    (Scalar::from(10u8), Scalar::from(1u8)),
                    (Scalar::from(10u8), Scalar::from(1u8)),
                    (Scalar::from(10u8), Scalar::from(1u8))];
    assert_eq!(&sorted[..], &expected[..]);
  }

  #[test]
  fn add() {
    let values = [(Scalar::from(30u8), Scalar::from(3u8)),
                  (Scalar::from(30u8), Scalar::from(3u8)),
                  (Scalar::from(30u8), Scalar::from(3u8)),
                  (Scalar::from(20u8), Scalar::from(2u8)),
                  (Scalar::from(10u8), Scalar::from(1u8)),
                  (Scalar::from(10u8), Scalar::from(1u8)),
                  (Scalar::from(10u8), Scalar::from(1u8))];

    let (_, added) = super::add(&values);
    let expected = [(Scalar::from(0u8), Scalar::from(0u8)),
                    (Scalar::from(0u8), Scalar::from(0u8)),
                    (Scalar::from(90u8), Scalar::from(3u8)),
                    (Scalar::from(20u8), Scalar::from(2u8)),
                    (Scalar::from(0u8), Scalar::from(0u8)),
                    (Scalar::from(0u8), Scalar::from(0u8)),
                    (Scalar::from(30u8), Scalar::from(1u8))];

    assert_eq!(&added[..], &expected[..]);
  }

  #[test]
  fn trim() {
    let values = [(Scalar::from(0u8), Scalar::from(0u8)),
                  (Scalar::from(0u8), Scalar::from(0u8)),
                  (Scalar::from(90u8), Scalar::from(3u8)),
                  (Scalar::from(20u8), Scalar::from(2u8)),
                  (Scalar::from(0u8), Scalar::from(0u8)),
                  (Scalar::from(0u8), Scalar::from(0u8)),
                  (Scalar::from(30u8), Scalar::from(1u8))];

    let trimmed = super::trim(&values);
    let expected = [(Scalar::from(90u8), Scalar::from(3u8)),
                    (Scalar::from(20u8), Scalar::from(2u8)),
                    (Scalar::from(30u8), Scalar::from(1u8)),
                    (Scalar::from(0u8), Scalar::from(0u8)),
                    (Scalar::from(0u8), Scalar::from(0u8)),
                    (Scalar::from(0u8), Scalar::from(0u8)),
                    (Scalar::from(0u8), Scalar::from(0u8))];

    assert_eq!(&trimmed[..], &expected[..]);
  }

  #[test]
  fn test_solvency() {
    let pc_gens = PedersenGens::default();
    let mut rates = LinearMap::new();
    rates.insert(Scalar::from(1u8), Scalar::from(1u8));
    rates.insert(Scalar::from(2u8), Scalar::from(2u8));
    rates.insert(Scalar::from(3u8), Scalar::from(3u8));
    let asset_set = [
            (Scalar::from(10u8), Scalar::from(1u8)), //total 10
            (Scalar::from(10u8), Scalar::from(2u8)), //total 20
            (Scalar::from(10u8), Scalar::from(2u8)), //total 20
            (Scalar::from(10u8), Scalar::from(1u8)), //total 10
            (Scalar::from(10u8), Scalar::from(3u8)), //total 30
            (Scalar::from(10u8), Scalar::from(1u8)), //total 10
            (Scalar::from(10u8), Scalar::from(1u8)), //total 10, total asset worth = 100
        ];

    let liability_set = [
            (Scalar::from(2u8), Scalar::from(2u8)), // total 4
            (Scalar::from(8u8), Scalar::from(2u8)),  // total 16
            (Scalar::from(10u8), Scalar::from(1u8)), // total 10
            (Scalar::from(20u8), Scalar::from(3u8)), // total 60
            (Scalar::from(10u8), Scalar::from(1u8)), // total 10
        ];

    let mut prover_transcript = Transcript::new(b"test");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    let asset_com_vars: Vec<(CompressedRistretto, CompressedRistretto, Variable, Variable)> =
      asset_set.iter()
               .map(|(a, t)| {
                 let (a_com, a_var) = prover.commit(*a, Scalar::from(1u8));
                 let (t_com, t_var) = prover.commit(*t, Scalar::from(2u8));
                 (a_com, t_com, a_var, t_var)
               })
               .collect();
    let asset_com: Vec<(CompressedRistretto, CompressedRistretto)> =
      asset_com_vars.iter().map(|(a, t, _, _)| (*a, *t)).collect();
    let asset_var: Vec<(Variable, Variable)> =
      asset_com_vars.iter().map(|(_, _, a, t)| (*a, *t)).collect();

    let lia_com_vars: Vec<(CompressedRistretto, CompressedRistretto, Variable, Variable)> =
      liability_set.iter()
                   .map(|(a, t)| {
                     let (a_com, a_var) = prover.commit(*a, Scalar::from(3u8));
                     let (t_com, t_var) = prover.commit(*t, Scalar::from(4u8));
                     (a_com, t_com, a_var, t_var)
                   })
                   .collect();
    let lia_com: Vec<(CompressedRistretto, CompressedRistretto)> =
      lia_com_vars.iter().map(|(a, t, _, _)| (*a, *t)).collect();
    let lia_var: Vec<(Variable, Variable)> =
      lia_com_vars.iter().map(|(_, _, a, t)| (*a, *t)).collect();

    let num_left_wires = super::solvency(&mut prover,
                                         &asset_var[..],
                                         Some(&asset_set),
                                         Scalar::zero(),
                                         &lia_var[..],
                                         Some(&liability_set),
                                         Scalar::zero(),
                                         &rates).unwrap();
    let bp_gens = BulletproofGens::new(num_left_wires.next_power_of_two(), 1);
    let proof = prover.prove(&bp_gens).unwrap();

    let mut verifier_transcript = Transcript::new(b"test");
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let asset_var: Vec<(Variable, Variable)> =
      asset_com.iter()
               .map(|(a, t)| (verifier.commit(*a), verifier.commit(*t)))
               .collect();

    let lia_var: Vec<(Variable, Variable)> =
      lia_com.iter()
             .map(|(a, t)| (verifier.commit(*a), verifier.commit(*t)))
             .collect();

    let num_left_wires = super::solvency(&mut verifier,
                                         &asset_var[..],
                                         None,
                                         Scalar::zero(),
                                         &lia_var[..],
                                         None,
                                         Scalar::zero(),
                                         &rates).unwrap();
    let bp_gens = BulletproofGens::new(num_left_wires.next_power_of_two(), 1);
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
  }
}
