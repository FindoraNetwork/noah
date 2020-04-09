/*
* This file implements the Cloak protocol for multiple confidential asset transactions.
* The protocol proves that
* 1) output amounts are in [0..2^64-1],
* 2) for each asset type, input amount equals output amount
*
* Prover first sorts by inputs and outputs by asset types, and proves that sorted lists are a permutation
* of input and output respectively. Then the sorted list are "merged", for each asset type we add up its amount into
* a single record, zeroing-out the rest. Then, the merged input or merged output list is padded
* with zero values so that they are of the same length.
* Having same length, do a third permutation proof, proving that input and output are equal once
* values of the same type are added.
* Also, we append a range proof on each output value.
*
* Soundness note: Note that the prover may produce any permutation, and not necessarily a sorted one.
* This doesn't help him as he
* 1) permutation ensures he is not faking on any value.
* 2) The "merge" proof ensures that only same asset types amounts are added

* Permutation proof:
* 1) For each record, (amount, asset type) produce a single variable (amount  + r * asset_type).
* 2) To prove that a list is a permutation of another list, we build a circuit that test if the product of the values
match on each list. On each product the elements are shifted by a random challenge.

* Merge proof:
* Given a sorted list of length n, the proof proceed by looking at consecutive pairs in1, in2
* proving that respective output out1 and out2 are either
*  + the same as in1 and in2, or
*  +  - in1 and in2 have the same asset type, and
      - out 1 is zero, and
      - out2 asset type matched inputs asset type
      - out2 amounts is the addition of the input amounts.
* To have a final output list with all amounts aggregates by asset type,
* the prover produces an intermediate list of length l - 2 storing the second output out2 of the previous description
* Hence, each intermediate value is used as in1, and each input (except first) is used as in2.
* Also, each intermediate value is used as out2, and each output is used as out1.
* Notes:
  - The fist in1 is actually input[0]
  - The last intermediate value is appended to the output list.
*/

use crate::errors::ZeiError;
use bulletproofs::r1cs::{
  ConstraintSystem, Prover, R1CSError, RandomizableConstraintSystem, Variable, Verifier,
};
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

/// Represent AssetRecord amount and asset type
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CloakValue {
  pub amount: Scalar,
  pub asset_type: Scalar,
}

impl CloakValue {
  pub fn new(amount: Scalar, asset_type: Scalar) -> CloakValue {
    CloakValue { amount, asset_type }
  }
}

impl CloakValue {
  /// Prover commits to amount and asset type using user provided blinding factors
  /// Returns commitments and circuit variables
  pub fn commit_prover(&self,
                       prover: &mut Prover,
                       blinds: &CloakValue)
                       -> (CloakCommitment, CloakVariable) {
    let (amount_com, amount_var) = prover.commit(self.amount, blinds.amount);
    let (asset_type_com, asset_type_var) = prover.commit(self.asset_type, blinds.asset_type);
    (CloakCommitment { amount: amount_com,
                       asset_type: asset_type_com },
     CloakVariable { amount: amount_var,
                     asset_type: asset_type_var })
  }
  pub fn commit(&self, pc_gens: &PedersenGens, blinds: &CloakValue) -> CloakCommitment {
    CloakCommitment { amount: pc_gens.commit(self.amount, blinds.amount).compress(),
                      asset_type: pc_gens.commit(self.asset_type, blinds.asset_type)
                                         .compress() }
  }
}

/// Represent a CloakValue variable in the circuit
#[derive(Clone, Copy, Debug)]
pub struct CloakVariable {
  pub amount: Variable,
  pub asset_type: Variable,
}

/// Represent a commitment Cloak value.
#[derive(Clone, Copy)]
pub struct CloakCommitment {
  pub amount: CompressedRistretto,
  pub asset_type: CompressedRistretto,
}

impl CloakCommitment {
  /// Verifier produce circuit variables corresponding to this commitment
  pub fn commit_verifier(&self, verifier: &mut Verifier) -> CloakVariable {
    CloakVariable { amount: verifier.commit(self.amount),
                    asset_type: verifier.commit(self.asset_type) }
  }
}

/// Implement the Cloak protocol, run by prover and verifier to prove that
/// 1) output values in [0..2^64(
/// 2) Once amounts are aggregated by asset type, input and output matches.
pub fn cloak<CS: RandomizableConstraintSystem>(cs: &mut CS,
                                               input_vars: &[CloakVariable],
                                               input_values: Option<&[CloakValue]>,
                                               output_vars: &[CloakVariable],
                                               output_values: Option<&[CloakValue]>)
                                               -> Result<usize, ZeiError> {
  let input_len = input_vars.len();
  let output_len = output_vars.len();

  assert!(input_len > 0 && output_len > 0 || output_len == input_len);
  if output_len == 0 {
    // nothing to prove
    return Ok(0usize);
  }
  let mut n_gates = 0;

  // sort and merge values by type
  let (n, mut merged_input_vars) = sort_and_merge(cs, input_vars, input_values)?;
  let (m, mut merged_output_vars) = sort_and_merge(cs, output_vars, output_values)?;

  n_gates += n + m;

  // pad input or output to be of same length
  let pad_value = input_values.map(|_| Scalar::zero());
  if input_len < output_len {
    pad(cs, output_len, &mut merged_input_vars, pad_value).map_err(|_| ZeiError::R1CSProofError)?;
  } else {
    pad(cs, input_len, &mut merged_output_vars, pad_value).map_err(|_| ZeiError::R1CSProofError)?;
  }

  // do a proof of shuffle
  n_gates +=
    super::gadgets::cloak_shuffle_gadget(cs, merged_input_vars, merged_output_vars).map_err(|_| {
                                                                       ZeiError::R1CSProofError
                                                                     })?;

  // final range proof:
  for (i, out) in output_vars.iter().enumerate() {
    super::gadgets::range_proof_64(
      cs,
      out.amount.into(),
      output_values.map(|out_values| out_values[i].amount))
      .map_err(|_| ZeiError::R1CSProofError)?;
  }

  Ok(n_gates)
}

// Pad list with with value to expected len
fn pad<CS: ConstraintSystem>(cs: &mut CS,
                             expected_len: usize,
                             list: &mut Vec<CloakVariable>,
                             value: Option<Scalar>)
                             -> Result<(), R1CSError> {
  for _ in list.len()..expected_len {
    list.push(CloakVariable { amount: cs.allocate(value)?,
                              asset_type: cs.allocate(value)? })
  }
  Ok(())
}

// sorts the input list by asset_type, in order of appearance in the list
fn sort(input: &[CloakValue]) -> Vec<CloakValue> {
  let mut sorted_values = input.to_vec();
  let mut i = 0;
  while i < input.len() {
    let asset_type = input[i].asset_type;
    let mut swap_index = input.len() - 1;
    let mut j = i + 1;
    while j < swap_index {
      if asset_type == sorted_values[j].asset_type {
        j += 1;
      } else {
        sorted_values.swap(j, swap_index);
        swap_index -= 1;
      }
    }
    i = j;
  }
  sorted_values
}

// Aggregate amounts of consecutive CloakValues if asset_types match
// Return vec 0 correspond to intermediate values storing the result
// of each current pair. That is, intermediate[i] = Merge(intermediate[i-1], input[i])[1]
// Where intermediate[0] = input[0]
// Return vec 1 is the final aggregated values. That is output[i] = Merge(intermediate[i-1], input[i])[0]
// Where output[l-1] = intermediate[l-1];
// Intermediate list is of length (l-2) ( all intermediate produced except last)
// Output list is of length l (all outputs plus last intermediate)
pub(super) fn merge(sorted: &[CloakValue]) -> (Vec<CloakValue>, Vec<CloakValue>) {
  let mut intermediate = vec![];
  let mut merged = vec![];
  let mut prev = sorted[0];
  let len = sorted.len();
  if len == 0 {
    return (intermediate, merged);
  }
  if len == 1 {
    return (intermediate, sorted.to_vec());
  }
  for value in sorted[1..].iter() {
    if value.asset_type == prev.asset_type {
      merged.push(CloakValue::new(Scalar::zero(), Scalar::zero()));
      intermediate.push(CloakValue::new(prev.amount + value.amount, value.asset_type));
      prev.amount += value.amount;
    } else {
      merged.push(prev);
      intermediate.push(*value);
      prev = *value;
    }
  }
  merged.push(intermediate.pop().unwrap());
  (intermediate, merged)
}

// Implements the sort and merge steps of the Cloak protocol
pub(super) fn sort_and_merge<CS: RandomizableConstraintSystem>(
  cs: &mut CS,
  vars: &[CloakVariable],
  values: Option<&[CloakValue]>)
  -> Result<(usize, Vec<CloakVariable>), ZeiError> {
  let len = vars.len();
  if len == 0 {
    return Ok((0, vec![]));
  }
  if len == 1 {
    let v = values.map(|v| v.to_vec());
    let vars = allocate_cloak_vector(cs, v.as_ref(), 1)?;
    return Ok((0, vars));
  }
  let mut n_gates = 0;
  let sorted_values = values.map(|v| sort(v));
  let merged_values = sorted_values.as_ref()
                                   .map(|sorted| merge(sorted.as_slice()));
  let sorted_vars = allocate_cloak_vector(cs, sorted_values.as_ref(), len)?;
  let intermediate_vars =
    allocate_cloak_vector(cs,
                          merged_values.as_ref().map(|(intermediate, _)| intermediate),
                          len - 2)?;
  let merged_vars =
    allocate_cloak_vector(cs, merged_values.as_ref().map(|(_, merged)| merged), len)?;

  n_gates +=
    super::gadgets::cloak_shuffle_gadget(cs, vars.to_vec(), sorted_vars.clone()).map_err(|_| ZeiError::R1CSProofError)?;
  n_gates +=
    super::gadgets::cloak_merge_gadget(cs, &sorted_vars, &intermediate_vars, &merged_vars).map_err(|_| {
      ZeiError::R1CSProofError
    })?;

  Ok((n_gates, merged_vars))
}

pub(crate) fn allocate_cloak_vector<CS: ConstraintSystem>(
  cs: &mut CS,
  list: Option<&Vec<CloakValue>>,
  len: usize)
  -> Result<Vec<CloakVariable>, ZeiError> {
  Ok(match list {
       None => {
         let mut v = vec![];
         for _ in 0..len {
           v.push(CloakVariable { amount: cs.allocate(None)
                                            .map_err(|_| ZeiError::R1CSProofError)?,
                                  asset_type: cs.allocate(None)
                                                .map_err(|_| ZeiError::R1CSProofError)? });
         }
         v
       }
       Some(values) => {
         let mut vars = vec![];
         for v in values.iter() {
           vars.push(CloakVariable { amount: cs.allocate(Some(v.amount))
                                               .map_err(|_| ZeiError::R1CSProofError)?,
                                     asset_type: cs.allocate(Some(v.asset_type))
                                                   .map_err(|_| ZeiError::R1CSProofError)? });
         }
         vars
       }
     })
}

#[cfg(test)]
mod tests {
  use crate::crypto::bp_circuits::cloak::{CloakCommitment, CloakValue};
  use bulletproofs::r1cs::{Prover, R1CSProof, Verifier};
  use bulletproofs::{BulletproofGens, PedersenGens};
  use curve25519_dalek::scalar::Scalar;
  use itertools::Itertools;
  use merlin::Transcript;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn merge() {
    let values = vec![CloakValue::new(Scalar::from(30u8), Scalar::from(3u8)),
                      CloakValue::new(Scalar::from(30u8), Scalar::from(3u8)),
                      CloakValue::new(Scalar::from(30u8), Scalar::from(3u8)),
                      CloakValue::new(Scalar::from(20u8), Scalar::from(2u8)),
                      CloakValue::new(Scalar::from(10u8), Scalar::from(1u8)),
                      CloakValue::new(Scalar::from(10u8), Scalar::from(1u8)),
                      CloakValue::new(Scalar::from(10u8), Scalar::from(1u8))];

    let (_, added) = super::merge(&values);
    let expected = vec![CloakValue::new(Scalar::from(0u8), Scalar::from(0u8)),
                        CloakValue::new(Scalar::from(0u8), Scalar::from(0u8)),
                        CloakValue::new(Scalar::from(90u8), Scalar::from(3u8)),
                        CloakValue::new(Scalar::from(20u8), Scalar::from(2u8)),
                        CloakValue::new(Scalar::from(0u8), Scalar::from(0u8)),
                        CloakValue::new(Scalar::from(0u8), Scalar::from(0u8)),
                        CloakValue::new(Scalar::from(30u8), Scalar::from(1u8))];

    assert_eq!(&added[..], &expected[..]);
  }

  fn test_cloak(inputs: &[CloakValue],
                outputs: &[CloakValue],
                pass: bool,
                bp_gens: &BulletproofGens) {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let input_coms: Vec<CloakCommitment>;
    let output_coms: Vec<CloakCommitment>;
    let pc_gens = PedersenGens::default();
    let proof: R1CSProof;
    {
      // prover scope

      let mut prover_transcript = Transcript::new(b"test");
      let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
      let in_com_and_vars = inputs.iter()
                                  .map(|input| {
                                    input.commit_prover(&mut prover,
                                                        &CloakValue::new(Scalar::random(&mut prng),
                                                                         Scalar::random(&mut prng)))
                                  })
                                  .collect_vec();
      input_coms = in_com_and_vars.iter().map(|(com, _)| *com).collect_vec();
      let input_vars = in_com_and_vars.iter().map(|(_, var)| *var).collect_vec();

      let out_com_and_vars = outputs.iter()
                                    .map(|output| {
                                      output.commit_prover(&mut prover,
                                      &CloakValue::new(Scalar::random(&mut prng),
                                                       Scalar::random(&mut prng)))
                                    })
                                    .collect_vec();
      output_coms = out_com_and_vars.iter().map(|(com, _)| *com).collect_vec();
      let output_vars = out_com_and_vars.iter().map(|(_, var)| *var).collect_vec();

      let n_gates = super::cloak(&mut prover,
                                 &input_vars,
                                 Some(inputs),
                                 &output_vars,
                                 Some(outputs)).unwrap();

      assert!(n_gates <= bp_gens.gens_capacity,
              format!("Increase number of bp generators to {}",
                      n_gates.next_power_of_two()));

      proof = prover.prove(&bp_gens).unwrap();
    }
    {
      // verifier scope
      let mut verifier_transcript = Transcript::new(b"test");
      let mut verifier = Verifier::new(&mut verifier_transcript);
      let in_vars = input_coms.iter()
                              .map(|input| input.commit_verifier(&mut verifier))
                              .collect_vec();

      let out_vars = output_coms.iter()
                                .map(|output| output.commit_verifier(&mut verifier))
                                .collect_vec();

      super::cloak(&mut verifier, &in_vars, None, &out_vars, None).unwrap();

      assert_eq!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok(), pass);
    }
  }
  #[test]
  fn cloak() {
    let bp_gens = BulletproofGens::new(10000, 1);
    test_cloak(&[], &[], true, &bp_gens);

    let asset_type0 = Scalar::from(0u8);
    let v_10_0 = CloakValue::new(Scalar::from(10u8), asset_type0);
    test_cloak(&[v_10_0], &[v_10_0], true, &bp_gens);
    let v_20_0 = CloakValue::new(Scalar::from(20u8), asset_type0);
    test_cloak(&[v_20_0], &[v_10_0, v_10_0], true, &bp_gens);
    test_cloak(&[v_10_0, v_10_0], &[v_20_0], true, &bp_gens);
    test_cloak(&[v_10_0, v_10_0, v_20_0], &[v_20_0, v_20_0], true, &bp_gens);
    test_cloak(&[v_10_0, v_20_0], &[v_20_0, v_20_0], false, &bp_gens);

    let asset_type1 = Scalar::from(1u8);
    let v_10_1 = CloakValue::new(Scalar::from(10u8), asset_type1);
    test_cloak(&[v_10_1], &[v_10_1], true, &bp_gens);
    test_cloak(&[v_10_1, v_20_0], &[v_10_1, v_20_0], true, &bp_gens);
    test_cloak(&[v_10_1, v_20_0, v_10_1, v_20_0],
               &[v_10_1, v_20_0, v_10_1, v_20_0],
               true,
               &bp_gens);
    let v_0_1 = CloakValue::new(Scalar::from(0u8), asset_type1);
    let v_0_0 = CloakValue::new(Scalar::from(0u8), asset_type0);
    test_cloak(&[v_0_1, v_0_1, v_10_1, v_20_0, v_10_1, v_20_0],
               &[v_10_1, v_20_0, v_10_1, v_0_0, v_20_0],
               true,
               &bp_gens);

    // make range proof fail
    let v_1_0 = CloakValue::new(Scalar::from(1u8), asset_type0);
    let amount_2_63 = Scalar::from(1u64 << 63);
    let amount_2_63_minus1: Scalar = amount_2_63 - Scalar::one();
    let v_out_pos = CloakValue::new(amount_2_63, asset_type0);
    let v_out_neg = CloakValue::new(-amount_2_63_minus1, asset_type0);
    assert_eq!(amount_2_63 - amount_2_63_minus1, Scalar::one());
    test_cloak(&[v_1_0], &[v_out_pos, v_out_neg], false, &bp_gens);
  }
}
