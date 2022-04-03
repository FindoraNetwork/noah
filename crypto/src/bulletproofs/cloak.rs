//! This file implements the Cloak protocol for multiple confidential asset transactions.
//! The protocol proves that
//! 1) output amounts are in [0..2^64-1],
//! 2) for each asset type, input amount equals output amount
//!
//! Prover first sorts by inputs and outputs by asset types, and proves that sorted lists
//! are a permutation of input and output respectively. Then the sorted list are "merged",
//! for each asset type we add up its amount into a single record, zeroing-out the rest.
//! Then, the merged input or merged output list is padded with zero values so that they
//! are of the same length.
//! Having same length, do a third permutation proof, proving that input and output are
//! equal once values of the same type are added.
//! Also, we append a range proof on each output value.
//!
//! Soundness note: Note that the prover may produce any permutation, and not necessarily
//! a sorted one.
//! This doesn't help him as he
//! 1) permutation ensures he is not faking on any value.
//! 2) The "merge" proof ensures that only same asset types amounts are added

//! Permutation proof:
//! 1) For each record, (amount, asset type) produce a single variable (amount  + r * asset_type).
//! 2) To prove that a list is a permutation of another list, we build a circuit that test
//! if the product of the values match on each list. On each product the elements are shifted
//! by a random challenge.
//!
//! Merge proof:
//! Given a sorted list of length n, the proof proceed by looking at consecutive pairs in1, in2
//! proving that respective output out1 and out2 are either
//!  - the same as in1 and in2, or
//!  - in1 and in2 have the same asset type, and
//!    - out 1 is zero, and
//!    - out2 asset type matched inputs asset type
//!    - out2 amounts is the addition of the input amounts.
//! To have a final output list with all amounts aggregates by asset type,
//! the prover produces an intermediate list of length l - 2 storing the second output out2
//! of the previous description
//! Hence, each intermediate value is used as in1, and each input (except first) is used as in2.
//! Also, each intermediate value is used as out2, and each output is used as out1.
//! Notes:
//!  - The fist in1 is actually input[0]
//!  - The last intermediate value is appended to the output list.

use crate::basic::ristretto_pedersen_comm::RistrettoPedersenCommitment;
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, Prover, R1CSError, RandomizableConstraintSystem,
    RandomizedConstraintSystem, Variable, Verifier,
};
use merlin::Transcript;
use std::iter;
use zei_algebra::{
    prelude::*,
    ristretto::{CompressedRistretto, RistrettoScalar as Scalar},
    traits::Scalar as _,
};

/// Represent AssetRecord amount and asset type
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloakValue {
    /// Represent the amount
    pub amount: Scalar,
    /// Represent the asset type
    pub asset_type: Scalar,
}

impl CloakValue {
    /// Create an AssetRecord
    pub fn new(amount: Scalar, asset_type: Scalar) -> CloakValue {
        CloakValue { amount, asset_type }
    }

    /// Prover commits to amount and asset type using user provided blinding factors.
    /// Returns commitments and circuit variables
    pub fn commit_prover(
        &self,
        prover: &mut Prover<&mut Transcript>,
        blinds: &CloakValue,
    ) -> (CloakCommitment, CloakVariable) {
        let (amount_com, amount_var) = prover.commit(self.amount.0, blinds.amount.0);
        let (asset_type_com, asset_type_var) =
            prover.commit(self.asset_type.0, blinds.asset_type.0);
        (
            CloakCommitment {
                amount: CompressedRistretto(amount_com),
                asset_type: CompressedRistretto(asset_type_com),
            },
            CloakVariable {
                amount: amount_var,
                asset_type: asset_type_var,
            },
        )
    }

    /// Commit to amount and asset type using user provided blinding factors.
    pub fn commit(
        &self,
        pc_gens: &RistrettoPedersenCommitment,
        blinds: &CloakValue,
    ) -> CloakCommitment {
        CloakCommitment {
            amount: pc_gens.commit(self.amount, blinds.amount).compress(),
            asset_type: pc_gens
                .commit(self.asset_type, blinds.asset_type)
                .compress(),
        }
    }
}

/// Represent a CloakValue variable in the circuit
#[derive(Clone, Copy, Debug)]
pub struct CloakVariable {
    /// Represent the amount variable
    pub amount: Variable,
    /// Represent the asset type variable
    pub asset_type: Variable,
}

/// Represent a commitment Cloak value.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct CloakCommitment {
    /// Represent the amount commitment
    pub amount: CompressedRistretto,
    /// Represent the asset type commitment
    pub asset_type: CompressedRistretto,
}

impl CloakCommitment {
    /// Verifier produce circuit variables corresponding to this commitment
    pub fn commit_verifier(&self, verifier: &mut Verifier<&mut Transcript>) -> CloakVariable {
        CloakVariable {
            amount: verifier.commit(self.amount.0),
            asset_type: verifier.commit(self.asset_type.0),
        }
    }
}

/// Implement the Cloak protocol, run by prover and verifier to prove that
/// 1) output values in [0..2^64(
/// 2) Once amounts are aggregated by asset type, input and output matches.
pub fn cloak<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    input_vars: &[CloakVariable],
    input_values: Option<&[CloakValue]>,
    output_vars: &[CloakVariable],
    output_values: Option<&[CloakValue]>,
) -> Result<usize> {
    let input_len = input_vars.len();
    let output_len = output_vars.len();

    assert!(input_len > 0 && output_len > 0 || output_len == input_len);
    if output_len == 0 {
        // nothing to prove
        return Ok(0usize);
    }
    let mut n_gates = 0;

    // sort and merge values by type
    let (n, mut merged_input_vars) = sort_and_merge(cs, input_vars, input_values).c(d!())?;
    let (m, mut merged_output_vars) = sort_and_merge(cs, output_vars, output_values).c(d!())?;

    n_gates += n + m;

    // pad input or output to be of same length
    let pad_value = input_values.map(|_| Scalar::zero());
    if input_len < output_len {
        pad(cs, output_len, &mut merged_input_vars, pad_value).c(d!(ZeiError::R1CSProofError))?;
    } else {
        pad(cs, input_len, &mut merged_output_vars, pad_value).c(d!(ZeiError::R1CSProofError))?;
    }

    // do a proof of shuffle
    n_gates += cloak_shuffle_gadget(cs, merged_input_vars, merged_output_vars)
        .c(d!(ZeiError::R1CSProofError))?;

    // final range proof:
    for (i, out) in output_vars.iter().enumerate() {
        n_gates += range_proof_64(
            cs,
            out.amount.into(),
            output_values.map(|out_values| out_values[i].amount),
        )
        .c(d!(ZeiError::R1CSProofError))?;
    }

    Ok(n_gates)
}

/// Pad list with with value to expected len
fn pad<CS: ConstraintSystem>(
    cs: &mut CS,
    expected_len: usize,
    list: &mut Vec<CloakVariable>,
    value: Option<Scalar>,
) -> Result<()> {
    for _ in list.len()..expected_len {
        list.push(CloakVariable {
            amount: cs.allocate(value.map(|x| x.0)).c(d!())?,
            asset_type: cs.allocate(value.map(|x| x.0)).c(d!())?,
        })
    }
    Ok(())
}

/// sorts the input list by asset_type
fn sort(input: &[CloakValue]) -> Vec<CloakValue> {
    let mut sorted_values = input.to_vec();
    let mut i = 0;
    while i < input.len() {
        let asset_type = sorted_values[i].asset_type;
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

/// Aggregate amounts of consecutive CloakValues if asset_types match
/// Return vec 0 correspond to intermediate values storing the result
/// of each current pair. That is, intermediate[i] = Merge(intermediate[i-1], input[i])[1]
/// Where intermediate[0] = input[0]. Return vec 1 is the final aggregated values.
/// That is output[i] = Merge(intermediate[i-1], input[i])[0]
/// Where output[l-1] = intermediate[l-1];
/// Intermediate list is of length (l-2) ( all intermediate produced except last)
/// Output list is of length l (all outputs plus last intermediate)
fn merge(sorted: &[CloakValue]) -> (Vec<CloakValue>, Vec<CloakValue>) {
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
            intermediate.push(CloakValue::new(
                prev.amount.add(&value.amount),
                value.asset_type,
            ));
            prev.amount = prev.amount.add(&value.amount);
        } else {
            merged.push(prev);
            intermediate.push(*value);
            prev = *value;
        }
    }
    merged.push(intermediate.pop().unwrap()); // safe unwrap
    (intermediate, merged)
}

/// Implements the sort and merge steps of the Cloak protocol
fn sort_and_merge<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    vars: &[CloakVariable],
    values: Option<&[CloakValue]>,
) -> Result<(usize, Vec<CloakVariable>)> {
    let len = vars.len();
    if len == 0 {
        return Ok((0, vec![]));
    }
    if len == 1 {
        let v = values.map(|v| v.to_vec());
        let vars = allocate_cloak_vector(cs, v.as_ref(), 1).c(d!())?;
        return Ok((0, vars));
    }
    let mut n_gates = 0;
    let sorted_values = values.map(sort);
    let merged_values = sorted_values
        .as_ref()
        .map(|sorted| merge(sorted.as_slice()));
    let sorted_vars = allocate_cloak_vector(cs, sorted_values.as_ref(), len).c(d!())?;
    let intermediate_vars = allocate_cloak_vector(
        cs,
        merged_values.as_ref().map(|(intermediate, _)| intermediate),
        len - 2,
    )
    .c(d!())?;
    let merged_vars =
        allocate_cloak_vector(cs, merged_values.as_ref().map(|(_, merged)| merged), len).c(d!())?;

    n_gates += cloak_shuffle_gadget(cs, vars.to_vec(), sorted_vars.clone())
        .c(d!(ZeiError::R1CSProofError))?;
    n_gates += cloak_merge_gadget(cs, &sorted_vars, &intermediate_vars, &merged_vars)
        .c(d!(ZeiError::R1CSProofError))?;

    Ok((n_gates, merged_vars))
}

/// Batch alloc cloak value
fn allocate_cloak_vector<CS: ConstraintSystem>(
    cs: &mut CS,
    list: Option<&Vec<CloakValue>>,
    len: usize,
) -> Result<Vec<CloakVariable>> {
    Ok(match list {
        None => {
            let mut v = vec![];
            for _ in 0..len {
                v.push(CloakVariable {
                    amount: cs.allocate(None).c(d!(ZeiError::R1CSProofError))?,
                    asset_type: cs.allocate(None).c(d!(ZeiError::R1CSProofError))?,
                });
            }
            v
        }
        Some(values) => {
            let mut vars = vec![];
            for v in values.iter() {
                vars.push(CloakVariable {
                    amount: cs
                        .allocate(Some(v.amount.0))
                        .c(d!(ZeiError::R1CSProofError))?,
                    asset_type: cs
                        .allocate(Some(v.asset_type.0))
                        .c(d!(ZeiError::R1CSProofError))?,
                });
            }
            vars
        }
    })
}

/// Implements the merge gadget of the Cloak protocol
fn cloak_merge_gadget<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    sorted: &[CloakVariable],
    intermediate: &[CloakVariable],
    merged: &[CloakVariable],
) -> Result<usize> {
    let in1 = sorted[0];
    let out1 = merged[0];
    let mut n_gates = 0;
    let l = sorted.len();
    if l == 0 {
        return Ok(0);
    }
    if l == 1 {
        // sorted and merges should be the same
        cs.constrain(in1.amount - out1.amount);
        cs.constrain(in1.asset_type - out1.asset_type);
        return Ok(0);
    }
    assert_eq!(l, merged.len());
    assert_eq!(l, intermediate.len() + 2);
    let first_in = sorted[0];
    let in1iter = iter::once(&first_in).chain(intermediate.iter());
    let in2iter = sorted[1..l].iter();
    let out1iter = merged[0..l - 1].iter();
    let out2iter = intermediate.iter().chain(iter::once(&merged[l - 1]));

    for (((in1, in2), out1), out2) in in1iter.zip(in2iter).zip(out1iter).zip(out2iter) {
        n_gates += gate_mix(cs, *in1, *in2, *out1, *out2).c(d!())?;
    }

    Ok(n_gates)
}

/// I implement the mix gate gadget, proving that either
/// in1 = out1 and in2 = out2  if in1 and in2 have different types or
/// out1 = 0 and out2 = in1 + in2 if in1 and in2 have same type
/// I return the number of left wires created
fn gate_mix<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    in1: CloakVariable,
    in2: CloakVariable,
    out1: CloakVariable,
    out2: CloakVariable,
) -> Result<usize> {
    cs.specify_randomized_constraints(move |cs| {
        let w1 = cs.challenge_scalar(b"mix challenge1");
        let w2 = cs.challenge_scalar(b"mix challenge2");
        let w3 = cs.challenge_scalar(b"mix challenge3");
        let (_, _, out) = cs.multiply(
            (in1.amount - out1.amount) +          // quantity maintains
                (in1.asset_type - out1.asset_type) * w1 + // asset type maintains in first input
                (in2.amount - out2.amount) * w2 + // quantity maintains
                (in2.asset_type - out2.asset_type) * w3, // asset type maintains in second input
            out1.amount + // or out1 is 0
                (in1.asset_type - in2.asset_type) * w1 + // or in flavors are equal
                (out2.amount - in1.amount - in2.amount) * w2 // or out2 is the sum of the inputs
                + (out2.asset_type - in1.asset_type) * w3, // in 1 and out2 have same asset type
        );
        cs.constrain(out.into());
        Ok(())
    })
    .c(d!())?;
    Ok(1usize)
}

/// Prove shuffling of a list of CloakValues
/// Return the number of gates created
fn cloak_shuffle_gadget<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    input: Vec<CloakVariable>,
    permuted: Vec<CloakVariable>,
) -> Result<usize> {
    let l = input.len();
    if l != permuted.len() {
        return Err(eg!(R1CSError::GadgetError {
            description: "list shuffle error, input and output list differ in length".to_string(),
        }));
    }
    if l == 0 {
        return Ok(0usize);
    }
    if l == 1 {
        cs.constrain(permuted[0].amount - input[0].amount);
        cs.constrain(permuted[0].asset_type - input[0].asset_type);
        return Ok(0usize);
    }

    cs.specify_randomized_constraints(move |cs| {
        let challenge = cs.challenge_scalar(b"k-value shuffle challenge");
        let mut single_input = Vec::with_capacity(l);
        let mut single_perm = Vec::with_capacity(l);

        for (in_var, perm_var) in input.iter().zip(permuted.iter()) {
            //compute a single representative for the pair
            let (single_in, single_pe, _) = cs.multiply(
                in_var.amount + challenge * in_var.asset_type,
                perm_var.amount + challenge * perm_var.asset_type,
            );
            single_input.push(single_in);
            single_perm.push(single_pe);
        }

        list_shuffle(cs, &single_input[..], &single_perm[..])
            .c(d!())
            .map_err(|e| R1CSError::GadgetError {
                description: e.to_string(),
            })
            .map(|_| ())
    })
    .c(d!())?;

    // list_shuffle does 2*(l-1) multiplications
    Ok(l + 2 * (l - 1))
}

/// Prove shuffling of a list of values
/// Return the number of left wires created
fn list_shuffle<CS: RandomizedConstraintSystem>(
    cs: &mut CS,
    input: &[Variable],
    permuted: &[Variable],
) -> Result<usize> {
    let l = input.len();
    if l != permuted.len() {
        return Err(eg!(R1CSError::GadgetError {
            description: "list shuffle error, input and output list differ in length".to_string(),
        }));
    }
    if l == 0 {
        return Ok(0usize);
    }
    if l == 1 {
        cs.constrain(permuted[0] - input[0]);
        return Ok(0usize);
    }

    let challenge = cs.challenge_scalar(b"shuffle challenge");

    // Make last x multiplier for i = l-1 and l-2
    let (_, _, last_mulx_out) = cs.multiply(input[l - 1] - challenge, input[l - 2] - challenge);

    // Make multipliers for x from i == [0, l-3]
    let first_mulx_out = (0..l - 2).rev().fold(last_mulx_out, |prev_out, i| {
        let (_, _, o) = cs.multiply(prev_out.into(), input[i] - challenge);
        o
    });

    // Make last y multiplier for i = l-1 and l-2
    let (_, _, last_muly_out) =
        cs.multiply(permuted[l - 1] - challenge, permuted[l - 2] - challenge);

    // Make multipliers for y from i == [0, l-3]
    let first_muly_out = (0..l - 2).rev().fold(last_muly_out, |prev_out, i| {
        let (_, _, o) = cs.multiply(prev_out.into(), permuted[i] - challenge);
        o
    });

    // Constrain last x mul output and last y mul output to be equal
    cs.constrain(first_mulx_out - first_muly_out);

    // l-1 multiplications for input + l-1 multiplication for permuted
    Ok(2 * (l - 1))
}

/// I prove that value is in [0..2^64-1]
fn range_proof_64<CS: ConstraintSystem>(
    cs: &mut CS,
    mut var: LinearCombination,
    value: Option<Scalar>,
) -> Result<usize> {
    let mut exp_2 = Scalar::one();
    let n_usize = 64usize;
    let value_bytes = value.as_ref().map(|v| v.to_bytes());
    for i in 0..n_usize {
        // Create low-level variables and add them to constraints
        let (a, b, o) = match value_bytes.as_ref() {
            Some(bytes) => {
                let index = i >> 3;
                if index > bytes.len() {
                    // This could happen due to the scalar's representation
                    return Err(eg!(R1CSError::FormatError));
                }
                let bit = ((bytes[index] >> (i & 7)) & 1u8) as i8;
                let assignment = (Scalar::from(1 - bit as u32), Scalar::from(bit as u32));
                cs.allocate_multiplier(Some(assignment).map(|(a, b)| (a.0, b.0)))
            }
            None => cs.allocate_multiplier(None),
        }
        .c(d!())?;

        // Enforce a * b = 0, so one of (a,b) is zero
        cs.constrain(o.into());

        // Enforce that a = 1 - b, so they both are 1 or 0.
        cs.constrain(a + (b - 1u64));

        // Add `-b_i*2^i` to the linear combination
        // in order to form the following constraint by the end of the loop:
        // v = Sum(b_i * 2^i, i = 0..n-1)
        var = var - b * exp_2.0;
        exp_2 = exp_2.add(&exp_2);
    }
    // Enforce that v = Sum(b_i * 2^i, i = 0..n-1)
    cs.constrain(var);

    // one multiplication gate per bit
    Ok(n_usize)
}

#[cfg(test)]
pub mod tests {
    use crate::bulletproofs::cloak::{
        allocate_cloak_vector, CloakCommitment, CloakValue, CloakVariable,
    };
    use bulletproofs::{
        r1cs::{Prover, R1CSProof, Verifier},
        BulletproofGens, PedersenGens,
    };
    use lazy_static::lazy_static;
    use merlin::Transcript;
    use rand_chacha::ChaChaRng;
    use zei_algebra::{prelude::*, ristretto::RistrettoScalar};

    #[test]
    fn test_cloak_merge() {
        let pc_gens = PedersenGens::default();

        let sorted_values = vec![
            CloakValue::new(RistrettoScalar::from(1u32), RistrettoScalar::from(10u32)),
            CloakValue::new(RistrettoScalar::from(3u32), RistrettoScalar::from(10u32)),
            CloakValue::new(RistrettoScalar::from(2u32), RistrettoScalar::from(11u32)),
            CloakValue::new(RistrettoScalar::from(5u32), RistrettoScalar::from(11u32)),
            CloakValue::new(RistrettoScalar::from(4u32), RistrettoScalar::from(12u32)),
        ];

        let mid_values = vec![
            CloakValue::new(RistrettoScalar::from(4u32), RistrettoScalar::from(10u32)),
            CloakValue::new(RistrettoScalar::from(2u32), RistrettoScalar::from(11u32)),
            CloakValue::new(RistrettoScalar::from(7u32), RistrettoScalar::from(11u32)),
        ];
        let out_values = vec![
            CloakValue::new(RistrettoScalar::zero(), RistrettoScalar::from(10u32)),
            CloakValue::new(RistrettoScalar::from(4u32), RistrettoScalar::from(10u32)),
            CloakValue::new(RistrettoScalar::zero(), RistrettoScalar::from(11u32)),
            CloakValue::new(RistrettoScalar::from(7u32), RistrettoScalar::from(11u32)),
            CloakValue::new(RistrettoScalar::from(4u32), RistrettoScalar::from(12u32)),
        ];

        let mut prover_transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let sorted =
            allocate_cloak_vector(&mut prover, Some(&sorted_values), sorted_values.len()).unwrap();
        let mid = allocate_cloak_vector(&mut prover, Some(&mid_values), mid_values.len()).unwrap();
        let added =
            allocate_cloak_vector(&mut prover, Some(&out_values), out_values.len()).unwrap();
        let num_wires =
            super::cloak_merge_gadget(&mut prover, &sorted[..], &mid[..], &added[..]).unwrap();
        let bp_gens = BulletproofGens::new(
            (num_wires + 2 * (sorted.len() + mid.len() + added.len())).next_power_of_two(),
            1,
        );
        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"test");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let sorted = allocate_cloak_vector(&mut verifier, None, sorted_values.len()).unwrap();
        let mid = allocate_cloak_vector(&mut verifier, None, mid_values.len()).unwrap();
        let added = allocate_cloak_vector(&mut verifier, None, out_values.len()).unwrap();
        let num_wires =
            super::cloak_merge_gadget(&mut verifier, &sorted[..], &mid[..], &added[..]).unwrap();
        let bp_gens = BulletproofGens::new(
            (num_wires + 2 * (sorted.len() + mid.len() + added.len())).next_power_of_two(),
            1,
        );
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());

        // test the same using commitments
        let mut prover_transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let sorted_coms_vars: Vec<(CloakCommitment, CloakVariable)> = sorted_values
            .iter()
            .map(|value| {
                value.commit_prover(
                    &mut prover,
                    &CloakValue::new(RistrettoScalar::from(1u32), RistrettoScalar::from(2u32)),
                )
            })
            .collect();
        let mid = allocate_cloak_vector(&mut prover, Some(&mid_values), mid_values.len()).unwrap();
        let added =
            allocate_cloak_vector(&mut prover, Some(&out_values), out_values.len()).unwrap();
        let sorted_vars: Vec<CloakVariable> =
            sorted_coms_vars.iter().map(|(_, var)| *var).collect();
        let num_wires =
            super::cloak_merge_gadget(&mut prover, &sorted_vars[..], &mid[..], &added[..]).unwrap();
        let num_wires = num_wires + added.len() + mid.len();
        let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"test");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let sorted_coms: Vec<CloakCommitment> =
            sorted_coms_vars.iter().map(|(com, _)| (*com)).collect();
        let sorted_vars: Vec<CloakVariable> = sorted_coms
            .iter()
            .map(|com| com.commit_verifier(&mut verifier))
            .collect();
        let mid = allocate_cloak_vector(&mut verifier, None, mid_values.len()).unwrap();
        let added = allocate_cloak_vector(&mut verifier, None, out_values.len()).unwrap();
        let num_wires =
            super::cloak_merge_gadget(&mut verifier, &sorted_vars[..], &mid[..], &added[..])
                .unwrap();
        let num_wires = num_wires + added.len() + mid.len();
        let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
    }

    #[test]
    fn test_shuffle() {
        let pc_gens = PedersenGens::default();
        let input_values = vec![
            CloakValue::new(RistrettoScalar::from(10u32), RistrettoScalar::from(10u32)),
            CloakValue::new(RistrettoScalar::from(20u32), RistrettoScalar::from(20u32)),
            CloakValue::new(RistrettoScalar::from(30u32), RistrettoScalar::from(30u32)),
            CloakValue::new(RistrettoScalar::from(40u32), RistrettoScalar::from(40u32)),
            CloakValue::new(RistrettoScalar::from(50u32), RistrettoScalar::from(50u32)),
        ];

        let shuffled_values = vec![
            CloakValue::new(RistrettoScalar::from(20u32), RistrettoScalar::from(20u32)),
            CloakValue::new(RistrettoScalar::from(40u32), RistrettoScalar::from(40u32)),
            CloakValue::new(RistrettoScalar::from(10u32), RistrettoScalar::from(10u32)),
            CloakValue::new(RistrettoScalar::from(50u32), RistrettoScalar::from(50u32)),
            CloakValue::new(RistrettoScalar::from(30u32), RistrettoScalar::from(30u32)),
        ];

        let mut prover_transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let input =
            allocate_cloak_vector(&mut prover, Some(&input_values), input_values.len()).unwrap();
        let shuffled =
            allocate_cloak_vector(&mut prover, Some(&shuffled_values), shuffled_values.len())
                .unwrap();
        let num_wires =
            super::cloak_shuffle_gadget(&mut prover, input.to_vec(), shuffled.to_vec()).unwrap();
        let num_wires = num_wires + input.len() + shuffled.len();
        let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"test");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let input = allocate_cloak_vector(&mut verifier, None, input_values.len()).unwrap();
        let shuffled = allocate_cloak_vector(&mut verifier, None, shuffled_values.len()).unwrap();
        super::cloak_shuffle_gadget(&mut verifier, input.to_vec(), shuffled.to_vec()).unwrap();
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());

        let bad_shuffle_values = vec![
            CloakValue::new(RistrettoScalar::zero(), RistrettoScalar::zero()),
            CloakValue::new(RistrettoScalar::from(40u32), RistrettoScalar::from(40u32)),
            CloakValue::new(RistrettoScalar::from(10u32), RistrettoScalar::from(10u32)),
            CloakValue::new(RistrettoScalar::from(50u32), RistrettoScalar::from(50u32)),
            CloakValue::new(RistrettoScalar::from(30u32), RistrettoScalar::from(30u32)),
        ];

        let mut prover_transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let input = allocate_cloak_vector(&mut prover, Some(&input_values), 0).unwrap();
        let bad_shuffle = allocate_cloak_vector(&mut prover, Some(&bad_shuffle_values), 0).unwrap();
        let num_wires =
            super::cloak_shuffle_gadget(&mut prover, input.to_vec(), bad_shuffle).unwrap();
        let num_wires = num_wires + input.len() + shuffled.len();
        let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"test");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let input = allocate_cloak_vector(&mut verifier, None, input_values.len()).unwrap();
        let bad_shuffle =
            allocate_cloak_vector(&mut verifier, None, bad_shuffle_values.len()).unwrap();
        super::cloak_shuffle_gadget(&mut verifier, input.to_vec(), bad_shuffle.to_vec()).unwrap();
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_err());
    }

    fn yuan(q: u64) -> CloakValue {
        CloakValue {
            amount: RistrettoScalar::from(q),
            asset_type: RistrettoScalar::from(888u64),
        }
    }

    fn peso(q: u64) -> CloakValue {
        CloakValue {
            amount: RistrettoScalar::from(q),
            asset_type: RistrettoScalar::from(666u64),
        }
    }

    fn euro(q: u64) -> CloakValue {
        CloakValue {
            amount: RistrettoScalar::from(q),
            asset_type: RistrettoScalar::from(444u64),
        }
    }

    fn zero() -> CloakValue {
        CloakValue {
            amount: RistrettoScalar::zero(),
            asset_type: RistrettoScalar::zero(),
        }
    }

    lazy_static! {
        static ref BP_GENS: BulletproofGens = BulletproofGens::new(2048, 1);
    }

    #[test]
    fn merge() {
        let values = vec![
            CloakValue::new(RistrettoScalar::from(30u32), RistrettoScalar::from(3u32)),
            CloakValue::new(RistrettoScalar::from(30u32), RistrettoScalar::from(3u32)),
            CloakValue::new(RistrettoScalar::from(30u32), RistrettoScalar::from(3u32)),
            CloakValue::new(RistrettoScalar::from(20u32), RistrettoScalar::from(2u32)),
            CloakValue::new(RistrettoScalar::from(10u32), RistrettoScalar::from(1u32)),
            CloakValue::new(RistrettoScalar::from(10u32), RistrettoScalar::from(1u32)),
            CloakValue::new(RistrettoScalar::from(10u32), RistrettoScalar::from(1u32)),
        ];

        let (_, added) = super::merge(&values);
        let expected = vec![
            CloakValue::new(RistrettoScalar::zero(), RistrettoScalar::zero()),
            CloakValue::new(RistrettoScalar::zero(), RistrettoScalar::zero()),
            CloakValue::new(RistrettoScalar::from(90u32), RistrettoScalar::from(3u32)),
            CloakValue::new(RistrettoScalar::from(20u32), RistrettoScalar::from(2u32)),
            CloakValue::new(RistrettoScalar::zero(), RistrettoScalar::zero()),
            CloakValue::new(RistrettoScalar::zero(), RistrettoScalar::zero()),
            CloakValue::new(RistrettoScalar::from(30u32), RistrettoScalar::from(1u32)),
        ];

        assert_eq!(&added[..], &expected[..]);
    }

    pub(crate) fn test_cloak(inputs: &[CloakValue], outputs: &[CloakValue], pass: bool) {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let input_coms: Vec<CloakCommitment>;
        let output_coms: Vec<CloakCommitment>;
        let pc_gens = PedersenGens::default();
        let proof: R1CSProof;
        {
            // prover scope
            let mut prover_transcript = Transcript::new(b"test");
            let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
            let in_com_and_vars = inputs
                .iter()
                .map(|input| {
                    input.commit_prover(
                        &mut prover,
                        &CloakValue::new(
                            RistrettoScalar::random(&mut prng),
                            RistrettoScalar::random(&mut prng),
                        ),
                    )
                })
                .collect_vec();
            input_coms = in_com_and_vars.iter().map(|(com, _)| *com).collect_vec();
            let input_vars = in_com_and_vars.iter().map(|(_, var)| *var).collect_vec();

            let out_com_and_vars = outputs
                .iter()
                .map(|output| {
                    output.commit_prover(
                        &mut prover,
                        &CloakValue::new(
                            RistrettoScalar::random(&mut prng),
                            RistrettoScalar::random(&mut prng),
                        ),
                    )
                })
                .collect_vec();
            output_coms = out_com_and_vars.iter().map(|(com, _)| *com).collect_vec();
            let output_vars = out_com_and_vars.iter().map(|(_, var)| *var).collect_vec();

            let n_gates = super::cloak(
                &mut prover,
                &input_vars,
                Some(inputs),
                &output_vars,
                Some(outputs),
            )
            .unwrap();

            assert!(n_gates <= BP_GENS.gens_capacity);

            proof = prover.prove(&BP_GENS).unwrap();
        }
        {
            // verifier scope
            let mut verifier_transcript = Transcript::new(b"test");
            let mut verifier = Verifier::new(&mut verifier_transcript);
            let in_vars = input_coms
                .iter()
                .map(|input| input.commit_verifier(&mut verifier))
                .collect_vec();

            let out_vars = output_coms
                .iter()
                .map(|output| output.commit_verifier(&mut verifier))
                .collect_vec();

            super::cloak(&mut verifier, &in_vars, None, &out_vars, None).unwrap();

            assert_eq!(verifier.verify(&proof, &pc_gens, &BP_GENS).is_ok(), pass);
        }
    }

    fn test_range_proof(in1: RistrettoScalar, in2: RistrettoScalar, pass: bool) {
        let asset_type0 = RistrettoScalar::zero();

        let v_in_1 = CloakValue::new(in1, asset_type0);
        let v_in_2 = CloakValue::new(in2, asset_type0);

        let out = in1.add(&in2);
        let v_out = CloakValue::new(out, asset_type0);

        assert_eq!(in1.add(&in2), out);
        test_cloak(&[v_in_1, v_in_2], &[v_out], pass);
    }

    #[test]
    fn range_proofs() {
        // Range proof verifies
        test_range_proof(
            RistrettoScalar::from(u64::MAX - 1),
            RistrettoScalar::from(1u32),
            true,
        );

        // Range proof does not verifies due to overflow in output
        test_range_proof(
            RistrettoScalar::from(u64::MAX),
            RistrettoScalar::from(1u32),
            false,
        );
    }

    #[test]
    fn cloak_misc() {
        test_cloak(&[], &[], true);
        test_cloak(&[yuan(10)], &[yuan(10)], true);
        test_cloak(&[yuan(20)], &[yuan(10), yuan(10)], true);
        test_cloak(&[yuan(10), yuan(10)], &[yuan(20)], true);
        test_cloak(&[yuan(10), yuan(10), yuan(20)], &[yuan(20), yuan(20)], true);
        test_cloak(&[yuan(10), yuan(20)], &[yuan(20), yuan(20)], false);
        test_cloak(&[peso(10)], &[peso(10)], true);
        test_cloak(&[peso(10), yuan(20)], &[peso(10), yuan(20)], true);
        test_cloak(
            &[peso(10), yuan(20), peso(10), yuan(20)],
            &[peso(10), yuan(20), peso(10), yuan(20)],
            true,
        );
        test_cloak(
            &[peso(0), peso(0), peso(10), yuan(20), peso(10), yuan(20)],
            &[peso(10), yuan(20), peso(10), yuan(0), yuan(20)],
            true,
        );
    }

    /////////////////////////////////////////////////////////////////////////////////////////
    // Port of https://github.com/stellar/slingshot/blob/main/spacesuit/tests/spacesuit.rs //
    /////////////////////////////////////////////////////////////////////////////////////////

    // m=1, n=1
    #[test]
    fn cloak_1_1() {
        test_cloak(&[yuan(1)], &[yuan(1)], true);
        test_cloak(&[peso(4)], &[peso(4)], true);
        test_cloak(&[yuan(1)], &[peso(4)], false);
    }

    // max(m, n) = 2
    #[test]
    fn cloak_uneven_2() {
        test_cloak(&[yuan(3)], &[yuan(1), yuan(2)], true);
        test_cloak(&[yuan(1), yuan(2)], &[yuan(3)], true);
    }

    // m=2, n=2
    #[test]
    fn cloak_2_2() {
        // Only shuffle (all different flavors)
        test_cloak(&[yuan(1), peso(4)], &[yuan(1), peso(4)], true);
        test_cloak(&[yuan(1), peso(4)], &[peso(4), yuan(1)], true);

        // Middle shuffle & merge & split (has multiple inputs or outputs of same flavor)
        test_cloak(&[peso(4), peso(4)], &[peso(4), peso(4)], true);
        test_cloak(&[peso(5), peso(3)], &[peso(5), peso(3)], true);
        test_cloak(&[peso(5), peso(3)], &[peso(1), peso(7)], true);
        test_cloak(&[peso(1), peso(8)], &[peso(0), peso(9)], true);
        test_cloak(&[yuan(1), yuan(1)], &[peso(4), yuan(1)], false);
    }

    // m=3, n=3
    #[test]
    fn cloak_3_3() {
        // Only shuffle
        test_cloak(
            &[yuan(1), peso(4), euro(8)],
            &[yuan(1), peso(4), euro(8)],
            true,
        );
        test_cloak(
            &[yuan(1), peso(4), euro(8)],
            &[yuan(1), euro(8), peso(4)],
            true,
        );
        test_cloak(
            &[yuan(1), peso(4), euro(8)],
            &[peso(4), yuan(1), euro(8)],
            true,
        );
        test_cloak(
            &[yuan(1), peso(4), euro(8)],
            &[peso(4), euro(8), yuan(1)],
            true,
        );
        test_cloak(
            &[yuan(1), peso(4), euro(8)],
            &[euro(8), yuan(1), peso(4)],
            true,
        );
        test_cloak(
            &[yuan(1), peso(4), euro(8)],
            &[euro(8), peso(4), yuan(1)],
            true,
        );
        test_cloak(
            &[yuan(1), peso(4), euro(8)],
            &[yuan(2), peso(4), euro(8)],
            false,
        );
        test_cloak(
            &[yuan(1), peso(4), euro(8)],
            &[yuan(1), euro(4), euro(8)],
            false,
        );
        test_cloak(
            &[yuan(1), peso(4), euro(8)],
            &[yuan(1), peso(4), euro(9)],
            false,
        );

        // Middle shuffle & merge & split
        test_cloak(
            &[yuan(1), yuan(1), peso(4)],
            &[yuan(1), yuan(1), peso(4)],
            true,
        );
        test_cloak(
            &[yuan(4), yuan(3), peso(4)],
            &[yuan(2), yuan(5), peso(4)],
            true,
        );
        test_cloak(
            &[yuan(4), yuan(3), peso(4)],
            &[peso(4), yuan(2), yuan(5)],
            true,
        );
        test_cloak(
            &[yuan(1), yuan(2), yuan(5)],
            &[yuan(4), yuan(3), yuan(1)],
            true,
        );
        test_cloak(
            &[yuan(1), yuan(2), yuan(5)],
            &[yuan(4), yuan(3), yuan(10)],
            false,
        );

        // End shuffles & merge & split & middle shuffle
        // (multiple asset types that need to be grouped and merged or split)
        test_cloak(
            &[yuan(1), peso(4), yuan(1)],
            &[yuan(1), yuan(1), peso(4)],
            true,
        );
        test_cloak(
            &[yuan(4), peso(4), yuan(3)],
            &[peso(3), yuan(7), peso(1)],
            true,
        );
    }

    // max(m, n) = 3
    #[test]
    fn cloak_uneven_3() {
        test_cloak(&[yuan(4), yuan(4), yuan(3)], &[yuan(11)], true);
        test_cloak(&[yuan(11)], &[yuan(4), yuan(4), yuan(3)], true);
        test_cloak(&[yuan(11), peso(4)], &[yuan(4), yuan(7), peso(4)], true);
        test_cloak(&[yuan(4), yuan(7), peso(4)], &[yuan(11), peso(4)], true);
        test_cloak(&[yuan(5), yuan(6)], &[yuan(4), yuan(4), yuan(3)], true);
        test_cloak(&[yuan(4), yuan(4), yuan(3)], &[yuan(5), yuan(6)], true);
    }

    // m=4, n=4
    #[test]
    fn cloak_4_4() {
        // Only shuffle
        test_cloak(
            &[yuan(1), peso(4), euro(7), euro(10)],
            &[yuan(1), peso(4), euro(7), euro(10)],
            true,
        );

        test_cloak(
            &[yuan(1), peso(4), euro(7), euro(10)],
            &[euro(7), yuan(1), euro(10), peso(4)],
            true,
        );

        // Middle shuffle & merge & split
        test_cloak(
            &[yuan(1), yuan(1), peso(4), peso(4)],
            &[yuan(1), yuan(1), peso(4), peso(4)],
            true,
        );
        test_cloak(
            &[yuan(4), yuan(3), peso(4), peso(4)],
            &[yuan(2), yuan(5), peso(1), peso(7)],
            true,
        );
        test_cloak(
            &[yuan(4), yuan(3), peso(4), peso(4)],
            &[peso(1), peso(7), yuan(2), yuan(5)],
            true,
        );
        test_cloak(
            &[yuan(1), yuan(1), yuan(5), yuan(2)],
            &[yuan(1), yuan(1), yuan(5), yuan(2)],
            true,
        );
        test_cloak(
            &[yuan(1), yuan(2), yuan(5), yuan(2)],
            &[yuan(4), yuan(3), yuan(3), zero()],
            true,
        );
        test_cloak(
            &[yuan(1), yuan(2), yuan(5), yuan(2)],
            &[yuan(4), yuan(3), yuan(3), yuan(20)],
            false,
        );

        // End shuffles & merge & split & middle shuffle
        test_cloak(
            &[yuan(1), peso(4), yuan(1), peso(4)],
            &[peso(4), yuan(1), yuan(1), peso(4)],
            true,
        );
        test_cloak(
            &[yuan(4), peso(4), peso(4), yuan(3)],
            &[peso(1), yuan(2), yuan(5), peso(7)],
            true,
        );
        test_cloak(
            &[yuan(10), peso(1), peso(2), peso(3)],
            &[yuan(5), yuan(4), yuan(1), peso(6)],
            true,
        );
    }
}
