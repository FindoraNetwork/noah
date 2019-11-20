use bulletproofs_yoloproof::r1cs::{
  ConstraintSystem, LinearCombination, R1CSError, RandomizableConstraintSystem,
  RandomizedConstraintSystem, Variable,
};
use curve25519_dalek::scalar::Scalar;
use std::iter;

/// I implement the mix gadget, proving that values in out list
/// are the added-by-type values of the input.
/// I return the number of left wires created
pub(super) fn list_mix<CS: RandomizableConstraintSystem>(cs: &mut CS,
                                                         input: &[(Variable, Variable)],
                                                         mid: &[(Variable, Variable)],
                                                         out: &[(Variable, Variable)])
                                                         -> Result<usize, R1CSError> {
  let mut num_left_wires = 0;
  let l = out.len();
  if l <= 1 {
    return Ok(0);
  }
  let first_in = input[0];
  let in1iter = iter::once(&first_in).chain(mid.iter());
  let in2iter = input[1..l].iter();
  let out1iter = out[0..l - 1].iter();
  let out2iter = mid.iter().chain(iter::once(&out[l - 1]));

  for (((in1, in2), out1), out2) in in1iter.zip(in2iter).zip(out1iter).zip(out2iter) {
    num_left_wires += gate_mix(cs, *in1, *in2, *out1, *out2)?;
  }
  Ok(num_left_wires)
}

/// I implement the mix gate gadget, proving that either
/// in1 = out1 and in2 = out2  if in1 and in2 have different types or
/// out1 = 0 and out2 = in1 + in2 if in1 and in2 have same type
/// I return the number of left wires created
pub(super) fn gate_mix<CS: RandomizableConstraintSystem>(cs: &mut CS,
                                                         in1: (Variable, Variable),
                                                         in2: (Variable, Variable),
                                                         out1: (Variable, Variable),
                                                         out2: (Variable, Variable))
                                                         -> Result<usize, R1CSError> {
  cs.specify_randomized_constraints(move |cs| {
      let w1 = cs.challenge_scalar(b"mix challenge1");
      let w2 = cs.challenge_scalar(b"mix challenge2");
      let w3 = cs.challenge_scalar(b"mix challenge3");
      let (_, _, out) = cs.multiply(
                                    (in1.0 - out1.0) +          // quantity maintains
                (in1.1 - out1.1) * w1 + // asset type maintains in first input
                (in2.0 - out2.0) * w2 + // quantity maintains
                (in2.1 - out2.1) * w3, // asset type maintains in second input
                                    out1.0 + // or out1 is 0
                (in1.1 - in2.1) * w1 + // or in flavors are equal
                (out2.0 - in1.0 - in2.0) * w2 // or out2 is the sum of the inputs
                + (out2.1 - in1.1) * w3, // in 1 and out2 have same asset type
    );
      cs.constrain(out.into());
      Ok(())
    })?;
  Ok(1usize)
}

/// I prove shuffling of a list of pairs
/// I return the number of left wires created
pub(super) fn pair_list_shuffle<CS: RandomizableConstraintSystem>(cs: &mut CS,
                                                                  input_pairs: Vec<(Variable,
                                                                       Variable)>,
                                                                  permuted_pairs: Vec<(Variable, Variable)>)
                                                                  -> Result<usize, R1CSError> {
  let l = input_pairs.len();
  if l != permuted_pairs.len() {
    return Err(R1CSError::GadgetError {
            description: "list shuffle error, input and output list differ in length".to_string(),
        });
  }
  if l == 0 {
    return Ok(0usize);
  }
  if l == 1 {
    cs.constrain(permuted_pairs[0].0 - input_pairs[0].0);
    cs.constrain(permuted_pairs[0].1 - input_pairs[0].1);
    return Ok(0usize);
  }

  cs.specify_randomized_constraints(move |cs| {
      let challenge = cs.challenge_scalar(b"k-value shuffle challenge");
      let mut single_input = Vec::with_capacity(l);
      let mut single_perm = Vec::with_capacity(l);

      for (in_var, perm_var) in input_pairs.iter().zip(permuted_pairs.iter()) {
        //compute a single representative for the pair
        let (single_in, single_pe, _) = cs.multiply(in_var.0 + challenge * in_var.1,
                                                    perm_var.0 + challenge * perm_var.1);
        single_input.push(single_in);
        single_perm.push(single_pe);
      }

      list_shuffle(cs, &single_input[..], &single_perm[..])?;
      Ok(())
    })?;

  // list_shuffle does 2*(l-1) multiplications
  Ok(2 * (l - 1))
}

/// I prove shuffling of a list of values
/// I return the number of left wires created
pub(super) fn list_shuffle<CS: RandomizedConstraintSystem>(cs: &mut CS,
                                                           input: &[Variable],
                                                           permuted: &[Variable])
                                                           -> Result<usize, R1CSError> {
  let l = input.len();
  if l != permuted.len() {
    return Err(R1CSError::GadgetError {
            description: "list shuffle error, input and output list differ in length".to_string(),
        });
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
                                         let (_, _, o) =
                                           cs.multiply(prev_out.into(), input[i] - challenge);
                                         o
                                       });

  // Make last y multiplier for i = l-1 and l-2
  let (_, _, last_muly_out) = cs.multiply(permuted[l - 1] - challenge, permuted[l - 2] - challenge);

  // Make multipliers for y from i == [0, l-3]
  let first_muly_out = (0..l - 2).rev().fold(last_muly_out, |prev_out, i| {
                                         let (_, _, o) =
                                           cs.multiply(prev_out.into(), permuted[i] - challenge);
                                         o
                                       });

  // Constrain last x mul output and last y mul output to be equal
  cs.constrain(first_mulx_out - first_muly_out);

  // l-1 multiplications for input + l-1 multiplication for permuted
  Ok(2 * (l - 1))
}

/// I prove that value is in [0..2^64-1]
pub fn range_proof<CS: ConstraintSystem>(cs: &mut CS,
                                         mut var: LinearCombination,
                                         value: Option<Scalar>)
                                         -> Result<usize, R1CSError> {
  let mut exp_2 = Scalar::one();
  let n_usize = 64usize;
  let value_bytes = value.as_ref().map(|v| v.as_bytes());
  for i in 0..n_usize {
    // Create low-level variables and add them to constraints
    let (a, b, o) = match value_bytes {
      Some(bytes) => {
        let bit = ((bytes[i >> 3] >> (i & 7)) & 1u8) as i8; //TODO this operation is unsafe, since it depends on Scalar's representation
        let assignment = (Scalar::from(1 - bit as u8), Scalar::from(bit as u8));
        cs.allocate_multiplier(Some(assignment))
      }
      None => cs.allocate_multiplier(None),
    }?;

    // Enforce a * b = 0, so one of (a,b) is zero
    cs.constrain(o.into());

    // Enforce that a = 1 - b, so they both are 1 or 0.
    cs.constrain(a + (b - 1u64));

    // Add `-b_i*2^i` to the linear combination
    // in order to form the following constraint by the end of the loop:
    // v = Sum(b_i * 2^i, i = 0..n-1)
    var = var - b * exp_2;
    exp_2 = exp_2 + exp_2;
  }
  // Enforce that v = Sum(b_i * 2^i, i = 0..n-1)
  cs.constrain(var);

  // one multiplication gate per bit
  Ok(n_usize)
}

#[cfg(test)]
mod test {
  use super::super::solvency::allocate_vector;
  use bulletproofs_yoloproof::r1cs::{Prover, Variable, Verifier};
  use bulletproofs_yoloproof::{BulletproofGens, PedersenGens};
  use curve25519_dalek::ristretto::CompressedRistretto;
  use curve25519_dalek::scalar::Scalar;
  use merlin::Transcript;

  #[test]
  fn test_list_mix() {
    let pc_gens = PedersenGens::default();

    let sorted_values = [(Scalar::from(1u8), Scalar::from(10u8)),
                         (Scalar::from(3u8), Scalar::from(10u8)),
                         (Scalar::from(2u8), Scalar::from(11u8)),
                         (Scalar::from(5u8), Scalar::from(11u8)),
                         (Scalar::from(4u8), Scalar::from(12u8))];

    let mid_values = [(Scalar::from(4u8), Scalar::from(10u8)),
                      (Scalar::from(2u8), Scalar::from(11u8)),
                      (Scalar::from(7u8), Scalar::from(11u8))];
    let out_values = [(Scalar::from(0u8), Scalar::from(10u8)),
                      (Scalar::from(4u8), Scalar::from(10u8)),
                      (Scalar::from(0u8), Scalar::from(11u8)),
                      (Scalar::from(7u8), Scalar::from(11u8)),
                      (Scalar::from(4u8), Scalar::from(12u8))];

    let mut prover_transcript = Transcript::new(b"test");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
    let sorted = allocate_vector(&mut prover, &sorted_values.to_vec());
    let mid = allocate_vector(&mut prover, &mid_values.to_vec());
    let added = allocate_vector(&mut prover, &out_values.to_vec());
    let num_wires = super::list_mix(&mut prover, &sorted[..], &mid[..], &added[..]).unwrap();
    let bp_gens = BulletproofGens::new((num_wires + 2*(sorted.len() + mid.len() + added.len())).next_power_of_two(), 1);
    let proof = prover.prove(&bp_gens).unwrap();

    let mut verifier_transcript = Transcript::new(b"test");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let sorted = allocate_vector(&mut verifier, &sorted_values.to_vec());
    let mid = allocate_vector(&mut verifier, &mid_values.to_vec());
    let added = allocate_vector(&mut verifier, &out_values.to_vec());
    let num_wires = super::list_mix(&mut verifier, &sorted[..], &mid[..], &added[..]).unwrap();
    let bp_gens = BulletproofGens::new((num_wires + 2*(sorted.len() + mid.len() + added.len())) .next_power_of_two(), 1);
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());

    // test the same using commitments
    let mut prover_transcript = Transcript::new(b"test");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
    let sorted_coms_vars: Vec<((CompressedRistretto, CompressedRistretto), (Variable, Variable))> =
      sorted_values.iter()
                   .map(|(amount, asset_type)| {
                     let (sorted_a_com, sorted_a_var) = prover.commit(*amount, Scalar::from(1u8));
                     let (sorted_t_com, sorted_t_var) =
                       prover.commit(*asset_type, Scalar::from(2u8));
                     ((sorted_a_com, sorted_t_com), (sorted_a_var, sorted_t_var))
                   })
                   .collect();
    let mid = allocate_vector(&mut prover, &mid_values.to_vec());
    let added = allocate_vector(&mut prover, &out_values.to_vec());
    let sorted_vars: Vec<(Variable, Variable)> =
      sorted_coms_vars.iter()
                      .map(|(_, (a_v, t_v))| (*a_v, *t_v))
                      .collect();
    let num_wires = super::list_mix(&mut prover, &sorted_vars[..], &mid[..], &added[..]).unwrap();
    let num_wires = num_wires + added.len() + mid.len();
    let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
    let proof = prover.prove(&bp_gens).unwrap();

    let mut verifier_transcript = Transcript::new(b"test");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let sorted_coms: Vec<(CompressedRistretto, CompressedRistretto)> =
      sorted_coms_vars.iter()
                      .map(|((a_c, t_c), _)| (*a_c, *t_c))
                      .collect();
    let sorted_vars: Vec<(Variable, Variable)> =
      sorted_coms.iter()
                 .map(|(a_c, t_c)| (verifier.commit(*a_c), verifier.commit(*t_c)))
                 .collect();
    let mid = allocate_vector(&mut verifier, &mid_values.to_vec());
    let added = allocate_vector(&mut verifier, &out_values.to_vec());
    let num_wires = super::list_mix(&mut verifier, &sorted_vars[..], &mid[..], &added[..]).unwrap();
    let num_wires = num_wires + added.len() + mid.len();
    let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
  }

  #[test]
  fn test_shuffle() {
    let pc_gens = PedersenGens::default();
    let input_values = [(Scalar::from(10u8), Scalar::from(10u8)),
                        (Scalar::from(20u8), Scalar::from(20u8)),
                        (Scalar::from(30u8), Scalar::from(30u8)),
                        (Scalar::from(40u8), Scalar::from(40u8)),
                        (Scalar::from(50u8), Scalar::from(50u8))];

    let shuffled_values = [(Scalar::from(20u8), Scalar::from(20u8)),
                           (Scalar::from(40u8), Scalar::from(40u8)),
                           (Scalar::from(10u8), Scalar::from(10u8)),
                           (Scalar::from(50u8), Scalar::from(50u8)),
                           (Scalar::from(30u8), Scalar::from(30u8))];

    let mut prover_transcript = Transcript::new(b"test");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
    let input = allocate_vector(&mut prover, &input_values.to_vec());
    let shuffled = allocate_vector(&mut prover, &shuffled_values.to_vec());
    let num_wires =
      super::pair_list_shuffle(&mut prover, input.to_vec(), shuffled.to_vec()).unwrap();
    let num_wires = num_wires + input.len() + shuffled.len();
    let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
    let proof = prover.prove(&bp_gens).unwrap();

    let mut verifier_transcript = Transcript::new(b"test");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let input = allocate_vector(&mut verifier, &input_values.to_vec());
    let shuffled = allocate_vector(&mut verifier, &shuffled_values.to_vec());
    let num_wires =
      super::pair_list_shuffle(&mut verifier, input.to_vec(), shuffled.to_vec()).unwrap();
    let num_wires = num_wires + input.len() + shuffled.len();
    let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());

    let bad_shuffle_values = [(Scalar::from(0u8), Scalar::from(0u8)),
                              (Scalar::from(40u8), Scalar::from(40u8)),
                              (Scalar::from(10u8), Scalar::from(10u8)),
                              (Scalar::from(50u8), Scalar::from(50u8)),
                              (Scalar::from(30u8), Scalar::from(30u8))];

    let mut prover_transcript = Transcript::new(b"test");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
    let input = allocate_vector(&mut prover, &input_values.to_vec());
    let bad_shuffle = allocate_vector(&mut prover, &bad_shuffle_values.to_vec());
    let num_wires =
      super::pair_list_shuffle(&mut prover, input.to_vec(), bad_shuffle.to_vec()).unwrap();
    let num_wires = num_wires + input.len() + shuffled.len();
    let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
    let proof = prover.prove(&bp_gens).unwrap();

    let mut verifier_transcript = Transcript::new(b"test");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let input = allocate_vector(&mut verifier, &input_values.to_vec());
    let bad_shuffle = allocate_vector(&mut verifier, &bad_shuffle_values.to_vec());
    let num_wires =
      super::pair_list_shuffle(&mut verifier, input.to_vec(), bad_shuffle.to_vec()).unwrap();
    let num_wires = num_wires + input.len() + shuffled.len();
    let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_err());
  }
}
