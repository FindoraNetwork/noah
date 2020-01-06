#![allow(non_snake_case)]

use crate::crypto::accumulators::merkle_tree::compute_mimc_constants;
use bulletproofs::r1cs::*;
use curve25519_dalek::scalar::Scalar;

pub(crate) fn mimc_func<CS: ConstraintSystem>(cs: &mut CS,
                                              x: LinearCombination,
                                              c: Scalar)
                                              -> Result<(Variable, usize), R1CSError> {
  let x_plus_c = x + c;
  let (left, _, out) = cs.multiply(x_plus_c.clone(), x_plus_c);
  let (_, _, out) = cs.multiply(out.into(), out.into());
  let (_, _, out) = cs.multiply(out.into(), left.into());
  Ok((out, 3))
}

fn feistel_round<CS: ConstraintSystem>(
  cs: &mut CS,
  x: LinearCombination,
  y: LinearCombination,
  c: Scalar)
  -> Result<(LinearCombination, LinearCombination, usize), R1CSError> {
  let new_y = x.clone();
  let (aux, num_left_wires) = mimc_func(cs, x, c)?;
  let new_x = y + aux;
  Ok((new_x, new_y, num_left_wires))
}

pub(crate) fn feistel_network<CS: ConstraintSystem>(
  cs: &mut CS,
  x: LinearCombination,
  y: LinearCombination,
  c: &[Scalar])
  -> Result<(LinearCombination, LinearCombination, usize), R1CSError> {
  let mut num_left_wires = 0;
  let mut xi = x;
  let mut yi = y;
  for ci in c {
    let (a, b, left_wires) = feistel_round(cs, xi, yi, *ci)?;
    xi = a;
    yi = b;
    num_left_wires += left_wires;
  }
  Ok((xi, yi, num_left_wires))
}

pub(crate) fn mimc_hash<CS: ConstraintSystem>(cs: &mut CS,
                                              values: &[LinearCombination],
                                              level: usize)
                                              -> Result<(LinearCombination, usize), R1CSError> {
  let c = compute_mimc_constants(level);

  let mut sa: LinearCombination = cs.allocate(Some(Scalar::zero()))?.into();
  let mut sc: LinearCombination = cs.allocate(Some(Scalar::zero()))?.into();
  let mut num_left_wires = 2;
  for v in values.iter() {
    let x = sa + (*v).clone();
    let out = feistel_network(cs, x, sc, &c[..])?;
    sa = out.0;
    sc = out.1;
    num_left_wires += out.2;
  }
  Ok((sa, num_left_wires))
}

pub fn hash_proof<CS: ConstraintSystem>(cs: &mut CS,
                                        x: Variable,
                                        y: Variable,
                                        out: Variable)
                                        -> Result<usize, R1CSError> {
  let (sa, num_left_wires) = mimc_hash(cs, &[x.into(), y.into()], 1)?;
  cs.constrain(sa - out);
  Ok(num_left_wires)
}

#[cfg(test)]
mod test {
  use super::*;
  use crate::crypto::accumulators::merkle_tree::{MTHash, MiMCHash};
  use bulletproofs::r1cs::Verifier;
  use bulletproofs::{BulletproofGens, PedersenGens};
  use curve25519_dalek::scalar::Scalar;
  use merlin::Transcript;

  #[test]
  fn test_mimc_fn() {
    let pc_gens = PedersenGens::default();
    let mut prover_transcript = Transcript::new(b"MiMCFunctionTest");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    let scalar_x = Scalar::from(2u8);
    let scalar_c = Scalar::from(0u8);
    let (cx, x) = prover.commit(scalar_x, Scalar::from(10u8));
    let (out, num_left_wires) = super::mimc_func(&mut prover, x.into(), scalar_c).unwrap();

    let expected_output = crate::crypto::accumulators::merkle_tree::mimc_f(&scalar_x, &scalar_c);
    let expected = prover.allocate(Some(expected_output)).unwrap();

    prover.constrain(out - expected);

    let bp_gens = BulletproofGens::new((num_left_wires + 1).next_power_of_two(), 1);
    let proof = prover.prove(&bp_gens).unwrap();

    let mut verifier_transcript = Transcript::new(b"MiMCFunctionTest");
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let ver_x = verifier.commit(cx);
    let (ver_out, num_left_wires) =
      super::mimc_func(&mut verifier, ver_x.into(), scalar_c).unwrap();
    let expected = verifier.allocate(Some(expected_output)).unwrap();
    verifier.constrain(ver_out - expected);
    let bp_gens = BulletproofGens::new((num_left_wires + 1).next_power_of_two(), 1);
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
  }

  #[test]
  fn test_feistel_network() {
    let pc_gens = PedersenGens::default();
    let mut prover_transcript = Transcript::new(b"FeistelNetworkTest");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    let scalar_x = Scalar::from(2u8);
    let scalar_y = Scalar::from(0u8);
    let scalar_c = [Scalar::from(0u8), Scalar::from(8u8), Scalar::from(0u8)];
    let (expected_output_x, expected_output_y) =
      crate::crypto::accumulators::merkle_tree::mimc_feistel(&scalar_x, &scalar_y, &scalar_c);

    let (cx, x) = prover.commit(scalar_x, Scalar::from(10u8));
    let (cy, y) = prover.commit(scalar_y, Scalar::from(11u8));
    let (outx, outy, num_left_wires) =
      super::feistel_network(&mut prover, x.into(), y.into(), &scalar_c).unwrap();
    let expected_x = prover.allocate(Some(expected_output_x)).unwrap();
    let expected_y = prover.allocate(Some(expected_output_y)).unwrap();
    prover.constrain(outx - expected_x);
    prover.constrain(outy - expected_y);
    let bp_gens = BulletproofGens::new((num_left_wires + 2).next_power_of_two(), 1);
    let proof = prover.prove(&bp_gens).unwrap();

    let mut verifier_transcript = Transcript::new(b"FeistelNetworkTest");
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let ver_x = verifier.commit(cx);
    let ver_y = verifier.commit(cy);
    let (ver_out_x, ver_out_y, num_left_wires) =
      super::feistel_network(&mut verifier, ver_x.into(), ver_y.into(), &scalar_c).unwrap();
    let expected_x = verifier.allocate(Some(expected_output_x)).unwrap();
    let expected_y = verifier.allocate(Some(expected_output_y)).unwrap();
    verifier.constrain(ver_out_x - expected_x);
    verifier.constrain(ver_out_y - expected_y);

    let bp_gens = BulletproofGens::new((num_left_wires + 2).next_power_of_two(), 1);
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
  }

  #[test]
  fn test_mimc_hash() {
    let pc_gens = PedersenGens::default();
    let mut prover_transcript = Transcript::new(b"MiMCHashTest");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    let scalar_x = Scalar::from(10u8);
    let scalar_y = Scalar::from(20u8);
    let (cx, x) = prover.commit(scalar_x, Scalar::from(10u8));
    let (cy, y) = prover.commit(scalar_y, Scalar::from(11u8));
    let hasher = MiMCHash::new(1);
    let real_hash = hasher.digest(&[&scalar_x, &scalar_y]);
    let (ch, h) = prover.commit(real_hash, Scalar::from(12u8));
    let num_left_wires = super::hash_proof(&mut prover, x, y, h).unwrap();
    let bp_gens = BulletproofGens::new((num_left_wires + 2).next_power_of_two(), 1);
    let proof = prover.prove(&bp_gens).unwrap();

    let mut verifier_transcript = Transcript::new(b"MiMCHashTest");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let ver_x = verifier.commit(cx);
    let ver_y = verifier.commit(cy);
    let ver_h = verifier.commit(ch);
    let num_left_wires = super::hash_proof(&mut verifier, ver_x, ver_y, ver_h).unwrap();
    let bp_gens = BulletproofGens::new((num_left_wires + 2).next_power_of_two(), 1);
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
  }
}
