use bulletproofs::r1cs::{ConstraintSystem, Variable};
use algebra::ristretto::RistrettoScalar as Scalar;

pub fn array_membership<CS: ConstraintSystem>(cs: &mut CS,
                                              set: &[Scalar],
                                              elem: Variable)
                                              -> usize {
  let k = set.len();

  if k == 1 {
    cs.constrain(set[0].0 - elem);
    return 0;
  }

  let (_, _, mut out) = cs.multiply(set[0].0 - elem, set[1].0 - elem);
  for item in set.iter().take(k).skip(2) {
    let (_, _, out_i) = cs.multiply(item.0 - elem, out.into());
    out = out_i;
  }
  cs.constrain(out.into());
  k - 1
}

#[cfg(test)]
mod test {
  use super::array_membership;
  use bulletproofs::r1cs::{Prover, Verifier};
  use bulletproofs::{BulletproofGens, PedersenGens};
  use algebra::ristretto::RistrettoScalar as Scalar;
  use algebra::groups::Scalar as _;
  use merlin::Transcript;

  #[test]
  fn test_membership() {
    let pc_gens = PedersenGens::default();
    let set = [Scalar::from_u32(0),
               Scalar::from_u32(10),
               Scalar::from_u32(30),
               Scalar::from_u32(40),
               Scalar::from_u32(50),
               Scalar::from_u32(60),
               Scalar::from_u32(70)];

    let mut prover_transcript = Transcript::new(b"TransactionTest");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
    let (com_elem, var_elem) = prover.commit(set[4].0, curve25519_dalek::scalar::Scalar::from(1299u32));
    let left_wires = array_membership(&mut prover, &set[..], var_elem);
    let bp_gens = BulletproofGens::new(left_wires.next_power_of_two(), 1);
    let proof = prover.prove(&bp_gens).unwrap();

    let mut verifier_transcript = Transcript::new(b"TransactionTest");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let ver_elem_var = verifier.commit(com_elem);
    let left_wires = array_membership(&mut verifier, &set[..], ver_elem_var);
    let bp_gens = BulletproofGens::new(left_wires.next_power_of_two(), 1);
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());

    let set = [Scalar::from_u32(0),
               Scalar::from_u32(10),
               Scalar::from_u32(30),
               Scalar::from_u32(40),
               Scalar::from_u32(556756756u32),
               Scalar::from_u32(60),
               Scalar::from_u32(70)];
    let mut verifier_transcript = Transcript::new(b"TransactionTest");
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let ver_elem_var = verifier.commit(com_elem);
    let left_wires = array_membership(&mut verifier, &set[..], ver_elem_var);
    let bp_gens = BulletproofGens::new(left_wires.next_power_of_two(), 1);
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_err());
  }
}
