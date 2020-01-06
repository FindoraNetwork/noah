use super::mimc_hash::mimc_hash;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError, Variable};
use curve25519_dalek::scalar::Scalar;

pub fn merkle_verify_mimc<CS: ConstraintSystem>(cs: &mut CS,
                                                element: Variable,
                                                path: &[(Variable, Variable)],
                                                root: Scalar,
                                                tree_size: Scalar)
                                                -> Result<usize, R1CSError> {
  let mut num_left_wires = 0;
  let mut node = element.into();
  let path_len = path.len();
  let one = Variable::One();
  for level in (1..path_len).rev() {
    let (b, sibling) = path[path_len - level - 1];
    let (b, node_copy, b_x_node) = cs.multiply(b.into(), node);
    let (not_b, sibling_copy, not_b_x_sibling) = cs.multiply(one - b, sibling.into());

    let (_, _, b_x_sibling) = cs.multiply(b.into(), sibling_copy.into());
    let (_, _, not_b_x_node) = cs.multiply(not_b.into(), node_copy.into());

    //if b is 1, then path follow right direction, hence sibling is hashed on the left.
    //if b is 0, then path follow left direction, hence sibling is hashed on the right.
    // left child = b * sibling + (1 - b) * node
    // right child = b * node + (1 - b) * sibling
    let (n, num_wires) = mimc_hash(cs,
                                   &[b_x_sibling + not_b_x_node, b_x_node + not_b_x_sibling],
                                   level)?;
    node = n;
    num_left_wires += 4 + num_wires;
  }

  let (b, sibling) = path[path_len - 1];
  let (b, node_copy, b_x_node) = cs.multiply(b.into(), node);
  let (not_b, sibling_copy, not_b_x_sibling) = cs.multiply(one - b, sibling.into());

  let (_, _, b_x_sibling) = cs.multiply(b.into(), sibling_copy.into());
  let (_, _, not_b_x_node) = cs.multiply(not_b.into(), node_copy.into());
  let (node, num_wires) = mimc_hash(cs,
                                    &[tree_size.into(),
                                      b_x_sibling + not_b_x_node,
                                      b_x_node + not_b_x_sibling],
                                    0)?;

  num_left_wires += 4 + num_wires;

  let constrain = node - root;
  cs.constrain(constrain);
  Ok(num_left_wires)
}

#[cfg(test)]
mod test {
  use crate::crypto::accumulators::merkle_tree::{
    mt_build, mt_prove, mt_verify, MiMCHash, PathDirection,
  };
  use bulletproofs::r1cs::{Prover, Variable, Verifier};
  use bulletproofs::{BulletproofGens, PedersenGens};
  use curve25519_dalek::ristretto::CompressedRistretto;
  use curve25519_dalek::scalar::Scalar;
  use merlin::Transcript;
  use rand_core::SeedableRng;
  use rand_chacha::ChaChaRng;

  #[test]
  fn test_bp_merkle_inclusion() {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(4500, 1);
    let mut prng = ChaChaRng::from_seed([0u8; 32]);

    let elements = [Scalar::from(1u8),
                    Scalar::from(2u8),
                    Scalar::from(3u8),
                    Scalar::from(4u8),
                    Scalar::from(5u8),
                    Scalar::from(6u8),
                    Scalar::from(7u8),
                    Scalar::from(8u8)];
    let merkle_tree = mt_build::<Scalar, MiMCHash>(&elements).unwrap();
    let merkle_root = merkle_tree.get_root();
    let (elem, path) = mt_prove(&merkle_tree, 0).unwrap();
    assert!(mt_verify::<_, MiMCHash>(&merkle_root, &elem, &path[..]).is_ok());

    let mut prover_transcript = Transcript::new(b"MerkleTreePath");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
    let (com_elem, var_elem) = prover.commit(elem, Scalar::random(&mut prng));
    let com_var_path: Vec<((CompressedRistretto, CompressedRistretto), (Variable, Variable))> =
      path.iter()
          .map(|(b, s)| {
            let (com_b, var_b) = match *b {
              PathDirection::RIGHT => prover.commit(Scalar::from(1u8), Scalar::random(&mut prng)),
              PathDirection::LEFT => prover.commit(Scalar::from(0u8), Scalar::random(&mut prng)),
            };
            let (com_s, var_s) = prover.commit(*s, Scalar::random(&mut prng));
            ((com_b, com_s), (var_b, var_s))
          })
          .collect();
    let var_path: Vec<(Variable, Variable)> = com_var_path.iter().map(|(_, y)| y.clone()).collect();
    super::merkle_verify_mimc(&mut prover,
                              var_elem,
                              &var_path[..],
                              merkle_root.value,
                              Scalar::from(merkle_root.size as u64)).unwrap();
    let proof = prover.prove(&bp_gens).unwrap();

    let mut verifier_transcript = Transcript::new(b"MerkleTreePath");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let ver_var_elem = verifier.commit(com_elem);
    let ver_var_path: Vec<(Variable, Variable)> =
      com_var_path.iter()
                  .map(|(coms, _)| {
                    let ver_var_b = verifier.commit(coms.0);
                    let ver_var_s = verifier.commit(coms.1);
                    (ver_var_b, ver_var_s)
                  })
                  .collect();

    super::merkle_verify_mimc(&mut verifier,
                              ver_var_elem,
                              &ver_var_path[..],
                              merkle_root.value,
                              Scalar::from(merkle_root.size as u64)).unwrap();
    assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
  }
}
