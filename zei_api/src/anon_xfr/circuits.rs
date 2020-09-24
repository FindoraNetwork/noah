use crate::anon_xfr::structs::{AXfrPubKey, BlindFactor, Commitment, MTNode, MTPath, Nullifier};
use algebra::bls12_381::BLSScalar;
use algebra::groups::{Group, GroupArithmetic, One, Scalar, ScalarArithmetic, Zero};
use algebra::jubjub::{JubjubGroup, JubjubScalar};
use crypto::basics::commitments::rescue::HashCommitment as CommScheme;
use crypto::basics::hash::rescue::RescueInstance;
use crypto::basics::prf::PRF;
use poly_iops::plonk::turbo_plonk_cs::rescue::StateVar;
use poly_iops::plonk::turbo_plonk_cs::{TurboPlonkConstraintSystem, VarIndex};

pub type TurboPlonkCS = TurboPlonkConstraintSystem<BLSScalar>;

// TODO: Move these constants to another file.
const SK_LEN: usize = 252; // secret key size (in bits)
const AMOUNT_LEN: usize = 64; // amount value size (in bits)
pub const TREE_DEPTH: usize = 20; // Depth of the Merkle Tree

#[derive(Debug, Clone)]
pub(crate) struct PayerSecret {
  pub sec_key: JubjubScalar,
  pub diversifier: JubjubScalar, // key randomizer for the signature verification key
  pub amount: u64,
  // pub asset_type: BLSScalar, // TODO: add it when we support multi-asset_types in a Xfr
  pub uid: u64,
  pub path: MTPath,
  pub blind: BlindFactor,
}

#[derive(Debug, Clone)]
pub(crate) struct PayeeSecret {
  pub amount: u64,
  pub blind: BlindFactor,
}

/// Secret witness of an anonymous transaction.
#[derive(Debug)]
pub(crate) struct AMultiXfrWitness {
  pub asset_type: BLSScalar,
  pub payers_secrets: Vec<PayerSecret>,
  pub payees_secrets: Vec<PayeeSecret>,
}

impl AMultiXfrWitness {
  // create a default `AMultiXfrWitness`.
  pub(crate) fn fake(n_payers: usize, n_payees: usize, tree_depth: usize) -> Self {
    let bls_zero = BLSScalar::zero();
    let jubjub_zero = JubjubScalar::zero();
    let node = MTNode { siblings1: bls_zero,
                        siblings2: bls_zero,
                        is_left_child: 0,
                        is_right_child: 0 };
    let payer_secret = PayerSecret { sec_key: jubjub_zero,
                                     diversifier: jubjub_zero,
                                     uid: 0,
                                     amount: 0,
                                     path: MTPath::new(vec![node; tree_depth]),
                                     blind: bls_zero };
    let payee_secret = PayeeSecret { amount: 0,
                                     blind: bls_zero };

    AMultiXfrWitness { asset_type: bls_zero,
                       payers_secrets: vec![payer_secret; n_payers],
                       payees_secrets: vec![payee_secret; n_payees] }
  }
}

/// Public inputs of an anonymous transaction.
#[derive(Debug)]
pub(crate) struct AMultiXfrPubInputs {
  pub payers_inputs: Vec<(Nullifier, AXfrPubKey)>,
  pub payees_commitments: Vec<Commitment>,
  pub merkle_root: BLSScalar,
  pub fee: u64, // transaction fee
}

impl AMultiXfrPubInputs {
  pub fn to_vec(&self) -> Vec<BLSScalar> {
    let mut result = vec![];
    // nullifiers and signature verification keys
    for (nullifier, pk_sign) in &self.payers_inputs {
      result.push(*nullifier);
      result.push(pk_sign.0.get_x());
      result.push(pk_sign.0.get_y());
    }
    // merkle_root
    result.push(self.merkle_root);
    // output commitments
    for comm in &self.payees_commitments {
      result.push(*comm);
    }
    // transaction fee
    result.push(BLSScalar::from_u64(self.fee));
    result
  }

  // Compute the public inputs from the secret inputs
  pub(crate) fn from_witness(witness: &AMultiXfrWitness) -> Self {
    // nullifiers and signature public keys
    let prf = PRF::new();
    let base = JubjubGroup::get_base();
    let payers_inputs: Vec<(Nullifier, AXfrPubKey)> =
      witness.payers_secrets
             .iter()
             .map(|sec| {
               let pk_point = base.mul(&sec.sec_key);
               let pk_sign = AXfrPubKey(pk_point.mul(&sec.diversifier));

               let pow_2_64 = BLSScalar::from_u64(u64::max_value()).add(&BLSScalar::one());
               let uid_amount = pow_2_64.mul(&BLSScalar::from_u64(sec.uid))
                                        .add(&BLSScalar::from_u64(sec.amount));
               let nullifier = prf.eval(&BLSScalar::from(&sec.sec_key),
                                        &[uid_amount,
                                          witness.asset_type,
                                          pk_point.get_x(),
                                          pk_point.get_y()]);
               (nullifier, pk_sign)
             })
             .collect();

    // output commitments
    let comm = CommScheme::new();
    let payees_commitments: Vec<Commitment> = witness.payees_secrets
                                                     .iter()
                                                     .map(|sec| {
                                                       comm.commit(&sec.blind,
                           &[BLSScalar::from_u64(sec.amount), witness.asset_type])
                   .unwrap()
                                                     })
                                                     .collect();

    // transaction fee
    let balance: u64 = witness.payers_secrets
                              .iter()
                              .fold(0, |acc, x| acc + x.amount);
    let fee: u64 = witness.payees_secrets
                          .iter()
                          .fold(balance, |acc, x| acc - x.amount);

    // merkle root
    let hash = RescueInstance::new();
    let payer = &witness.payers_secrets[0];
    let pk_point = base.mul(&payer.sec_key);
    let zero = BLSScalar::zero();
    let pk_hash = hash.rescue_hash(&[pk_point.get_x(), pk_point.get_y(), zero, zero])[0];
    let commitment = comm.commit(&payer.blind,
                                 &[BLSScalar::from_u64(payer.amount), witness.asset_type])
                         .unwrap();
    let mut node =
      hash.rescue_hash(&[BLSScalar::from_u64(payer.uid), commitment, pk_hash, zero])[0];
    for path_node in payer.path.nodes.iter().rev() {
      let input = match (path_node.is_left_child, path_node.is_right_child) {
        (1, 0) => vec![node, path_node.siblings1, path_node.siblings2, zero],
        (0, 0) => vec![path_node.siblings1, node, path_node.siblings2, zero],
        _ => vec![path_node.siblings1, path_node.siblings2, node, zero],
      };
      node = hash.rescue_hash(&input)[0];
    }

    Self { payers_inputs,
           payees_commitments,
           merkle_root: node,
           fee }
  }
}

/// Returns the constraint system for a multi-inputs/outputs transaction, and the corresponding number of constraints.
/// A prover can provide honest `secret_inputs` and obtain the cs witness by calling `cs.get_and_clear_witness()`.
/// One provide an empty secret_inputs to get the constraint system `cs` for verification only.
pub(crate) fn build_multi_xfr_cs(secret_inputs: AMultiXfrWitness) -> (TurboPlonkCS, usize) {
  assert_ne!(secret_inputs.payers_secrets.len(), 0);
  assert_ne!(secret_inputs.payees_secrets.len(), 0);

  let mut cs = TurboPlonkConstraintSystem::new();
  let payers_secrets = add_payers_secrets(&mut cs, &secret_inputs.payers_secrets);
  let payees_secrets = add_payees_secrets(&mut cs, &secret_inputs.payees_secrets);
  let asset_type = cs.new_variable(secret_inputs.asset_type);

  let base = JubjubGroup::get_base();
  let pow_2_64 = BLSScalar::from_u64(u64::max_value()).add(&BLSScalar::one());
  let zero = BLSScalar::zero();
  let one = BLSScalar::one();
  let zero_var = cs.zero_var();
  let mut root_var: Option<VarIndex> = None;
  for payer in &payers_secrets {
    // prove knowledge of payer's secret key: pk = base^{sk}
    let (pk_var, pk_point) = cs.scalar_mul(base.clone(), payer.sec_key, SK_LEN);
    let pk_x = pk_var.get_x();
    let pk_y = pk_var.get_y();

    // prove knowledge of diversifier: pk_sign = pk^{diversifier}
    let (pk_sign_var, _) = cs.var_base_scalar_mul(pk_var, pk_point, payer.diversifier, SK_LEN);

    // commitments
    let com_abar_in_var = commit(&mut cs, payer.blind, payer.amount, asset_type);

    // prove pre-image of the nullifier
    // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`
    let uid_amount = cs.linear_combine(&[payer.uid, payer.amount, zero_var, zero_var],
                                       pow_2_64,
                                       one,
                                       zero,
                                       zero);
    let nullifier_input_vars = NullifierInputVars { uid_amount,
                                                    asset_type,
                                                    pub_key_x: pk_x,
                                                    pub_key_y: pk_y };
    let nullifier_var = nullify(&mut cs, payer.sec_key, nullifier_input_vars);

    // Merkle path authentication
    let acc_elem = AccElemVars { uid: payer.uid,
                                 commitment: com_abar_in_var,
                                 pub_key_x: pk_x,
                                 pub_key_y: pk_y };
    let tmp_root_var = compute_merkle_root(&mut cs, acc_elem, &payer.path);

    if let Some(root) = root_var {
      cs.equal(root, tmp_root_var);
    } else {
      root_var = Some(tmp_root_var);
    }

    // prepare public inputs variables
    cs.prepare_io_variable(nullifier_var);
    cs.prepare_io_point_variable(pk_sign_var);
  }
  // prepare the publc input for merkle_root
  cs.prepare_io_variable(root_var.unwrap()); // safe unwrap

  for payee in &payees_secrets {
    // commitment
    let com_abar_out_var = commit(&mut cs, payee.blind, payee.amount, asset_type);

    // Range check `amount`
    // Note we don't need to range-check payers' `amount`, because those amounts are bound
    // to payers' accumulated abars, whose underlying amounts have already been range-checked
    // in the transactions that created the payers' abars.
    cs.range_check(payee.amount, AMOUNT_LEN);

    // prepare the public input for the output commitment
    cs.prepare_io_variable(com_abar_out_var);
  }

  // Balance check: fee = \sum_{i} amount_in_i - \sum_{j} amount_out_j
  let mut balance_var = zero_var;
  for payer in &payers_secrets {
    balance_var = cs.add(balance_var, payer.amount);
  }
  for payee in &payees_secrets {
    balance_var = cs.sub(balance_var, payee.amount);
  }
  // prepare the public input for the transaction fee
  cs.prepare_io_variable(balance_var);

  // pad the number of constraints to power of two
  cs.pad();

  let n_constraints = cs.size;
  (cs, n_constraints)
}

fn add_payers_secrets(cs: &mut TurboPlonkCS, secrets: &[PayerSecret]) -> Vec<PayerSecretVars> {
  secrets.iter()
         .map(|secret| {
           let bls_sk = BLSScalar::from(&secret.sec_key);
           let bls_diversifier = BLSScalar::from(&secret.diversifier);
           let sec_key = cs.new_variable(bls_sk);
           let diversifier = cs.new_variable(bls_diversifier);
           let uid = cs.new_variable(BLSScalar::from_u64(secret.uid));
           let amount = cs.new_variable(BLSScalar::from_u64(secret.amount));
           let blind = cs.new_variable(secret.blind);
           let path = add_merkle_path_variables(cs, secret.path.clone());
           PayerSecretVars { sec_key,
                             diversifier,
                             uid,
                             amount,
                             path,
                             blind }
         })
         .collect()
}

fn add_payees_secrets(cs: &mut TurboPlonkCS, secrets: &[PayeeSecret]) -> Vec<PayeeSecretVars> {
  secrets.iter()
         .map(|secret| {
           let amount = cs.new_variable(BLSScalar::from_u64(secret.amount));
           let blind = cs.new_variable(secret.blind);
           PayeeSecretVars { amount, blind }
         })
         .collect()
}

struct PayerSecretVars {
  pub sec_key: VarIndex,
  pub diversifier: VarIndex,
  pub uid: VarIndex,
  pub amount: VarIndex,
  pub path: MerklePathVars,
  pub blind: VarIndex,
}

struct PayeeSecretVars {
  pub amount: VarIndex,
  pub blind: VarIndex,
}

// cs variables for a Merkle node
struct MerkleNodeVars {
  pub siblings1: VarIndex,
  pub siblings2: VarIndex,
  pub is_left_child: VarIndex,
  pub is_right_child: VarIndex,
}

// cs variables for a merkle authentication path
struct MerklePathVars {
  pub nodes: Vec<MerkleNodeVars>,
}

// cs variables for an accumulated element
struct AccElemVars {
  pub uid: VarIndex,
  pub commitment: VarIndex,
  pub pub_key_x: VarIndex,
  pub pub_key_y: VarIndex,
}

// cs variables for the nullifier PRF inputs
struct NullifierInputVars {
  pub uid_amount: VarIndex,
  pub asset_type: VarIndex,
  pub pub_key_x: VarIndex,
  pub pub_key_y: VarIndex,
}

fn add_merkle_path_variables(cs: &mut TurboPlonkCS, path: MTPath) -> MerklePathVars {
  let path_vars: Vec<MerkleNodeVars> = path.nodes
                                           .into_iter()
                                           .map(|node| {
                                             MerkleNodeVars{
    siblings1: cs.new_variable(node.siblings1),
    siblings2: cs.new_variable(node.siblings2),
    is_left_child: cs.new_variable(BLSScalar::from_u32(node.is_left_child as u32)),
    is_right_child: cs.new_variable(BLSScalar::from_u32(node.is_right_child as u32)),
  }
                                           })
                                           .collect();
  // Boolean-constrain `is_left_child` and `is_right_child`
  for node_var in path_vars.iter() {
    cs.insert_boolean_gate(node_var.is_left_child);
    cs.insert_boolean_gate(node_var.is_right_child);
    // 0 <= is_left_child[i] + is_right_child[i] <= 1 for every i,
    // because a node can't simultaneously be the left and right child of its parent
    let left_add_right = cs.add(node_var.is_left_child, node_var.is_right_child);
    cs.insert_boolean_gate(left_add_right);
  }

  MerklePathVars { nodes: path_vars }
}

// Add the sorting constraints that arrange the positions of the sibling nodes.
// If `node` is the left child of parent, output (`node`, `sib1`, `sib2`);
// if `node` is the right child of parent, output (`sib1`, `sib2`, `node`);
// otherwise, output (`sib1`, `node`, `sib2`)
fn sort(cs: &mut TurboPlonkCS,
        node: VarIndex,
        sib1: VarIndex,
        sib2: VarIndex,
        is_left_child: VarIndex,
        is_right_child: VarIndex)
        -> StateVar {
  let left = cs.select(sib1, node, is_left_child);
  let right = cs.select(sib2, node, is_right_child);
  let sum_left_right = cs.add(left, right);
  let one = BLSScalar::one();
  let mid = cs.linear_combine(&[node, sib1, sib2, sum_left_right],
                              one,
                              one,
                              one,
                              one.neg());
  StateVar::new([left, mid, right, cs.zero_var()])
}

fn compute_merkle_root(cs: &mut TurboPlonkCS,
                       elem: AccElemVars,
                       path_vars: &MerklePathVars)
                       -> VarIndex {
  let (uid, commitment, pub_key_x, pub_key_y) =
    (elem.uid, elem.commitment, elem.pub_key_x, elem.pub_key_y);
  let zero_var = cs.zero_var();
  // TODO: compute `pk_hash_var` using a simpler encoding that has fewer constraints
  let pk_hash_var = cs.rescue_hash(&StateVar::new([pub_key_x, pub_key_y, zero_var, zero_var]));
  let mut node_var = cs.rescue_hash(&StateVar::new([uid, commitment, pk_hash_var, zero_var]));

  for path_node in path_vars.nodes.iter().rev() {
    let input_var = sort(cs,
                         node_var,
                         path_node.siblings1,
                         path_node.siblings2,
                         path_node.is_left_child,
                         path_node.is_right_child);
    node_var = cs.rescue_hash(&input_var);
  }
  node_var
}

// Add the commitment constraints to the constraint system:
// comm = commit(blinding, amount, asset_type)
fn commit(cs: &mut TurboPlonkCS,
          blinding_var: VarIndex,
          amount_var: VarIndex,
          asset_var: VarIndex)
          -> VarIndex {
  let input_var = StateVar::new([blinding_var, amount_var, asset_var, cs.zero_var()]);
  cs.rescue_hash(&input_var)
}

// Add the nullifier constraints to the constraint system.
// nullifer = PRF(sk, msg = [uid_amount, asset_type, pk_x, pk_y])
// The PRF follows the Full-State Keyed Sponge (FKS) paradigm explained in https://eprint.iacr.org/2015/541.pdf
// Let perm : Fp^w -> Fp^w be a public permutation.
// Given secret key `key`, set initial state `s_key` := (0 || ... || 0 || key), the PRF output is:
// PRF^p(key, (m1, ..., mw)) = perm(s_key \xor (m1 || ... || mw))[0]
fn nullify(cs: &mut TurboPlonkCS,
           sk_var: VarIndex,
           nullifier_input_vars: NullifierInputVars)
           -> VarIndex {
  let (uid_amount, asset_type, pub_key_x, pub_key_y) = (nullifier_input_vars.uid_amount,
                                                        nullifier_input_vars.asset_type,
                                                        nullifier_input_vars.pub_key_x,
                                                        nullifier_input_vars.pub_key_y);
  let input_var = StateVar::new([uid_amount, asset_type, pub_key_x, cs.add(pub_key_y, sk_var)]);
  cs.rescue_hash(&input_var)
}

#[cfg(test)]
pub(crate) mod tests {
  use super::*;
  use algebra::bls12_381::BLSScalar;
  use algebra::groups::{One, Scalar, Zero};
  use crypto::basics::commitments::rescue::HashCommitment;
  use crypto::basics::hash::rescue::RescueInstance;
  use crypto::basics::prf::PRF;
  use poly_iops::plonk::turbo_plonk_cs::ecc::Point;
  use poly_iops::plonk::turbo_plonk_cs::TurboPlonkConstraintSystem;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
  use std::cmp::min;

  pub(crate) fn new_multi_xfr_witness_for_test(n_payers: usize,
                                               n_payees: usize,
                                               seed: [u8; 32])
                                               -> AMultiXfrWitness {
    assert!(n_payers <= 3);
    assert!(n_payees <= 3);
    let mut prng = ChaChaRng::from_seed(seed);
    let asset_type = BLSScalar::random(&mut prng);
    let zero = BLSScalar::zero();
    let mut payers_secrets: Vec<PayerSecret> =
      (0..n_payers).map(|i| {
                     let (is_left_child, is_right_child) = match i % 3 {
                       0 => (1, 0),
                       1 => (0, 0),
                       _ => (0, 1),
                     };
                     let node = MTNode { siblings1: zero,
                                         siblings2: zero,
                                         is_left_child,
                                         is_right_child };
                     PayerSecret { sec_key: JubjubScalar::random(&mut prng),
                                   diversifier: JubjubScalar::random(&mut prng),
                                   uid: i as u64,
                                   amount: 10 * (i + 1) as u64,
                                   path: MTPath::new(vec![node]),
                                   blind: BLSScalar::random(&mut prng) }
                   })
                   .collect();
    // compute the merkle leafs and update the merkle paths if there are more than 1 payers
    if n_payers > 1 {
      let hash = RescueInstance::new();
      let comm = CommScheme::new();
      let base = JubjubGroup::get_base();
      let leafs: Vec<BLSScalar> =
        payers_secrets.iter()
                      .map(|payer| {
                        let pk_point = base.mul(&payer.sec_key);
                        let pk_hash =
                          hash.rescue_hash(&[pk_point.get_x(), pk_point.get_y(), zero, zero])[0];
                        let commitment = comm.commit(&payer.blind,
                                                     &[BLSScalar::from_u64(payer.amount),
                                                       asset_type])
                                             .unwrap();
                        hash.rescue_hash(&[BLSScalar::from_u64(payer.uid),
                                           commitment,
                                           pk_hash,
                                           zero])[0]
                      })
                      .collect();
      if n_payers == 2 {
        payers_secrets[0].path.nodes[0].siblings1 = leafs[1];
        payers_secrets[0].path.nodes[0].siblings2 = zero;
        payers_secrets[1].path.nodes[0].siblings1 = leafs[0];
        payers_secrets[1].path.nodes[0].siblings2 = zero;
      } else {
        payers_secrets[0].path.nodes[0].siblings1 = leafs[1];
        payers_secrets[0].path.nodes[0].siblings2 = leafs[2];
        payers_secrets[1].path.nodes[0].siblings1 = leafs[0];
        payers_secrets[1].path.nodes[0].siblings2 = leafs[2];
        payers_secrets[2].path.nodes[0].siblings1 = leafs[0];
        payers_secrets[2].path.nodes[0].siblings2 = leafs[1];
      }
    }

    let mut balance = (n_payers * (n_payers + 1) * 5) as u64;
    let payees_secrets: Vec<PayeeSecret> = (0..n_payees).map(|i| {
                                                          let amount =
                                                            min(9 * (i + 1) as u64, balance);
                                                          balance -= amount;
                                                          PayeeSecret { amount,
                      blind: BLSScalar::random(&mut prng) }
                                                        })
                                                        .collect();

    AMultiXfrWitness { asset_type,
                       payers_secrets,
                       payees_secrets }
  }

  #[test]
  fn test_commit() {
    let mut cs = TurboPlonkConstraintSystem::new();
    let amount = BLSScalar::from_u32(7);
    let asset_type = BLSScalar::from_u32(5);
    let comm = HashCommitment::new();
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let blind = BLSScalar::random(&mut prng);
    let commitment = comm.commit(&blind, &[amount, asset_type]).unwrap(); // safe unwrap

    let amount_var = cs.new_variable(amount);
    let asset_var = cs.new_variable(asset_type);
    let blind_var = cs.new_variable(blind);
    let comm_var = commit(&mut cs, blind_var, amount_var, asset_var);
    let mut witness = cs.get_and_clear_witness();

    // Check commitment consistency
    assert_eq!(witness[comm_var], commitment);

    // Check the constraints
    assert!(cs.verify_witness(&witness, &[]).is_ok());
    witness[comm_var] = BLSScalar::zero();
    assert!(cs.verify_witness(&witness, &[]).is_err());
  }

  #[test]
  fn test_nullify() {
    let one = BLSScalar::one();
    let zero = BLSScalar::zero();
    let mut cs = TurboPlonkConstraintSystem::new();
    let mut prng = ChaChaRng::from_seed([1u8; 32]);
    let sk = BLSScalar::random(&mut prng);
    let bytes = vec![1u8; 32];
    let uid_amount = BLSScalar::from_bytes(&bytes[..]).unwrap(); // safe unwrap
    let asset_type = one;
    let pk = Point::new(zero, one);
    let prf = PRF::new();
    let expected_output = prf.eval(&sk, &[uid_amount, asset_type, *pk.get_x(), *pk.get_y()]);

    let sk_var = cs.new_variable(sk);
    let uid_amount_var = cs.new_variable(uid_amount);
    let asset_var = cs.new_variable(asset_type);
    let pk_var = cs.new_point_variable(pk);
    let nullifier_input_var = NullifierInputVars { uid_amount: uid_amount_var,
                                                   asset_type: asset_var,
                                                   pub_key_x: pk_var.get_x(),
                                                   pub_key_y: pk_var.get_y() };
    let nullifier_var = nullify(&mut cs, sk_var, nullifier_input_var);
    let mut witness = cs.get_and_clear_witness();

    // Check PRF output consistency
    assert_eq!(witness[nullifier_var], expected_output);

    // Check the constraints
    assert!(cs.verify_witness(&witness, &[]).is_ok());
    witness[nullifier_var] = zero;
    assert!(cs.verify_witness(&witness, &[]).is_err());
  }

  #[test]
  fn test_sort() {
    let mut cs = TurboPlonkConstraintSystem::new();
    let num: Vec<BLSScalar> = (0..5).map(|x| BLSScalar::from_u32(x as u32)).collect();
    let node_var = cs.new_variable(num[2]);
    let sib1_var = cs.new_variable(num[3]);
    let sib2_var = cs.new_variable(num[4]);
    let is_left_var = cs.new_variable(num[0]);
    let is_right_var = cs.new_variable(num[1]);
    let out_state = sort(&mut cs,
                         node_var,
                         sib1_var,
                         sib2_var,
                         is_left_var,
                         is_right_var);
    let mut witness = cs.get_and_clear_witness();
    let output: Vec<BLSScalar> = out_state.as_slice()
                                          .iter()
                                          .map(|&idx| witness[idx])
                                          .collect();
    // node_var is at the right position
    let expected_output = vec![witness[sib1_var],
                               witness[sib2_var],
                               witness[node_var],
                               witness[cs.zero_var()]];
    // Check output correctness
    assert_eq!(output, expected_output);

    // Check constraints
    assert!(cs.verify_witness(&witness, &[]).is_ok());
    witness[sib1_var] = BLSScalar::one();
    assert!(cs.verify_witness(&witness, &[]).is_err());
  }

  #[test]
  fn test_merkle_root() {
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let two = one.add(&one);
    let three = two.add(&one);
    let four = two.add(&two);
    let mut cs = TurboPlonkConstraintSystem::new();
    let uid_var = cs.new_variable(one);
    let comm_var = cs.new_variable(two);
    let pk_var = cs.new_point_variable(Point::new(zero, one));
    let elem = AccElemVars { uid: uid_var,
                             commitment: comm_var,
                             pub_key_x: pk_var.get_x(),
                             pub_key_y: pk_var.get_y() };

    let path_node1 = MTNode { siblings1: one,
                              siblings2: three,
                              is_left_child: 1u8,
                              is_right_child: 0u8 };
    let path_node2 = MTNode { siblings1: two,
                              siblings2: four,
                              is_left_child: 0u8,
                              is_right_child: 1u8 };
    // compute the root value
    let hash = RescueInstance::new();
    let pk_hash = hash.rescue_hash(&[/*pk_x=*/ zero, /*pk_y=*/ one, zero, zero])[0];
    let leaf = hash.rescue_hash(&[/*uid=*/ one, /*comm=*/ two, pk_hash, zero])[0];
    // leaf is the right child of node1
    let node1 = hash.rescue_hash(&[path_node2.siblings1, path_node2.siblings2, leaf, zero])[0];
    // node1 is the left child of the root
    let root = hash.rescue_hash(&[node1, path_node1.siblings1, path_node1.siblings2, zero])[0];

    // compute the constraints
    let path = MTPath::new(vec![path_node1, path_node2]);
    let path_vars = add_merkle_path_variables(&mut cs, path);
    let root_var = compute_merkle_root(&mut cs, elem, &path_vars);

    // Check Merkle root correctness
    let mut witness = cs.get_and_clear_witness();
    assert_eq!(witness[root_var], root);

    // Check constraints
    assert!(cs.verify_witness(&witness, &[]).is_ok());
    witness[root_var] = one;
    assert!(cs.verify_witness(&witness, &[]).is_err());
  }

  #[test]
  fn test_add_merkle_path_variables() {
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    // happy path: `is_left_child`/`is_right_child`/`is_left_child + is_right_child` are boolean
    let mut cs = TurboPlonkConstraintSystem::new();
    let node = MTNode { siblings1: one,
                        siblings2: zero,
                        is_left_child: 1u8,
                        is_right_child: 0u8 };
    let path = MTPath::new(vec![node]);
    let _ = add_merkle_path_variables(&mut cs, path);
    let witness = cs.get_and_clear_witness();
    assert!(cs.verify_witness(&witness, &[]).is_ok());

    // cs cannot be satisfied when `is_left_child` (or `is_right_child`) is not boolean
    let mut cs = TurboPlonkConstraintSystem::new();
    // is_left is not boolean
    let node = MTNode { siblings1: one,
                        siblings2: zero,
                        is_left_child: 2u8,
                        is_right_child: 0u8 };
    let path = MTPath::new(vec![node]);
    let _ = add_merkle_path_variables(&mut cs, path);
    let witness = cs.get_and_clear_witness();
    assert!(cs.verify_witness(&witness, &[]).is_err());

    // cs cannot be satisfied when `is_left_child` + `is_right_child` is not boolean
    let mut cs = TurboPlonkConstraintSystem::new();
    // `is_left` and `is_right` are both 1
    let node = MTNode { siblings1: one,
                        siblings2: zero,
                        is_left_child: 1u8,
                        is_right_child: 1u8 };
    let path = MTPath::new(vec![node]);
    let _ = add_merkle_path_variables(&mut cs, path);
    let witness = cs.get_and_clear_witness();
    assert!(cs.verify_witness(&witness, &[]).is_err());
  }

  #[test]
  fn test_build_multi_xfr_cs() {
    test_multi_xfr_cs(1, 2);
    test_multi_xfr_cs(2, 1);
    test_multi_xfr_cs(2, 3);
    test_multi_xfr_cs(3, 2);
  }

  fn test_multi_xfr_cs(n_payers: usize, n_payees: usize) {
    let secret_inputs = new_multi_xfr_witness_for_test(n_payers, n_payees, [0u8; 32]);
    let pub_inputs = AMultiXfrPubInputs::from_witness(&secret_inputs);

    // check the constraints
    let (mut cs, _) = build_multi_xfr_cs(secret_inputs);
    let mut witness = cs.get_and_clear_witness();
    let online_inputs = pub_inputs.to_vec();
    let verify = cs.verify_witness(&witness, &online_inputs);
    assert!(verify.is_ok(), verify.unwrap_err());
    witness[1].add_assign(&BLSScalar::one());
    assert!(cs.verify_witness(&witness, &online_inputs).is_err());
  }
}
