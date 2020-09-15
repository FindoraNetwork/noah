use crate::anon_xfr::structs::{
  AXfrPubKey, AXfrSecKey, BlindFactor, Commitment, MTNode, MTPath, Nullifier,
};
use algebra::bls12_381::BLSScalar;
use algebra::groups::{Group, One, Scalar, ScalarArithmetic, Zero};
use algebra::jubjub::{JubjubGroup, JubjubScalar};
use poly_iops::plonk::turbo_plonk_cs::rescue::StateVar;
use poly_iops::plonk::turbo_plonk_cs::{TurboPlonkConstraintSystem, VarIndex};

pub type TurboPlonkCS = TurboPlonkConstraintSystem<BLSScalar>;

// TODO: Move these constants to another file.
const SK_LEN: usize = 252; // secret key size (in bits)
const AMOUNT_LEN: usize = 64; // amount value size (in bits)
const TREE_DEPTH: usize = 20; // Depth of the Merkle Tree

/// Public inputs of a single input/output anonymous transaction.
#[derive(Debug)]
pub(crate) struct AXfrPubInputs {
  pub nullifier: Nullifier,
  pub recv_amount_type_commitment: Commitment,
  pub merkle_root: BLSScalar,
  pub signing_key: AXfrPubKey,
}

impl AXfrPubInputs {
  pub fn to_vec(&self) -> Vec<BLSScalar> {
    vec![self.nullifier,
         self.recv_amount_type_commitment,
         self.merkle_root,
         self.signing_key.0.get_x(),
         self.signing_key.0.get_y()]
  }
}

/// Secret witness of a single input/output anonymous transaction.
#[derive(Debug)]
pub(crate) struct AXfrWitness<'a> {
  pub sec_key_in: &'a AXfrSecKey,
  pub diversifier: JubjubScalar, // the randomness for re-randomizing sender's public key
  pub uid: u64,
  pub amount: u64,
  pub asset_type: BLSScalar,
  pub path: MTPath,
  pub blind_in: BlindFactor,
  pub blind_out: BlindFactor,
}

impl<'a> From<&'a AXfrSecKey> for AXfrWitness<'a> {
  // create a default `AXfrWitness` from an anonymous transfer secret key.
  fn from(sec_key_in: &'a AXfrSecKey) -> Self {
    let zero = BLSScalar::zero();
    let node = MTNode { siblings1: zero,
                        siblings2: zero,
                        is_left_child: 0,
                        is_right_child: 0 };

    AXfrWitness { sec_key_in,
                  diversifier: JubjubScalar::zero(),
                  uid: 0,
                  amount: 0,
                  asset_type: zero,
                  path: MTPath::new(vec![node; TREE_DEPTH]),
                  blind_in: BlindFactor::zero(),
                  blind_out: BlindFactor::zero() }
  }
}

/// Returns the constraint system for the single input/output transaction
/// A prover can provide honest `secret_inputs` and obtain the cs witness by calling `cs.get_and_clear_witness()`.
/// A verifier can provide an empty secret_inputs to get the constraint system `cs` for verification only.
pub(crate) fn build_single_spend_cs(secret_inputs: AXfrWitness) -> TurboPlonkCS {
  let mut cs = TurboPlonkConstraintSystem::new();
  let witness_vars = add_secret_inputs(&mut cs, secret_inputs);
  let (sec_key_in, diversifier, uid, amount, asset_type, blind_in, blind_out) =
    (witness_vars.sec_key_in,
     witness_vars.diversifier,
     witness_vars.uid,
     witness_vars.amount,
     witness_vars.asset_type,
     witness_vars.blind_in,
     witness_vars.blind_out);

  // prove knowledge of sender's secret key: pk = base^{sk}
  let base = JubjubGroup::get_base();
  let (pub_key_in_var, pub_key_in_point) = cs.scalar_mul(base, sec_key_in, SK_LEN);
  let pk_in_x = pub_key_in_var.get_x();
  let pk_in_y = pub_key_in_var.get_y();

  // prove knowledge of diversifier for sender's signing key: pk_sign = pk^{diversifier}
  let (signing_key_var, _) =
    cs.var_base_scalar_mul(pub_key_in_var, pub_key_in_point, diversifier, SK_LEN);

  // commitments
  let com_abar_in_var = commit(&mut cs, blind_in, amount, asset_type);
  let com_abar_out_var = commit(&mut cs, blind_out, amount, asset_type);

  // prove pre-image of the nullifier
  let pow_2_63 = BLSScalar::from_u64(1 << 63);
  let pow_2_64 = pow_2_63.add(&pow_2_63);
  let zero = BLSScalar::zero();
  let one = BLSScalar::one();
  let zero_var = cs.zero_var();

  // we can encode (`uid`||`amount`) to `uid_amount` := `uid` * 2^64 + `amount` because 0 <= `amount` < 2^64
  let uid_amount = cs.linear_combine(&[uid, amount, zero_var, zero_var],
                                     pow_2_64,
                                     one,
                                     zero,
                                     zero);
  let nullifier_input_vars = NullifierInputVars { uid_amount,
                                                  asset_type,
                                                  pub_key_x: pk_in_x,
                                                  pub_key_y: pk_in_y };
  let nullifier_var = nullify(&mut cs, sec_key_in, nullifier_input_vars);

  // Merkle path authentication
  let acc_elem = AccElemVars { uid,
                               commitment: com_abar_in_var,
                               pub_key_x: pk_in_x,
                               pub_key_y: pk_in_y };
  let root_var = compute_merkle_root(&mut cs, acc_elem, witness_vars.path);

  // Range check `amount`
  cs.range_check(amount, AMOUNT_LEN);

  // prepare public inputs variables
  cs.prepare_io_variable(nullifier_var);
  cs.prepare_io_variable(com_abar_out_var);
  cs.prepare_io_variable(root_var);
  cs.prepare_io_point_variable(signing_key_var);

  // pad to power of two
  cs.pad();
  cs
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

// cs variables for the secret inputs of a single input/output anonymous transaction
struct WitnessVars {
  pub sec_key_in: VarIndex,
  pub diversifier: VarIndex,
  pub uid: VarIndex,
  pub amount: VarIndex,
  pub asset_type: VarIndex,
  pub path: MerklePathVars,
  pub blind_in: VarIndex,
  pub blind_out: VarIndex,
}

// Add secret inputs into the constraint system.
fn add_secret_inputs(cs: &mut TurboPlonkCS, witness: AXfrWitness) -> WitnessVars {
  let sec_key_scalar = BLSScalar::from(&witness.sec_key_in.0);
  let diversifier_scalar = BLSScalar::from(&witness.diversifier);
  let sec_key_in = cs.new_variable(sec_key_scalar);
  let diversifier = cs.new_variable(diversifier_scalar);

  let uid = cs.new_variable(BLSScalar::from_u64(witness.uid));
  let amount = cs.new_variable(BLSScalar::from_u64(witness.amount));
  let asset_type = cs.new_variable(witness.asset_type);
  let blind_in = cs.new_variable(witness.blind_in);
  let blind_out = cs.new_variable(witness.blind_out);
  let path = add_merkle_path_variables(cs, witness.path);
  WitnessVars { sec_key_in,
                diversifier,
                uid,
                amount,
                asset_type,
                path,
                blind_in,
                blind_out }
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
                       path_vars: MerklePathVars)
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
  use algebra::groups::{Group, GroupArithmetic, One, Scalar, Zero};
  use algebra::jubjub::JubjubScalar;
  use crypto::basics::commitment::Commitment;
  use crypto::basics::hash::rescue::RescueInstance;
  use crypto::basics::prf::PRF;
  use poly_iops::plonk::turbo_plonk_cs::ecc::Point;
  use poly_iops::plonk::turbo_plonk_cs::TurboPlonkConstraintSystem;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
  use utils::errors::ZeiError;

  pub(crate) fn gen_secret_pub_inputs(sec_key_in: &AXfrSecKey)
                                      -> Result<(AXfrWitness, AXfrPubInputs), ZeiError> {
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let two = one.add(&one);
    let jubjub_one = JubjubScalar::one();
    // build secret inputs
    let diversifier = jubjub_one.add(&jubjub_one);
    let siblings1 = one;
    let siblings2 = two;
    let is_left_child = 0u8;
    let is_right_child = 1u8;
    let node = MTNode { siblings1,
                        siblings2,
                        is_left_child,
                        is_right_child };
    let path = MTPath::new(vec![node]);
    // generate blinding factors
    let comm = Commitment::new();
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let blind_in = BLSScalar::random(&mut prng);
    let blind_out = BLSScalar::random(&mut prng);
    let send_commitment = comm.commit(&blind_in, &[/*amount=*/ two, /*asset_type=*/ one])?;
    let recv_commitment = comm.commit(&blind_out, &[/*amount=*/ two, /*asset_type=*/ one])?;
    let secret_inputs = AXfrWitness { sec_key_in,
                                      diversifier,
                                      uid: 1,
                                      amount: 2,
                                      asset_type: one,
                                      path,
                                      blind_in,
                                      blind_out };

    // compute public inputs
    // sender's randomized public key
    let base = JubjubGroup::get_base();
    let pub_key_in = AXfrPubKey(base.mul(&sec_key_in.0));
    let signing_key = AXfrPubKey(pub_key_in.0.mul(&diversifier));
    // nullifier
    let pow_2_63 = BLSScalar::from_u64(1 << 63);
    let pow_2_64 = pow_2_63.add(&pow_2_63);
    // encode `uid_amount` = `uid` * 2^64 + `amount`
    let uid_amount = pow_2_64.add(&two);
    let prf = PRF::new();
    let nullifier = prf.eval(/*sec_key_in=*/
                             &BLSScalar::from(&sec_key_in.0),
                             &[uid_amount,
                               /*asset_type=*/ one,
                               pub_key_in.0.get_x(),
                               pub_key_in.0.get_y()]);
    // merkle root
    let hash = RescueInstance::new();
    let pk_hash = hash.rescue_hash(&[pub_key_in.0.get_x(), pub_key_in.0.get_y(), zero, zero])[0];
    let leaf = hash.rescue_hash(&[/*uid=*/ one, send_commitment, pk_hash, zero])[0];
    // leaf is the right child
    let merkle_root = hash.rescue_hash(&[/*sib1[0]=*/ one, /*sib2[0]=*/ two, leaf, zero])[0];
    let pub_inputs = AXfrPubInputs { nullifier,
                                     merkle_root,
                                     signing_key,
                                     recv_amount_type_commitment: recv_commitment };
    Ok((secret_inputs, pub_inputs))
  }
  #[test]
  fn test_build_single_spend_cs() {
    let mut prng = ChaChaRng::from_seed([1u8; 32]);
    let sec_key_in = AXfrSecKey(JubjubScalar::random(&mut prng));
    let (secret_inputs, pub_inputs) = gen_secret_pub_inputs(&sec_key_in).unwrap();

    // check the constraints
    let mut cs = build_single_spend_cs(secret_inputs);
    let mut witness = cs.get_and_clear_witness();
    let online_inputs = pub_inputs.to_vec();
    let verify = cs.verify_witness(&witness, &online_inputs);
    assert!(verify.is_ok(), verify.unwrap_err());
    witness[1].add_assign(&BLSScalar::one());
    assert!(cs.verify_witness(&witness, &online_inputs).is_err());
  }

  #[test]
  fn test_commit() {
    let mut cs = TurboPlonkConstraintSystem::new();
    let amount = BLSScalar::from_u32(7);
    let asset_type = BLSScalar::from_u32(5);
    let comm = Commitment::new();
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
    let root_var = compute_merkle_root(&mut cs, elem, path_vars);

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
}
