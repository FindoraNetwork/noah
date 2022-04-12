use crate::anon_xfr::structs::{BlindFactor, Commitment, MTNode, MTPath, Nullifier};
use num_bigint::BigUint;
use zei_algebra::{
    bls12_381::BLSScalar,
    jubjub::{JubjubPoint, JubjubScalar},
    ops::*,
    ristretto::RistrettoScalar,
    traits::{Group, Scalar},
    One, Zero,
};
use zei_crypto::basic::rescue::RescueInstance;
use zei_crypto::{
    field_simulation::{SimFr, BIT_PER_LIMB, NUM_OF_LIMBS},
    pc_eq_rescue_split_verifier_zk_part::{NonZKState, ZKPartProof},
};
use zei_plonk::plonk::constraint_system::{
    field_simulation::SimFrVar, rescue::StateVar, TurboConstraintSystem, VarIndex,
};

pub type TurboPlonkCS = TurboConstraintSystem<BLSScalar>;

// TODO: Move these constants to another file.
pub(crate) const SK_LEN: usize = 252; // secret key size (in bits)
pub(crate) const AMOUNT_LEN: usize = 64; // amount value size (in bits)

// Depth of the Merkle Tree circuit. here <= accumulators::merkle_tree::TREE_DEPTH (20)
pub const TREE_DEPTH: usize = 20;

#[derive(Debug, Clone)]
pub struct PayerSecret {
    pub sec_key: JubjubScalar,
    pub amount: u64,
    pub asset_type: BLSScalar,
    pub uid: u64,
    pub path: MTPath,
    pub blind: BlindFactor,
}

#[derive(Debug, Clone)]
pub struct PayeeSecret {
    pub amount: u64,
    pub blind: BlindFactor,
    pub asset_type: BLSScalar,
    pub pubkey_x: BLSScalar,
}

/// Secret witness of an anonymous transaction.
#[derive(Debug)]
pub(crate) struct AMultiXfrWitness {
    pub payers_secrets: Vec<PayerSecret>,
    pub payees_secrets: Vec<PayeeSecret>,
}

impl AMultiXfrWitness {
    // create a default `AMultiXfrWitness`.
    pub(crate) fn fake(n_payers: usize, n_payees: usize, tree_depth: usize) -> Self {
        let bls_zero = BLSScalar::zero();
        let jubjub_zero = JubjubScalar::zero();
        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerSecret {
            sec_key: jubjub_zero,
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };
        let payee_secret = PayeeSecret {
            amount: 0,
            blind: bls_zero,
            asset_type: bls_zero,
            pubkey_x: bls_zero,
        };

        AMultiXfrWitness {
            payers_secrets: vec![payer_secret; n_payers],
            payees_secrets: vec![payee_secret; n_payees],
        }
    }
}

/// Public inputs of an anonymous transaction.
#[derive(Debug)]
pub(crate) struct AMultiXfrPubInputs {
    pub payers_inputs: Vec<Nullifier>,
    pub payees_commitments: Vec<Commitment>,
    pub merkle_root: BLSScalar,
}

impl AMultiXfrPubInputs {
    pub fn to_vec(&self) -> Vec<BLSScalar> {
        let mut result = vec![];
        // nullifiers and signature verification keys
        for nullifier in &self.payers_inputs {
            result.push(*nullifier);
        }
        // merkle_root
        result.push(self.merkle_root);
        // output commitments
        for comm in &self.payees_commitments {
            result.push(*comm);
        }
        result
    }

    // Compute the public inputs from the secret inputs
    #[allow(dead_code)]
    pub(crate) fn from_witness(witness: &AMultiXfrWitness) -> Self {
        // nullifiers and signature public keys
        let hash = RescueInstance::new();
        let base = JubjubPoint::get_base();
        let payers_inputs: Vec<Nullifier> = witness
            .payers_secrets
            .iter()
            .map(|sec| {
                let pk_point = base.mul(&sec.sec_key);

                let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::one());
                let uid_amount = pow_2_64
                    .mul(&BLSScalar::from(sec.uid))
                    .add(&BLSScalar::from(sec.amount));
                hash.rescue(&[
                    uid_amount,
                    sec.asset_type,
                    pk_point.get_x(),
                    BLSScalar::from(&sec.sec_key),
                ])[0]
            })
            .collect();

        // output commitments
        let hash = RescueInstance::new();
        let zero = BLSScalar::zero();
        let payees_commitments: Vec<Commitment> = witness
            .payees_secrets
            .iter()
            .map(|sec| {
                hash.rescue(&[sec.blind, BLSScalar::from(sec.amount), sec.asset_type, zero])[0]
            })
            .collect();

        // merkle root
        let payer = &witness.payers_secrets[0];
        let pk_point = base.mul(&payer.sec_key);
        let commitment = hash.rescue(&[
            payer.blind,
            BLSScalar::from(payer.amount),
            payer.asset_type,
            zero,
        ])[0];
        let mut node = hash.rescue(&[
            BLSScalar::from(payer.uid),
            commitment,
            pk_point.get_x(),
            zero,
        ])[0];
        for path_node in payer.path.nodes.iter() {
            let input = match (path_node.is_left_child, path_node.is_right_child) {
                (1, 0) => vec![node, path_node.siblings1, path_node.siblings2, zero],
                (0, 0) => vec![path_node.siblings1, node, path_node.siblings2, zero],
                _ => vec![path_node.siblings1, path_node.siblings2, node, zero],
            };
            node = hash.rescue(&input)[0];
        }

        Self {
            payers_inputs,
            payees_commitments,
            merkle_root: node,
        }
    }
}

/// Returns the constraint system (and associated number of constraints) for a multi-inputs/outputs transaction.
/// A prover can provide honest `secret_inputs` and obtain the cs witness by calling `cs.get_and_clear_witness()`.
/// One provide an empty secret_inputs to get the constraint system `cs` for verification only.
/// This one also takes fee parameters as input.
pub(crate) fn build_multi_xfr_cs(
    secret_inputs: AMultiXfrWitness,
    fee_type: BLSScalar,
    fee_calculating_func: &dyn Fn(u32, u32) -> u32,
) -> (TurboPlonkCS, usize) {
    assert_ne!(secret_inputs.payers_secrets.len(), 0);
    assert_ne!(secret_inputs.payees_secrets.len(), 0);

    let mut cs = TurboConstraintSystem::new();
    let payers_secrets = add_payers_secrets(&mut cs, &secret_inputs.payers_secrets);
    let payees_secrets = add_payees_secrets(&mut cs, &secret_inputs.payees_secrets);

    let base = JubjubPoint::get_base();
    let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::one());
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let zero_var = cs.zero_var();
    let mut root_var: Option<VarIndex> = None;
    for payer in &payers_secrets {
        // prove knowledge of payer's secret key: pk = base^{sk}
        let pk_var = cs.scalar_mul(base, payer.sec_key, SK_LEN);
        let pk_x = pk_var.get_x();

        // commitments
        let com_abar_in_var = commit(&mut cs, payer.blind, payer.amount, payer.asset_type, pk_x);

        // prove pre-image of the nullifier
        // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`
        let uid_amount = cs.linear_combine(
            &[payer.uid, payer.amount, zero_var, zero_var],
            pow_2_64,
            one,
            zero,
            zero,
        );
        let nullifier_input_vars = NullifierInputVars {
            uid_amount,
            asset_type: payer.asset_type,
            pub_key_x: pk_x,
        };
        let nullifier_var = nullify(&mut cs, payer.sec_key, nullifier_input_vars);

        // Merkle path authentication
        let acc_elem = AccElemVars {
            uid: payer.uid,
            commitment: com_abar_in_var,
        };
        let tmp_root_var = compute_merkle_root(&mut cs, acc_elem, &payer.path);

        if let Some(root) = root_var {
            cs.equal(root, tmp_root_var);
        } else {
            root_var = Some(tmp_root_var);
        }

        // prepare public inputs variables
        cs.prepare_io_variable(nullifier_var);
    }
    // prepare the publc input for merkle_root
    cs.prepare_io_variable(root_var.unwrap()); // safe unwrap

    for payee in &payees_secrets {
        // commitment
        let com_abar_out_var = commit(
            &mut cs,
            payee.blind,
            payee.amount,
            payee.asset_type,
            payee.pubkey_x,
        );

        // Range check `amount`
        // Note we don't need to range-check payers' `amount`, because those amounts are bound
        // to payers' accumulated abars, whose underlying amounts have already been range-checked
        // in the transactions that created the payers' abars.
        cs.range_check(payee.amount, AMOUNT_LEN);

        // prepare the public input for the output commitment
        cs.prepare_io_variable(com_abar_out_var);
    }

    // add asset-mixing constraints
    let inputs: Vec<(VarIndex, VarIndex)> = payers_secrets
        .into_iter()
        .map(|payer| (payer.asset_type, payer.amount))
        .collect();
    let outputs: Vec<(VarIndex, VarIndex)> = payees_secrets
        .into_iter()
        .map(|payee| (payee.asset_type, payee.amount))
        .collect();
    asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_calculating_func);

    println!("before pad: {}", cs.size);
    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

/// Returns the constraint system (and associated number of constraints) for equality of values
/// in a Pedersen commitment and a Rescue commitment.
pub(crate) fn build_eq_committed_vals_cs(
    amount: BLSScalar,
    asset_type: BLSScalar,
    blind_hash: BLSScalar,
    pubkey_x: BLSScalar,
    proof: &ZKPartProof,
    non_zk_state: &NonZKState,
    beta: &RistrettoScalar,
    lambda: &RistrettoScalar,
) -> (TurboPlonkCS, usize) {
    let mut cs = TurboConstraintSystem::new();
    let zero_var = cs.zero_var();

    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let step_1 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB));
    let step_2 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 2));
    let step_3 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 3));
    let step_4 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 4));
    let step_5 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 5));

    // 1. Input Ristretto commitment data
    let amount_var = cs.new_variable(amount);
    let at_var = cs.new_variable(asset_type);
    let blind_hash_var = cs.new_variable(blind_hash);
    let pubkey_x_var = cs.new_variable(pubkey_x);

    // 2. Input witness x, y, a, b, r, public input comm, beta, s1, s2
    let x_sim_fr = SimFr::from(&BigUint::from_bytes_le(&non_zk_state.x.to_bytes()));
    let y_sim_fr = SimFr::from(&BigUint::from_bytes_le(&non_zk_state.y.to_bytes()));
    let a_sim_fr = SimFr::from(&BigUint::from_bytes_le(&non_zk_state.a.to_bytes()));
    let b_sim_fr = SimFr::from(&BigUint::from_bytes_le(&non_zk_state.b.to_bytes()));
    let comm = proof.non_zk_part_state_commitment;
    let r = non_zk_state.r;

    let beta_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta.to_bytes()));
    let lambda_sim_fr = SimFr::from(&BigUint::from_bytes_le(&lambda.to_bytes()));

    let beta_lambda = *beta * lambda;
    let beta_lambda_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta_lambda.to_bytes()));

    let s1_plus_lambda_s2 = proof.s_1 + proof.s_2 * lambda;
    let s1_plus_lambda_s2_sim_fr =
        SimFr::from(&BigUint::from_bytes_le(&s1_plus_lambda_s2.to_bytes()));

    let x_sim_fr_var = SimFrVar::alloc_witness_bounded_total_bits(&mut cs, &x_sim_fr, 64);
    let y_sim_fr_var = SimFrVar::alloc_witness_bounded_total_bits(&mut cs, &y_sim_fr, 240);
    let a_sim_fr_var = SimFrVar::alloc_witness(&mut cs, &a_sim_fr);
    let b_sim_fr_var = SimFrVar::alloc_witness(&mut cs, &b_sim_fr);
    let comm_var = cs.new_variable(comm);
    let r_var = cs.new_variable(r);
    let beta_sim_fr_var = SimFrVar::alloc_input(&mut cs, &beta_sim_fr);
    let lambda_sim_fr_var = SimFrVar::alloc_input(&mut cs, &lambda_sim_fr);
    let beta_lambda_sim_fr_var = SimFrVar::alloc_input(&mut cs, &beta_lambda_sim_fr);
    let s1_plus_lambda_s2_sim_fr_var = SimFrVar::alloc_input(&mut cs, &s1_plus_lambda_s2_sim_fr);

    // 3. Merge the limbs for x, y, a, b
    let mut all_limbs = Vec::with_capacity(4 * NUM_OF_LIMBS);
    all_limbs.extend_from_slice(&x_sim_fr.limbs);
    all_limbs.extend_from_slice(&y_sim_fr.limbs);
    all_limbs.extend_from_slice(&a_sim_fr.limbs);
    all_limbs.extend_from_slice(&b_sim_fr.limbs);

    let mut all_limbs_var = Vec::with_capacity(4 * NUM_OF_LIMBS);
    all_limbs_var.extend_from_slice(&x_sim_fr_var.var);
    all_limbs_var.extend_from_slice(&y_sim_fr_var.var);
    all_limbs_var.extend_from_slice(&a_sim_fr_var.var);
    all_limbs_var.extend_from_slice(&b_sim_fr_var.var);

    let mut compressed_limbs = Vec::with_capacity(5);
    let mut compressed_limbs_var = Vec::with_capacity(5);
    for (limbs, limbs_var) in all_limbs.chunks(5).zip(all_limbs_var.chunks(5)) {
        let mut sum = BigUint::zero();
        for (i, limb) in limbs.iter().enumerate() {
            sum.add_assign(<&BLSScalar as Into<BigUint>>::into(limb).shl(BIT_PER_LIMB * i));
        }
        compressed_limbs.push(BLSScalar::from(&sum));

        let mut sum_var = {
            let first_var = *limbs_var.get(0).unwrap_or(&zero_var);
            let second_var = *limbs_var.get(1).unwrap_or(&zero_var);
            let third_var = *limbs_var.get(2).unwrap_or(&zero_var);
            let fourth_var = *limbs_var.get(3).unwrap_or(&zero_var);

            cs.linear_combine(
                &[first_var, second_var, third_var, fourth_var],
                one,
                step_1,
                step_2,
                step_3,
            )
        };

        if limbs.len() == 5 {
            let fifth_var = *limbs_var.get(4).unwrap_or(&zero_var);
            sum_var = cs.linear_combine(
                &[sum_var, fifth_var, zero_var, zero_var],
                one,
                step_4,
                zero,
                zero,
            );
        }

        compressed_limbs_var.push(sum_var);
    }

    // 4. Open the non-ZK verifier state
    {
        let h1_var = cs.rescue_hash(&StateVar::new([
            compressed_limbs_var[0],
            compressed_limbs_var[1],
            compressed_limbs_var[2],
            compressed_limbs_var[3],
        ]))[0];

        let h2_var = cs.rescue_hash(&StateVar::new([
            h1_var,
            compressed_limbs_var[4],
            r_var,
            zero_var,
        ]))[0];
        cs.equal(h2_var, comm_var);
    }

    // 5. Perform the check in field simulation
    {
        let beta_x_sim_fr_mul_var = beta_sim_fr_var.mul(&mut cs, &x_sim_fr_var);
        let beta_lambda_y_sim_fr_mul_var = beta_lambda_sim_fr_var.mul(&mut cs, &y_sim_fr_var);
        let lambda_b_sim_fr_mul_var = lambda_sim_fr_var.mul(&mut cs, &b_sim_fr_var);

        let mut rhs = beta_x_sim_fr_mul_var.add(&mut cs, &beta_lambda_y_sim_fr_mul_var);
        rhs = rhs.add(&mut cs, &lambda_b_sim_fr_mul_var);

        let s1_plus_lambda_s2_minus_a_sim_fr_var =
            s1_plus_lambda_s2_sim_fr_var.sub(&mut cs, &a_sim_fr_var);

        let eqn = rhs.sub(&mut cs, &s1_plus_lambda_s2_minus_a_sim_fr_var);
        eqn.enforce_zero(&mut cs);
    }

    // 6. Check x = amount_var and y = at_var
    {
        let mut x_in_bls12_381 = cs.linear_combine(
            &[
                x_sim_fr_var.var[0],
                x_sim_fr_var.var[1],
                x_sim_fr_var.var[2],
                x_sim_fr_var.var[3],
            ],
            one,
            step_1,
            step_2,
            step_3,
        );
        x_in_bls12_381 = cs.linear_combine(
            &[
                x_in_bls12_381,
                x_sim_fr_var.var[4],
                x_sim_fr_var.var[5],
                zero_var,
            ],
            one,
            step_4,
            step_5,
            zero,
        );

        let mut y_in_bls12_381 = cs.linear_combine(
            &[
                y_sim_fr_var.var[0],
                y_sim_fr_var.var[1],
                y_sim_fr_var.var[2],
                y_sim_fr_var.var[3],
            ],
            one,
            step_1,
            step_2,
            step_3,
        );
        y_in_bls12_381 = cs.linear_combine(
            &[
                y_in_bls12_381,
                y_sim_fr_var.var[4],
                y_sim_fr_var.var[5],
                zero_var,
            ],
            one,
            step_4,
            step_5,
            zero,
        );

        cs.equal(x_in_bls12_381, amount_var);
        cs.equal(y_in_bls12_381, at_var);
    }

    // 7. Rescue commitment
    let rescue_comm_var = cs.rescue_hash(&StateVar::new([
        blind_hash_var,
        amount_var,
        at_var,
        pubkey_x_var,
    ]))[0];

    // prepare public inputs
    cs.prepare_io_variable(rescue_comm_var);
    cs.prepare_io_variable(comm_var);

    for i in 0..NUM_OF_LIMBS {
        cs.prepare_io_variable(beta_sim_fr_var.var[i]);
    }
    for i in 0..NUM_OF_LIMBS {
        cs.prepare_io_variable(lambda_sim_fr_var.var[i]);
    }
    for i in 0..NUM_OF_LIMBS {
        cs.prepare_io_variable(beta_lambda_sim_fr_var.var[i]);
    }
    for i in 0..NUM_OF_LIMBS {
        cs.prepare_io_variable(s1_plus_lambda_s2_sim_fr_var.var[i]);
    }

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

pub(crate) fn add_payers_secrets(
    cs: &mut TurboPlonkCS,
    secrets: &[PayerSecret],
) -> Vec<PayerSecretVars> {
    secrets
        .iter()
        .map(|secret| {
            let bls_sk = BLSScalar::from(&secret.sec_key);
            let sec_key = cs.new_variable(bls_sk);
            let uid = cs.new_variable(BLSScalar::from(secret.uid));
            let amount = cs.new_variable(BLSScalar::from(secret.amount));
            let blind = cs.new_variable(secret.blind);
            let path = add_merkle_path_variables(cs, secret.path.clone());
            let asset_type = cs.new_variable(secret.asset_type);
            PayerSecretVars {
                sec_key,
                uid,
                amount,
                asset_type,
                path,
                blind,
            }
        })
        .collect()
}

pub(crate) fn add_payees_secrets(
    cs: &mut TurboPlonkCS,
    secrets: &[PayeeSecret],
) -> Vec<PayeeSecretVars> {
    secrets
        .iter()
        .map(|secret| {
            let amount = cs.new_variable(BLSScalar::from(secret.amount));
            let blind = cs.new_variable(secret.blind);
            let asset_type = cs.new_variable(secret.asset_type);
            let pubkey_x = cs.new_variable(secret.pubkey_x);
            PayeeSecretVars {
                amount,
                blind,
                asset_type,
                pubkey_x,
            }
        })
        .collect()
}

pub struct PayerSecretVars {
    pub sec_key: VarIndex,
    pub uid: VarIndex,
    pub amount: VarIndex,
    pub asset_type: VarIndex,
    pub path: MerklePathVars,
    pub blind: VarIndex,
}

pub(crate) struct PayeeSecretVars {
    pub amount: VarIndex,
    pub blind: VarIndex,
    pub asset_type: VarIndex,
    pub pubkey_x: VarIndex,
}

// cs variables for a Merkle node
pub struct MerkleNodeVars {
    pub siblings1: VarIndex,
    pub siblings2: VarIndex,
    pub is_left_child: VarIndex,
    pub is_right_child: VarIndex,
}

// cs variables for a merkle authentication path
pub struct MerklePathVars {
    pub nodes: Vec<MerkleNodeVars>,
}

// cs variables for an accumulated element
pub(crate) struct AccElemVars {
    pub uid: VarIndex,
    pub commitment: VarIndex,
}

// cs variables for the nullifier PRF inputs
pub(crate) struct NullifierInputVars {
    pub uid_amount: VarIndex,
    pub asset_type: VarIndex,
    pub pub_key_x: VarIndex,
}

pub(crate) fn add_merkle_path_variables(cs: &mut TurboPlonkCS, path: MTPath) -> MerklePathVars {
    let path_vars: Vec<MerkleNodeVars> = path
        .nodes
        .into_iter()
        .map(|node| MerkleNodeVars {
            siblings1: cs.new_variable(node.siblings1),
            siblings2: cs.new_variable(node.siblings2),
            is_left_child: cs.new_variable(BLSScalar::from(node.is_left_child as u32)),
            is_right_child: cs.new_variable(BLSScalar::from(node.is_right_child as u32)),
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
fn sort(
    cs: &mut TurboPlonkCS,
    node: VarIndex,
    sib1: VarIndex,
    sib2: VarIndex,
    is_left_child: VarIndex,
    is_right_child: VarIndex,
) -> StateVar {
    let left = cs.select(sib1, node, is_left_child);
    let right = cs.select(sib2, node, is_right_child);
    let sum_left_right = cs.add(left, right);
    let one = BLSScalar::one();
    let mid = cs.linear_combine(
        &[node, sib1, sib2, sum_left_right],
        one,
        one,
        one,
        one.neg(),
    );
    StateVar::new([left, mid, right, cs.zero_var()])
}

pub(crate) fn compute_merkle_root(
    cs: &mut TurboPlonkCS,
    elem: AccElemVars,
    path_vars: &MerklePathVars,
) -> VarIndex {
    let (uid, commitment) = (elem.uid, elem.commitment);
    let zero_var = cs.zero_var();

    let mut node_var = cs.rescue_hash(&StateVar::new([uid, commitment, zero_var, zero_var]))[0];
    println!("tree height: {}", path_vars.nodes.len());
    for path_node in path_vars.nodes.iter() {
        let input_var = sort(
            cs,
            node_var,
            path_node.siblings1,
            path_node.siblings2,
            path_node.is_left_child,
            path_node.is_right_child,
        );
        node_var = cs.rescue_hash(&input_var)[0];
    }
    node_var
}

// Add the commitment constraints to the constraint system:
// comm = commit(blinding, amount, asset_type)
pub fn commit(
    cs: &mut TurboPlonkCS,
    blinding_var: VarIndex,
    amount_var: VarIndex,
    asset_var: VarIndex,
    pubkey_x_var: VarIndex,
) -> VarIndex {
    let input_var = StateVar::new([blinding_var, amount_var, asset_var, pubkey_x_var]);
    cs.rescue_hash(&input_var)[0]
}

// Add the nullifier constraints to the constraint system.
// nullifer = PRF(sk, msg = [uid_amount, asset_type, pk_x, pk_y])
// The PRF follows the Full-State Keyed Sponge (FKS) paradigm explained in https://eprint.iacr.org/2015/541.pdf
// Let perm : Fp^w -> Fp^w be a public permutation.
// Given secret key `key`, set initial state `s_key` := (0 || ... || 0 || key), the PRF output is:
// PRF^p(key, (m1, ..., mw)) = perm(s_key \xor (m1 || ... || mw))[0]
pub(crate) fn nullify(
    cs: &mut TurboPlonkCS,
    sk_var: VarIndex,
    nullifier_input_vars: NullifierInputVars,
) -> VarIndex {
    let (uid_amount, asset_type, pub_key_x) = (
        nullifier_input_vars.uid_amount,
        nullifier_input_vars.asset_type,
        nullifier_input_vars.pub_key_x,
    );
    let input_var = StateVar::new([uid_amount, asset_type, pub_key_x, sk_var]);
    cs.rescue_hash(&input_var)[0]
}

/// Enforce asset_mixing_with_fees constraints:
/// Inputs = [(type_in_1, v_in_1), ..., (type_in_n, v_in_n)], `values {v_in_i}` are guaranteed to be positive.
/// Outputs = [(type_out_1, v_out_1), ..., (type_out_m, v_out_m)], `values {v_out_j}` are guaranteed to be positive.
/// Fee parameters = `fee_type` and `fee_calculating func`
///
/// Goal:
/// - Prove that for every asset type except `fee_type`, the corresponding inputs sum equals the corresponding outputs sum.
/// - Prove that for every asset type that equals `fee_type`, the inputs sum = the outputs sum + fee
/// - Prove that at least one input is of type `fee_type`
///
/// The circuit:
/// 1. Compute [sum_in_1, ..., sum_in_n] from inputs, where `sum_in_i = \sum_{j : type_in_j == type_in_i} v_in_j`
///    Note: If there are two inputs with the same asset type, then their `sum_in_i` would be the same.
/// 2. Similarly, compute [sum_out_1, ..., sum_out_m] from outputs.
/// 3. Enumerate pair `(i \in [n], j \in [m])`, check that:
///         `(type_in_i == fee_type) \lor (type_in_i != type_out_j) \lor (sum_in_i == sum_out_j)`
///         `(type_in_i != fee_type) \lor (type_in_i != type_out_j) \lor (sum_in_i == sum_out_j + fee)`
/// 4. Ensure that except the fee type, all the input type has also shown up as an output type.
/// 5. Ensure that for the fee type, if there is no output fee type, then the input must provide the exact fee.
///
/// This function assumes that the inputs and outputs have been correctly bounded.
fn asset_mixing(
    cs: &mut TurboPlonkCS,
    inputs: &[(VarIndex, VarIndex)],
    outputs: &[(VarIndex, VarIndex)],
    fee_type: BLSScalar,
    fee_calculating_func: &dyn Fn(u32, u32) -> u32,
) {
    // Compute the `sum_in_i`
    let inputs_type_sum_amounts: Vec<(VarIndex, VarIndex)> = inputs
        .iter()
        .map(|input| {
            let zero_var = cs.zero_var();
            let sum_var = inputs.iter().fold(zero_var, |sum, other_input| {
                let adder = match_select(
                    cs,
                    input.0,       // asset_type
                    other_input.0, // asset_type
                    other_input.1,
                ); // amount
                cs.add(sum, adder)
            });
            (input.0, sum_var)
        })
        .collect();

    // Compute the `sum_out_i`
    let outputs_type_sum_amounts: Vec<(VarIndex, VarIndex)> = outputs
        .iter()
        .map(|output| {
            let zero_var = cs.zero_var();
            let sum_var = outputs.iter().fold(zero_var, |sum, other_output| {
                let adder = match_select(
                    cs,
                    output.0,       // asset_type
                    other_output.0, // asset_type
                    other_output.1,
                ); // amount
                cs.add(sum, adder)
            });
            (output.0, sum_var)
        })
        .collect();

    // Initialize a constant value `fee_type_val`
    let fee_type_val = cs.new_variable(fee_type);
    cs.insert_constant_gate(fee_type_val, fee_type);

    // Calculate the fee
    let fee = BLSScalar::from(fee_calculating_func(
        inputs.len() as u32,
        outputs.len() as u32,
    ));
    let fee_var = cs.new_variable(fee);
    cs.insert_constant_gate(fee_var, fee);

    // At least one input type is `fee_type` by checking `flag_no_fee_type = 0`
    // and also check that the amount is matching
    // and also check that every input type appears in the set of output types (except if the fee has used up)
    let mut flag_no_fee_type = cs.one_var();
    for (input_type, input_sum) in inputs_type_sum_amounts {
        let (is_fee_type, is_not_fee_type) = cs.is_equal_or_not_equal(input_type, fee_type_val);
        flag_no_fee_type = cs.mul(flag_no_fee_type, is_not_fee_type);

        let zero_var = cs.zero_var();

        // If there is at least one output that is of the same type as the input, then `flag_no_matching_output = 0`
        // Otherwise, `flag_no_matching_output = 1`.
        let mut flag_no_matching_output = cs.one_var();
        for &(output_type, output_sum) in &outputs_type_sum_amounts {
            let (type_matched, type_not_matched) =
                cs.is_equal_or_not_equal(input_type, output_type);
            flag_no_matching_output = cs.mul(flag_no_matching_output, type_not_matched);
            let diff = cs.sub(input_sum, output_sum);

            // enforce `type_matched` * `is_not_fee_type` * (input_sum - output_sum) == 0,
            // which guarantees that (`input_type` != `output_type`) \lor (`input_type` == fee_type) \lor (`input_sum` == `output_sum`)
            let type_matched_and_is_not_fee_type = cs.mul(type_matched, is_not_fee_type);
            cs.insert_mul_gate(type_matched_and_is_not_fee_type, diff, zero_var);

            // enforce `type_matched` * `is_fee_type` * (input_sum - output_sum - fee) == 0,
            let type_matched_and_is_fee_type = cs.mul(type_matched, is_fee_type);
            let diff_minus_fee = cs.sub(diff, fee_var);
            cs.insert_mul_gate(type_matched_and_is_fee_type, diff_minus_fee, zero_var)
        }

        // If it is not the fee type, then `flag_no_matching_output` must be 0
        cs.insert_mul_gate(is_not_fee_type, flag_no_matching_output, zero_var);

        // Otherwise, `flag_no_matching_output * (input_sum - fee_var) = 0`
        let input_minus_fee = cs.sub(input_sum, fee_var);
        let condition = cs.mul(is_fee_type, flag_no_matching_output);
        cs.insert_mul_gate(condition, input_minus_fee, zero_var)
    }
    cs.insert_constant_gate(flag_no_fee_type, BLSScalar::zero());

    // check that every output type appears in the set of input types
    for &(output_type, _) in outputs {
        // \prod_i (input_type_i - output_type) == 0
        let mut product = cs.one_var();
        for &(input_type, _) in inputs {
            let diff = cs.sub(input_type, output_type);
            product = cs.mul(product, diff);
        }
        cs.insert_constant_gate(product, BLSScalar::zero());
    }
}

// If `type1` == `type2`, returns a variable that equals `val`, otherwise returns a zero variable
fn match_select(
    cs: &mut TurboPlonkCS,
    type1: VarIndex,
    type2: VarIndex,
    val: VarIndex,
) -> VarIndex {
    let is_equal_var = cs.is_equal(type1, type2);
    cs.mul(is_equal_var, val)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ruc::*;
    use zei_algebra::{bls12_381::BLSScalar, traits::Scalar};
    use zei_crypto::basic::rescue::RescueInstance;
    use zei_crypto::basic::ristretto_pedersen_comm::RistrettoPedersenCommitment;
    use zei_crypto::pc_eq_rescue_split_verifier_zk_part::prove_pc_eq_rescue_external;
    use zei_plonk::plonk::constraint_system::{ecc::Point, TurboConstraintSystem};

    pub(crate) fn new_multi_xfr_witness_for_test(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar, BLSScalar)>,
        seed: [u8; 32],
    ) -> AMultiXfrWitness {
        let n_payers = inputs.len();
        assert!(n_payers <= 3);
        let mut prng = ChaChaRng::from_seed(seed);
        let zero = BLSScalar::zero();
        let mut payers_secrets: Vec<PayerSecret> = inputs
            .iter()
            .enumerate()
            .map(|(i, &(amount, asset_type))| {
                let (is_left_child, is_right_child) = match i % 3 {
                    0 => (1, 0),
                    1 => (0, 0),
                    _ => (0, 1),
                };
                let node = MTNode {
                    siblings1: zero,
                    siblings2: zero,
                    is_left_child,
                    is_right_child,
                };
                PayerSecret {
                    sec_key: JubjubScalar::random(&mut prng),
                    uid: i as u64,
                    amount,
                    asset_type,
                    path: MTPath::new(vec![node]),
                    blind: BLSScalar::random(&mut prng),
                }
            })
            .collect();
        // compute the merkle leaves and update the merkle paths if there are more than 1 payers
        if n_payers > 1 {
            let hash = RescueInstance::new();
            let base = JubjubPoint::get_base();
            let leafs: Vec<BLSScalar> = payers_secrets
                .iter()
                .map(|payer| {
                    let pk_point = base.mul(&payer.sec_key);
                    let commitment = hash.rescue(&[
                        payer.blind,
                        BLSScalar::from(payer.amount),
                        payer.asset_type,
                        zero,
                    ])[0];
                    hash.rescue(&[
                        BLSScalar::from(payer.uid),
                        commitment,
                        pk_point.get_x(),
                        zero,
                    ])[0]
                })
                .collect();
            payers_secrets[0].path.nodes[0].siblings1 = leafs[1];
            if n_payers == 2 {
                payers_secrets[0].path.nodes[0].siblings2 = zero;
                payers_secrets[1].path.nodes[0].siblings1 = leafs[0];
                payers_secrets[1].path.nodes[0].siblings2 = zero;
            } else {
                payers_secrets[0].path.nodes[0].siblings2 = leafs[2];
                payers_secrets[1].path.nodes[0].siblings1 = leafs[0];
                payers_secrets[1].path.nodes[0].siblings2 = leafs[2];
                payers_secrets[2].path.nodes[0].siblings1 = leafs[0];
                payers_secrets[2].path.nodes[0].siblings2 = leafs[1];
            }
        }

        let payees_secrets: Vec<PayeeSecret> = outputs
            .iter()
            .map(|&(amount, asset_type, pubkey_x)| PayeeSecret {
                amount,
                blind: BLSScalar::random(&mut prng),
                asset_type,
                pubkey_x,
            })
            .collect();

        AMultiXfrWitness {
            payers_secrets,
            payees_secrets,
        }
    }

    #[test]
    fn test_asset_mixing() {
        // Fee type
        let fee_type = BLSScalar::from(1234u32);

        // Fee function
        // base fee 5, every input 1, every output 2
        let fee_calculating_func = |x: u32, y: u32| 5 + x + 2 * y;

        // Constants
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        let two = one.add(&one);

        // Test case 1: success
        // A minimalist transaction that pays sufficient fee
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (1234)
        let in_types = [cs.new_variable(fee_type)];
        // amounts = (5 + 1)
        let in_amounts = [cs.new_variable(BLSScalar::from((5 + 1) as u32))];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &[], fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());

        // Test case 2: error
        // A minimalist transaction that pays too much fee
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (1234)
        let in_types = [cs.new_variable(fee_type)];
        // amounts = (5 + 1 + 1)
        let in_amounts = [cs.new_variable(BLSScalar::from((5 + 1 + 1) as u32))];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &[], fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        // Test case 3: error
        // A minimalist transaction that pays insufficient fee
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (1234)
        let in_types = [cs.new_variable(fee_type)];
        // amounts = (5 + 1 - 1)
        let in_amounts = [cs.new_variable(BLSScalar::from((5 + 1 - 1) as u32))];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &[], fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        // Test case 4: error
        // A classical case when the non-fee elements are wrong, but the fee is paid correctly
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (0, 2, 1234)
        let in_types = [
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (60, 100, 5 + 3 + 2 * 2)
        let in_amounts = [
            cs.new_variable(BLSScalar::from(60u32)),
            cs.new_variable(BLSScalar::from(100u32)),
            cs.new_variable(BLSScalar::from((5 + 3 + 2 * 2) as u32)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        // asset_types = (2, 2)
        let out_types = [cs.new_variable(two), cs.new_variable(two)];
        // amounts = (40, 10)
        let out_amounts = [
            cs.new_variable(BLSScalar::from(40u32)),
            cs.new_variable(BLSScalar::from(10u32)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &outputs, fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        // Test case 5: success
        // A classical case when the non-fee elements and fee are both correct
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (0, 2, 1234)
        let in_types = [
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (60, 100, 5 + 3 + 2 * 2)
        let in_amounts = [
            cs.new_variable(BLSScalar::from(60u32)),
            cs.new_variable(BLSScalar::from(100u32)),
            cs.new_variable(BLSScalar::from((5 + 3 + 2 * 2) as u32)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        // asset_types = (2, 0)
        let out_types = [cs.new_variable(two), cs.new_variable(zero)];
        // amounts = (100, 60)
        let out_amounts = [
            cs.new_variable(BLSScalar::from(100u32)),
            cs.new_variable(BLSScalar::from(60u32)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &outputs, fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());

        // Test case 6: success
        // More assets, with the exact fee
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (0, 2, 1, 2, 1234)
        let in_types = [
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (60, 100, 10, 50, 5 + 5 + 2 * 7)
        let in_amounts = [
            cs.new_variable(BLSScalar::from(60u32)),
            cs.new_variable(BLSScalar::from(100u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from((5 + 5 + 2 * 7) as u32)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        // asset_types = (2, 1, 1, 2, 0, 0, 2)
        let out_types = [
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(zero),
            cs.new_variable(zero),
            cs.new_variable(two),
        ];
        // amounts = (40, 9, 1, 80, 50, 10, 30)
        let out_amounts = [
            cs.new_variable(BLSScalar::from(40u32)),
            cs.new_variable(BLSScalar::from(9u32)),
            cs.new_variable(BLSScalar::from(1u32)),
            cs.new_variable(BLSScalar::from(80u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(30u32)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &outputs, fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());

        // Test case 7: success
        // More assets, with more than enough fees, but are spent properly
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (0, 2, 1, 2, 1234)
        let in_types = [
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (60, 100, 10, 50, 5 + 5 + 2 * 8 + 100)
        let in_amounts = [
            cs.new_variable(BLSScalar::from(60u32)),
            cs.new_variable(BLSScalar::from(100u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from((5 + 5 + 2 * 8 + 100) as u32)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        // asset_types = (2, 1, 1, 2, 0, 0, 2, 1234)
        let out_types = [
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(zero),
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (40, 9, 1, 80, 50, 10, 30, 100)
        let out_amounts = [
            cs.new_variable(BLSScalar::from(40u32)),
            cs.new_variable(BLSScalar::from(9u32)),
            cs.new_variable(BLSScalar::from(1u32)),
            cs.new_variable(BLSScalar::from(80u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(30u32)),
            cs.new_variable(BLSScalar::from(100u32)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &outputs, fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());

        // Test case 8: error
        // More assets, with more than enough fees, but are not spent properly
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (0, 2, 1, 2, 1234)
        let in_types = [
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (60, 100, 10, 50, 5 + 5 + 2 * 8 + 100)
        let in_amounts = [
            cs.new_variable(BLSScalar::from(60u32)),
            cs.new_variable(BLSScalar::from(100u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from((5 + 5 + 2 * 8 + 100) as u32)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        // asset_types = (2, 1, 1, 2, 0, 0, 2, 1234)
        let out_types = [
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(zero),
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (40, 9, 1, 80, 50, 10, 30, 10)
        let out_amounts = [
            cs.new_variable(BLSScalar::from(40u32)),
            cs.new_variable(BLSScalar::from(9u32)),
            cs.new_variable(BLSScalar::from(1u32)),
            cs.new_variable(BLSScalar::from(80u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(30u32)),
            cs.new_variable(BLSScalar::from(10u32)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &outputs, fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        // Test case 9: error
        // More assets, with insufficient fees, case 1: no output of the fee type
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (0, 2, 1, 2, 1234)
        let in_types = [
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (60, 100, 10, 50, 5 + 5 + 2 * 7 - 2)
        let in_amounts = [
            cs.new_variable(BLSScalar::from(60u32)),
            cs.new_variable(BLSScalar::from(100u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from((5 + 5 + 2 * 7 - 2) as u32)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        // asset_types = (2, 1, 1, 2, 0, 0, 2)
        let out_types = [
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(zero),
            cs.new_variable(zero),
            cs.new_variable(two),
        ];
        // amounts = (40, 9, 1, 80, 50, 10, 30)
        let out_amounts = [
            cs.new_variable(BLSScalar::from(40u32)),
            cs.new_variable(BLSScalar::from(9u32)),
            cs.new_variable(BLSScalar::from(1u32)),
            cs.new_variable(BLSScalar::from(80u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(30u32)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &outputs, fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        // Test case 10: error
        // More assets, with insufficient fees, case 2: with output of the fee type
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (0, 2, 1, 2, 1234)
        let in_types = [
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (60, 100, 10, 50, 5 + 5 + 2 * 8)
        let in_amounts = [
            cs.new_variable(BLSScalar::from(60u32)),
            cs.new_variable(BLSScalar::from(100u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from((5 + 5 + 2 * 8) as u32)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        // asset_types = (2, 1, 1, 2, 0, 0, 2, 1234)
        let out_types = [
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(zero),
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (40, 9, 1, 80, 50, 10, 30, 2)
        let out_amounts = [
            cs.new_variable(BLSScalar::from(40u32)),
            cs.new_variable(BLSScalar::from(9u32)),
            cs.new_variable(BLSScalar::from(1u32)),
            cs.new_variable(BLSScalar::from(80u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(30u32)),
            cs.new_variable(BLSScalar::from(2u32)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &outputs, fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        // Test case 11: error
        // More assets, with insufficient fees, case 3: with output of the fee type, fees not exact
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (0, 2, 1, 2, 1234)
        let in_types = [
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (60, 100, 10, 50, 5 + 5 + 2 * 8)
        let in_amounts = [
            cs.new_variable(BLSScalar::from(60u32)),
            cs.new_variable(BLSScalar::from(100u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from((5 + 5 + 2 * 8 + 1) as u32)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        // asset_types = (2, 1, 1, 2, 0, 0, 2, 1234)
        let out_types = [
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(zero),
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(fee_type),
        ];
        // amounts = (40, 9, 1, 80, 50, 10, 30, 2)
        let out_amounts = [
            cs.new_variable(BLSScalar::from(40u32)),
            cs.new_variable(BLSScalar::from(9u32)),
            cs.new_variable(BLSScalar::from(1u32)),
            cs.new_variable(BLSScalar::from(80u32)),
            cs.new_variable(BLSScalar::from(50u32)),
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(30u32)),
            cs.new_variable(BLSScalar::from(2u32)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &outputs, fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        // Test case 12: error
        // The circuit cannot be satisfied when the set of input asset types is different from the set of output asset types.
        // Missing output for an input type.
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (1, 0, 1, 2)
        let in_types = [
            cs.new_variable(one),
            cs.new_variable(zero),
            cs.new_variable(one),
            cs.new_variable(two),
        ];
        // amounts = (10, 5, 5, 10)
        let in_amounts = [
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(5u32)),
            cs.new_variable(BLSScalar::from(5u32)),
            cs.new_variable(BLSScalar::from(10u32)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();
        // asset_types = (0, 1, 0)
        let out_types = [
            cs.new_variable(zero),
            cs.new_variable(one),
            cs.new_variable(zero),
        ];
        // amounts = (1, 15, 4)
        let out_amounts = [
            cs.new_variable(BLSScalar::from(1u32)),
            cs.new_variable(BLSScalar::from(15u32)),
            cs.new_variable(BLSScalar::from(4u32)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        // Test case 13: error
        // The circuit cannot be satisfied when the set of input asset types is different from the set of output asset types.
        // Missing input for an output type.
        let mut cs = TurboConstraintSystem::new();
        // asset_types = (1, 0, 1)
        let in_types = [
            cs.new_variable(one),
            cs.new_variable(zero),
            cs.new_variable(one),
        ];
        // amounts = (10, 5, 5)
        let in_amounts = [
            cs.new_variable(BLSScalar::from(10u32)),
            cs.new_variable(BLSScalar::from(5u32)),
            cs.new_variable(BLSScalar::from(5u32)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();
        // asset_types = (0, 1, 2)
        let out_types = [
            cs.new_variable(zero),
            cs.new_variable(one),
            cs.new_variable(two),
        ];
        // amounts = (5, 15, 4)
        let out_amounts = [
            cs.new_variable(BLSScalar::from(5u32)),
            cs.new_variable(BLSScalar::from(15u32)),
            cs.new_variable(BLSScalar::from(4u32)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, &fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());
    }

    #[test]
    fn test_eq_committed_vals_cs() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = RistrettoPedersenCommitment::default();

        // 1. compute the parameters
        let amount = BLSScalar::from(71u32);
        let asset_type = BLSScalar::from(52u32);

        let x = RistrettoScalar::from_bytes(&amount.to_bytes()).unwrap();
        let y = RistrettoScalar::from_bytes(&asset_type.to_bytes()).unwrap();

        let gamma = RistrettoScalar::random(&mut rng);
        let delta = RistrettoScalar::random(&mut rng);

        let point_p = pc_gens.commit(x, gamma);
        let point_q = pc_gens.commit(y, delta);

        let z_randomizer = BLSScalar::random(&mut rng);
        let z_instance = RescueInstance::<BLSScalar>::new();

        let x_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&x.to_bytes()));
        let y_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&y.to_bytes()));

        let pubkey_x = BLSScalar::random(&mut rng);

        let z = z_instance.rescue(&[z_randomizer, x_in_bls12_381, y_in_bls12_381, pubkey_x])[0];

        // 2. compute the ZK part of the proof
        let (proof, non_zk_state, beta, lambda) = prove_pc_eq_rescue_external(
            &mut rng, &x, &gamma, &y, &delta, &pc_gens, &point_p, &point_q, &z,
        )
        .unwrap();

        // compute cs
        let (mut cs, _) = build_eq_committed_vals_cs(
            amount,
            asset_type,
            z_randomizer,
            pubkey_x,
            &proof,
            &non_zk_state,
            &beta,
            &lambda,
        );
        let witness = cs.get_and_clear_witness();

        let mut online_inputs = Vec::with_capacity(2 + 3 * NUM_OF_LIMBS);
        online_inputs.push(z);
        online_inputs.push(proof.non_zk_part_state_commitment);
        let beta_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta.to_bytes()));
        let s1_sim_fr = SimFr::from(&BigUint::from_bytes_le(&proof.s_1.to_bytes()));
        let s2_sim_fr = SimFr::from(&BigUint::from_bytes_le(&proof.s_2.to_bytes()));
        online_inputs.extend_from_slice(&beta_sim_fr.limbs);
        online_inputs.extend_from_slice(&s1_sim_fr.limbs);
        online_inputs.extend_from_slice(&s2_sim_fr.limbs);

        // Check the constraints
        assert!(cs.verify_witness(&witness, &online_inputs).is_ok());
        online_inputs[0].add_assign(&BLSScalar::one());
        assert!(cs.verify_witness(&witness, &online_inputs).is_err());
    }

    #[test]
    fn test_commit() {
        let mut cs = TurboConstraintSystem::new();
        let amount = BLSScalar::from(7u32);
        let asset_type = BLSScalar::from(5u32);
        let hash = RescueInstance::new();
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let blind = BLSScalar::random(&mut prng);
        let pubkey_x = BLSScalar::random(&mut prng);
        let commitment = hash.rescue(&[blind, amount, asset_type, pubkey_x])[0];

        let amount_var = cs.new_variable(amount);
        let asset_var = cs.new_variable(asset_type);
        let blind_var = cs.new_variable(blind);
        let pubkey_x_var = cs.new_variable(pubkey_x);
        let comm_var = commit(&mut cs, blind_var, amount_var, asset_var, pubkey_x_var);
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
        let mut cs = TurboConstraintSystem::new();
        let mut prng = ChaChaRng::from_seed([1u8; 32]);
        let sk = BLSScalar::random(&mut prng);
        let bytes = vec![1u8; 32];
        let uid_amount = BLSScalar::from_bytes(&bytes[..]).unwrap(); // safe unwrap
        let asset_type = one;
        let pk = Point::new(zero, one);
        let hash = RescueInstance::new();
        let expected_output = hash.rescue(&[uid_amount, asset_type, *pk.get_x(), sk])[0];

        let sk_var = cs.new_variable(sk);
        let uid_amount_var = cs.new_variable(uid_amount);
        let asset_var = cs.new_variable(asset_type);
        let pk_var = cs.new_point_variable(pk);
        let nullifier_input_var = NullifierInputVars {
            uid_amount: uid_amount_var,
            asset_type: asset_var,
            pub_key_x: pk_var.get_x(),
        };
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
        let mut cs = TurboConstraintSystem::new();
        let num: Vec<BLSScalar> = (0..5).map(|x| BLSScalar::from(x as u32)).collect();
        let node_var = cs.new_variable(num[2]);
        let sib1_var = cs.new_variable(num[3]);
        let sib2_var = cs.new_variable(num[4]);
        let is_left_var = cs.new_variable(num[0]);
        let is_right_var = cs.new_variable(num[1]);
        let out_state = sort(
            &mut cs,
            node_var,
            sib1_var,
            sib2_var,
            is_left_var,
            is_right_var,
        );
        let mut witness = cs.get_and_clear_witness();
        let output: Vec<BLSScalar> = out_state
            .as_slice()
            .iter()
            .map(|&idx| witness[idx])
            .collect();
        // node_var is at the right position
        let expected_output = vec![
            witness[sib1_var],
            witness[sib2_var],
            witness[node_var],
            witness[cs.zero_var()],
        ];
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
        let mut cs = TurboConstraintSystem::new();
        let uid_var = cs.new_variable(one);
        let comm_var = cs.new_variable(two);
        let elem = AccElemVars {
            uid: uid_var,
            commitment: comm_var,
        };

        let path_node1 = MTNode {
            siblings1: one,
            siblings2: three,
            is_left_child: 1u8,
            is_right_child: 0u8,
        };
        let path_node2 = MTNode {
            siblings1: two,
            siblings2: four,
            is_left_child: 0u8,
            is_right_child: 1u8,
        };
        // compute the root value
        let hash = RescueInstance::new();
        let leaf = hash.rescue(&[
            /*uid=*/ one, /*comm=*/ two, /*pk_x=*/ zero, zero,
        ])[0];
        // leaf is the right child of node1
        let node1 = hash.rescue(&[path_node2.siblings1, path_node2.siblings2, leaf, zero])[0];
        // node1 is the left child of the root
        let root = hash.rescue(&[node1, path_node1.siblings1, path_node1.siblings2, zero])[0];

        // compute the constraints
        let path = MTPath::new(vec![path_node2, path_node1]);
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
        let mut cs = TurboConstraintSystem::new();
        let node = MTNode {
            siblings1: one,
            siblings2: zero,
            is_left_child: 1u8,
            is_right_child: 0u8,
        };
        let path = MTPath::new(vec![node]);
        let _ = add_merkle_path_variables(&mut cs, path);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());

        // cs cannot be satisfied when `is_left_child` (or `is_right_child`) is not boolean
        let mut cs = TurboConstraintSystem::new();
        // is_left is not boolean
        let node = MTNode {
            siblings1: one,
            siblings2: zero,
            is_left_child: 2u8,
            is_right_child: 0u8,
        };
        let path = MTPath::new(vec![node]);
        let _ = add_merkle_path_variables(&mut cs, path);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        // cs cannot be satisfied when `is_left_child` + `is_right_child` is not boolean
        let mut cs = TurboConstraintSystem::new();
        // `is_left` and `is_right` are both 1
        let node = MTNode {
            siblings1: one,
            siblings2: zero,
            is_left_child: 1u8,
            is_right_child: 1u8,
        };
        let path = MTPath::new(vec![node]);
        let _ = add_merkle_path_variables(&mut cs, path);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());
    }

    #[test]
    fn test_build_multi_xfr_cs() {
        // Fee type
        let fee_type = BLSScalar::from(1234u32);

        // Fee function
        // base fee 5, every input 1, every output 2
        let fee_calculating_func = |x: u32, y: u32| 5 + x + 2 * y;

        // Receiver pub key x coordinate
        let pubkey_x = BLSScalar::from(4567u32);

        // single-asset api: good witness
        let zero = BLSScalar::zero();
        let inputs = vec![
            (/*amount=*/ 30, /*asset_type=*/ zero),
            (30, zero),
            (5 + 3 + 2 * 3, fee_type),
        ];
        let mut outputs = vec![
            (19, zero, pubkey_x),
            (17, zero, pubkey_x),
            (24, zero, pubkey_x),
        ];
        test_xfr_cs(
            inputs.to_vec(),
            outputs.to_vec(),
            true,
            fee_type,
            &fee_calculating_func,
        );

        // single-asset api: bad witness
        outputs[2].0 = 5 + 3 + 2 * 3 - 1;
        test_xfr_cs(inputs, outputs, false, fee_type, &fee_calculating_func);

        // multi-assets api: good witness
        let one = BLSScalar::one();
        let inputs = vec![
            (/*amount=*/ 70, /*asset_type=*/ zero),
            (60, one),
            (5 + 3 + 2 * 7 + 100, fee_type),
        ];
        let mut outputs = vec![
            (19, one, pubkey_x),
            (15, zero, pubkey_x),
            (1, one, pubkey_x),
            (35, zero, pubkey_x),
            (20, zero, pubkey_x),
            (40, one, pubkey_x),
            (100, fee_type, pubkey_x),
        ];
        test_xfr_cs(
            inputs.to_vec(),
            outputs.to_vec(),
            true,
            fee_type,
            &fee_calculating_func,
        );

        // multi-assets api: bad witness
        outputs[2].0 = 5 + 3 + 2 * 7 + 100 - 1;
        test_xfr_cs(inputs, outputs, false, fee_type, &fee_calculating_func);
    }

    fn test_xfr_cs(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar, BLSScalar)>,
        witness_is_valid: bool,
        fee_type: BLSScalar,
        fee_calculating_func: &dyn Fn(u32, u32) -> u32,
    ) {
        let secret_inputs = new_multi_xfr_witness_for_test(inputs, outputs, [0u8; 32]);
        let pub_inputs = AMultiXfrPubInputs::from_witness(&secret_inputs);

        // check the constraints
        let (mut cs, _) = build_multi_xfr_cs(secret_inputs, fee_type, fee_calculating_func);
        let witness = cs.get_and_clear_witness();
        let online_inputs = pub_inputs.to_vec();
        let verify = cs.verify_witness(&witness, &online_inputs);
        if witness_is_valid {
            pnk!(verify);
        } else {
            assert!(verify.is_err());
        }
    }
}
