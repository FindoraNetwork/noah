use crate::anon_xfr::structs::{BlindFactor, Commitment, MTNode, MTPath, Nullifier};
use zei_algebra::{
    bls12_381::BLSScalar,
    jubjub::{JubjubPoint, JubjubScalar},
    ops::*,
    traits::Group,
    One, Zero,
};
use zei_crypto::basic::rescue::RescueInstance;
use zei_plonk::plonk::constraint_system::{rescue::StateVar, TurboCS, VarIndex};

pub type TurboPlonkCS = TurboCS<BLSScalar>;

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
                hash.rescue(&[
                    sec.blind,
                    BLSScalar::from(sec.amount),
                    sec.asset_type,
                    sec.pubkey_x,
                ])[0]
            })
            .collect();

        // merkle root
        let payer = &witness.payers_secrets[0];
        let pk_point = base.mul(&payer.sec_key);
        let commitment = hash.rescue(&[
            payer.blind,
            BLSScalar::from(payer.amount),
            payer.asset_type,
            pk_point.get_x(),
        ])[0];
        let mut node = hash.rescue(&[BLSScalar::from(payer.uid), commitment, zero, zero])[0];
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
    hash: &BLSScalar,
    non_malleability_randomizer: &BLSScalar,
    non_malleability_tag: &BLSScalar,
) -> (TurboPlonkCS, usize) {
    assert_ne!(secret_inputs.payers_secrets.len(), 0);
    assert_ne!(secret_inputs.payees_secrets.len(), 0);

    let mut cs = TurboCS::new();
    let payers_secrets = add_payers_secrets(&mut cs, &secret_inputs.payers_secrets);
    let payees_secrets = add_payees_secrets(&mut cs, &secret_inputs.payees_secrets);

    let hash_var = cs.new_variable(*hash);
    let non_malleability_randomizer_var = cs.new_variable(*non_malleability_randomizer);
    let non_malleability_tag_var = cs.new_variable(*non_malleability_tag);

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
        cs.prepare_pi_variable(nullifier_var);
    }
    // prepare the publc input for merkle_root
    cs.prepare_pi_variable(root_var.unwrap()); // safe unwrap

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
        cs.prepare_pi_variable(com_abar_out_var);
    }

    // add asset-mixing constraints
    let inputs: Vec<(VarIndex, VarIndex)> = payers_secrets
        .iter()
        .map(|payer| (payer.asset_type, payer.amount))
        .collect();
    let outputs: Vec<(VarIndex, VarIndex)> = payees_secrets
        .iter()
        .map(|payee| (payee.asset_type, payee.amount))
        .collect();
    asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_calculating_func);

    // Check that validity of the the non malleability tag.
    {
        let num_inputs = BLSScalar::from(payers_secrets.len() as u64);
        let num_inputs_var = cs.new_variable(num_inputs);
        cs.insert_constant_gate(num_inputs_var, num_inputs);

        let mut non_malleability_tag_var_supposed = cs.rescue_hash(&StateVar::new([
            num_inputs_var,
            hash_var,
            non_malleability_randomizer_var,
            payers_secrets[0].sec_key,
        ]))[0];

        for chunk in payers_secrets[1..].chunks(3) {
            let mut sec_keys: Vec<VarIndex> = chunk.iter().map(|x| x.sec_key).collect();
            sec_keys.resize(3, zero_var);

            non_malleability_tag_var_supposed = cs.rescue_hash(&StateVar::new([
                non_malleability_tag_var_supposed,
                sec_keys[0],
                sec_keys[1],
                sec_keys[2],
            ]))[0];
        }

        cs.equal(non_malleability_tag_var_supposed, non_malleability_tag_var);
    }

    cs.prepare_pi_variable(hash_var);
    cs.prepare_pi_variable(non_malleability_tag_var);

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
    use crate::anon_xfr::compute_non_malleability_tag;
    use crate::anon_xfr::keys::AXfrKeyPair;
    use rand_chacha::ChaChaRng;
    use rand_core::{RngCore, SeedableRng};
    use ruc::*;
    use zei_algebra::{bls12_381::BLSScalar, traits::Scalar};
    use zei_crypto::basic::rescue::RescueInstance;
    use zei_plonk::plonk::constraint_system::{ecc::Point, TurboCS};

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
                        pk_point.get_x(),
                    ])[0];
                    hash.rescue(&[BLSScalar::from(payer.uid), commitment, zero, zero])[0]
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
    fn test_commit() {
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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
        let mut cs = TurboCS::new();
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

        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let mut msg = [0u8; 32];
        prng.fill_bytes(&mut msg);

        let input_keypairs: Vec<AXfrKeyPair> = secret_inputs
            .payers_secrets
            .iter()
            .map(|x| AXfrKeyPair::from_secret_scalar(x.sec_key))
            .collect();
        let input_keypairs_ref: Vec<&AXfrKeyPair> = input_keypairs.iter().collect();
        let (hash, non_malleability_randomizer, non_malleability_tag) =
            compute_non_malleability_tag(&mut prng, b"AnonXfr", &msg, &input_keypairs_ref);

        // check the constraints
        let (mut cs, _) = build_multi_xfr_cs(
            secret_inputs,
            fee_type,
            fee_calculating_func,
            &hash,
            &non_malleability_randomizer,
            &non_malleability_tag,
        );
        let witness = cs.get_and_clear_witness();
        let mut online_inputs = pub_inputs.to_vec();
        online_inputs.push(hash);
        online_inputs.push(non_malleability_tag);
        let verify = cs.verify_witness(&witness, &online_inputs);
        if witness_is_valid {
            pnk!(verify);
        } else {
            assert!(verify.is_err());
        }
    }
}
