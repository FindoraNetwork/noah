use crate::anon_xfr::{
    add_merkle_path_variables, check_asset_amount, check_inputs, check_roots,
    commit_in_cs_with_native_address, compute_merkle_root, compute_non_malleability_tag,
    nullify_in_cs_with_native_address, nullify_with_native_address,
    structs::{
        AXfrKeyPair, AccElemVars, AnonBlindAssetRecord, Commitment, MTNode, MTPath, Nullifier,
        NullifierInputVars, OpenAnonBlindAssetRecord, PayeeWitness, PayeeWitnessVars, PayerWitness,
        PayerWitnessVars,
    },
    AXfrPlonkPf, TurboPlonkCS, AMOUNT_LEN, FEE_TYPE, SK_LEN,
};
use crate::errors::ZeiError;
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::structs::OwnerMemo;
use digest::Digest;
use merlin::Transcript;
use sha2::Sha512;
use zei_algebra::{
    bls12_381::BLSScalar,
    jubjub::{JubjubPoint, JubjubScalar},
    prelude::*,
};
use zei_crypto::basic::rescue::RescueInstance;
use zei_plonk::plonk::{
    constraint_system::{rescue::StateVar, TurboCS, VarIndex},
    prover::prover_with_lagrange,
    verifier::verifier,
};

/// The domain separator for anonymous transfer.
const ANON_XFR_TRANSCRIPT: &[u8] = b"Anon Xfr";
/// The domain separator for the number of inputs.
const N_INPUTS_TRANSCRIPT: &[u8] = b"Number of input ABARs";
/// The domain separator for the number of outputs.
const N_OUTPUTS_TRANSCRIPT: &[u8] = b"Number of output ABARs";

/// Anonymous transfer note.
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AXfrNote {
    /// The anonymous transfer body.
    pub body: AXfrBody,
    /// The spending proof (assuming non-malleability).
    pub anon_xfr_proof: AXfrPlonkPf,
    /// The non-malleability tag.
    pub non_malleability_tag: BLSScalar,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
/// Anonymous transfer body.
pub struct AXfrBody {
    /// The inputs, in terms of nullifiers.
    pub inputs: Vec<Nullifier>,
    /// The outputs, in terms of new anonymous asset records.
    pub outputs: Vec<AnonBlindAssetRecord>,
    /// The Merkle tree root.
    pub merkle_root: BLSScalar,
    /// An index of the Merkle tree root in the ledger.
    pub merkle_root_version: u64,
    /// The amount of fee.
    pub fee: u32,
    /// The owner memos.
    pub owner_memos: Vec<OwnerMemo>,
}

/// Build an anonymous transfer note.
pub fn gen_anon_xfr_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    inputs: &[OpenAnonBlindAssetRecord],
    outputs: &[OpenAnonBlindAssetRecord],
    fee: u32,
    input_keypairs: &[AXfrKeyPair],
) -> Result<AXfrNote> {
    // 1. check input correctness
    if inputs.is_empty() || outputs.is_empty() {
        return Err(eg!(ZeiError::AXfrProverParamsError));
    }
    check_inputs(inputs, input_keypairs).c(d!())?;
    check_asset_amount(inputs, outputs, fee).c(d!())?;
    check_roots(inputs).c(d!())?;

    // 2. build input witness infos
    let nullifiers = inputs
        .iter()
        .zip(input_keypairs.iter())
        .map(|(input, keypair)| {
            let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();
            nullify_with_native_address(&keypair, input.amount, &input.asset_type, mt_leaf_info.uid)
        })
        .collect();

    // 3. build proof
    let payers_secrets = inputs
        .iter()
        .zip(input_keypairs.iter())
        .map(|(input, keypair)| {
            let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();
            PayerWitness {
                sec_key: keypair.get_secret_scalar(),
                uid: mt_leaf_info.uid,
                amount: input.amount,
                asset_type: input.asset_type.as_scalar(),
                path: mt_leaf_info.path.clone(),
                blind: input.blind,
            }
        })
        .collect();
    let payees_secrets = outputs
        .iter()
        .map(|output| PayeeWitness {
            amount: output.amount,
            blind: output.blind,
            asset_type: output.asset_type.as_scalar(),
            pubkey_x: output.pub_key.0.point_ref().get_x(),
        })
        .collect();

    let secret_inputs = AMultiXfrWitness {
        payers_secrets,
        payees_secrets,
        fee,
    };
    let out_abars = outputs
        .iter()
        .map(AnonBlindAssetRecord::from_oabar)
        .collect_vec();
    let out_memos: Result<Vec<OwnerMemo>> = outputs
        .iter()
        .map(|output| output.owner_memo.clone().c(d!(ZeiError::ParameterError)))
        .collect();

    let mt_info_temp = inputs[0].mt_leaf_info.as_ref().unwrap();
    let body = AXfrBody {
        inputs: nullifiers,
        outputs: out_abars,
        merkle_root: mt_info_temp.root,
        merkle_root_version: mt_info_temp.root_version,
        fee,
        owner_memos: out_memos.c(d!())?,
    };

    let msg = bincode::serialize(&body)
        .c(d!(ZeiError::SerializationError))
        .c(d!())?;

    let input_keypairs_ref: Vec<&AXfrKeyPair> = input_keypairs.iter().collect();

    let (hash, non_malleability_randomizer, non_malleability_tag) =
        compute_non_malleability_tag(prng, b"AnonXfr", &msg, &input_keypairs_ref);

    let proof = prove_xfr(
        prng,
        params,
        secret_inputs,
        &hash,
        &non_malleability_randomizer,
        &non_malleability_tag,
    )
    .c(d!())?;

    Ok(AXfrNote {
        body,
        anon_xfr_proof: proof,
        non_malleability_tag,
    })
}

/// Verifies an anonymous transfer note.
pub fn verify_anon_xfr_note(
    params: &VerifierParams,
    note: &AXfrNote,
    merkle_root: &BLSScalar,
) -> Result<()> {
    if *merkle_root != note.body.merkle_root {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }
    let payees_commitments = note
        .body
        .outputs
        .iter()
        .map(|output| output.commitment)
        .collect();
    let pub_inputs = AMultiXfrPubInputs {
        payers_inputs: note.body.inputs.clone(),
        payees_commitments,
        merkle_root: *merkle_root,
        fee: note.body.fee,
    };

    let msg = bincode::serialize(&note.body)
        .c(d!(ZeiError::SerializationError))
        .c(d!())?;
    let mut hasher = Sha512::new();
    hasher.update(b"AnonXfr");
    hasher.update(&msg);
    let hash = BLSScalar::from_hash(hasher);

    verify_xfr(
        params,
        &pub_inputs,
        &note.anon_xfr_proof,
        &hash,
        &note.non_malleability_tag,
    )
    .c(d!(ZeiError::AXfrVerificationError))
}

/// Generate a Plonk proof for anonymous transfer.
pub(crate) fn prove_xfr<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    secret_inputs: AMultiXfrWitness,
    hash: &BLSScalar,
    non_malleability_randomizer: &BLSScalar,
    non_malleability_tag: &BLSScalar,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(ANON_XFR_TRANSCRIPT);
    transcript.append_u64(
        N_INPUTS_TRANSCRIPT,
        secret_inputs.payers_secrets.len() as u64,
    );
    transcript.append_u64(
        N_OUTPUTS_TRANSCRIPT,
        secret_inputs.payees_secrets.len() as u64,
    );

    let fee_type = FEE_TYPE.as_scalar();
    let (mut cs, _) = build_multi_xfr_cs(
        secret_inputs,
        fee_type,
        &hash,
        &non_malleability_randomizer,
        &non_malleability_tag,
    );
    let witness = cs.get_and_clear_witness();

    prover_with_lagrange(
        rng,
        &mut transcript,
        &params.pcs,
        params.lagrange_pcs.as_ref(),
        &params.cs,
        &params.prover_params,
        &witness,
    )
    .c(d!(ZeiError::AXfrProofError))
}

/// Verify a Plonk proof for anonymous transfer.
pub(crate) fn verify_xfr(
    params: &VerifierParams,
    pub_inputs: &AMultiXfrPubInputs,
    proof: &AXfrPlonkPf,
    hash: &BLSScalar,
    non_malleability_tag: &BLSScalar,
) -> Result<()> {
    let mut transcript = Transcript::new(ANON_XFR_TRANSCRIPT);
    transcript.append_u64(N_INPUTS_TRANSCRIPT, pub_inputs.payers_inputs.len() as u64);
    transcript.append_u64(
        N_OUTPUTS_TRANSCRIPT,
        pub_inputs.payees_commitments.len() as u64,
    );
    let mut online_inputs = pub_inputs.to_vec();
    online_inputs.push(*hash);
    online_inputs.push(*non_malleability_tag);

    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        proof,
    )
    .c(d!(ZeiError::ZKProofVerificationError))
}

/// The witness of an anonymous transfer.
#[derive(Debug)]
pub(crate) struct AMultiXfrWitness {
    pub(crate) payers_secrets: Vec<PayerWitness>,
    pub(crate) payees_secrets: Vec<PayeeWitness>,
    pub(crate) fee: u32,
}

impl AMultiXfrWitness {
    /// Create a fake `AMultiXfrWitness` for testing.
    pub(crate) fn fake(n_payers: usize, n_payees: usize, tree_depth: usize, fee: u32) -> Self {
        let bls_zero = BLSScalar::zero();
        let jubjub_zero = JubjubScalar::zero();
        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerWitness {
            sec_key: jubjub_zero,
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };
        let payee_secret = PayeeWitness {
            amount: 0,
            blind: bls_zero,
            asset_type: bls_zero,
            pubkey_x: bls_zero,
        };

        AMultiXfrWitness {
            payers_secrets: vec![payer_secret; n_payers],
            payees_secrets: vec![payee_secret; n_payees],
            fee,
        }
    }
}

/// Public inputs of an anonymous transfer.
#[derive(Debug)]
pub(crate) struct AMultiXfrPubInputs {
    pub(crate) payers_inputs: Vec<Nullifier>,
    pub(crate) payees_commitments: Vec<Commitment>,
    pub(crate) merkle_root: BLSScalar,
    pub(crate) fee: u32,
}

impl AMultiXfrPubInputs {
    pub(crate) fn to_vec(&self) -> Vec<BLSScalar> {
        let mut result = vec![];
        for nullifier in &self.payers_inputs {
            result.push(*nullifier);
        }
        result.push(self.merkle_root);
        for comm in &self.payees_commitments {
            result.push(*comm);
        }
        result.push(BLSScalar::from(self.fee));
        result
    }

    #[allow(dead_code)]
    pub(crate) fn from_witness(witness: &AMultiXfrWitness) -> Self {
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
                let cur = hash.rescue(&[
                    uid_amount,
                    sec.asset_type,
                    BLSScalar::zero(),
                    pk_point.get_x(),
                ])[0];
                hash.rescue(&[
                    cur,
                    BLSScalar::from(&sec.sec_key),
                    BLSScalar::zero(),
                    BLSScalar::zero(),
                ])[0]
            })
            .collect();

        let hash = RescueInstance::new();
        let zero = BLSScalar::zero();
        let payees_commitments: Vec<Commitment> = witness
            .payees_secrets
            .iter()
            .map(|sec| {
                let cur = hash.rescue(&[
                    sec.blind,
                    BLSScalar::from(sec.amount),
                    sec.asset_type,
                    BLSScalar::zero(),
                ])[0];
                hash.rescue(&[cur, sec.pubkey_x, BLSScalar::zero(), BLSScalar::zero()])[0]
            })
            .collect();

        let payer = &witness.payers_secrets[0];
        let pk_point = base.mul(&payer.sec_key);
        let commitment = {
            let cur = hash.rescue(&[
                payer.blind,
                BLSScalar::from(payer.amount),
                payer.asset_type,
                BLSScalar::zero(),
            ])[0];
            hash.rescue(&[cur, pk_point.get_x(), BLSScalar::zero(), BLSScalar::zero()])[0]
        };
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
            fee: witness.fee,
        }
    }
}

/// Instantiate the constraint system for anonymous transfer.
pub(crate) fn build_multi_xfr_cs(
    witness: AMultiXfrWitness,
    fee_type: BLSScalar,
    hash: &BLSScalar,
    non_malleability_randomizer: &BLSScalar,
    non_malleability_tag: &BLSScalar,
) -> (TurboPlonkCS, usize) {
    assert_ne!(witness.payers_secrets.len(), 0);
    assert_ne!(witness.payees_secrets.len(), 0);

    let mut cs = TurboCS::new();
    let payers_secrets = add_payers_witnesses(&mut cs, &witness.payers_secrets);
    let payees_secrets = add_payees_witnesses(&mut cs, &witness.payees_secrets);

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
        // prove knowledge of payer's secret key: pk = base^{sk}.
        let pk_var = cs.scalar_mul(base, payer.sec_key, SK_LEN);
        let pk_x = pk_var.get_x();

        // commitments.
        let com_abar_in_var = commit_in_cs_with_native_address(
            &mut cs,
            payer.blind,
            payer.amount,
            payer.asset_type,
            pk_x,
        );

        // prove pre-image of the nullifier.
        // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`.
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
        let nullifier_var =
            nullify_in_cs_with_native_address(&mut cs, payer.sec_key, nullifier_input_vars);

        // Merkle path authentication.
        let acc_elem = AccElemVars {
            uid: payer.uid,
            commitment: com_abar_in_var,
        };
        let tmp_root_var = compute_merkle_root(&mut cs, acc_elem, &payer.path);

        // additional safegaurd to check the payer's amount, although in theory this is not needed.
        cs.range_check(payer.amount, AMOUNT_LEN);

        if let Some(root) = root_var {
            cs.equal(root, tmp_root_var);
        } else {
            root_var = Some(tmp_root_var);
        }

        // prepare public inputs variables.
        cs.prepare_pi_variable(nullifier_var);
    }
    // prepare the public input for merkle_root.
    cs.prepare_pi_variable(root_var.unwrap()); // safe unwrap

    for payee in &payees_secrets {
        // commitment.
        let com_abar_out_var = commit_in_cs_with_native_address(
            &mut cs,
            payee.blind,
            payee.amount,
            payee.asset_type,
            payee.pubkey_x,
        );

        // Range check `amount`.
        cs.range_check(payee.amount, AMOUNT_LEN);

        // prepare the public input for the output commitment.
        cs.prepare_pi_variable(com_abar_out_var);
    }

    // add asset-mixing constraints.
    let inputs: Vec<(VarIndex, VarIndex)> = payers_secrets
        .iter()
        .map(|payer| (payer.asset_type, payer.amount))
        .collect();
    let outputs: Vec<(VarIndex, VarIndex)> = payees_secrets
        .iter()
        .map(|payee| (payee.asset_type, payee.amount))
        .collect();

    let fee_var = cs.new_variable(BLSScalar::from(witness.fee));
    cs.prepare_pi_variable(fee_var);

    asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);

    // check the validity of the non-malleability tag.
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

    // pad the number of constraints to power of two.
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
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
pub fn asset_mixing(
    cs: &mut TurboPlonkCS,
    inputs: &[(VarIndex, VarIndex)],
    outputs: &[(VarIndex, VarIndex)],
    fee_type: BLSScalar,
    fee_var: VarIndex,
) {
    // compute the `sum_in_i`.
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

    // compute the `sum_out_i`.
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

    // initialize a constant value `fee_type_val`.
    let fee_type_val = cs.new_variable(fee_type);
    cs.insert_constant_gate(fee_type_val, fee_type);

    // at least one input type is `fee_type` by checking `flag_no_fee_type = 0`,
    // and also check that the amount is matching,
    // and also check that every input type appears in the set of output types (except if the fee has used up).
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

    // check that every output type appears in the set of input types.
    for &(output_type, _) in outputs {
        // `\prod_i (input_type_i - output_type) == 0` for each `output_type`.
        let mut product = cs.one_var();
        for &(input_type, _) in inputs {
            let diff = cs.sub(input_type, output_type);
            product = cs.mul(product, diff);
        }
        cs.insert_constant_gate(product, BLSScalar::zero());
    }
}

/// If `type1` == `type2`, return a variable that equals `val`, otherwise return zero.
fn match_select(
    cs: &mut TurboPlonkCS,
    type1: VarIndex,
    type2: VarIndex,
    val: VarIndex,
) -> VarIndex {
    let is_equal_var = cs.is_equal(type1, type2);
    cs.mul(is_equal_var, val)
}

/// Allocate payers' witnesses.
pub(crate) fn add_payers_witnesses(
    cs: &mut TurboPlonkCS,
    secrets: &[PayerWitness],
) -> Vec<PayerWitnessVars> {
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
            PayerWitnessVars {
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

/// Allocate payees' witnesses.
pub(crate) fn add_payees_witnesses(
    cs: &mut TurboPlonkCS,
    secrets: &[PayeeWitness],
) -> Vec<PayeeWitnessVars> {
    secrets
        .iter()
        .map(|secret| {
            let amount = cs.new_variable(BLSScalar::from(secret.amount));
            let blind = cs.new_variable(secret.blind);
            let asset_type = cs.new_variable(secret.asset_type);
            let pubkey_x = cs.new_variable(secret.pubkey_x);
            PayeeWitnessVars {
                amount,
                blind,
                asset_type,
                pubkey_x,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::{
        abar_to_abar::{
            asset_mixing, build_multi_xfr_cs, gen_anon_xfr_note, prove_xfr, verify_anon_xfr_note,
            verify_xfr, AMultiXfrPubInputs, AMultiXfrWitness,
        },
        add_merkle_path_variables, commit_in_cs_with_native_address, compute_merkle_root,
        compute_non_malleability_tag, nullify_in_cs_with_native_address, sort,
        structs::{
            AXfrKeyPair, AccElemVars, AnonBlindAssetRecord, MTLeafInfo, MTNode, MTPath,
            NullifierInputVars, OpenAnonBlindAssetRecord, OpenAnonBlindAssetRecordBuilder,
            PayeeWitness, PayerWitness,
        },
        FEE_TYPE, TREE_DEPTH,
    };
    use crate::setup::{ProverParams, VerifierParams};
    use crate::xfr::structs::AssetType;
    use mem_db::MemoryDB;
    use parking_lot::lock_api::RwLock;
    use rand_chacha::ChaChaRng;
    use std::sync::Arc;
    use storage::{
        state::{ChainState, State},
        store::PrefixedStore,
    };
    use zei_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
    use zei_algebra::{
        bls12_381::BLSScalar,
        jubjub::{JubjubPoint, JubjubScalar},
        prelude::*,
    };
    use zei_crypto::basic::{
        hybrid_encryption::{XPublicKey, XSecretKey},
        rescue::RescueInstance,
    };
    use zei_plonk::plonk::constraint_system::{ecc::Point, TurboCS, VarIndex};

    #[test]
    fn test_anon_multi_xfr_proof_3in_6out_single_asset() {
        let fee_type = FEE_TYPE.as_scalar();
        let pubkey_x = BLSScalar::from(4567u32);

        let mut rng = ChaChaRng::from_entropy();
        let mut total_input = 50 + rng.next_u64() % 50;
        let mut total_output = total_input;

        let mut inputs: Vec<(u64, BLSScalar)> = Vec::new();

        let rnd_amount = rng.next_u64();
        let amount = rnd_amount % total_input;
        inputs.push((amount, fee_type));
        total_input -= amount;
        inputs.push((total_input, fee_type));

        let mut outputs: Vec<(u64, BLSScalar, BLSScalar)> = Vec::new();
        for _i in 1..6 {
            let rnd_amount = rng.next_u64();
            let amount = rnd_amount % total_output;
            outputs.push((amount, fee_type, pubkey_x));
            total_output -= amount;
        }
        outputs.push((total_output, fee_type, pubkey_x));

        let fee_amount = 50;
        inputs.push((fee_amount, fee_type));
        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
    }

    #[test]
    fn test_anon_multi_xfr_proof_3in_3out_single_asset() {
        let fee_type = FEE_TYPE.as_scalar();
        let pubkey_x = BLSScalar::from(4567u32);

        // (n, m) = (3, 3)
        let mut rng = ChaChaRng::from_entropy();
        let mut total_input = 50 + rng.next_u64() % 50;

        let mut total_output = total_input;

        let mut inputs: Vec<(u64, BLSScalar)> = Vec::new();
        let mut outputs: Vec<(u64, BLSScalar, BLSScalar)> = Vec::new();

        let amount = rng.next_u64() % total_input;
        inputs.push((amount, fee_type));
        total_input -= amount;
        inputs.push((total_input, fee_type));

        let amount_out = rng.next_u64() % total_output;
        outputs.push((amount_out, fee_type, pubkey_x));
        total_output -= amount_out;
        outputs.push((total_output, fee_type, pubkey_x));

        let fee_amount = 50;
        inputs.push((fee_amount, fee_type));
        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
    }

    #[test]
    fn test_anon_multi_xfr_proof_1in_2out_single_asset() {
        let fee_type = FEE_TYPE.as_scalar();
        let pubkey_x = BLSScalar::from(4567u32);

        // (n, m) = (1, 2)
        let amount = 0;
        let outputs = vec![(amount, fee_type, pubkey_x), (amount, fee_type, pubkey_x)];

        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);
        let fee_amount = fee_calculating_func(1, outputs.len()) as u64;
        let inputs = vec![(fee_amount, fee_type)];

        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
    }

    #[test]
    fn test_anon_multi_xfr_proof_2in_1out_single_asset() {
        let fee_type = FEE_TYPE.as_scalar();

        // (n, m) = (2, 1)
        let mut rng = ChaChaRng::from_entropy();
        let pubkey_x = BLSScalar::from(4567u32);

        // This time we need one input equal to the output, besides the input for fees
        let amount = 50 + rng.next_u64() % 50; // a random number in [50, 100)

        let outputs = vec![(amount, fee_type, pubkey_x)];
        let mut inputs = vec![(amount, fee_type)];

        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);
        let fee_amount = fee_calculating_func(inputs.len() + 1, outputs.len()) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
    }

    #[test]
    fn test_anon_multi_xfr_proof_3in_6out_multi_asset() {
        let fee_type = FEE_TYPE.as_scalar();

        // multiple asset types
        // (n, m) = (3, 6)
        let one = BLSScalar::one();

        let pubkey_x = BLSScalar::from(4567u32);

        let mut inputs = vec![(/*amount=*/ 40, /*asset_type=*/ fee_type), (80, one)];

        let outputs = vec![
            (5, fee_type, pubkey_x),
            (10, fee_type, pubkey_x),
            (25, fee_type, pubkey_x),
            (20, one, pubkey_x),
            (20, one, pubkey_x),
            (40, one, pubkey_x),
        ];

        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);
        let fee_amount = fee_calculating_func(inputs.len() + 1, outputs.len()) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
    }

    #[test]
    fn test_anon_multi_xfr_proof_2in_3out_multi_asset() {
        let fee_type = FEE_TYPE.as_scalar();
        let one = BLSScalar::one();

        let pubkey_x = BLSScalar::from(4567u32);

        // (n, m) = (2, 3)
        let input_1 = 20u64;
        let input_2 = 52u64;

        let output_1 = 17u64;
        let output_2 = 3u64;
        let output_3 = 52u64;

        let mut inputs = vec![(input_1, fee_type), (input_2, one)];

        let outputs = vec![
            (output_1, fee_type, pubkey_x),
            (output_2, fee_type, pubkey_x),
            (output_3, one, pubkey_x),
        ];

        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);
        let fee_amount = fee_calculating_func(inputs.len() + 1, outputs.len()) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
    }

    fn test_anon_xfr_proof(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar, BLSScalar)>,
        fee: u32,
    ) {
        let n_payers = inputs.len();
        let n_payees = outputs.len();

        // build cs
        let secret_inputs =
            new_multi_xfr_witness_for_test(inputs.to_vec(), outputs.to_vec(), fee, [0u8; 32]);
        let pub_inputs = AMultiXfrPubInputs::from_witness(&secret_inputs);
        let params = ProverParams::new(n_payers, n_payees, Some(1)).unwrap();
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

        let proof = prove_xfr(
            &mut prng,
            &params,
            secret_inputs,
            &hash,
            &non_malleability_randomizer,
            &non_malleability_tag,
        )
        .unwrap();

        // good witness.
        let node_params = VerifierParams::from(params);
        assert!(verify_xfr(
            &node_params,
            &pub_inputs,
            &proof,
            &hash,
            &non_malleability_tag
        )
        .is_ok());

        // An unmatched input should fail the verification.
        let bad_secret_inputs = AMultiXfrPubInputs::from_witness(&new_multi_xfr_witness_for_test(
            inputs.to_vec(),
            outputs.to_vec(),
            fee,
            [1u8; 32],
        ));
        // bad witness.
        assert!(verify_xfr(
            &node_params,
            &bad_secret_inputs,
            &proof,
            &hash,
            &non_malleability_tag
        )
        .is_err());
    }

    pub(crate) fn create_mt_leaf_info(proof: Proof) -> MTLeafInfo {
        MTLeafInfo {
            path: MTPath {
                nodes: proof
                    .nodes
                    .iter()
                    .map(|e| MTNode {
                        siblings1: e.siblings1,
                        siblings2: e.siblings2,
                        is_left_child: (e.path == TreePath::Left) as u8,
                        is_right_child: (e.path == TreePath::Right) as u8,
                    })
                    .collect(),
            },
            root: proof.root,
            root_version: proof.root_version,
            uid: proof.uid,
        }
    }

    #[test]
    fn test_anon_xfr() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let user_params = ProverParams::new(1, 1, Some(1)).unwrap();

        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        let two = one.add(&one);

        let asset_type = FEE_TYPE;
        let fee_amount = 65u32;

        let output_amount = 1 + prng.next_u64() % 100;
        let input_amount = output_amount + fee_amount as u64;

        // sample an input anonymous asset record for testing.
        let (oabar, keypair_in, dec_key_in, _) =
            gen_oabar_and_keys(&mut prng, input_amount, asset_type);
        let abar = AnonBlindAssetRecord::from_oabar(&oabar);
        assert_eq!(keypair_in.pub_key(), *oabar.pub_key_ref());

        let owner_memo = oabar.get_owner_memo().unwrap();

        // simulate Merkle tree state with that input record for testing.
        let node = MTNode {
            siblings1: one,
            siblings2: two,
            is_left_child: 0u8,
            is_right_child: 1u8,
        };
        let hash = RescueInstance::new();
        let leaf = hash.rescue(&[/*uid=*/ two, oabar.compute_commitment(), zero, zero])[0];
        let merkle_root = hash.rescue(&[/*sib1[0]=*/ one, /*sib2[0]=*/ two, leaf, zero])[0];
        let mt_leaf_info = MTLeafInfo {
            path: MTPath { nodes: vec![node] },
            root: merkle_root,
            uid: 2,
            root_version: 0,
        };

        // sample output keys for testing.
        let keypair_out = AXfrKeyPair::generate(&mut prng);
        let dec_key_out = XSecretKey::new(&mut prng);
        let enc_key_out = XPublicKey::from(&dec_key_out);

        let (note, merkle_root) = {
            // prover scope
            let oabar_in = OpenAnonBlindAssetRecordBuilder::from_abar(
                &abar,
                owner_memo,
                &keypair_in,
                &dec_key_in,
            )
            .unwrap()
            .mt_leaf_info(mt_leaf_info)
            .build()
            .unwrap();
            assert_eq!(input_amount, oabar_in.get_amount());
            assert_eq!(asset_type, oabar_in.get_asset_type());
            assert_eq!(keypair_in.pub_key(), oabar_in.pub_key);

            let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
                .amount(output_amount)
                .asset_type(asset_type)
                .pub_key(keypair_out.pub_key())
                .finalize(&mut prng, &enc_key_out)
                .unwrap()
                .build()
                .unwrap();

            let note = gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &[oabar_in],
                &[oabar_out],
                fee_amount,
                &[keypair_in],
            )
            .unwrap();
            (note, merkle_root)
        };
        {
            // owner scope
            let oabar = OpenAnonBlindAssetRecordBuilder::from_abar(
                &note.body.outputs[0],
                note.body.owner_memos[0].clone(),
                &keypair_out,
                &dec_key_out,
            )
            .unwrap()
            .build()
            .unwrap();
            assert_eq!(output_amount, oabar.get_amount());
            assert_eq!(asset_type, oabar.get_asset_type());
        }
        {
            // verifier scope
            let verifier_params = VerifierParams::from(user_params);
            assert!(verify_anon_xfr_note(&verifier_params, &note, &merkle_root).is_ok());
        }
    }

    // Helper function to build a Merkle tree for testing.
    fn build_new_merkle_tree(n: i32, mt: &mut PersistentMerkleTree<'_, MemoryDB>) -> Result<()> {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        // add some random anonymous asset records to the tree.

        let mut abar = AnonBlindAssetRecord {
            commitment: BLSScalar::random(&mut prng),
        };

        let _ = mt.add_commitment_hash(compute_merkle_leaf_value(mt.entry_count(), &abar))?;
        mt.commit()?;

        for _i in 0..n - 1 {
            abar = AnonBlindAssetRecord {
                commitment: BLSScalar::random(&mut prng),
            };

            let _ = mt.add_commitment_hash(compute_merkle_leaf_value(mt.entry_count(), &abar))?;
            mt.commit()?;
        }

        Ok(())
    }

    #[test]
    fn test_new_anon_xfr() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);

        let user_params = ProverParams::new(1, 1, Some(TREE_DEPTH)).unwrap();

        let fee_amount = 25u32;
        let output_amount = 10u64;
        let input_amount = output_amount + fee_amount as u64;
        let asset_type = FEE_TYPE;

        // sample an input anonymous asset record for testing.
        let (oabar, keypair_in, dec_key_in, _) =
            gen_oabar_and_keys(&mut prng, input_amount, asset_type);
        assert_eq!(keypair_in.pub_key(), *oabar.pub_key_ref());

        let owner_memo = oabar.get_owner_memo().unwrap();

        let mut mt = PersistentMerkleTree::new(store).unwrap();
        build_new_merkle_tree(5, &mut mt).unwrap();

        let abar = AnonBlindAssetRecord::from_oabar(&oabar);
        let uid = mt
            .add_commitment_hash(compute_merkle_leaf_value(mt.entry_count(), &abar))
            .unwrap();
        let _ = mt.commit();
        let mt_proof = mt.generate_proof(uid).unwrap();
        assert_eq!(mt.get_root().unwrap(), mt_proof.root);

        // sample output keys for testing.
        let keypair_out = AXfrKeyPair::generate(&mut prng);
        let dec_key_out = XSecretKey::new(&mut prng);
        let enc_key_out = XPublicKey::from(&dec_key_out);

        let (note, _merkle_root) = {
            // prover scope
            let oabar_in = OpenAnonBlindAssetRecordBuilder::from_abar(
                &abar,
                owner_memo,
                &keypair_in,
                &dec_key_in,
            )
            .unwrap()
            .mt_leaf_info(create_mt_leaf_info(mt_proof.clone()))
            .build()
            .unwrap();
            assert_eq!(input_amount, oabar_in.get_amount());
            assert_eq!(asset_type, oabar_in.get_asset_type());
            assert_eq!(keypair_in.pub_key(), oabar_in.pub_key);

            let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
                .amount(output_amount)
                .asset_type(asset_type)
                .pub_key(keypair_out.pub_key())
                .finalize(&mut prng, &enc_key_out)
                .unwrap()
                .build()
                .unwrap();

            let note = gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &[oabar_in],
                &[oabar_out],
                fee_amount,
                &[keypair_in],
            )
            .unwrap();
            (note, mt_proof.root)
        };
        {
            // owner scope
            let oabar = OpenAnonBlindAssetRecordBuilder::from_abar(
                &note.body.outputs[0],
                note.body.owner_memos[0].clone(),
                &keypair_out,
                &dec_key_out,
            )
            .unwrap()
            .build()
            .unwrap();
            assert_eq!(output_amount, oabar.get_amount());
            assert_eq!(asset_type, oabar.get_asset_type());
        }
        {
            let mut hash = {
                let hasher = RescueInstance::new();
                hasher.rescue(&[
                    BLSScalar::from(uid),
                    abar.commitment,
                    BLSScalar::zero(),
                    BLSScalar::zero(),
                ])[0]
            };
            let hasher = RescueInstance::new();
            for i in mt_proof.nodes.iter() {
                let (s1, s2, s3) = match i.path {
                    TreePath::Left => (hash, i.siblings1, i.siblings2),
                    TreePath::Middle => (i.siblings1, hash, i.siblings2),
                    TreePath::Right => (i.siblings1, i.siblings2, hash),
                };
                hash = hasher.rescue(&[s1, s2, s3, BLSScalar::zero()])[0];
            }
            assert_eq!(hash, mt.get_root().unwrap());
        }
        {
            // verifier scope
            let verifier_params = VerifierParams::from(user_params);
            let t = verify_anon_xfr_note(&verifier_params, &note, &mt.get_root().unwrap());
            assert!(t.is_ok());

            let vk1 = verifier_params.shrink().unwrap();
            assert!(verify_anon_xfr_note(&vk1, &note, &mt.get_root().unwrap()).is_ok());

            let vk2 = VerifierParams::load(1, 1).unwrap();
            assert!(verify_anon_xfr_note(&vk2, &note, &mt.get_root().unwrap()).is_ok());
        }
    }

    #[test]
    fn test_anon_xfr_multi_assets() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let n_payers = 3;
        let n_payees = 3;
        let user_params = ProverParams::new(n_payers, n_payees, Some(1)).unwrap();

        let zero = BLSScalar::zero();
        let one = BLSScalar::one();

        let fee_amount = 15;

        // generate some input records for testing.
        let amounts_in = vec![10u64 + fee_amount, 20u64, 30u64];
        let asset_types_in = vec![
            FEE_TYPE,
            AssetType::from_identical_byte(1),
            AssetType::from_identical_byte(1),
        ];
        let mut in_abars = vec![];
        let mut in_keypairs = vec![];
        let mut in_dec_keys = vec![];
        let mut in_owner_memos = vec![];
        for i in 0..n_payers {
            let (oabar, keypair, dec_key, _) =
                gen_oabar_and_keys(&mut prng, amounts_in[i], asset_types_in[i]);
            let abar = AnonBlindAssetRecord::from_oabar(&oabar);
            let owner_memo = oabar.get_owner_memo().unwrap();
            in_abars.push(abar);
            in_keypairs.push(keypair);
            in_dec_keys.push(dec_key);
            in_owner_memos.push(owner_memo);
        }

        // simulate Merkle tree state with these inputs for testing.
        let hash = RescueInstance::new();
        let leafs: Vec<BLSScalar> = in_abars
            .iter()
            .enumerate()
            .map(|(uid, in_abar)| {
                hash.rescue(&[BLSScalar::from(uid as u32), in_abar.commitment, zero, zero])[0]
            })
            .collect();
        let node0 = MTNode {
            siblings1: leafs[1],
            siblings2: leafs[2],
            is_left_child: 1u8,
            is_right_child: 0u8,
        };
        let node1 = MTNode {
            siblings1: leafs[0],
            siblings2: leafs[2],
            is_left_child: 0u8,
            is_right_child: 0u8,
        };
        let node2 = MTNode {
            siblings1: leafs[0],
            siblings2: leafs[1],
            is_left_child: 0u8,
            is_right_child: 1u8,
        };
        let nodes = vec![node0, node1, node2];
        let merkle_root = hash.rescue(&[leafs[0], leafs[1], leafs[2], zero])[0];

        // generate some output records for testing.
        let (keypairs_out, dec_keys_out, enc_keys_out) = gen_keys(&mut prng, n_payees);
        let amounts_out = vec![5u64, 5u64, 50u64];
        let asset_types_out = vec![FEE_TYPE, FEE_TYPE, AssetType::from_identical_byte(1)];
        let mut outputs = vec![];
        for i in 0..n_payees {
            outputs.push(
                OpenAnonBlindAssetRecordBuilder::new()
                    .amount(amounts_out[i])
                    .asset_type(asset_types_out[i])
                    .pub_key(keypairs_out[i].pub_key())
                    .finalize(&mut prng, &enc_keys_out[i])
                    .unwrap()
                    .build()
                    .unwrap(),
            );
        }

        let (note, merkle_root) = {
            // prover scope
            let mut open_abars_in: Vec<OpenAnonBlindAssetRecord> = (0..n_payers)
                .map(|uid| {
                    let mt_leaf_info = MTLeafInfo {
                        path: MTPath {
                            nodes: vec![nodes[uid].clone()],
                        },
                        root: merkle_root,
                        uid: uid as u64,
                        root_version: 0,
                    };
                    let open_abar_in = OpenAnonBlindAssetRecordBuilder::from_abar(
                        &in_abars[uid],
                        in_owner_memos[uid].clone(),
                        &in_keypairs[uid],
                        &in_dec_keys[uid],
                    )
                    .unwrap()
                    .mt_leaf_info(mt_leaf_info)
                    .build()
                    .unwrap();
                    assert_eq!(amounts_in[uid], open_abar_in.amount);
                    assert_eq!(asset_types_in[uid], open_abar_in.asset_type);
                    open_abar_in
                })
                .collect();

            let open_abars_out = (0..n_payees)
                .map(|i| {
                    OpenAnonBlindAssetRecordBuilder::new()
                        .amount(amounts_out[i])
                        .asset_type(asset_types_out[i])
                        .pub_key(keypairs_out[i].pub_key())
                        .finalize(&mut prng, &enc_keys_out[i])
                        .unwrap()
                        .build()
                        .unwrap()
                })
                .collect_vec();

            // empty inputs/outputs
            msg_eq!(
                ZeiError::AXfrProverParamsError,
                gen_anon_xfr_note(&mut prng, &user_params, &[], &open_abars_out, 15, &[])
                    .unwrap_err(),
            );
            msg_eq!(
                ZeiError::AXfrProverParamsError,
                gen_anon_xfr_note(
                    &mut prng,
                    &user_params,
                    &open_abars_in,
                    &[],
                    15,
                    &in_keypairs
                )
                .unwrap_err(),
            );
            // invalid inputs/outputs
            open_abars_in[0].amount += 1;
            assert!(gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &open_abars_in,
                &open_abars_out,
                15,
                &in_keypairs
            )
            .is_err());
            open_abars_in[0].amount -= 1;
            // inconsistent roots
            let mut mt_info = open_abars_in[0].mt_leaf_info.clone().unwrap();
            mt_info.root.add_assign(&one);
            open_abars_in[0].mt_leaf_info = Some(mt_info);
            assert!(gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &open_abars_in,
                &open_abars_out,
                15,
                &in_keypairs
            )
            .is_err());
            let mut mt_info = open_abars_in[0].mt_leaf_info.clone().unwrap();
            mt_info.root.sub_assign(&one);
            open_abars_in[0].mt_leaf_info = Some(mt_info);

            let note = gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &open_abars_in,
                &open_abars_out,
                15,
                &in_keypairs,
            )
            .unwrap();
            (note, merkle_root)
        };
        {
            // owner scope
            for i in 0..n_payees {
                let oabar_out = OpenAnonBlindAssetRecordBuilder::from_abar(
                    &note.body.outputs[i],
                    note.body.owner_memos[i].clone(),
                    &keypairs_out[i],
                    &dec_keys_out[i],
                )
                .unwrap()
                .build()
                .unwrap();
                assert_eq!(amounts_out[i], oabar_out.amount);
                assert_eq!(asset_types_out[i], oabar_out.asset_type);
            }
        }
        {
            // verifier scope
            let verifier_params = VerifierParams::from(user_params);
            assert!(verify_anon_xfr_note(&verifier_params, &note, &merkle_root).is_ok());
            // inconsistent merkle roots
            assert!(verify_anon_xfr_note(&verifier_params, &note, &zero).is_err());
        }
    }

    fn gen_keys<R: CryptoRng + RngCore>(
        prng: &mut R,
        n: usize,
    ) -> (Vec<AXfrKeyPair>, Vec<XSecretKey>, Vec<XPublicKey>) {
        let keypairs_in: Vec<AXfrKeyPair> = (0..n).map(|_| AXfrKeyPair::generate(prng)).collect();

        let dec_keys_in: Vec<XSecretKey> = (0..n).map(|_| XSecretKey::new(prng)).collect();
        let enc_keys_in: Vec<XPublicKey> = dec_keys_in.iter().map(XPublicKey::from).collect();
        (keypairs_in, dec_keys_in, enc_keys_in)
    }

    fn gen_oabar_and_keys<R: CryptoRng + RngCore>(
        prng: &mut R,
        amount: u64,
        asset_type: AssetType,
    ) -> (
        OpenAnonBlindAssetRecord,
        AXfrKeyPair,
        XSecretKey,
        XPublicKey,
    ) {
        let keypair = AXfrKeyPair::generate(prng);
        let dec_key = XSecretKey::new(prng);
        let enc_key = XPublicKey::from(&dec_key);
        let oabar = OpenAnonBlindAssetRecordBuilder::new()
            .amount(amount)
            .asset_type(asset_type)
            .pub_key(keypair.pub_key())
            .finalize(prng, &enc_key)
            .unwrap()
            .build()
            .unwrap();
        (oabar, keypair, dec_key, enc_key)
    }

    #[test]
    fn test_asset_mixing() {
        // Fee type
        let fee_type = BLSScalar::from(1234u32);

        // Fee function
        // base fee 5, every input 1, every output 2
        let fee_calculating_func =
            |x: usize, y: usize| BLSScalar::from(5 + (x as u32) + 2 * (y as u32));

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

        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), 0));
        asset_mixing(&mut cs, &inputs, &[], fee_type, fee_var);

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

        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), 0));
        asset_mixing(&mut cs, &inputs, &[], fee_type, fee_var);

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

        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), 0));
        asset_mixing(&mut cs, &inputs, &[], fee_type, fee_var);

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

        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), outputs.len()));
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);
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

        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), outputs.len()));
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);
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

        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), outputs.len()));
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);
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

        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), outputs.len()));
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);
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

        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), outputs.len()));
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);
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
        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), outputs.len()));
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);
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
        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), outputs.len()));
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);
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
        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), outputs.len()));
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);
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
        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), outputs.len()));
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);
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
        let fee_var = cs.new_variable(fee_calculating_func(inputs.len(), outputs.len()));
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);
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
        let commitment = {
            let cur = hash.rescue(&[blind, amount, asset_type, BLSScalar::zero()])[0];
            hash.rescue(&[cur, pubkey_x, BLSScalar::zero(), BLSScalar::zero()])[0]
        };

        let amount_var = cs.new_variable(amount);
        let asset_var = cs.new_variable(asset_type);
        let blind_var = cs.new_variable(blind);
        let pubkey_x_var = cs.new_variable(pubkey_x);
        let comm_var = commit_in_cs_with_native_address(
            &mut cs,
            blind_var,
            amount_var,
            asset_var,
            pubkey_x_var,
        );
        let mut witness = cs.get_and_clear_witness();

        // check commitment consistency.
        assert_eq!(witness[comm_var], commitment);

        // check the constraints.
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        // incorrect witness.
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
        let expected_output = {
            let cur = hash.rescue(&[uid_amount, asset_type, BLSScalar::zero(), *pk.get_x()])[0];
            hash.rescue(&[cur, sk, BLSScalar::zero(), BLSScalar::zero()])[0]
        };

        let sk_var = cs.new_variable(sk);
        let uid_amount_var = cs.new_variable(uid_amount);
        let asset_var = cs.new_variable(asset_type);
        let pk_var = cs.new_point_variable(pk);
        let nullifier_input_var = NullifierInputVars {
            uid_amount: uid_amount_var,
            asset_type: asset_var,
            pub_key_x: pk_var.get_x(),
        };
        let nullifier_var = nullify_in_cs_with_native_address(&mut cs, sk_var, nullifier_input_var);
        let mut witness = cs.get_and_clear_witness();

        // check the output consistency.
        assert_eq!(witness[nullifier_var], expected_output);

        // check the constraints.
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        // incorrect witness.
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

        // node_var is at the right position.
        let expected_output = vec![
            witness[sib1_var],
            witness[sib2_var],
            witness[node_var],
            witness[cs.zero_var()],
        ];
        // check output correctness.
        assert_eq!(output, expected_output);

        // check constraints.
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        // incorrect witness.
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

        // compute the root value.
        let hash = RescueInstance::new();
        let leaf = hash.rescue(&[/*uid=*/ one, /*comm=*/ two, zero, zero])[0];
        // leaf is the right child of node1.
        let node1 = hash.rescue(&[path_node2.siblings1, path_node2.siblings2, leaf, zero])[0];
        // node1 is the left child of the root.
        let root = hash.rescue(&[node1, path_node1.siblings1, path_node1.siblings2, zero])[0];

        // compute the constraints.
        let path = MTPath::new(vec![path_node2, path_node1]);
        let path_vars = add_merkle_path_variables(&mut cs, path);
        let root_var = compute_merkle_root(&mut cs, elem, &path_vars);

        // check Merkle root correctness.
        let mut witness = cs.get_and_clear_witness();
        assert_eq!(witness[root_var], root);

        // check constraints.
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        // incorrect witness.
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

    pub(crate) fn new_multi_xfr_witness_for_test(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar, BLSScalar)>,
        fee: u32,
        seed: [u8; 32],
    ) -> AMultiXfrWitness {
        let n_payers = inputs.len();
        assert!(n_payers <= 3);
        let mut prng = ChaChaRng::from_seed(seed);
        let zero = BLSScalar::zero();
        let mut payers_secrets: Vec<PayerWitness> = inputs
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
                PayerWitness {
                    sec_key: JubjubScalar::random(&mut prng),
                    uid: i as u64,
                    amount,
                    asset_type,
                    path: MTPath::new(vec![node]),
                    blind: BLSScalar::random(&mut prng),
                }
            })
            .collect();

        // compute the merkle leaves and update the merkle paths if there are more than 1 payers.
        if n_payers > 1 {
            let hash = RescueInstance::new();
            let base = JubjubPoint::get_base();
            let leafs: Vec<BLSScalar> = payers_secrets
                .iter()
                .map(|payer| {
                    let pk_point = base.mul(&payer.sec_key);
                    let cur = hash.rescue(&[
                        payer.blind,
                        BLSScalar::from(payer.amount),
                        payer.asset_type,
                        BLSScalar::zero(),
                    ])[0];
                    let commitment =
                        hash.rescue(&[cur, pk_point.get_x(), BLSScalar::zero(), BLSScalar::zero()])
                            [0];
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

        let payees_secrets: Vec<PayeeWitness> = outputs
            .iter()
            .map(|&(amount, asset_type, pubkey_x)| PayeeWitness {
                amount,
                blind: BLSScalar::random(&mut prng),
                asset_type,
                pubkey_x,
            })
            .collect();

        AMultiXfrWitness {
            payers_secrets,
            payees_secrets,
            fee,
        }
    }

    #[test]
    fn test_build_multi_xfr_cs() {
        // fee type.
        let fee_type = BLSScalar::from(1234u32);

        // fee function
        // base fee 5, every input 1, every output 29
        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);

        let pubkey_x = BLSScalar::from(4567u32);

        // single-asset: good witness.
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
            fee_calculating_func(inputs.len(), outputs.len()),
        );

        // single-asset: bad witness.
        outputs[2].0 = 5 + 3 + 2 * 3 - 1;
        let fee = fee_calculating_func(inputs.len(), outputs.len());
        test_xfr_cs(inputs, outputs, false, fee_type, fee);

        // multi-assets api: good witness.
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
            fee_calculating_func(inputs.len(), outputs.len()),
        );

        // bad witness.
        outputs[2].0 = 5 + 3 + 2 * 7 + 100 - 1;
        let fee = fee_calculating_func(inputs.len(), outputs.len());
        test_xfr_cs(inputs, outputs, false, fee_type, fee);
    }

    fn test_xfr_cs(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar, BLSScalar)>,
        witness_is_valid: bool,
        fee_type: BLSScalar,
        fee: u32,
    ) {
        let secret_inputs = new_multi_xfr_witness_for_test(inputs, outputs, fee, [0u8; 32]);
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

        // check the constraints.
        let (mut cs, _) = build_multi_xfr_cs(
            secret_inputs,
            fee_type,
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

    /// Compute the commitment hash for the Merkle tree leaf for an anonymous asset
    fn compute_merkle_leaf_value(uid: u64, abar: &AnonBlindAssetRecord) -> BLSScalar {
        let hash = RescueInstance::new();
        hash.rescue(&[
            BLSScalar::from(uid),
            abar.commitment,
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0]
    }
}
