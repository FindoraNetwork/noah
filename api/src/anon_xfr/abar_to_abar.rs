use crate::anon_xfr::address_folding_ed25519::{
    create_address_folding_ed25519, prepare_verifier_input_ed25519,
    prove_address_folding_in_cs_ed25519, verify_address_folding_ed25519,
};
use crate::anon_xfr::address_folding_secp256k1::{
    create_address_folding_secp256k1, prepare_verifier_input_secp256k1,
    prove_address_folding_in_cs_secp256k1, verify_address_folding_secp256k1,
};
use crate::anon_xfr::{
    add_merkle_path_variables, check_asset_amount, check_inputs, check_roots, commit, commit_in_cs,
    compute_merkle_root_variables, nullify, nullify_in_cs,
    structs::{
        AccElemVars, AnonAssetRecord, AxfrOwnerMemo, Commitment, MTNode, MTPath, Nullifier,
        OpenAnonAssetRecord, PayeeWitness, PayeeWitnessVars, PayerWitness, PayerWitnessVars,
    },
    AXfrAddressFoldingInstance, AXfrAddressFoldingWitness, AXfrPlonkPf, TurboPlonkCS, AMOUNT_LEN,
    FEE_TYPE,
};
use crate::errors::NoahError;
use crate::keys::{KeyPair, PublicKey, PublicKeyInner, SecretKey};
use crate::setup::{ProverParams, VerifierParams};
use digest::{consts::U64, Digest};
use merlin::Transcript;
use noah_algebra::{bls12_381::BLSScalar, prelude::*};
use noah_crypto::basic::anemoi_jive::{
    AnemoiJive, AnemoiJive381, AnemoiVLHTrace, ANEMOI_JIVE_381_SALTS,
};
use noah_plonk::plonk::{
    constraint_system::{TurboCS, VarIndex},
    prover::prover_with_lagrange,
    verifier::verifier,
};
#[cfg(feature = "parallel")]
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

/// The domain separator for anonymous transfer, for the Plonk proof.
const ANON_XFR_PLONK_PROOF_TRANSCRIPT: &[u8] = b"Anon Xfr Plonk Proof";
/// The domain separator for anonymous transfer, for address folding.
const ANON_XFR_FOLDING_PROOF_TRANSCRIPT: &[u8] = b"Anon Xfr Folding Proof";
/// The domain separator for the number of inputs.
const N_INPUTS_TRANSCRIPT: &[u8] = b"Number of input ABARs";
/// The domain separator for the number of outputs.
const N_OUTPUTS_TRANSCRIPT: &[u8] = b"Number of output ABARs";

/// Anonymous transfer note.
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AXfrNote {
    /// The anonymous transfer body.
    pub body: AXfrBody,
    /// The Plonk proof (assuming non-malleability).
    pub proof: AXfrPlonkPf,
    /// The address folding instance.
    pub folding_instance: AXfrAddressFoldingInstance,
}

/// Anonymous transfer pre-note without proofs and signatures.
#[derive(Debug, Clone)]
pub struct AXfrPreNote {
    /// The anonymous transfer body.
    pub body: AXfrBody,
    /// Witness.
    pub witness: AXfrWitness,
    /// The traces of the input commitments.
    pub input_commitments_traces: Vec<AnemoiVLHTrace<BLSScalar, 2, 12>>,
    /// The traces of the output commitments.
    pub output_commitments_traces: Vec<AnemoiVLHTrace<BLSScalar, 2, 12>>,
    /// The traces of the nullifiers.
    pub nullifiers_traces: Vec<AnemoiVLHTrace<BLSScalar, 2, 12>>,
    /// Input key pair.
    pub input_keypair: KeyPair,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
/// Anonymous transfer body.
pub struct AXfrBody {
    /// The inputs, in terms of nullifiers.
    pub inputs: Vec<Nullifier>,
    /// The outputs, in terms of new anonymous asset records.
    pub outputs: Vec<AnonAssetRecord>,
    /// The Merkle tree root.
    pub merkle_root: BLSScalar,
    /// An index of the Merkle tree root in the ledger.
    pub merkle_root_version: u64,
    /// The amount of fee.
    pub fee: u32,
    /// The owner memos.
    pub owner_memos: Vec<AxfrOwnerMemo>,
}

/// Build an anonymous transfer note without generating the proof.
pub fn init_anon_xfr_note(
    inputs: &[OpenAnonAssetRecord],
    outputs: &[OpenAnonAssetRecord],
    fee: u32,
    input_keypair: &KeyPair,
) -> Result<AXfrPreNote> {
    // 1. check input correctness
    if inputs.is_empty() || outputs.is_empty() {
        return Err(eg!(NoahError::AXfrProverParamsError));
    }
    check_inputs(inputs, input_keypair).c(d!())?;
    check_asset_amount(inputs, outputs, fee).c(d!())?;
    check_roots(inputs).c(d!())?;

    // 2. build input witness information
    let mut nullifiers = Vec::new();
    let mut nullifiers_traces = Vec::new();
    let mut input_commitments_traces = Vec::new();

    inputs.iter().for_each(|input| {
        let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();

        let (nullifier, nullifier_trace) = nullify(
            input_keypair,
            input.amount,
            input.asset_type.as_scalar(),
            mt_leaf_info.uid,
        )
        .unwrap();

        nullifiers.push(nullifier);
        nullifiers_traces.push(nullifier_trace);

        let (_, commitment_trace) = commit(
            &input_keypair.get_pk(),
            input.blind,
            input.amount,
            input.asset_type.as_scalar(),
        )
        .unwrap();

        input_commitments_traces.push(commitment_trace);
    });

    // 3. build proof
    let payers_secrets = inputs
        .iter()
        .map(|input| {
            let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();
            PayerWitness {
                secret_key: input_keypair.get_sk(),
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
            public_key: output.pub_key,
        })
        .collect();

    let secret_inputs = AXfrWitness {
        payers_witnesses: payers_secrets,
        payees_witnesses: payees_secrets,
        fee,
    };
    let out_abars = outputs
        .iter()
        .map(AnonAssetRecord::from_oabar)
        .collect_vec();
    let out_memos: Result<Vec<AxfrOwnerMemo>> = outputs
        .iter()
        .map(|output| output.owner_memo.clone().c(d!(NoahError::ParameterError)))
        .collect();

    let output_commitments_traces: Vec<AnemoiVLHTrace<BLSScalar, 2, 12>> = outputs
        .iter()
        .map(|output| {
            let (_, commitment_trace) = commit(
                &output.pub_key,
                output.blind,
                output.amount,
                output.asset_type.as_scalar(),
            )
            .unwrap();

            commitment_trace
        })
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

    Ok(AXfrPreNote {
        body,
        witness: secret_inputs,
        input_commitments_traces,
        output_commitments_traces,
        nullifiers_traces,
        input_keypair: input_keypair.clone(),
    })
}

/// Build an anonymous transfer note without generating the proof.
pub fn finish_anon_xfr_note<R: CryptoRng + RngCore, D: Digest<OutputSize = U64> + Default>(
    prng: &mut R,
    params: &ProverParams,
    pre_note: AXfrPreNote,
    hash: D,
) -> Result<AXfrNote> {
    let AXfrPreNote {
        body,
        witness,
        input_commitments_traces,
        output_commitments_traces,
        nullifiers_traces,
        input_keypair,
    } = pre_note;

    let mut transcript = Transcript::new(ANON_XFR_FOLDING_PROOF_TRANSCRIPT);

    let (folding_instance, folding_witness) = match input_keypair.get_sk_ref() {
        SecretKey::Secp256k1(_) => {
            let (folding_instance, folding_witness) =
                create_address_folding_secp256k1(prng, hash, &mut transcript, &input_keypair)?;
            (
                AXfrAddressFoldingInstance::Secp256k1(folding_instance),
                AXfrAddressFoldingWitness::Secp256k1(folding_witness),
            )
        }
        SecretKey::Ed25519(_) => {
            let (folding_instance, folding_witness) =
                create_address_folding_ed25519(prng, hash, &mut transcript, &input_keypair)?;
            (
                AXfrAddressFoldingInstance::Ed25519(folding_instance),
                AXfrAddressFoldingWitness::Ed25519(folding_witness),
            )
        }
    };

    let proof = prove_xfr(
        prng,
        params,
        &witness,
        &nullifiers_traces,
        &input_commitments_traces,
        &output_commitments_traces,
        &folding_witness,
    )
    .c(d!())?;

    Ok(AXfrNote {
        body,
        proof,
        folding_instance,
    })
}

/// Verify an anonymous transfer note.
pub fn verify_anon_xfr_note<D: Digest<OutputSize = U64> + Default>(
    params: &VerifierParams,
    note: &AXfrNote,
    merkle_root: &BLSScalar,
    hash: D,
) -> Result<()> {
    if *merkle_root != note.body.merkle_root {
        return Err(eg!(NoahError::AXfrVerificationError));
    }
    let payees_commitments = note
        .body
        .outputs
        .iter()
        .map(|output| output.commitment)
        .collect();
    let pub_inputs = AXfrPubInputs {
        payers_inputs: note.body.inputs.clone(),
        payees_commitments,
        merkle_root: *merkle_root,
        fee: note.body.fee,
    };

    let mut transcript = Transcript::new(ANON_XFR_FOLDING_PROOF_TRANSCRIPT);

    let address_folding_public_input = match &note.folding_instance {
        AXfrAddressFoldingInstance::Secp256k1(a) => {
            let (beta, lambda) = verify_address_folding_secp256k1(hash, &mut transcript, a)?;
            prepare_verifier_input_secp256k1(&a, &beta, &lambda)
        }
        AXfrAddressFoldingInstance::Ed25519(a) => {
            let (beta, lambda) = verify_address_folding_ed25519(hash, &mut transcript, a)?;
            prepare_verifier_input_ed25519(&a, &beta, &lambda)
        }
    };

    verify_xfr(
        params,
        &pub_inputs,
        &note.proof,
        &address_folding_public_input,
        &note.folding_instance,
    )
    .c(d!(NoahError::AXfrVerificationError))
}

/// Batch verify the anonymous transfer notes.
/// Note: this function assumes that the correctness of the Merkle roots has been checked outside.
#[cfg(feature = "parallel")]
pub fn batch_verify_anon_xfr_note<D: Digest<OutputSize = U64> + Default + Sync + Send>(
    params: &[&VerifierParams],
    notes: &[&AXfrNote],
    merkle_roots: &[&BLSScalar],
    hashes: Vec<D>,
) -> Result<()> {
    if merkle_roots
        .par_iter()
        .zip(notes)
        .any(|(x, y)| **x != y.body.merkle_root)
    {
        return Err(eg!(NoahError::AXfrVerificationError));
    }

    let is_ok = params
        .par_iter()
        .zip(notes)
        .zip(merkle_roots)
        .zip(hashes)
        .map(|(((param, note), merkle_root), hash)| {
            let payees_commitments = note
                .body
                .outputs
                .iter()
                .map(|output| output.commitment)
                .collect();
            let pub_inputs = AXfrPubInputs {
                payers_inputs: note.body.inputs.clone(),
                payees_commitments,
                merkle_root: **merkle_root,
                fee: note.body.fee,
            };

            let mut transcript = Transcript::new(ANON_XFR_FOLDING_PROOF_TRANSCRIPT);

            let address_folding_public_input = match &note.folding_instance {
                AXfrAddressFoldingInstance::Secp256k1(a) => {
                    let (beta, lambda) =
                        verify_address_folding_secp256k1(hash, &mut transcript, a)?;
                    prepare_verifier_input_secp256k1(&a, &beta, &lambda)
                }
                AXfrAddressFoldingInstance::Ed25519(a) => {
                    let (beta, lambda) = verify_address_folding_ed25519(hash, &mut transcript, a)?;
                    prepare_verifier_input_ed25519(&a, &beta, &lambda)
                }
            };

            verify_xfr(
                *param,
                &pub_inputs,
                &note.proof,
                &address_folding_public_input,
                &note.folding_instance,
            )
        })
        .all(|x| x.is_ok());

    if is_ok {
        Ok(())
    } else {
        Err(eg!(NoahError::AXfrVerificationError))
    }
}

/// Generate a Plonk proof for anonymous transfer.
pub(crate) fn prove_xfr<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    secret_inputs: &AXfrWitness,
    nullifiers_traces: &[AnemoiVLHTrace<BLSScalar, 2, 12>],
    input_commitments_traces: &[AnemoiVLHTrace<BLSScalar, 2, 12>],
    output_commitments_traces: &[AnemoiVLHTrace<BLSScalar, 2, 12>],
    folding_witness: &AXfrAddressFoldingWitness,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(ANON_XFR_PLONK_PROOF_TRANSCRIPT);
    transcript.append_u64(
        N_INPUTS_TRANSCRIPT,
        secret_inputs.payers_witnesses.len() as u64,
    );
    transcript.append_u64(
        N_OUTPUTS_TRANSCRIPT,
        secret_inputs.payees_witnesses.len() as u64,
    );

    let fee_type = FEE_TYPE.as_scalar();
    let (mut cs, _) = build_multi_xfr_cs(
        secret_inputs,
        fee_type,
        nullifiers_traces,
        input_commitments_traces,
        output_commitments_traces,
        &folding_witness,
    );
    let witness = cs.get_and_clear_witness();

    let (cs, prover_params) = params.cs_params(Some(folding_witness));

    prover_with_lagrange(
        rng,
        &mut transcript,
        &params.pcs,
        params.lagrange_pcs.as_ref(),
        cs,
        prover_params,
        &witness,
    )
    .c(d!(NoahError::AXfrProofError))
}

/// Verify a Plonk proof for anonymous transfer.
pub(crate) fn verify_xfr(
    params: &VerifierParams,
    pub_inputs: &AXfrPubInputs,
    proof: &AXfrPlonkPf,
    address_folding_public_input: &Vec<BLSScalar>,
    folding_instance: &AXfrAddressFoldingInstance,
) -> Result<()> {
    let mut transcript = Transcript::new(ANON_XFR_PLONK_PROOF_TRANSCRIPT);
    transcript.append_u64(N_INPUTS_TRANSCRIPT, pub_inputs.payers_inputs.len() as u64);
    transcript.append_u64(
        N_OUTPUTS_TRANSCRIPT,
        pub_inputs.payees_commitments.len() as u64,
    );

    let mut online_inputs = pub_inputs.to_vec();
    online_inputs.extend_from_slice(address_folding_public_input);

    let (cs, verifier_params) = params.cs_params(Some(folding_instance));

    verifier(
        &mut transcript,
        &params.pcs,
        &cs,
        verifier_params,
        &online_inputs,
        proof,
    )
    .c(d!(NoahError::ZKProofVerificationError))
}

/// The witness of an anonymous transfer.
#[derive(Debug, Clone)]
pub struct AXfrWitness {
    /// The payers' witnesses.
    pub payers_witnesses: Vec<PayerWitness>,
    /// The payees' witnesses.
    pub payees_witnesses: Vec<PayeeWitness>,
    /// The fee.
    pub fee: u32,
}

impl AXfrWitness {
    /// Create a fake `AXfrWitness` for testing.
    pub fn fake_secp256k1(n_payers: usize, n_payees: usize, tree_depth: usize, fee: u32) -> Self {
        let bls_zero = BLSScalar::zero();

        let node = MTNode {
            left: bls_zero,
            mid: bls_zero,
            right: bls_zero,
            is_left_child: 0,
            is_mid_child: 0,
            is_right_child: 0,
        };
        let payer_witness = PayerWitness {
            secret_key: SecretKey::default_secp256k1(),
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };
        let payee_witness = PayeeWitness {
            amount: 0,
            blind: bls_zero,
            asset_type: bls_zero,
            public_key: PublicKey::default_secp256k1(),
        };

        AXfrWitness {
            payers_witnesses: vec![payer_witness; n_payers],
            payees_witnesses: vec![payee_witness; n_payees],
            fee,
        }
    }

    /// Create a fake `AXfrWitness` for testing.
    pub fn fake_ed25519(n_payers: usize, n_payees: usize, tree_depth: usize, fee: u32) -> Self {
        let bls_zero = BLSScalar::zero();

        let node = MTNode {
            left: bls_zero,
            mid: bls_zero,
            right: bls_zero,
            is_left_child: 0,
            is_mid_child: 0,
            is_right_child: 0,
        };
        let payer_witness = PayerWitness {
            secret_key: SecretKey::default_ed25519(),
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };
        let payee_witness = PayeeWitness {
            amount: 0,
            blind: bls_zero,
            asset_type: bls_zero,
            public_key: PublicKey::default_ed25519(),
        };

        AXfrWitness {
            payers_witnesses: vec![payer_witness; n_payers],
            payees_witnesses: vec![payee_witness; n_payees],
            fee,
        }
    }
}

/// Public inputs of an anonymous transfer.
#[derive(Debug)]
pub struct AXfrPubInputs {
    /// The payers' inputs.
    pub payers_inputs: Vec<Nullifier>,
    /// The payees' commitments.
    pub payees_commitments: Vec<Commitment>,
    /// The Merkle tree root.
    pub merkle_root: BLSScalar,
    /// The fee.
    pub fee: u32,
}

impl AXfrPubInputs {
    /// Convert the public inputs into a vector of scalars.
    pub fn to_vec(&self) -> Vec<BLSScalar> {
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

    /// Convert from the witness.
    pub fn from_witness(witness: &AXfrWitness) -> Self {
        let payers_inputs: Vec<Nullifier> = witness
            .payers_witnesses
            .iter()
            .map(|sec| {
                let keypair = sec.secret_key.clone().into_keypair();
                let (hash, _) = nullify(&keypair, sec.amount, sec.asset_type, sec.uid).unwrap();

                hash
            })
            .collect();

        let zero = BLSScalar::zero();
        let payees_commitments: Vec<Commitment> = witness
            .payees_witnesses
            .iter()
            .map(|sec| {
                let public_key_scalars = sec.public_key.to_bls_scalars().unwrap();
                AnemoiJive381::eval_variable_length_hash(&[
                    zero, /* protocol version number */
                    sec.blind,
                    BLSScalar::from(sec.amount),
                    sec.asset_type,
                    zero, /* address format */
                    public_key_scalars[0],
                    public_key_scalars[1],
                    public_key_scalars[2],
                ])
            })
            .collect();

        let payer = &witness.payers_witnesses[0];

        let node = payer.path.nodes.last().unwrap();
        let merkle_root = AnemoiJive381::eval_jive(
            &[node.left, node.mid],
            &[
                node.right,
                ANEMOI_JIVE_381_SALTS[payer.path.nodes.len() - 1],
            ],
        );

        Self {
            payers_inputs,
            payees_commitments,
            merkle_root,
            fee: witness.fee,
        }
    }
}

/// Instantiate the constraint system for anonymous transfer.
pub(crate) fn build_multi_xfr_cs(
    witness: &AXfrWitness,
    fee_type: BLSScalar,
    nullifiers_traces: &[AnemoiVLHTrace<BLSScalar, 2, 12>],
    input_commitments_traces: &[AnemoiVLHTrace<BLSScalar, 2, 12>],
    output_commitments_traces: &[AnemoiVLHTrace<BLSScalar, 2, 12>],
    folding_witness: &AXfrAddressFoldingWitness,
) -> (TurboPlonkCS, usize) {
    assert_ne!(witness.payers_witnesses.len(), 0);
    assert_ne!(witness.payees_witnesses.len(), 0);

    let mut cs = TurboCS::new();

    cs.load_anemoi_jive_parameters::<AnemoiJive381>();

    let payers_secrets =
        add_payers_witnesses(&mut cs, &witness.payers_witnesses.iter().collect_vec());
    let payees_secrets = add_payees_witnesses(&mut cs, &witness.payees_witnesses);

    let keypair = folding_witness.keypair();
    let public_key_scalars = keypair.get_pk().to_bls_scalars().unwrap();
    let secret_key_scalars = keypair.get_sk().to_bls_scalars().unwrap();

    let public_key_scalars_vars = [
        cs.new_variable(public_key_scalars[0]),
        cs.new_variable(public_key_scalars[1]),
        cs.new_variable(public_key_scalars[2]),
    ];
    let secret_key_scalars_vars = [
        cs.new_variable(secret_key_scalars[0]),
        cs.new_variable(secret_key_scalars[1]),
    ];

    let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::one());
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let zero_var = cs.zero_var();
    let mut root_var: Option<VarIndex> = None;

    let secret_key_type = match keypair.get_sk_ref() {
        SecretKey::Ed25519(_) => BLSScalar::one(),
        SecretKey::Secp256k1(_) => BLSScalar::zero(),
    };
    let secret_key_type_var = cs.new_variable(secret_key_type);
    cs.insert_boolean_gate(secret_key_type_var);

    for (((payer_witness_var, input_commitment_trace), nullifier_trace), payer_witness) in
        payers_secrets
            .iter()
            .zip(input_commitments_traces.iter())
            .zip(nullifiers_traces.iter())
            .zip(witness.payers_witnesses.iter())
    {
        // commitments.
        let com_abar_in_var = commit_in_cs(
            &mut cs,
            payer_witness_var.blind,
            payer_witness_var.amount,
            payer_witness_var.asset_type,
            secret_key_type_var,
            &public_key_scalars_vars,
            &input_commitment_trace,
        );

        // prove pre-image of the nullifier.
        // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`.
        let uid_amount = cs.linear_combine(
            &[
                payer_witness_var.uid,
                payer_witness_var.amount,
                zero_var,
                zero_var,
            ],
            pow_2_64,
            one,
            zero,
            zero,
        );
        let nullifier_var = nullify_in_cs(
            &mut cs,
            &secret_key_scalars_vars,
            uid_amount,
            payer_witness_var.asset_type,
            secret_key_type_var,
            &public_key_scalars_vars,
            nullifier_trace,
        );

        // Merkle path authentication.
        let acc_elem = AccElemVars {
            uid: payer_witness_var.uid,
            commitment: com_abar_in_var,
        };
        let mut path_traces = Vec::new();
        let (commitment, _) = commit(
            &keypair.get_pk(),
            payer_witness.blind,
            payer_witness.amount,
            payer_witness.asset_type,
        )
        .unwrap();
        let leaf_trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[
            BLSScalar::from(payer_witness.uid),
            commitment,
        ]);
        for (i, mt_node) in payer_witness.path.nodes.iter().enumerate() {
            let trace = AnemoiJive381::eval_jive_with_trace(
                &[mt_node.left, mt_node.mid],
                &[mt_node.right, ANEMOI_JIVE_381_SALTS[i]],
            );
            path_traces.push(trace);
        }
        let tmp_root_var = compute_merkle_root_variables(
            &mut cs,
            acc_elem,
            &payer_witness_var.path,
            &leaf_trace,
            &path_traces,
        );

        // additional safegaurd to check the payer's amount, although in theory this is not needed.
        cs.range_check(payer_witness_var.amount, AMOUNT_LEN);

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

    for (payee, output_commitment_trace) in
        payees_secrets.iter().zip(output_commitments_traces.iter())
    {
        // commitment.
        let com_abar_out_var = commit_in_cs(
            &mut cs,
            payee.blind,
            payee.amount,
            payee.asset_type,
            payee.public_key_type,
            &payee.public_key_scalars,
            &output_commitment_trace,
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

    match folding_witness {
        AXfrAddressFoldingWitness::Secp256k1(a) => prove_address_folding_in_cs_secp256k1(
            &mut cs,
            &public_key_scalars_vars,
            &secret_key_scalars_vars,
            &a,
        )
        .unwrap(),
        AXfrAddressFoldingWitness::Ed25519(a) => prove_address_folding_in_cs_ed25519(
            &mut cs,
            &public_key_scalars_vars,
            &secret_key_scalars_vars,
            &a,
        )
        .unwrap(),
    }

    if inputs.len() == 1 {
        asset_summing(&mut cs, &inputs, &outputs, fee_type, fee_var);
    } else {
        asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);
    }

    // pad the number of constraints to power of two.
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

/// Enforce asset_summing constraints:
/// Input = [(type, v_in)], `values {v_in}` is guaranteed to be positive.
/// Outputs = [(type, v_out_1), ..., (type, v_out_m)], `values {v_out_j}` are guaranteed to be positive.
/// Fee parameters = `fee_type` and `fee_calculating func`
///
/// Goal:
/// - Prove that all the types are the same.
/// - If the asset type is not `fee_type`, the input = the outputs sum, and the `fee` is zero.
/// - Otherwise, the input = the outputs sum + fee.
///
pub fn asset_summing(
    cs: &mut TurboPlonkCS,
    inputs: &[(VarIndex, VarIndex)],
    outputs: &[(VarIndex, VarIndex)],
    fee_type: BLSScalar,
    fee_var: VarIndex,
) {
    assert_eq!(inputs.len(), 1);
    assert!(outputs.len() >= 1);

    // Prove that all the types are the same.
    for output in outputs.iter() {
        cs.equal(inputs[0].0, output.0);
    }

    // Compute the sum of the outputs.
    let zero_var = cs.zero_var();
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();

    let mut acc = outputs[0].1;
    for chunk in outputs[1..].chunks(3) {
        let len = chunk.len();
        if len == 1 {
            acc = cs.linear_combine(&[acc, chunk[0].1, zero_var, zero_var], one, one, zero, zero);
        } else if len == 2 {
            acc = cs.linear_combine(
                &[acc, chunk[0].1, chunk[1].1, zero_var],
                one,
                one,
                one,
                zero,
            );
        } else if len == 3 {
            acc = cs.linear_combine(
                &[acc, chunk[0].1, chunk[1].1, chunk[2].1],
                one,
                one,
                one,
                one,
            );
        }
    }

    // Check that either the fee type is the type, or that the fee is zero
    // (fee_type - type) * fee = 0
    // i.e., type * fee = fee_type * fee
    cs.push_add_selectors(fee_type.neg(), zero, zero, zero);
    cs.push_mul_selectors(one, zero);
    cs.push_constant_selector(zero);
    cs.push_ecc_selector(zero);
    cs.push_out_selector(zero);

    cs.wiring[0].push(fee_var);
    cs.wiring[1].push(inputs[0].0);
    cs.wiring[2].push(zero_var);
    cs.wiring[3].push(zero_var);
    cs.wiring[4].push(zero_var);
    cs.finish_new_gate();

    // Check that input = output + fee
    cs.insert_add_gate(fee_var, acc, inputs[0].1);
}

/// Enforce asset_mixing constraints:
/// Inputs = [(type_in_1, v_in_1), ..., (type_in_n, v_in_n)], `values {v_in_i}` are guaranteed to be positive.
/// Outputs = [(type_out_1, v_out_1), ..., (type_out_m, v_out_m)], `values {v_out_j}` are guaranteed to be positive.
/// Fee parameters = `fee_type` and `fee`
///
/// Goal:
/// - Prove that for every asset type except `fee_type`, the corresponding inputs sum equals the corresponding outputs sum.
/// - Prove that for every asset type that equals `fee_type`, the inputs sum = the outputs sum + fee
/// - Prove that either at least one input is of type `fee_type`, or the `fee` is zero.
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
/// This function does not scale well with large amounts of asset types.
///
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

    let zero_var = cs.zero_var();
    cs.insert_mul_gate(flag_no_fee_type, fee_var, zero_var);

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
    secrets: &[&PayerWitness],
) -> Vec<PayerWitnessVars> {
    secrets
        .iter()
        .map(|secret| {
            let uid = cs.new_variable(BLSScalar::from(secret.uid));
            let amount = cs.new_variable(BLSScalar::from(secret.amount));
            let blind = cs.new_variable(secret.blind);
            let path = add_merkle_path_variables(cs, secret.path.clone());
            let asset_type = cs.new_variable(secret.asset_type);
            PayerWitnessVars {
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

            let public_key_scalars = secret.public_key.to_bls_scalars().unwrap();
            let public_key_scalars_vars = [
                cs.new_variable(public_key_scalars[0]),
                cs.new_variable(public_key_scalars[1]),
                cs.new_variable(public_key_scalars[2]),
            ];

            let public_key_type = match secret.public_key.0 {
                PublicKeyInner::Ed25519(_) => cs.new_variable(BLSScalar::one()),
                PublicKeyInner::Secp256k1(_) => cs.new_variable(BLSScalar::zero()),
                PublicKeyInner::EthAddress(_) => unimplemented!(),
            };

            PayeeWitnessVars {
                amount,
                blind,
                asset_type,
                public_key_type,
                public_key_scalars: public_key_scalars_vars,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::abar_to_abar::{
        finish_anon_xfr_note, init_anon_xfr_note, AXfrNote, ANON_XFR_FOLDING_PROOF_TRANSCRIPT,
    };
    use crate::anon_xfr::address_folding_secp256k1::{
        create_address_folding_secp256k1, prepare_verifier_input_secp256k1,
        verify_address_folding_secp256k1,
    };
    use crate::anon_xfr::{
        abar_to_abar::{
            asset_mixing, build_multi_xfr_cs, verify_anon_xfr_note, AXfrPubInputs, AXfrWitness,
        },
        add_merkle_path_variables, check_merkle_tree_validity, commit, commit_in_cs,
        compute_merkle_root_variables, nullify, nullify_in_cs,
        structs::{
            AccElemVars, AnonAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonAssetRecord,
            OpenAnonAssetRecordBuilder, PayeeWitness, PayerWitness,
        },
        AXfrAddressFoldingWitness, FEE_TYPE,
    };
    use crate::keys::KeyPair;
    use crate::setup::{ProverParams, VerifierParams};
    use crate::xfr::structs::AssetType;
    use digest::{consts::U64, Digest};
    use merlin::Transcript;
    use noah_algebra::{bls12_381::BLSScalar, prelude::*};
    use noah_crypto::basic::anemoi_jive::{
        AnemoiJive, AnemoiJive381, AnemoiVLHTrace, ANEMOI_JIVE_381_SALTS,
    };
    use noah_plonk::plonk::constraint_system::{TurboCS, VarIndex};
    use sha2::Sha512;

    fn gen_keys<R: CryptoRng + RngCore>(prng: &mut R, n: usize) -> Vec<KeyPair> {
        (0..n).map(|_| KeyPair::generate_secp256k1(prng)).collect()
    }

    fn gen_oabar_with_key<R: CryptoRng + RngCore>(
        prng: &mut R,
        amount: u64,
        asset_type: AssetType,
        keypair: &KeyPair,
    ) -> OpenAnonAssetRecord {
        let oabar = OpenAnonAssetRecordBuilder::new()
            .amount(amount)
            .asset_type(asset_type)
            .pub_key(&keypair.get_pk())
            .finalize(prng)
            .unwrap()
            .build()
            .unwrap();
        oabar
    }

    /// Helper function that resembles the original `gen_anon_xfr_note`
    fn gen_anon_xfr_note<R: CryptoRng + RngCore, D: Digest<OutputSize = U64> + Default>(
        prng: &mut R,
        params: &ProverParams,
        inputs: &[OpenAnonAssetRecord],
        outputs: &[OpenAnonAssetRecord],
        fee: u32,
        input_keypair: &KeyPair,
        hash: D,
    ) -> Result<AXfrNote> {
        let pre_note = init_anon_xfr_note(inputs, outputs, fee, input_keypair)?;
        let note = finish_anon_xfr_note(prng, params, pre_note, hash)?;
        Ok(note)
    }

    fn new_multi_xfr_witness_for_test(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar)>,
        fee: u32,
    ) -> (AXfrWitness, KeyPair) {
        let n_payers = inputs.len();
        assert!(n_payers <= 3);
        let mut prng = test_rng();
        let zero = BLSScalar::zero();

        let input_keypair = KeyPair::generate_secp256k1(&mut prng);

        let mut payers_secrets: Vec<PayerWitness> = inputs
            .iter()
            .enumerate()
            .map(|(i, &(amount, asset_type))| {
                let (is_left_child, is_mid_child, is_right_child) = match i % 3 {
                    0 => (1, 0, 0),
                    1 => (0, 1, 0),
                    _ => (0, 0, 1),
                };
                let blind = BLSScalar::random(&mut prng);

                let (commitment, _) =
                    commit(&input_keypair.get_pk(), blind, amount, asset_type).unwrap();

                let mut left = zero;
                let mut mid = zero;
                let mut right = zero;

                if is_left_child == 1 {
                    left = commitment;
                } else if is_right_child == 1 {
                    right = commitment;
                } else {
                    mid = commitment;
                }

                let node = MTNode {
                    left,
                    mid,
                    right,
                    is_left_child,
                    is_mid_child,
                    is_right_child,
                };
                PayerWitness {
                    secret_key: input_keypair.get_sk(),
                    uid: i as u64,
                    amount,
                    asset_type,
                    path: MTPath::new(vec![node]),
                    blind,
                }
            })
            .collect();

        let public_key = input_keypair.get_pk();

        // compute the merkle leaves and update the merkle paths if there are more than 1 payers.
        if n_payers > 1 {
            let leafs: Vec<BLSScalar> = payers_secrets
                .iter()
                .map(|payer| {
                    let (commitment, _) =
                        commit(&public_key, payer.blind, payer.amount, payer.asset_type).unwrap();
                    AnemoiJive381::eval_variable_length_hash(&[
                        BLSScalar::from(payer.uid),
                        commitment,
                    ])
                })
                .collect();
            payers_secrets[0].path.nodes[0].left = leafs[0];
            payers_secrets[0].path.nodes[0].mid = leafs[1];
            if n_payers == 2 {
                payers_secrets[0].path.nodes[0].right = zero;
                payers_secrets[1].path.nodes[0].left = leafs[0];
                payers_secrets[1].path.nodes[0].mid = leafs[1];
                payers_secrets[1].path.nodes[0].right = zero;
            } else {
                payers_secrets[0].path.nodes[0].right = leafs[2];
                payers_secrets[1].path.nodes[0].left = leafs[0];
                payers_secrets[1].path.nodes[0].mid = leafs[1];
                payers_secrets[1].path.nodes[0].right = leafs[2];
                payers_secrets[2].path.nodes[0].left = leafs[0];
                payers_secrets[2].path.nodes[0].mid = leafs[1];
                payers_secrets[2].path.nodes[0].right = leafs[2];
            }
        }

        let payees_secrets: Vec<PayeeWitness> = outputs
            .iter()
            .map(|&(amount, asset_type)| PayeeWitness {
                amount,
                blind: BLSScalar::random(&mut prng),
                asset_type,
                public_key: KeyPair::generate_secp256k1(&mut prng).get_pk(),
            })
            .collect();

        (
            AXfrWitness {
                payers_witnesses: payers_secrets,
                payees_witnesses: payees_secrets,
                fee,
            },
            input_keypair,
        )
    }

    #[test]
    fn test_anon_xfr() {
        let mut prng = test_rng();

        let user_params = ProverParams::new(1, 1, Some(1)).unwrap();
        let one = BLSScalar::one();
        let two = one.add(&one);

        let asset_type = FEE_TYPE;
        let fee_amount = 65u32;

        let output_amount = 1 + prng.next_u64() % 100;
        let input_amount = output_amount + fee_amount as u64;

        let keypair = KeyPair::generate_secp256k1(&mut prng);

        // sample an input anonymous asset record for testing.
        let oabar = gen_oabar_with_key(&mut prng, input_amount, asset_type, &keypair);
        let abar = AnonAssetRecord::from_oabar(&oabar);
        assert_eq!(keypair.get_pk(), *oabar.pub_key_ref());

        let leaf = AnemoiJive381::eval_variable_length_hash(&[/*uid=*/ two, abar.commitment]);

        // simulate Merkle tree state with that input record for testing.
        let node = MTNode {
            left: one,
            mid: two,
            right: leaf,
            is_left_child: 0u8,
            is_mid_child: 0u8,
            is_right_child: 1u8,
        };

        let merkle_root = AnemoiJive381::eval_jive(
            &[/*sib1[0]=*/ one, /*sib2[0]=*/ two],
            &[leaf, ANEMOI_JIVE_381_SALTS[0]],
        );

        let mt_leaf_info = MTLeafInfo {
            path: MTPath::new(vec![node]),
            root: merkle_root,
            uid: 2,
            root_version: 0,
        };

        // sample output keys for testing.
        let keypair_out = KeyPair::generate_secp256k1(&mut prng);

        let test_hash = {
            let mut hasher = Sha512::new();
            let mut random_bytes = [0u8; 32];
            prng.fill_bytes(&mut random_bytes);
            hasher.update(&random_bytes);
            hasher
        };

        let (note, merkle_root) = {
            // prover scope
            let owner_memo = oabar.get_owner_memo().unwrap();
            let oabar_in = OpenAnonAssetRecordBuilder::from_abar(&abar, owner_memo, &keypair)
                .unwrap()
                .mt_leaf_info(mt_leaf_info)
                .build()
                .unwrap();
            assert_eq!(input_amount, oabar_in.get_amount());
            assert_eq!(asset_type, oabar_in.get_asset_type());
            assert_eq!(keypair.get_pk(), oabar_in.pub_key);

            let oabar_out = OpenAnonAssetRecordBuilder::new()
                .amount(output_amount)
                .asset_type(asset_type)
                .pub_key(&keypair_out.get_pk())
                .finalize(&mut prng)
                .unwrap()
                .build()
                .unwrap();

            let note = gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &[oabar_in],
                &[oabar_out],
                fee_amount,
                &keypair,
                test_hash.clone(),
            )
            .unwrap();
            (note, merkle_root)
        };
        {
            // owner scope
            let oabar = OpenAnonAssetRecordBuilder::from_abar(
                &note.body.outputs[0],
                note.body.owner_memos[0].clone(),
                &keypair_out,
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
            assert!(
                verify_anon_xfr_note(&verifier_params, &note, &merkle_root, test_hash.clone())
                    .is_ok()
            );
        }
    }

    #[test]
    fn test_anon_xfr_multi_assets() {
        let mut prng = test_rng();
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
        let in_keypair = KeyPair::generate_secp256k1(&mut prng);
        let mut in_owner_memos = vec![];
        for i in 0..n_payers {
            let oabar =
                gen_oabar_with_key(&mut prng, amounts_in[i], asset_types_in[i], &in_keypair);
            let abar = AnonAssetRecord::from_oabar(&oabar);
            let owner_memo = oabar.get_owner_memo().unwrap();
            in_abars.push(abar);
            in_owner_memos.push(owner_memo);
        }

        let test_hash = {
            let mut hasher = Sha512::new();
            let mut random_bytes = [0u8; 32];
            prng.fill_bytes(&mut random_bytes);
            hasher.update(&random_bytes);
            hasher
        };

        // simulate Merkle tree state with these inputs for testing.
        let leafs: Vec<BLSScalar> = in_abars
            .iter()
            .enumerate()
            .map(|(uid, in_abar)| {
                AnemoiJive381::eval_variable_length_hash(&[
                    BLSScalar::from(uid as u32),
                    in_abar.commitment,
                ])
            })
            .collect();
        let node0 = MTNode {
            left: leafs[0],
            mid: leafs[1],
            right: leafs[2],
            is_left_child: 1u8,
            is_mid_child: 0u8,
            is_right_child: 0u8,
        };
        let node1 = MTNode {
            left: leafs[0],
            mid: leafs[1],
            right: leafs[2],
            is_left_child: 0u8,
            is_mid_child: 1u8,
            is_right_child: 0u8,
        };
        let node2 = MTNode {
            left: leafs[0],
            mid: leafs[1],
            right: leafs[2],
            is_left_child: 0u8,
            is_mid_child: 0u8,
            is_right_child: 1u8,
        };
        let nodes = vec![node0, node1, node2];
        let merkle_root =
            AnemoiJive381::eval_jive(&[leafs[0], leafs[1]], &[leafs[2], ANEMOI_JIVE_381_SALTS[0]]);

        // generate some output records for testing.
        let keypairs_out = gen_keys(&mut prng, n_payees);
        let amounts_out = vec![5u64, 5u64, 50u64];
        let asset_types_out = vec![FEE_TYPE, FEE_TYPE, AssetType::from_identical_byte(1)];
        let mut outputs = vec![];
        for i in 0..n_payees {
            outputs.push(
                OpenAnonAssetRecordBuilder::new()
                    .amount(amounts_out[i])
                    .asset_type(asset_types_out[i])
                    .pub_key(&keypairs_out[i].get_pk())
                    .finalize(&mut prng)
                    .unwrap()
                    .build()
                    .unwrap(),
            );
        }

        let (note, merkle_root) = {
            // prover scope
            let mut open_abars_in: Vec<OpenAnonAssetRecord> = (0..n_payers)
                .map(|uid| {
                    let mt_leaf_info = MTLeafInfo {
                        path: MTPath {
                            nodes: vec![nodes[uid].clone()],
                        },
                        root: merkle_root,
                        uid: uid as u64,
                        root_version: 0,
                    };
                    let open_abar_in = OpenAnonAssetRecordBuilder::from_abar(
                        &in_abars[uid],
                        in_owner_memos[uid].clone(),
                        &in_keypair,
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
                    OpenAnonAssetRecordBuilder::new()
                        .amount(amounts_out[i])
                        .asset_type(asset_types_out[i])
                        .pub_key(&keypairs_out[i].get_pk())
                        .finalize(&mut prng)
                        .unwrap()
                        .build()
                        .unwrap()
                })
                .collect_vec();

            // empty inputs/outputs
            msg_eq!(
                NoahError::AXfrProverParamsError,
                gen_anon_xfr_note(
                    &mut prng,
                    &user_params,
                    &[],
                    &open_abars_out,
                    15,
                    &in_keypair,
                    test_hash.clone()
                )
                .unwrap_err(),
            );
            msg_eq!(
                NoahError::AXfrProverParamsError,
                gen_anon_xfr_note(
                    &mut prng,
                    &user_params,
                    &open_abars_in,
                    &[],
                    15,
                    &in_keypair,
                    test_hash.clone()
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
                &in_keypair,
                test_hash.clone()
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
                &in_keypair,
                test_hash.clone()
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
                &in_keypair,
                test_hash.clone(),
            )
            .unwrap();
            (note, merkle_root)
        };
        {
            // owner scope
            for i in 0..n_payees {
                let oabar_out = OpenAnonAssetRecordBuilder::from_abar(
                    &note.body.outputs[i],
                    note.body.owner_memos[i].clone(),
                    &keypairs_out[i],
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
            assert!(
                verify_anon_xfr_note(&verifier_params, &note, &merkle_root, test_hash.clone())
                    .is_ok()
            );
            // inconsistent merkle roots
            assert!(
                verify_anon_xfr_note(&verifier_params, &note, &zero, test_hash.clone()).is_err()
            );
        }
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
        cs.load_anemoi_jive_parameters::<AnemoiJive381>();
        let amount = BLSScalar::from(7u32);
        let asset_type = BLSScalar::from(5u32);
        let mut prng = test_rng();
        let blind = BLSScalar::random(&mut prng);

        let keypair = KeyPair::generate_secp256k1(&mut prng);

        let public_key_scalars = keypair.pub_key.to_bls_scalars().unwrap();
        let public_key_scalars_vars = [
            cs.new_variable(public_key_scalars[0]),
            cs.new_variable(public_key_scalars[1]),
            cs.new_variable(public_key_scalars[2]),
        ];

        let (commitment, input_commitment_trace) =
            commit(&keypair.get_pk(), blind, 7, asset_type).unwrap();

        let amount_var = cs.new_variable(amount);
        let asset_var = cs.new_variable(asset_type);
        let blind_var = cs.new_variable(blind);
        let key_type = cs.new_variable(BLSScalar::zero());
        let comm_var = commit_in_cs(
            &mut cs,
            blind_var,
            amount_var,
            asset_var,
            key_type,
            &public_key_scalars_vars,
            &input_commitment_trace,
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

        cs.load_anemoi_jive_parameters::<AnemoiJive381>();

        let mut prng = test_rng();
        let bytes = vec![1u8; 32];
        let uid_amount = BLSScalar::from_bytes(&bytes[..]).unwrap(); // safe unwrap
        let asset_type = one;

        let keypair = KeyPair::generate_secp256k1(&mut prng);

        let public_key_scalars = keypair.pub_key.to_bls_scalars().unwrap();
        let public_key_scalars_vars = [
            cs.new_variable(public_key_scalars[0]),
            cs.new_variable(public_key_scalars[1]),
            cs.new_variable(public_key_scalars[2]),
        ];

        let secret_key_scalars = keypair.sec_key.to_bls_scalars().unwrap();
        let secret_key_scalars_vars = [
            cs.new_variable(secret_key_scalars[0]),
            cs.new_variable(secret_key_scalars[1]),
        ];

        let trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[
            zero,                  /* protocol version number */
            uid_amount,            /* uid and amount */
            asset_type,            /* asset type */
            zero,                  /* address format number */
            public_key_scalars[0], /* public key */
            public_key_scalars[1], /* public key */
            public_key_scalars[2], /* public key */
            secret_key_scalars[0], /* secret key */
            secret_key_scalars[1], /* secret key */
        ]);

        let expected_output = trace.output;

        let uid_amount_var = cs.new_variable(uid_amount);
        let asset_var = cs.new_variable(asset_type);

        let secret_key_type = cs.new_variable(BLSScalar::zero());

        let nullifier_var = nullify_in_cs(
            &mut cs,
            &secret_key_scalars_vars,
            uid_amount_var,
            asset_var,
            secret_key_type,
            &public_key_scalars_vars,
            &trace,
        );
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
        let num: Vec<BLSScalar> = (0u32..5u32).map(|x| BLSScalar::from(x)).collect();
        let node_var = cs.new_variable(num[4]);
        let left_var = cs.new_variable(num[2]);
        let mid_var = cs.new_variable(num[3]);
        let right_var = cs.new_variable(num[4]);
        let is_left_var = cs.new_variable(num[0]);
        let is_mid_var = cs.new_variable(num[0]);
        let is_right_var = cs.new_variable(num[1]);

        // note: check_merkle_tree_validity assumes `is_left_var`, `is_mid_var`, and `is_right_var`
        // are already checked to be binary
        check_merkle_tree_validity(
            &mut cs,
            node_var,
            left_var,
            mid_var,
            right_var,
            is_left_var,
            is_mid_var,
            is_right_var,
        );
        let mut witness = cs.get_and_clear_witness();
        let output: Vec<BLSScalar> = [left_var, mid_var, right_var]
            .as_slice()
            .iter()
            .map(|&idx| witness[idx])
            .collect();

        // node_var is at the right position.
        let expected_output = vec![witness[left_var], witness[mid_var], witness[node_var]];
        // check output correctness.
        assert_eq!(output, expected_output);

        // check constraints.
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        // incorrect witness.
        witness[node_var] = num[2];
        assert!(cs.verify_witness(&witness, &[]).is_err());
    }

    #[test]
    fn test_merkle_root() {
        let one = BLSScalar::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = two.add(&two);

        let mut cs = TurboCS::new();
        cs.load_anemoi_jive_parameters::<AnemoiJive381>();

        let uid_var = cs.new_variable(one);
        let comm_var = cs.new_variable(two);
        let elem = AccElemVars {
            uid: uid_var,
            commitment: comm_var,
        };

        // compute the root value.
        let leaf_trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[
            /*uid=*/ one, /*comm=*/ two,
        ]);

        let leaf = leaf_trace.output;

        let path_node2 = MTNode {
            left: two,
            mid: four,
            right: leaf,
            is_left_child: 0u8,
            is_mid_child: 0u8,
            is_right_child: 1u8,
        };

        let trace1 = AnemoiJive381::eval_jive_with_trace(
            &[path_node2.left, path_node2.mid],
            &[leaf, ANEMOI_JIVE_381_SALTS[0]],
        );

        let path_node1 = MTNode {
            left: trace1.output,
            mid: one,
            right: three,
            is_left_child: 1u8,
            is_mid_child: 0,
            is_right_child: 0u8,
        };

        let trace2 = AnemoiJive381::eval_jive_with_trace(
            &[path_node1.left, path_node1.mid],
            &[path_node1.right, ANEMOI_JIVE_381_SALTS[1]],
        );
        let root = trace2.output;

        // compute the constraints.
        let path = MTPath::new(vec![path_node2, path_node1]);
        let path_vars = add_merkle_path_variables(&mut cs, path);

        let root_var = compute_merkle_root_variables(
            &mut cs,
            elem,
            &path_vars,
            &leaf_trace,
            &vec![trace1, trace2],
        );

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

        // happy path: `is_left_child`/`is_mid_child`/`is_right_child` are boolean
        let mut cs = TurboCS::new();
        let node = MTNode {
            left: zero,
            mid: one,
            right: zero,
            is_left_child: 1u8,
            is_mid_child: 0u8,
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
            left: zero,
            mid: one,
            right: zero,
            is_left_child: 2u8,
            is_mid_child: 0u8,
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
            left: zero,
            mid: one,
            right: zero,
            is_left_child: 1u8,
            is_mid_child: 0u8,
            is_right_child: 1u8,
        };
        let path = MTPath::new(vec![node]);
        let _ = add_merkle_path_variables(&mut cs, path);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());
    }

    #[test]
    fn test_build_multi_xfr_cs() {
        // fee type.
        let fee_type = BLSScalar::from(1234u32);

        // fee function
        // base fee 5, every input 1, every output 29
        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);

        // single-asset: good witness.
        let zero = BLSScalar::zero();
        let inputs = vec![
            (/*amount=*/ 30, /*asset_type=*/ zero),
            (30, zero),
            (5 + 3 + 2 * 3, fee_type),
        ];
        let mut outputs = vec![(19, zero), (17, zero), (24, zero)];
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
            (19, one),
            (15, zero),
            (1, one),
            (35, zero),
            (20, zero),
            (40, one),
            (100, fee_type),
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
        outputs: Vec<(u64, BLSScalar)>,
        witness_is_valid: bool,
        fee_type: BLSScalar,
        fee: u32,
    ) {
        let (secret_inputs, keypair) = new_multi_xfr_witness_for_test(inputs, outputs, fee);
        let pub_inputs = AXfrPubInputs::from_witness(&secret_inputs);

        let mut prng = test_rng();

        let test_hash = {
            let mut hasher = Sha512::new();
            let mut random_bytes = [0u8; 32];
            prng.fill_bytes(&mut random_bytes);
            hasher.update(&random_bytes);
            hasher
        };

        let mut transcript = Transcript::new(ANON_XFR_FOLDING_PROOF_TRANSCRIPT);
        let (folding_instance, folding_witness) = create_address_folding_secp256k1(
            &mut prng,
            test_hash.clone(),
            &mut transcript,
            &keypair,
        )
        .unwrap();

        let mut nullifiers_traces = Vec::<AnemoiVLHTrace<BLSScalar, 2, 12>>::new();
        let mut input_commitments_traces = Vec::<AnemoiVLHTrace<BLSScalar, 2, 12>>::new();
        for payer_witness in secret_inputs.payers_witnesses.iter() {
            let (_, nullifier_trace) = nullify(
                &payer_witness.secret_key.clone().into_keypair(),
                payer_witness.amount,
                payer_witness.asset_type,
                payer_witness.uid,
            )
            .unwrap();
            nullifiers_traces.push(nullifier_trace);

            let (_, input_commitment_trace) = commit(
                &payer_witness.secret_key.clone().into_keypair().pub_key,
                payer_witness.blind,
                payer_witness.amount,
                payer_witness.asset_type,
            )
            .unwrap();
            input_commitments_traces.push(input_commitment_trace);
        }

        let mut output_commitments_traces = Vec::<AnemoiVLHTrace<BLSScalar, 2, 12>>::new();
        for payee_witness in secret_inputs.payees_witnesses.iter() {
            let (_, output_commitment_trace) = commit(
                &payee_witness.public_key,
                payee_witness.blind,
                payee_witness.amount,
                payee_witness.asset_type,
            )
            .unwrap();
            output_commitments_traces.push(output_commitment_trace);
        }

        // check the constraints.
        let (mut cs, _) = build_multi_xfr_cs(
            &secret_inputs,
            fee_type,
            &nullifiers_traces,
            &input_commitments_traces,
            &output_commitments_traces,
            &AXfrAddressFoldingWitness::Secp256k1(folding_witness),
        );
        let witness = cs.get_and_clear_witness();

        let mut transcript = Transcript::new(ANON_XFR_FOLDING_PROOF_TRANSCRIPT);

        let (beta, lambda) =
            verify_address_folding_secp256k1(test_hash, &mut transcript, &folding_instance)
                .unwrap();

        let address_folding_public_input =
            prepare_verifier_input_secp256k1(&folding_instance, &beta, &lambda);

        let mut online_inputs = pub_inputs.to_vec();
        online_inputs.extend_from_slice(&address_folding_public_input);

        let verify = cs.verify_witness(&witness, &online_inputs);
        if witness_is_valid {
            pnk!(verify);
        } else {
            assert!(verify.is_err());
        }
    }
}
