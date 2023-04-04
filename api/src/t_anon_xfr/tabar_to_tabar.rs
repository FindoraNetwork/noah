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

use super::structs::TAxfrAuditorMemo;

/// The domain separator for traceable anonymous transfer, for the Plonk proof.
const T_ANON_XFR_PLONK_PROOF_TRANSCRIPT: &[u8] = b"traceable Anon Xfr Plonk Proof";
/// The domain separator for anonymous transfer, for address folding.
const T_ANON_XFR_FOLDING_PROOF_TRANSCRIPT: &[u8] = b"traceable Anon Xfr Folding Proof";
/// The domain separator for the number of inputs.
const N_INPUTS_TRANSCRIPT: &[u8] = b"Number of input TABARs";
/// The domain separator for the number of outputs.
const N_OUTPUTS_TRANSCRIPT: &[u8] = b"Number of output TABARs";

/// Traceable anonymous transfer note.
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct TAXfrNote {
    /// The traceable anonymous transfer body.
    pub body: TAXfrBody,
    /// The Plonk proof (assuming non-malleability).
    pub proof: AXfrPlonkPf,
    /// The address folding instance.
    pub folding_instance: AXfrAddressFoldingInstance,
}

/// Traceable anonymous transfer pre-note without proofs and signatures.
#[derive(Debug, Clone)]
pub struct TAXfrPreNote {
    /// The traceable anonymous transfer body.
    pub body: TAXfrBody,
    /// Witness.
    pub witness: TAXfrWitness,
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
/// Traceable anonymous transfer body. 
pub struct TAXfrBody {
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
    // /// The auditor memos.
    // pub auditor_memos: Vec<TAxfrAuditorMemo>,
}

/// Build a traceable anonymous transfer note without generating the proof.
pub fn init_t_anon_xfr_note(
    inputs: &[OpenAnonAssetRecord],
    outputs: &[OpenAnonAssetRecord],
    fee: u32,
    input_keypair: &KeyPair,
) -> Result<TAXfrPreNote> {
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
    let body = TAXfrBody {
        inputs: nullifiers,
        outputs: out_abars,
        merkle_root: mt_info_temp.root,
        merkle_root_version: mt_info_temp.root_version,
        fee,
        owner_memos: out_memos.c(d!())?,
    };

    Ok(TAXfrPreNote {
        body,
        witness: secret_inputs,
        input_commitments_traces,
        output_commitments_traces,
        nullifiers_traces,
        input_keypair: input_keypair.clone(),
    })
}

/// Build a traceable anonymous transfer note without generating the proof.
pub fn finish_t_anon_xfr_note<R: CryptoRng + RngCore, D: Digest<OutputSize = U64> + Default>(
    prng: &mut R,
    params: &ProverParams,
    pre_note: TAXfrPreNote,
    hash: D,
) -> Result<TAXfrNote> {
    let TAXfrPreNote {
        body,
        witness,
        input_commitments_traces,
        output_commitments_traces,
        nullifiers_traces,
        input_keypair,
    } = pre_note;

    let mut transcript = Transcript::new(T_ANON_XFR_FOLDING_PROOF_TRANSCRIPT);

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

    Ok(TAXfrNote {
        body,
        proof,
        folding_instance,
    })
}

/// Verify a traceable anonymous transfer note.
pub fn verify_t_anon_xfr_note<D: Digest<OutputSize = U64> + Default>(
    params: &VerifierParams,
    note: &TAXfrNote,
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

/// Generate a Plonk proof for traceable anonymous transfer.
pub(crate) fn prove_xfr<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    secret_inputs: &TAXfrWitness,
    nullifiers_traces: &[AnemoiVLHTrace<BLSScalar, 2, 12>],
    input_commitments_traces: &[AnemoiVLHTrace<BLSScalar, 2, 12>],
    output_commitments_traces: &[AnemoiVLHTrace<BLSScalar, 2, 12>],
    folding_witness: &AXfrAddressFoldingWitness,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(T_ANON_XFR_PLONK_PROOF_TRANSCRIPT);
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

/// Verify a Plonk proof for traceable anonymous transfer.
pub(crate) fn verify_xfr(
    params: &VerifierParams,
    pub_inputs: &AXfrPubInputs,
    proof: &AXfrPlonkPf,
    address_folding_public_input: &Vec<BLSScalar>,
    folding_instance: &AXfrAddressFoldingInstance,
) -> Result<()> {
    let mut transcript = Transcript::new(T_ANON_XFR_PLONK_PROOF_TRANSCRIPT);
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

/// The witness of a traceable anonymous transfer.
#[derive(Debug, Clone)]
pub struct TAXfrWitness {
    /// The payers' witnesses.
    pub payers_witnesses: Vec<PayerWitness>,
    /// The payees' witnesses.
    pub payees_witnesses: Vec<PayeeWitness>,
    /// The fee.
    pub fee: u32,
}

impl TAXfrWitness {
    /// Create a fake `TAXfrWitness` for testing.
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

        TAXfrWitness {
            payers_witnesses: vec![payer_witness; n_payers],
            payees_witnesses: vec![payee_witness; n_payees],
            fee,
        }
    }

    /// Create a fake `TAXfrWitness` for testing.
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

        TAXfrWitness {
            payers_witnesses: vec![payer_witness; n_payers],
            payees_witnesses: vec![payee_witness; n_payees],
            fee,
        }
    }
}

/// Public inputs of a traceable anonymous transfer.
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

/// Instantiate the constraint system for traceable anonymous transfer.
pub(crate) fn build_multi_xfr_cs(
    witness: &TAXfrWitness,
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

    asset_mixing(&mut cs, &inputs, &outputs, fee_type, fee_var);

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
