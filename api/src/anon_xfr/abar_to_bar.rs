use crate::anon_xfr::address_folding::{
    create_address_folding, prepare_verifier_input, prove_address_folding_in_cs,
    verify_address_folding, AXfrAddressFoldingWitness,
};
use crate::anon_xfr::{
    abar_to_abar::add_payers_witnesses,
    address_folding::AXfrAddressFoldingInstance,
    commit_in_cs, compute_merkle_root_variables,
    keys::AXfrKeyPair,
    nullify, nullify_in_cs,
    structs::{AccElemVars, Nullifier, OpenAnonAssetRecord, PayerWitness},
    AXfrPlonkPf, TurboPlonkCS, ANON_XFR_BP_GENS_LEN, TWO_POW_32,
};
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::{
    asset_record::{build_open_asset_record, AssetRecordType},
    sig::XfrPublicKey,
    structs::{AssetRecordTemplate, BlindAssetRecord, OwnerMemo, XfrAmount, XfrAssetType},
};
use digest::{consts::U64, Digest};
use merlin::Transcript;
use num_bigint::BigUint;
use zei_algebra::{
    bls12_381::BLSScalar,
    prelude::*,
    ristretto::{RistrettoPoint, RistrettoScalar},
};
use zei_crypto::{
    basic::pedersen_comm::{PedersenCommitment, PedersenCommitmentRistretto},
    delegated_chaum_pedersen::{
        prove_delegated_chaum_pedersen, verify_delegated_chaum_pedersen,
        DelegatedChaumPedersenInspection, DelegatedChaumPedersenProof,
    },
    field_simulation::{SimFr, SimFrParams, SimFrParamsRistretto},
};
use zei_plonk::plonk::{
    constraint_system::{field_simulation::SimFrVar, rescue::StateVar, TurboCS, VarIndex},
    prover::prover_with_lagrange,
    verifier::verifier,
};

const ABAR_TO_BAR_TRANSCRIPT: &[u8] = b"ABAR to BAR proof";

/// An anonymous-to-confidential note.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToBarNote {
    /// The anonymous-to-confidential body.
    pub body: AbarToBarBody,
    /// The PLonk proof (assuming non-malleability).
    pub proof: AXfrPlonkPf,
    /// The address folding instance.
    pub folding_instance: AXfrAddressFoldingInstance,
}

/// An anonymous-to-confidential note without the proof or non-malleability tag..
#[derive(Clone, Debug)]
pub struct AbarToBarPreNote {
    /// The anonymous-to-confidential body.
    pub body: AbarToBarBody,
    /// Witness.
    pub witness: PayerWitness,
    /// Input key pair.
    pub input_keypair: AXfrKeyPair,
    /// Inspection data in the delegated Chaum-Pedersen proof on Ristretto.
    pub inspection:
        DelegatedChaumPedersenInspection<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto>,
    /// Beta on Ristretto.
    pub beta: RistrettoScalar,
    /// Lambda on Ristretto.
    pub lambda: RistrettoScalar,
}

/// An anonymous-to-confidential body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToBarBody {
    /// Input ABAR being spent.
    pub input: Nullifier,
    /// The new BAR to be created.
    pub output: BlindAssetRecord,
    /// The inspector's proof on Ristretto.
    pub delegated_cp_proof:
        DelegatedChaumPedersenProof<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto>,
    /// The Merkle root hash.
    pub merkle_root: BLSScalar,
    /// The Merkle root version.
    pub merkle_root_version: u64,
    /// The owner memo.
    pub memo: Option<OwnerMemo>,
}

/// Generate the anonymous-to-confidential pre-note.
pub fn init_abar_to_bar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    oabar: &OpenAnonAssetRecord,
    abar_keypair: &AXfrKeyPair,
    bar_pub_key: &XfrPublicKey,
    asset_record_type: AssetRecordType,
) -> Result<AbarToBarPreNote> {
    if oabar.mt_leaf_info.is_none() || abar_keypair.get_public_key() != oabar.pub_key {
        return Err(eg!(ZeiError::ParameterError));
    }

    // Reject anonymous-to-confidential note that actually has transparent output.
    // Should direct to AbarToAr.
    if asset_record_type == AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType {
        return Err(eg!(ZeiError::ParameterError));
    }

    let obar_amount = oabar.amount;
    let obar_type = oabar.asset_type;

    let pc_gens = PedersenCommitmentRistretto::default();
    let art = AssetRecordTemplate::with_no_asset_tracing(
        obar_amount,
        obar_type,
        asset_record_type,
        bar_pub_key.clone(),
    );
    let (obar, _, owner_memo) = build_open_asset_record(prng, &pc_gens, &art, vec![]);

    // 1. Build input witness info.
    let mt_leaf_info = oabar.mt_leaf_info.as_ref().unwrap();
    let this_nullifier = nullify(
        &abar_keypair,
        oabar.amount,
        &oabar.asset_type,
        mt_leaf_info.uid,
    )?;

    // 2. Construct the equality proof.
    let x = RistrettoScalar::from(oabar.amount);
    let y: RistrettoScalar = oabar.asset_type.as_scalar();
    let gamma = obar
        .amount_blinds
        .0
        .add(&obar.amount_blinds.1.mul(&RistrettoScalar::from(TWO_POW_32)));
    let delta = obar.type_blind;

    let pc_gens = PedersenCommitmentRistretto::default();

    let point_p = pc_gens.commit(x, gamma);
    let point_q = pc_gens.commit(y, delta);

    // 4. Compute the inspector's proof.
    let (delegated_cp_proof, delegated_cp_inspection, beta, lambda) = {
        let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);
        transcript.append_message(b"nullifier", &this_nullifier.to_bytes());
        prove_delegated_chaum_pedersen(
            prng,
            &vec![(x, gamma), (y, delta)],
            &pc_gens,
            &vec![point_p, point_q],
            &mut transcript,
        )
        .c(d!())?
    };

    // 5. Build the Plonk proof.
    let payers_witness = PayerWitness {
        secret_key: abar_keypair.get_secret_key(),
        uid: mt_leaf_info.uid,
        amount: oabar.amount,
        asset_type: oabar.asset_type.as_scalar(),
        path: mt_leaf_info.path.clone(),
        blind: oabar.blind,
    };

    let mt_info_temp = oabar.mt_leaf_info.as_ref().unwrap();

    let body = AbarToBarBody {
        input: this_nullifier,
        output: obar.blind_asset_record.clone(),
        delegated_cp_proof: delegated_cp_proof.clone(),
        merkle_root: mt_info_temp.root,
        merkle_root_version: mt_info_temp.root_version,
        memo: owner_memo,
    };

    Ok(AbarToBarPreNote {
        body,
        witness: payers_witness,
        input_keypair: abar_keypair.clone(),
        inspection: delegated_cp_inspection,
        beta,
        lambda,
    })
}

/// Finalize an anonymous-to-confidential note.
pub fn finish_abar_to_bar_note<R: CryptoRng + RngCore, D: Digest<OutputSize = U64> + Default>(
    prng: &mut R,
    params: &ProverParams,
    pre_note: AbarToBarPreNote,
    hash: D,
) -> Result<AbarToBarNote> {
    let AbarToBarPreNote {
        body,
        witness,
        input_keypair,
        inspection,
        beta,
        lambda,
    } = pre_note;

    let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);
    let (folding_instance, folding_witness) = create_address_folding(
        prng,
        hash,
        &mut transcript,
        ANON_XFR_BP_GENS_LEN,
        &input_keypair,
    )?;

    let proof = prove_abar_to_bar(
        prng,
        params,
        witness,
        &body.delegated_cp_proof,
        &inspection,
        &beta,
        &lambda,
        &folding_witness,
    )
    .c(d!())?;

    Ok(AbarToBarNote {
        body,
        proof,
        folding_instance,
    })
}

/// Verify the anonymous-to-confidential note.
pub fn verify_abar_to_bar_note<D: Digest<OutputSize = U64> + Default>(
    params: &VerifierParams,
    note: &AbarToBarNote,
    merkle_root: &BLSScalar,
    hash: D,
) -> Result<()> {
    if *merkle_root != note.body.merkle_root {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }

    let bar = note.body.output.clone();
    let pc_gens = PedersenCommitmentRistretto::default();

    // Reject anonymous-to-confidential notes whose outputs are transparent.
    if note.body.output.get_record_type()
        == AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
    {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }

    // 1. Get commitments.
    // 1.1 Reconstruct total amount commitment from bar.
    let (com_low, com_high) = match bar.amount {
        XfrAmount::Confidential((low, high)) => (
            low.decompress()
                .ok_or(ZeiError::DecompressElementError)
                .c(d!())?,
            high.decompress()
                .ok_or(ZeiError::DecompressElementError)
                .c(d!())?,
        ),
        XfrAmount::NonConfidential(amount) => {
            // Use a trivial commitment
            let (l, h) = u64_to_u32_pair(amount);
            (
                pc_gens.commit(RistrettoScalar::from(l), RistrettoScalar::zero()),
                pc_gens.commit(RistrettoScalar::from(h), RistrettoScalar::zero()),
            )
        }
    };

    // 1.2 Get asset type commitment.
    let com_amount = com_low.add(&com_high.mul(&RistrettoScalar::from(TWO_POW_32)));
    let com_asset_type = match bar.asset_type {
        XfrAssetType::Confidential(a) => a
            .decompress()
            .ok_or(ZeiError::DecompressElementError)
            .c(d!())?,
        XfrAssetType::NonConfidential(a) => {
            // Use a trivial commitment
            pc_gens.commit(a.as_scalar(), RistrettoScalar::zero())
        }
    };

    let input = note.body.input;

    let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);

    // important: address folding relies significantly on the Fiat-Shamir transform.
    transcript.append_message(b"nullifier", &note.body.input.to_bytes());

    // 2. Verify the delegated Chaum-Pedersen proof.
    let (beta, lambda) = verify_delegated_chaum_pedersen(
        &pc_gens,
        &vec![com_amount, com_asset_type],
        &note.body.delegated_cp_proof,
        &mut transcript,
    )
    .c(d!())?;

    let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);
    let (beta_folding, lambda_folding) = verify_address_folding(
        hash,
        &mut transcript,
        ANON_XFR_BP_GENS_LEN,
        &note.folding_instance,
    )?;
    let address_folding_public_input =
        prepare_verifier_input(&note.folding_instance, &beta_folding, &lambda_folding);

    let delegated_cp_proof = note.body.delegated_cp_proof.clone();

    let beta_lambda = beta * &lambda;
    let s1_plus_lambda_s2 = delegated_cp_proof.response_scalars[0].0
        + delegated_cp_proof.response_scalars[1].0 * &lambda;

    let beta_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&beta.to_bytes()));
    let lambda_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&lambda.to_bytes()));
    let beta_lambda_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&beta_lambda.to_bytes()));
    let s1_plus_lambda_s2_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&s1_plus_lambda_s2.to_bytes()));

    let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);
    let mut online_inputs = vec![];

    online_inputs.push(input.clone());
    online_inputs.push(merkle_root.clone());
    online_inputs.push(delegated_cp_proof.inspection_comm);
    online_inputs.extend_from_slice(&beta_sim_fr.limbs);
    online_inputs.extend_from_slice(&lambda_sim_fr.limbs);
    online_inputs.extend_from_slice(&beta_lambda_sim_fr.limbs);
    online_inputs.extend_from_slice(&s1_plus_lambda_s2_sim_fr.limbs);
    online_inputs.extend_from_slice(&address_folding_public_input);

    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        &note.proof,
    )
    .c(d!(ZeiError::AXfrVerificationError))
}

fn prove_abar_to_bar<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    payers_witness: PayerWitness,
    proof: &DelegatedChaumPedersenProof<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto>,
    inspection: &DelegatedChaumPedersenInspection<
        RistrettoScalar,
        RistrettoPoint,
        SimFrParamsRistretto,
    >,
    beta: &RistrettoScalar,
    lambda: &RistrettoScalar,
    folding_witness: &AXfrAddressFoldingWitness,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);

    let (mut cs, _) = build_abar_to_bar_cs(
        payers_witness,
        proof,
        inspection,
        beta,
        lambda,
        folding_witness,
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

/// Construct the anonymous-to-confidential constraint system.
pub fn build_abar_to_bar_cs(
    payers_witness: PayerWitness,
    proof: &DelegatedChaumPedersenProof<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto>,
    inspection: &DelegatedChaumPedersenInspection<
        RistrettoScalar,
        RistrettoPoint,
        SimFrParamsRistretto,
    >,
    beta: &RistrettoScalar,
    lambda: &RistrettoScalar,
    folding_witness: &AXfrAddressFoldingWitness,
) -> (TurboPlonkCS, usize) {
    let mut cs = TurboCS::new();

    let payers_witnesses_vars = add_payers_witnesses(&mut cs, &[payers_witness]);
    let payers_witness_vars = &payers_witnesses_vars[0];

    let keypair = folding_witness.keypair.clone();
    let public_key_scalars = keypair.get_public_key().get_public_key_scalars().unwrap();
    let secret_key_scalars = keypair.get_secret_key().get_secret_key_scalars().unwrap();

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

    let step_1 = BLSScalar::from(&BigUint::one().shl(SimFrParamsRistretto::BIT_PER_LIMB));
    let step_2 = BLSScalar::from(&BigUint::one().shl(SimFrParamsRistretto::BIT_PER_LIMB * 2));
    let step_3 = BLSScalar::from(&BigUint::one().shl(SimFrParamsRistretto::BIT_PER_LIMB * 3));
    let step_4 = BLSScalar::from(&BigUint::one().shl(SimFrParamsRistretto::BIT_PER_LIMB * 4));
    let step_5 = BLSScalar::from(&BigUint::one().shl(SimFrParamsRistretto::BIT_PER_LIMB * 5));

    // Commit.
    let com_abar_in_var = commit_in_cs(
        &mut cs,
        payers_witness_vars.blind,
        payers_witness_vars.amount,
        payers_witness_vars.asset_type,
        &public_key_scalars_vars,
    );

    // Nullify.
    // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`.
    let uid_amount = cs.linear_combine(
        &[
            payers_witness_vars.uid,
            payers_witness_vars.amount,
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
        payers_witness_vars.asset_type,
        &public_key_scalars_vars,
    );

    // Merkle path authentication.
    let acc_elem = AccElemVars {
        uid: payers_witness_vars.uid,
        commitment: com_abar_in_var,
    };

    let tmp_root_var = compute_merkle_root_variables(&mut cs, acc_elem, &payers_witness_vars.path);

    if let Some(root) = root_var {
        cs.equal(root, tmp_root_var);
    } else {
        root_var = Some(tmp_root_var);
    }

    // 2. Input witness x, y, a, b, r, public input comm, beta, s1, s2.
    let x_sim_fr = SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(
        &inspection.committed_data_and_randomizer[0].0.to_bytes(),
    ));
    let y_sim_fr = SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(
        &inspection.committed_data_and_randomizer[1].0.to_bytes(),
    ));
    let a_sim_fr = SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(
        &inspection.committed_data_and_randomizer[0].1.to_bytes(),
    ));
    let b_sim_fr = SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(
        &inspection.committed_data_and_randomizer[1].1.to_bytes(),
    ));
    let comm = proof.inspection_comm;
    let r = inspection.r;
    let beta_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&beta.to_bytes()));
    let lambda_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&lambda.to_bytes()));

    let beta_lambda = *beta * lambda;
    let beta_lambda_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&beta_lambda.to_bytes()));

    let s1_plus_lambda_s2 = proof.response_scalars[0].0 + proof.response_scalars[1].0 * lambda;
    let s1_plus_lambda_s2_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&s1_plus_lambda_s2.to_bytes()));

    let (x_sim_fr_var, _) = SimFrVar::alloc_witness_bounded_total_bits(&mut cs, &x_sim_fr, 64);
    let (y_sim_fr_var, _) = SimFrVar::alloc_witness_bounded_total_bits(&mut cs, &y_sim_fr, 240);
    let (a_sim_fr_var, _) = SimFrVar::alloc_witness(&mut cs, &a_sim_fr);
    let (b_sim_fr_var, _) = SimFrVar::alloc_witness(&mut cs, &b_sim_fr);
    let comm_var = cs.new_variable(comm);
    let r_var = cs.new_variable(r);
    let beta_sim_fr_var = SimFrVar::alloc_input(&mut cs, &beta_sim_fr);
    let lambda_sim_fr_var = SimFrVar::alloc_input(&mut cs, &lambda_sim_fr);
    let beta_lambda_sim_fr_var = SimFrVar::alloc_input(&mut cs, &beta_lambda_sim_fr);
    let s1_plus_lambda_s2_sim_fr_var = SimFrVar::alloc_input(&mut cs, &s1_plus_lambda_s2_sim_fr);

    // 3. Merge the limbs for x, y, a, b.
    let mut all_limbs = Vec::with_capacity(4 * SimFrParamsRistretto::NUM_OF_LIMBS);
    all_limbs.extend_from_slice(&x_sim_fr.limbs);
    all_limbs.extend_from_slice(&y_sim_fr.limbs);
    all_limbs.extend_from_slice(&a_sim_fr.limbs);
    all_limbs.extend_from_slice(&b_sim_fr.limbs);

    let mut all_limbs_var = Vec::with_capacity(4 * SimFrParamsRistretto::NUM_OF_LIMBS);
    all_limbs_var.extend_from_slice(&x_sim_fr_var.var);
    all_limbs_var.extend_from_slice(&y_sim_fr_var.var);
    all_limbs_var.extend_from_slice(&a_sim_fr_var.var);
    all_limbs_var.extend_from_slice(&b_sim_fr_var.var);

    let mut compressed_limbs = Vec::with_capacity(5);
    let mut compressed_limbs_var = Vec::with_capacity(5);
    for (limbs, limbs_var) in all_limbs.chunks(5).zip(all_limbs_var.chunks(5)) {
        let mut sum = BigUint::zero();
        for (i, limb) in limbs.iter().enumerate() {
            sum.add_assign(
                <BLSScalar as Into<BigUint>>::into(*limb)
                    .shl(SimFrParamsRistretto::BIT_PER_LIMB * i),
            );
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

    // 4. Check the inspector's state commitment.
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

    // 5. Perform the check in field simulation.
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

    // 6. Check x = amount_var and y = at_var.
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

        cs.equal(x_in_bls12_381, payers_witness_vars.amount);
        cs.equal(y_in_bls12_381, payers_witness_vars.asset_type);
    }

    // prepare public inputs variables.
    cs.prepare_pi_variable(nullifier_var);
    cs.prepare_pi_variable(root_var.unwrap()); // safe unwrap

    cs.prepare_pi_variable(comm_var);

    for i in 0..SimFrParamsRistretto::NUM_OF_LIMBS {
        cs.prepare_pi_variable(beta_sim_fr_var.var[i]);
    }
    for i in 0..SimFrParamsRistretto::NUM_OF_LIMBS {
        cs.prepare_pi_variable(lambda_sim_fr_var.var[i]);
    }
    for i in 0..SimFrParamsRistretto::NUM_OF_LIMBS {
        cs.prepare_pi_variable(beta_lambda_sim_fr_var.var[i]);
    }
    for i in 0..SimFrParamsRistretto::NUM_OF_LIMBS {
        cs.prepare_pi_variable(s1_plus_lambda_s2_sim_fr_var.var[i]);
    }

    prove_address_folding_in_cs(
        &mut cs,
        &public_key_scalars_vars,
        &secret_key_scalars_vars,
        &folding_witness,
    )
    .unwrap();

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::anon_xfr::{
        abar_to_bar::{finish_abar_to_bar_note, init_abar_to_bar_note, verify_abar_to_bar_note},
        structs::{AnonAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonAssetRecordBuilder},
        TREE_DEPTH,
    };
    use crate::setup::{ProverParams, VerifierParams};
    use crate::xfr::{
        asset_record::AssetRecordType::ConfidentialAmount_ConfidentialAssetType, sig::XfrKeyPair,
        structs::AssetType,
    };
    use digest::Digest;
    use mem_db::MemoryDB;
    use parking_lot::RwLock;
    use rand_chacha::ChaChaRng;
    use sha2::Sha512;
    use std::sync::Arc;
    use storage::{
        state::{ChainState, State},
        store::PrefixedStore,
    };
    use zei_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
    use zei_algebra::{bls12_381::BLSScalar, prelude::*};
    use zei_crypto::basic::rescue::RescueInstance;

    #[test]
    fn test_abar_to_bar() {
        let mut prng = ChaChaRng::from_seed([5u8; 32]);
        let params = ProverParams::abar_to_bar_params(TREE_DEPTH).unwrap();

        let recv = XfrKeyPair::generate(&mut prng);
        let sender = AXfrKeyPair::generate(&mut prng);

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(
            fdb,
            "test_abar_to_bar_db".to_string(),
            0,
        )));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut oabar = OpenAnonAssetRecordBuilder::new()
            .pub_key(&sender.get_public_key())
            .amount(1234u64)
            .asset_type(AssetType::from_identical_byte(0u8))
            .finalize(&mut prng)
            .unwrap()
            .build()
            .unwrap();

        let abar = AnonAssetRecord::from_oabar(&oabar);
        mt.add_commitment_hash(hash_abar(0, &abar)).unwrap();
        mt.commit().unwrap();
        let proof = mt.generate_proof(0).unwrap();

        oabar.update_mt_leaf_info(build_mt_leaf_info_from_proof(proof.clone()));

        let pre_note = init_abar_to_bar_note(
            &mut prng,
            &oabar.clone(),
            &sender,
            &recv.pub_key,
            ConfidentialAmount_ConfidentialAssetType,
        )
        .unwrap();

        let hash = {
            let mut hasher = Sha512::new();
            let mut random_bytes = [0u8; 32];
            prng.fill_bytes(&mut random_bytes);
            hasher.update(&random_bytes);
            hasher
        };

        let note = finish_abar_to_bar_note(&mut prng, &params, pre_note, hash.clone()).unwrap();

        let node_params = VerifierParams::abar_to_bar_params().unwrap();
        verify_abar_to_bar_note(&node_params, &note, &proof.root, hash.clone()).unwrap();
        assert!(verify_abar_to_bar_note(
            &node_params,
            &note,
            &BLSScalar::random(&mut prng),
            hash.clone()
        )
        .is_err());

        let mut note_wrong_nullifier = note.clone();
        note_wrong_nullifier.body.input = BLSScalar::random(&mut prng);
        assert!(verify_abar_to_bar_note(
            &node_params,
            &note_wrong_nullifier,
            &proof.root,
            hash.clone()
        )
        .is_err());

        let hash2 = {
            let mut hasher = Sha512::new();
            let mut random_bytes = [0u8; 32];
            prng.fill_bytes(&mut random_bytes);
            hasher.update(&random_bytes);
            hasher
        };

        assert!(verify_abar_to_bar_note(&node_params, &note, &proof.root, hash2).is_err())
    }

    fn hash_abar(uid: u64, abar: &AnonAssetRecord) -> BLSScalar {
        let hash = RescueInstance::new();
        hash.rescue(&[
            BLSScalar::from(uid),
            abar.commitment,
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0]
    }

    fn build_mt_leaf_info_from_proof(proof: Proof) -> MTLeafInfo {
        return MTLeafInfo {
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
            uid: 0,
        };
    }
}
