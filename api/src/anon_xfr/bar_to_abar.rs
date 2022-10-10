use crate::anon_xfr::{
    commit, commit_in_cs,
    keys::AXfrPubKey,
    structs::{AnonAssetRecord, AxfrOwnerMemo, OpenAnonAssetRecord, OpenAnonAssetRecordBuilder},
    AXfrPlonkPf, TurboPlonkCS, TWO_POW_32,
};
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::{
    asset_record::AssetRecordType,
    sig::{XfrKeyPair, XfrPublicKey, XfrSignature},
    structs::{BlindAssetRecord, OpenAssetRecord, XfrAmount, XfrAssetType},
};
use merlin::Transcript;
use noah_algebra::{
    bls12_381::BLSScalar,
    prelude::*,
    ristretto::{RistrettoPoint, RistrettoScalar},
};
use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381, AnemoiVLHTrace};
use noah_crypto::{
    basic::pedersen_comm::{PedersenCommitment, PedersenCommitmentRistretto},
    delegated_schnorr::{
        prove_delegated_schnorr, verify_delegated_schnorr, DelegatedSchnorrInspection,
        DelegatedSchnorrProof,
    },
    field_simulation::{SimFr, SimFrParams, SimFrParamsRistretto},
};
use noah_plonk::plonk::{
    constraint_system::{field_simulation::SimFrVar, TurboCS},
    prover::prover_with_lagrange,
    verifier::verifier,
};
use num_bigint::BigUint;
#[cfg(feature = "parallel")]
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

const BAR_TO_ABAR_PLONK_PROOF_TRANSCRIPT: &[u8] = b"BAR to ABAR Plonk Proof";

/// A confidential-to-anonymous note.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct BarToAbarNote {
    /// The confidential-to-anonymous body.
    pub body: BarToAbarBody,
    /// The signature.
    pub signature: XfrSignature,
}

/// A confidential-to-anonymous body.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct BarToAbarBody {
    /// The input, as a blind asset record.
    pub input: BlindAssetRecord,
    /// The output, as an anonymous asset record.
    pub output: AnonAssetRecord,
    /// The zero-knowledge proofs.
    pub proof: (
        DelegatedSchnorrProof<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto>,
        AXfrPlonkPf,
    ),
    /// The owner memo.
    pub memo: AxfrOwnerMemo,
}

/// Generate confidential-to-anonymous note.
pub fn gen_bar_to_abar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    record: &OpenAssetRecord,
    bar_keypair: &XfrKeyPair,
    abar_pubkey: &AXfrPubKey,
) -> Result<BarToAbarNote> {
    // Reject confidential-to-anonymous note that actually has transparent input.
    // Should direct to ArToAbar.
    if record.get_record_type() == AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType {
        return Err(eg!(NoahError::ParameterError));
    }

    let (open_abar, delegated_schnorr_proof, inspector_proof) =
        prove_bar_to_abar(prng, params, record, abar_pubkey).c(d!())?;
    let body = BarToAbarBody {
        input: record.blind_asset_record.clone(),
        output: AnonAssetRecord::from_oabar(&open_abar),
        proof: (delegated_schnorr_proof, inspector_proof),
        memo: open_abar.owner_memo.unwrap(),
    };

    let msg = bincode::serialize(&body)
        .map_err(|_| NoahError::SerializationError)
        .c(d!())?;
    let signature = bar_keypair.sign(&msg)?;

    let note = BarToAbarNote { body, signature };
    Ok(note)
}

/// Verify a confidential-to-anonymous note.
pub fn verify_bar_to_abar_note(
    params: &VerifierParams,
    note: &BarToAbarNote,
    bar_pub_key: &XfrPublicKey,
) -> Result<()> {
    verify_bar_to_abar(
        params,
        &note.body.input,
        &note.body.output,
        &note.body.proof,
    )
    .c(d!())?;

    let msg = bincode::serialize(&note.body).c(d!(NoahError::SerializationError))?;
    bar_pub_key.verify(&msg, &note.signature).c(d!())
}

/// Batch verify the confidential-to-anonymous notes.
#[cfg(feature = "parallel")]
pub fn batch_verify_bar_to_abar_note(
    params: &VerifierParams,
    notes: &[&BarToAbarNote],
    bar_pub_keys: &[&XfrPublicKey],
) -> Result<()> {
    let is_ok = notes
        .par_iter()
        .zip(bar_pub_keys)
        .map(|(note, bar_pub_key)| {
            verify_bar_to_abar(
                params,
                &note.body.input,
                &note.body.output,
                &note.body.proof,
            )
            .c(d!())?;

            let msg = bincode::serialize(&note.body).c(d!(NoahError::SerializationError))?;
            bar_pub_key.verify(&msg, &note.signature)
        })
        .all(|x| x.is_ok());

    if is_ok {
        Ok(())
    } else {
        Err(eg!())
    }
}

pub(crate) fn prove_bar_to_abar<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    obar: &OpenAssetRecord,
    abar_pubkey: &AXfrPubKey,
) -> Result<(
    OpenAnonAssetRecord,
    DelegatedSchnorrProof<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto>,
    AXfrPlonkPf,
)> {
    let oabar_amount = obar.amount;

    let pc_gens = PedersenCommitmentRistretto::default();

    // 1. Construct ABAR.
    let oabar = OpenAnonAssetRecordBuilder::new()
        .amount(oabar_amount)
        .asset_type(obar.asset_type)
        .pub_key(abar_pubkey)
        .finalize(prng)
        .c(d!())?
        .build()
        .c(d!())?;

    // 2. Reconstruct the points.
    let x = RistrettoScalar::from(oabar_amount);
    let y: RistrettoScalar = obar.asset_type.as_scalar();
    let gamma = obar
        .amount_blinds
        .0
        .add(&obar.amount_blinds.1.mul(&RistrettoScalar::from(TWO_POW_32)));
    let delta = obar.type_blind;
    let point_p = pc_gens.commit(x, gamma);
    let point_q = pc_gens.commit(y, delta);

    let x_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&x.to_bytes()));
    let y_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&y.to_bytes()));

    let (comm, comm_trace) = commit(
        abar_pubkey,
        oabar.blind,
        oabar_amount,
        obar.asset_type.as_scalar(),
    )?;

    let mut transcript = Transcript::new(BAR_TO_ABAR_PLONK_PROOF_TRANSCRIPT);
    // important: address folding relies significantly on the Fiat-Shamir transform.
    transcript.append_message(b"commitment", &comm.to_bytes());

    // 3. Compute the delegated Schnorr proof.
    let (delegated_schnorr_proof, inspection, beta, lambda) = prove_delegated_schnorr(
        prng,
        &vec![(x, gamma), (y, delta)],
        &pc_gens,
        &vec![point_p, point_q],
        &mut transcript,
    )
    .c(d!())?;

    // 4. Compute the inspector's proof.
    let inspector_proof = prove_bar_to_abar_cs(
        prng,
        params,
        x_in_bls12_381,
        y_in_bls12_381,
        oabar.blind,
        abar_pubkey,
        &delegated_schnorr_proof,
        &inspection,
        &beta,
        &lambda,
        &comm_trace,
    )
    .c(d!())?;

    Ok((oabar, delegated_schnorr_proof, inspector_proof))
}

pub(crate) fn verify_bar_to_abar(
    params: &VerifierParams,
    bar: &BlindAssetRecord,
    abar: &AnonAssetRecord,
    proof: &(
        DelegatedSchnorrProof<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto>,
        AXfrPlonkPf,
    ),
) -> Result<()> {
    let pc_gens = PedersenCommitmentRistretto::default();

    // Reject confidential-to-anonymous notes whose inputs are transparent.
    if bar.get_record_type() == AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType {
        return Err(eg!(NoahError::AXfrVerificationError));
    }

    // 1. Get commitments.
    // 1.1 Reconstruct the commitments for the amount.
    let (com_low, com_high) = match bar.amount {
        XfrAmount::Confidential((low, high)) => (
            low.decompress()
                .ok_or(NoahError::DecompressElementError)
                .c(d!())?,
            high.decompress()
                .ok_or(NoahError::DecompressElementError)
                .c(d!())?,
        ),
        XfrAmount::NonConfidential(amount) => {
            // a trivial commitment
            let (l, h) = u64_to_u32_pair(amount);
            (
                pc_gens.commit(RistrettoScalar::from(l), RistrettoScalar::zero()),
                pc_gens.commit(RistrettoScalar::from(h), RistrettoScalar::zero()),
            )
        }
    };

    // 1.2 Reconstruct the commitments for the asset types.
    let com_amount = com_low.add(&com_high.mul(&RistrettoScalar::from(TWO_POW_32)));
    let com_asset_type = match bar.asset_type {
        XfrAssetType::Confidential(a) => a
            .decompress()
            .ok_or(NoahError::DecompressElementError)
            .c(d!())?,
        XfrAssetType::NonConfidential(a) => {
            // a trivial commitment
            pc_gens.commit(a.as_scalar(), RistrettoScalar::zero())
        }
    };

    let mut transcript = Transcript::new(BAR_TO_ABAR_PLONK_PROOF_TRANSCRIPT);

    // important: address folding relies significantly on the Fiat-Shamir transform.
    transcript.append_message(b"commitment", &abar.commitment.to_bytes());

    // 2. Verify the delegated Schnorr proof.
    let (beta, lambda) = verify_delegated_schnorr(
        &pc_gens,
        &vec![com_amount, com_asset_type],
        &proof.0,
        &mut transcript,
    )
    .c(d!())?;

    // 3. Verify the inspector's proof.
    verify_inspection(params, abar.commitment, &proof.0, &proof.1, &beta, &lambda).c(d!())
}

/// Generate the inspector's proof.
pub(crate) fn prove_bar_to_abar_cs<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    amount: BLSScalar,
    asset_type: BLSScalar,
    blind_hash: BLSScalar,
    pubkey: &AXfrPubKey,
    delegated_schnorr_proof: &DelegatedSchnorrProof<
        RistrettoScalar,
        RistrettoPoint,
        SimFrParamsRistretto,
    >,
    inspection: &DelegatedSchnorrInspection<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto>,
    beta: &RistrettoScalar,
    lambda: &RistrettoScalar,
    comm_trace: &AnemoiVLHTrace<BLSScalar, 2, 12>,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(BAR_TO_ABAR_PLONK_PROOF_TRANSCRIPT);
    let (mut cs, _) = build_bar_to_abar_cs(
        amount,
        asset_type,
        blind_hash,
        pubkey,
        delegated_schnorr_proof,
        inspection,
        beta,
        lambda,
        comm_trace,
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
    .c(d!(NoahError::AXfrProofError))
}

/// Verify the inspector's proof.
pub(crate) fn verify_inspection(
    params: &VerifierParams,
    hash_comm: BLSScalar,
    proof_zk_part: &DelegatedSchnorrProof<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto>,
    proof: &AXfrPlonkPf,
    beta: &RistrettoScalar,
    lambda: &RistrettoScalar,
) -> Result<()> {
    let mut transcript = Transcript::new(BAR_TO_ABAR_PLONK_PROOF_TRANSCRIPT);
    let mut online_inputs = Vec::with_capacity(2 + 3 * SimFrParamsRistretto::NUM_OF_LIMBS);
    online_inputs.push(hash_comm);
    online_inputs.push(proof_zk_part.inspection_comm);
    let beta_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&beta.to_bytes()));
    let lambda_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&lambda.to_bytes()));

    let beta_lambda = *beta * lambda;
    let beta_lambda_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&beta_lambda.to_bytes()));

    let s1_plus_lambda_s2 =
        proof_zk_part.response_scalars[0].0 + proof_zk_part.response_scalars[1].0 * lambda;
    let s1_plus_lambda_s2_sim_fr =
        SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&s1_plus_lambda_s2.to_bytes()));

    online_inputs.extend_from_slice(&beta_sim_fr.limbs);
    online_inputs.extend_from_slice(&lambda_sim_fr.limbs);
    online_inputs.extend_from_slice(&beta_lambda_sim_fr.limbs);
    online_inputs.extend_from_slice(&s1_plus_lambda_s2_sim_fr.limbs);

    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        proof,
    )
    .c(d!(NoahError::ZKProofVerificationError))
}

/// Construct the confidential-to-anonymous constraint system.
pub(crate) fn build_bar_to_abar_cs(
    amount: BLSScalar,
    asset_type: BLSScalar,
    blind: BLSScalar,
    pubkey: &AXfrPubKey,
    proof: &DelegatedSchnorrProof<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto>,
    non_zk_state: &DelegatedSchnorrInspection<
        RistrettoScalar,
        RistrettoPoint,
        SimFrParamsRistretto,
    >,
    beta: &RistrettoScalar,
    lambda: &RistrettoScalar,
    comm_trace: &AnemoiVLHTrace<BLSScalar, 2, 12>,
) -> (TurboPlonkCS, usize) {
    let mut cs = TurboCS::new();
    cs.load_anemoi_jive_parameters::<AnemoiJive381>();

    let zero_var = cs.zero_var();

    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let step_1 = BLSScalar::from(&BigUint::one().shl(SimFrParamsRistretto::BIT_PER_LIMB));
    let step_2 = BLSScalar::from(&BigUint::one().shl(SimFrParamsRistretto::BIT_PER_LIMB * 2));
    let step_3 = BLSScalar::from(&BigUint::one().shl(SimFrParamsRistretto::BIT_PER_LIMB * 3));
    let step_4 = BLSScalar::from(&BigUint::one().shl(SimFrParamsRistretto::BIT_PER_LIMB * 4));
    let step_5 = BLSScalar::from(&BigUint::one().shl(SimFrParamsRistretto::BIT_PER_LIMB * 5));

    // 1. Input commitment witnesses.
    let amount_var = cs.new_variable(amount);
    let at_var = cs.new_variable(asset_type);
    let blind_var = cs.new_variable(blind);

    let public_key_scalars = pubkey.get_public_key_scalars().unwrap();
    let public_key_scalars_vars = [
        cs.new_variable(public_key_scalars[0]),
        cs.new_variable(public_key_scalars[1]),
        cs.new_variable(public_key_scalars[2]),
    ];

    // 2. Input witness x, y, a, b, r, public input comm, beta, s1, s2.
    let x_sim_fr = SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(
        &non_zk_state.committed_data_and_randomizer[0].0.to_bytes(),
    ));
    let y_sim_fr = SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(
        &non_zk_state.committed_data_and_randomizer[1].0.to_bytes(),
    ));
    let a_sim_fr = SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(
        &non_zk_state.committed_data_and_randomizer[0].1.to_bytes(),
    ));
    let b_sim_fr = SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(
        &non_zk_state.committed_data_and_randomizer[1].1.to_bytes(),
    ));
    let comm = proof.inspection_comm;
    let r = non_zk_state.r;

    let beta_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta.to_bytes()));
    let lambda_sim_fr = SimFr::from(&BigUint::from_bytes_le(&lambda.to_bytes()));

    let beta_lambda = *beta * lambda;
    let beta_lambda_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta_lambda.to_bytes()));

    let s1_plus_lambda_s2 = proof.response_scalars[0].0 + proof.response_scalars[1].0 * lambda;
    let s1_plus_lambda_s2_sim_fr =
        SimFr::from(&BigUint::from_bytes_le(&s1_plus_lambda_s2.to_bytes()));

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

    // 4. Open the inspector's state commitment.
    {
        let trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[
            compressed_limbs[0],
            compressed_limbs[1],
            compressed_limbs[2],
            compressed_limbs[3],
            compressed_limbs[4],
            r,
        ]);

        cs.anemoi_variable_length_hash(
            &trace,
            &[
                compressed_limbs_var[0],
                compressed_limbs_var[1],
                compressed_limbs_var[2],
                compressed_limbs_var[3],
                compressed_limbs_var[4],
                r_var,
            ],
            comm_var,
        );
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

        cs.equal(x_in_bls12_381, amount_var);
        cs.equal(y_in_bls12_381, at_var);
    }

    // 7. Coin commitment
    let coin_comm_var = commit_in_cs(
        &mut cs,
        blind_var,
        amount_var,
        at_var,
        &public_key_scalars_vars,
        comm_trace,
    );

    // prepare public inputs.
    cs.prepare_pi_variable(coin_comm_var);
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

    // pad the number of constraints to power of two.
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

#[cfg(test)]
mod test {
    use crate::anon_xfr::{
        bar_to_abar::BAR_TO_ABAR_PLONK_PROOF_TRANSCRIPT, commit, keys::AXfrKeyPair,
    };
    use crate::xfr::structs::AssetType;
    use ark_std::test_rng;
    use merlin::Transcript;
    use noah_algebra::{bls12_381::BLSScalar, ristretto::RistrettoScalar, traits::Scalar};
    use noah_crypto::{
        basic::pedersen_comm::{PedersenCommitment, PedersenCommitmentRistretto},
        delegated_schnorr::prove_delegated_schnorr,
        field_simulation::{SimFr, SimFrParams, SimFrParamsRistretto},
    };
    use num_bigint::BigUint;
    use num_traits::One;
    use std::ops::AddAssign;

    #[test]
    fn test_bar_to_abar() {
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();

        // 1. compute the parameters
        let amount = 71u64;
        let asset_type = AssetType::from_identical_byte(1u8);

        let amount_bls12_381 = BLSScalar::from(amount);
        let asset_type_bls12_381: BLSScalar = asset_type.as_scalar();

        let x = RistrettoScalar::from_bytes(&amount_bls12_381.to_bytes()).unwrap();
        let y: RistrettoScalar =
            RistrettoScalar::from_bytes(&asset_type_bls12_381.to_bytes()).unwrap();

        let gamma = RistrettoScalar::random(&mut prng);
        let delta = RistrettoScalar::random(&mut prng);

        let point_p = pc_gens.commit(x, gamma);
        let point_q = pc_gens.commit(y, delta);

        let z_randomizer = BLSScalar::random(&mut prng);
        let keypair = AXfrKeyPair::generate(&mut prng);
        let pubkey = keypair.get_public_key();

        let (z, output_commitment_trace) =
            commit(&pubkey, z_randomizer, 71u64, asset_type.as_scalar()).unwrap();

        // 2. compute the ZK part of the proof

        let mut transcript = Transcript::new(BAR_TO_ABAR_PLONK_PROOF_TRANSCRIPT);
        transcript.append_message(b"commitment", &z.to_bytes());

        let (proof, non_zk_state, beta, lambda) = prove_delegated_schnorr(
            &mut prng,
            &vec![(x, gamma), (y, delta)],
            &pc_gens,
            &vec![point_p, point_q],
            &mut transcript,
        )
        .unwrap();

        // compute cs
        let (mut cs, _) = super::build_bar_to_abar_cs(
            amount_bls12_381,
            asset_type_bls12_381,
            z_randomizer,
            &pubkey,
            &proof,
            &non_zk_state,
            &beta,
            &lambda,
            &output_commitment_trace,
        );
        let witness = cs.get_and_clear_witness();

        let mut online_inputs = Vec::with_capacity(2 + 3 * SimFrParamsRistretto::NUM_OF_LIMBS);
        online_inputs.push(z);
        online_inputs.push(proof.inspection_comm);

        let beta_sim_fr =
            SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&beta.to_bytes()));
        let lambda_sim_fr =
            SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&lambda.to_bytes()));

        let beta_lambda = beta * &lambda;
        let beta_lambda_sim_fr =
            SimFr::<SimFrParamsRistretto>::from(&BigUint::from_bytes_le(&beta_lambda.to_bytes()));

        let s1_plus_lambda_s2 = proof.response_scalars[0].0 + proof.response_scalars[1].0 * lambda;
        let s1_plus_lambda_s2_sim_fr = SimFr::<SimFrParamsRistretto>::from(
            &BigUint::from_bytes_le(&s1_plus_lambda_s2.to_bytes()),
        );

        online_inputs.extend_from_slice(&beta_sim_fr.limbs);
        online_inputs.extend_from_slice(&lambda_sim_fr.limbs);
        online_inputs.extend_from_slice(&beta_lambda_sim_fr.limbs);
        online_inputs.extend_from_slice(&s1_plus_lambda_s2_sim_fr.limbs);

        // Check the constraints
        assert!(cs.verify_witness(&witness, &online_inputs).is_ok());
        online_inputs[0].add_assign(&BLSScalar::one());
        assert!(cs.verify_witness(&witness, &online_inputs).is_err());
    }
}
