use crate::plonk::{
    constraint_system::ConstraintSystem,
    errors::PlonkError,
    helpers::{eval_pi_poly, first_lagrange_poly, r_commitment, r_eval_zeta, PlonkChallenges},
    indexer::{get_domain_and_root, PlonkPf, PlonkVK},
    transcript::{
        transcript_get_plonk_challenge_alpha, transcript_get_plonk_challenge_beta,
        transcript_get_plonk_challenge_gamma, transcript_get_plonk_challenge_u,
        transcript_get_plonk_challenge_zeta, transcript_init_plonk,
    },
};
use crate::poly_commit::{pcs::PolyComScheme, transcript::PolyComTranscript};
use merlin::Transcript;
use noah_algebra::prelude::*;

/// Verify a proof.
pub fn verifier<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    transcript: &mut Transcript,
    pcs: &PCS,
    cs: &CS,
    verifier_params: &PlonkVK<PCS>,
    pi: &[PCS::Field],
    proof: &PlonkPf<PCS>,
) -> Result<()> {
    let (_, root) = get_domain_and_root::<PCS>(&verifier_params.domain);
    transcript_init_plonk(transcript, verifier_params, pi, &root);
    let mut challenges = PlonkChallenges::new();
    // 1. compute all challenges such as gamma, beta, alpha, zeta and u.
    compute_challenges::<PCS>(&mut challenges, transcript, &proof, cs.size());

    // 2. compute Z_h(\zeta) and L_1(\zeta).
    let (z_h_eval_zeta, first_lagrange_eval_zeta) =
        first_lagrange_poly::<PCS>(&challenges, verifier_params.cs_size as u64);

    // 3. compute PI(\zeta).
    let pi_eval_zeta = eval_pi_poly::<PCS>(
        verifier_params,
        pi,
        &z_h_eval_zeta,
        challenges.get_zeta().unwrap(),
        &root,
    );

    // 4. derive the linearization polynomial commitment.
    let r_eval_zeta = r_eval_zeta::<PCS>(
        proof,
        &challenges,
        &pi_eval_zeta,
        &first_lagrange_eval_zeta,
        verifier_params.anemoi_generator,
        verifier_params.anemoi_generator_inv,
    );

    let w_polys_eval_zeta_as_ref: Vec<&PCS::Field> = proof.w_polys_eval_zeta.iter().collect();
    let s_eval_zeta_as_ref: Vec<&PCS::Field> = proof.s_polys_eval_zeta.iter().collect();
    let cm_r = r_commitment::<PCS, CS>(
        verifier_params,
        &proof.cm_z,
        &w_polys_eval_zeta_as_ref[..],
        &s_eval_zeta_as_ref[..],
        &proof.prk_3_poly_eval_zeta,
        &proof.z_eval_zeta_omega,
        &challenges,
        &proof.cm_t_vec[..],
        &first_lagrange_eval_zeta,
        &z_h_eval_zeta,
        verifier_params.cs_size + 2,
    );

    // 5. verify opening proofs.
    let mut commitments: Vec<&PCS::Commitment> = proof
        .cm_w_vec
        .iter()
        .chain(
            verifier_params
                .cm_s_vec
                .iter()
                .take(CS::n_wires_per_gate() - 1),
        )
        .collect();
    commitments.push(&verifier_params.cm_prk_vec[2]);
    commitments.push(&verifier_params.cm_prk_vec[3]);
    commitments.push(&cm_r);

    let mut values: Vec<PCS::Field> = proof
        .w_polys_eval_zeta
        .iter()
        .chain(proof.s_polys_eval_zeta.iter())
        .cloned()
        .collect();
    values.push(proof.prk_3_poly_eval_zeta);
    values.push(proof.prk_4_poly_eval_zeta);
    values.push(r_eval_zeta);

    let zeta = challenges.get_zeta().unwrap();
    let zeta_omega = zeta.mul(&root);

    let (comm, val) = pcs.batch(
        transcript,
        &commitments[..],
        verifier_params.cs_size + 2,
        &zeta,
        &values[..],
    );

    let (comm_omega, val_omega) = pcs.batch(
        transcript,
        &[
            &proof.cm_z,
            &proof.cm_w_vec[0],
            &proof.cm_w_vec[1],
            &proof.cm_w_vec[2],
        ],
        verifier_params.cs_size + 2,
        &zeta_omega,
        &[
            proof.z_eval_zeta_omega,
            proof.w_polys_eval_zeta_omega[0],
            proof.w_polys_eval_zeta_omega[1],
            proof.w_polys_eval_zeta_omega[2],
        ],
    );

    pcs.batch_verify_diff_points(
        transcript,
        &[comm, comm_omega],
        verifier_params.cs_size + 32,
        &[zeta.clone(), zeta_omega.clone()],
        &[val, val_omega],
        &[
            proof.opening_witness_zeta.clone(),
            proof.opening_witness_zeta_omega.clone(),
        ],
        challenges.get_u().unwrap(),
    )
    .c(d!(PlonkError::VerificationError))
}

fn compute_challenges<PCS: PolyComScheme>(
    challenges: &mut PlonkChallenges<PCS::Field>,
    transcript: &mut Transcript,
    proof: &PlonkPf<PCS>,
    group_order: usize,
) {
    // 1. compute gamma and beta challenges.
    for cm_w in proof.cm_w_vec.iter() {
        transcript.append_commitment::<PCS::Commitment>(cm_w);
    }
    let beta = transcript_get_plonk_challenge_beta(transcript, group_order);
    let gamma = transcript_get_plonk_challenge_gamma(transcript, group_order);
    challenges.insert_beta_gamma(beta, gamma).unwrap();

    // 2. compute alpha challenge.
    transcript.append_commitment::<PCS::Commitment>(&proof.cm_z);
    let alpha = transcript_get_plonk_challenge_alpha(transcript, group_order);
    challenges.insert_alpha(alpha).unwrap();
    for cm_t in &proof.cm_t_vec {
        transcript.append_commitment::<PCS::Commitment>(&cm_t);
    }

    // 3. compute zeta challenge.
    let zeta = transcript_get_plonk_challenge_zeta(transcript, group_order);
    challenges.insert_zeta(zeta).unwrap();
    for eval_zeta in proof
        .w_polys_eval_zeta
        .iter()
        .chain(proof.s_polys_eval_zeta.iter())
    {
        transcript.append_field_elem(eval_zeta);
    }
    transcript.append_field_elem(&proof.prk_3_poly_eval_zeta);
    transcript.append_field_elem(&proof.prk_4_poly_eval_zeta);
    transcript.append_field_elem(&proof.z_eval_zeta_omega);
    for eval_zeta_omega in proof.w_polys_eval_zeta_omega.iter() {
        transcript.append_field_elem(eval_zeta_omega);
    }

    // 4. compute u challenge.
    let u = transcript_get_plonk_challenge_u(transcript, group_order);
    challenges.insert_u(u).unwrap();
}
