use algebra::traits::ScalarArithmetic;
use merlin::Transcript;
use ruc::*;

use crate::commitments::{pcs::PolyComScheme, transcript::PolyComTranscript};
use crate::plonk::{
    constraint_system::ConstraintSystem,
    errors::PlonkError,
    helpers::{
        combine_q_polys, derive_q_eval_beta, eval_public_var_poly, linearization_commitment,
        PlonkChallenges,
    },
    setup::{PlonkPf, VerifierParams},
    transcript::{
        transcript_get_plonk_challenge_alpha, transcript_get_plonk_challenge_beta,
        transcript_get_plonk_challenge_delta, transcript_get_plonk_challenge_gamma,
        transcript_init_plonk,
    },
};

/// Verify a proof for a constraint system previously preprocessed into `cs_params`
/// State of the transcript must match prover state of the transcript
/// Polynomial Commitement parameters must be shared between prover and verifier.
/// # Example
/// See plonk::prover::prover
#[allow(non_snake_case)]
pub fn verifier<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    transcript: &mut Transcript,
    pcs: &PCS,
    cs: &CS,
    cs_params: &VerifierParams<PCS>,
    public_values: &[PCS::Field],
    proof: &PlonkPf<PCS>,
) -> Result<()> {
    transcript_init_plonk(transcript, cs_params, public_values);

    let mut challenges = PlonkChallenges::new();

    // 1. compute gamma and delta challenges
    for C in proof.C_witness_polys.iter() {
        transcript.append_commitment::<PCS::Commitment>(C);
    }
    let gamma = transcript_get_plonk_challenge_gamma(transcript, cs.size());
    let delta = transcript_get_plonk_challenge_delta(transcript, cs.size());
    challenges.insert_gamma_delta(gamma, delta).unwrap();

    // 2. compute alpha challenge
    transcript.append_commitment::<PCS::Commitment>(&proof.C_Sigma);
    let alpha = transcript_get_plonk_challenge_alpha(transcript, cs.size());
    challenges.insert_alpha(alpha).unwrap();
    for C_q in &proof.C_q_polys {
        transcript.append_commitment::<PCS::Commitment>(&C_q);
    }

    // 3. compute beta challenge
    let beta = transcript_get_plonk_challenge_beta(transcript, cs.size());
    challenges.insert_beta(beta).unwrap();
    for eval_beta in proof
        .witness_polys_eval_beta
        .iter()
        .chain(proof.perms_eval_beta.iter())
    {
        transcript.append_field_elem(eval_beta);
    }
    transcript.append_field_elem(&proof.Sigma_eval_g_beta);
    transcript.append_field_elem(&proof.L_eval_beta);

    let public_vars_eval_beta =
        eval_public_var_poly::<PCS>(cs_params, public_values, challenges.get_beta().unwrap());

    // 4. derive linearization polynomial commitment
    let witness_polys_eval_beta_as_ref: Vec<&PCS::Field> =
        proof.witness_polys_eval_beta.iter().collect();
    let perms_eval_beta_as_ref: Vec<&PCS::Field> = proof.perms_eval_beta.iter().collect();
    let C_L = linearization_commitment::<PCS, CS>(
        cs_params,
        &proof.C_Sigma,
        &witness_polys_eval_beta_as_ref[..],
        &perms_eval_beta_as_ref[..],
        &proof.Sigma_eval_g_beta,
        &challenges,
    );
    // Note: for completeness steps 5 and 6 is analogous to getting Q(beta) in the proof, verify it, and then
    // check that P(\beta) - Q(\beta) * Z_H(\beta) (plus checking all eval proofs)

    // 5. derive value of Q(\beta) such that P(\beta) - Q(\beta) * Z_H(\beta) = 0
    let beta = challenges.get_beta().unwrap();
    let derived_q_eval_beta =
        derive_q_eval_beta::<PCS>(cs_params, proof, &challenges, &public_vars_eval_beta);
    let g_beta = beta.mul(&cs_params.root);

    // 6. verify batch eval proofs for witness/permutation polynomials evaluations at point beta, and Q(beta), L(beta), \Sigma(g*beta)
    let mut commitments: Vec<&PCS::Commitment> = proof
        .C_witness_polys
        .iter()
        .chain(
            cs_params
                .extended_permutations
                .iter()
                .take(CS::n_wires_per_gate() - 1),
        )
        .collect();
    let C_q_combined = combine_q_polys(&proof.C_q_polys[..], &beta, cs_params.cs_size + 2);
    commitments.push(&C_q_combined);
    commitments.push(&C_L);
    commitments.push(&proof.C_Sigma);
    let mut points = vec![*beta; 2 * CS::n_wires_per_gate() + 1];
    points.push(g_beta);
    let mut values: Vec<PCS::Field> = proof
        .witness_polys_eval_beta
        .iter()
        .chain(proof.perms_eval_beta.iter())
        .cloned()
        .collect();
    values.push(derived_q_eval_beta);
    values.push(proof.L_eval_beta);
    values.push(proof.Sigma_eval_g_beta);
    pcs.batch_verify_eval(
        transcript,
        &commitments[..],
        cs_params.cs_size + 2,
        &points[..],
        &values[..],
        &proof.batch_eval_proof,
        None,
    )
    .c(d!(PlonkError::VerificationError))
}
