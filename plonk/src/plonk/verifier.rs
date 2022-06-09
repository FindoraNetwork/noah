use crate::plonk::{
    constraint_system::ConstraintSystem,
    errors::PlonkError,
    helpers::{
        derive_q_eval_beta, eval_public_var_poly, linearization_commitment, PlonkChallenges,
    },
    setup::{PlonkPf, PlonkVK},
    transcript::{
        transcript_get_plonk_challenge_alpha, transcript_get_plonk_challenge_beta,
        transcript_get_plonk_challenge_delta, transcript_get_plonk_challenge_gamma,
        transcript_init_plonk,
    },
};
use crate::poly_commit::{pcs::PolyComScheme, transcript::PolyComTranscript};
use merlin::Transcript;
use zei_algebra::prelude::*;

/// Verify a proof for a constraint system previously preprocessed into `cs_params`
/// State of the transcript must match prover state of the transcript
/// Polynomial Commitement parameters must be shared between prover and verifier.
/// # Example
/// See plonk::prover::prover
pub fn verifier<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    transcript: &mut Transcript,
    pcs: &PCS,
    cs: &CS,
    cs_params: &PlonkVK<PCS>,
    public_values: &[PCS::Field],
    proof: &PlonkPf<PCS>,
) -> Result<()> {
    transcript_init_plonk(transcript, cs_params, public_values);

    let mut challenges = PlonkChallenges::new();

    // 1. compute gamma and delta challenges
    for c in proof.c_witness_polys.iter() {
        transcript.append_commitment::<PCS::Commitment>(c);
    }
    let gamma = transcript_get_plonk_challenge_gamma(transcript, cs.size());
    let delta = transcript_get_plonk_challenge_delta(transcript, cs.size());
    challenges.insert_gamma_delta(gamma, delta).unwrap();

    // 2. compute alpha challenge
    transcript.append_commitment::<PCS::Commitment>(&proof.c_sigma);
    let alpha = transcript_get_plonk_challenge_alpha(transcript, cs.size());
    challenges.insert_alpha(alpha).unwrap();
    for c_q in &proof.c_q_polys {
        transcript.append_commitment::<PCS::Commitment>(&c_q);
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
    transcript.append_field_elem(&proof.sigma_eval_g_beta);

    let public_vars_eval_beta =
        eval_public_var_poly::<PCS>(cs_params, public_values, challenges.get_beta().unwrap());

    // 4. derive linearization polynomial commitment
    // Note: for completeness steps 5 and 6 is analogous to getting Q(beta) in the proof,
    // verify it, and then check that
    // P(\beta) - Q(\beta) * Z_H(\beta) (plus checking all eval proofs)

    // 5. derive value of Q(\beta) such that P(\beta) - Q(\beta) * Z_H(\beta) = 0
    let beta = challenges.get_beta().unwrap();
    let derived_q_eval_beta =
        derive_q_eval_beta::<PCS>(cs_params, proof, &challenges, &public_vars_eval_beta);
    let g_beta = beta.mul(&cs_params.root);

    let witness_polys_eval_beta_as_ref: Vec<&PCS::Field> =
        proof.witness_polys_eval_beta.iter().collect();
    let perms_eval_beta_as_ref: Vec<&PCS::Field> = proof.perms_eval_beta.iter().collect();
    let c_q_combined = linearization_commitment::<PCS, CS>(
        cs_params,
        &proof.c_sigma,
        &witness_polys_eval_beta_as_ref[..],
        &perms_eval_beta_as_ref[..],
        &proof.sigma_eval_g_beta,
        &challenges,
        &proof.c_q_polys[..],
        cs_params.cs_size + 2,
    );

    // 6. verify batch eval proofs for witness/permutation polynomials evaluations
    // at point beta, and Q(beta), L(beta), \Sigma(g*beta)
    let mut commitments: Vec<&PCS::Commitment> = proof
        .c_witness_polys
        .iter()
        .chain(
            cs_params
                .extended_permutations
                .iter()
                .take(CS::n_wires_per_gate() - 1),
        )
        .collect();
    commitments.push(&c_q_combined);
    let mut values: Vec<PCS::Field> = proof
        .witness_polys_eval_beta
        .iter()
        .chain(proof.perms_eval_beta.iter())
        .cloned()
        .collect();
    values.push(derived_q_eval_beta);
    pcs.batch_verify(
        transcript,
        &commitments[..],
        cs_params.cs_size + 2,
        &beta,
        &values[..],
        &proof.eval_proof_1,
    )
    .c(d!(PlonkError::VerificationError))
    /*pcs.verify(
        transcript,
        &proof.c_sigma,
        cs_params.cs_size + 2,
        &g_beta,
        &proof.sigma_eval_g_beta,
        &proof.eval_proof_2,
    )
    .c(d!(PlonkError::VerificationError))*/
}
