use crate::plonk::{
    constraint_system::ConstraintSystem,
    errors::PlonkError,
    helpers::{
        combine_q_polys, hide_polynomial, linearization_polynomial_opening, public_vars_polynomial,
        quotient_polynomial, sigma_polynomial, split_q_and_commit, PlonkChallenges,
    },
    setup::{PlonkPK, PlonkPf, PlonkProof},
    transcript::{
        transcript_get_plonk_challenge_alpha, transcript_get_plonk_challenge_beta,
        transcript_get_plonk_challenge_delta, transcript_get_plonk_challenge_gamma,
        transcript_init_plonk,
    },
};
use crate::poly_commit::{
    field_polynomial::FpPolynomial, pcs::PolyComScheme, transcript::PolyComTranscript,
};
use merlin::Transcript;
use zei_algebra::prelude::*;

/// PLONK Prover: it produces a proof that `witness` satisfies the constraint system `cs`
/// Proof verifier must use a transcript with same state as prover and match the public parameters
/// Returns PlonkErrorInvalidWitness if witness does not satisfy the the constraint system.
/// It returns PlonkError if an error occurs in computing proof commitments, meaning parameters of the polynomial
/// commitment scheme `pcs` do not match the constraint system parameters.
/// # Example
/// ```
/// use zei_plonk::plonk::{
///     constraint_system::TurboConstraintSystem,
///     verifier::verifier,
///     prover::prover,
///     setup::{preprocess_prover, preprocess_verifier}
/// };
/// use zei_plonk::poly_commit::kzg_poly_com::KZGCommitmentScheme;
/// use merlin::Transcript;
/// use rand_chacha::ChaChaRng;
/// use zei_algebra::{prelude::*, bls12_381::BLSScalar};
///
/// let mut prng = ChaChaRng::from_seed([1u8; 32]);
/// let pcs = KZGCommitmentScheme::new(20, &mut prng);
/// let mut cs = TurboConstraintSystem::new();
///
/// // circuit (x_0 + x_1);
/// let one = BLSScalar::one();
/// let two = one.add(&one);
/// let three = two.add(&one);
/// let var_one = cs.new_variable(one);
/// let var_two = cs.new_variable(two);
/// let var_three = cs.new_variable(three);
/// cs.insert_add_gate(var_one, var_two, var_three);
/// cs.pad();
///
/// let common_seed = [0u8; 32];
/// let proof = {
///     let witness = cs.get_and_clear_witness();
///     let prover_params = preprocess_prover(&cs, &pcs, common_seed).unwrap();
///     let mut transcript = Transcript::new(b"Test");
///     prover(
///         &mut prng,
///         &mut transcript,
///         &pcs,
///         &cs,
///         &prover_params,
///         &witness,
///     )
///         .unwrap()
/// };
///
/// let verifier_params = preprocess_verifier(&cs, &pcs, common_seed).unwrap();
/// let mut transcript = Transcript::new(b"Test");
/// assert!(
///     verifier(&mut transcript, &pcs, &cs, &verifier_params, &[], &proof).is_ok()
/// )
/// ```
pub fn prover<
    R: CryptoRng + RngCore,
    PCS: PolyComScheme,
    CS: ConstraintSystem<Field = PCS::Field>,
>(
    prng: &mut R,
    transcript: &mut Transcript,
    pcs: &PCS,
    cs: &CS,
    params: &PlonkPK<PCS>,
    witness: &[PCS::Field],
) -> Result<PlonkPf<PCS>> {
    if cs.is_verifier_only() {
        return Err(eg!(PlonkError::FuncParamsError));
    }

    let online_values: Vec<PCS::Field> = cs
        .public_vars_witness_indices()
        .iter()
        .map(|index| witness[*index])
        .collect();
    // Init transcript
    transcript_init_plonk::<_, PCS::Field>(transcript, &params.verifier_params, &online_values);
    let mut challenges = PlonkChallenges::new();
    let n_constraints = cs.size();

    // Prepare extended witness
    let extended_witness = cs.extend_witness(witness);
    let io = public_vars_polynomial::<PCS>(&params, &online_values);

    // 1. build witness polynomials, hide them and commit
    let root = &params.verifier_params.root;
    let n_wires_per_gate = CS::n_wires_per_gate();
    let mut witness_openings = vec![];
    let mut c_witness_polys = vec![];
    for i in 0..n_wires_per_gate {
        let mut f = FpPolynomial::ffti(
            root,
            &extended_witness[i * n_constraints..(i + 1) * n_constraints],
            n_constraints,
        );
        hide_polynomial(prng, &mut f, 1, n_constraints);
        let (c_f, o_f) = pcs.commit(f).c(d!(PlonkError::CommitmentError))?;
        transcript.append_commitment::<PCS::Commitment>(&c_f);
        witness_openings.push(o_f);
        c_witness_polys.push(c_f);
    }

    // 2. get challenges gamma and delta
    let gamma = transcript_get_plonk_challenge_gamma(transcript, n_constraints);
    let delta = transcript_get_plonk_challenge_delta(transcript, n_constraints);
    challenges.insert_gamma_delta(gamma, delta).unwrap(); // safe unwrap

    // 3. build sigma, hide it and commit
    let mut sigma = sigma_polynomial::<PCS, CS>(cs, params, &extended_witness, &challenges);
    hide_polynomial(prng, &mut sigma, 2, n_constraints);
    let (c_sigma, o_sigma) = pcs.commit(sigma).c(d!(PlonkError::CommitmentError))?;
    transcript.append_commitment::<PCS::Commitment>(&c_sigma);

    // 4. get challenge alpha
    let alpha = transcript_get_plonk_challenge_alpha(transcript, n_constraints);
    challenges.insert_alpha(alpha).unwrap();

    // 5. build Q, split into `n_wires_per_gate` degree-(N+2) polynomials and commit
    // TODO: avoid the cloning when computing witness_polys and Sigma
    let witness_polys: Vec<FpPolynomial<PCS::Field>> = witness_openings
        .iter()
        .map(|open| pcs.polynomial_from_opening_ref(open))
        .collect();
    let sigma = pcs.polynomial_from_opening_ref(&o_sigma);
    let q = quotient_polynomial::<PCS, CS>(cs, params, &witness_polys, &sigma, &challenges, &io)
        .c(d!())?;
    let (c_q_polys, o_q_polys) =
        split_q_and_commit(pcs, &q, n_wires_per_gate, n_constraints + 2).c(d!())?;
    for c_q in c_q_polys.iter() {
        transcript.append_commitment::<PCS::Commitment>(c_q);
    }

    // 6. get challenge beta
    let beta = transcript_get_plonk_challenge_beta(transcript, n_constraints);

    // 7. a) Evaluate the openings of witness/permutation polynomials at beta, and
    // evaluate the opening of Sigma(X) at point g * beta.
    let witness_polys_eval_beta: Vec<PCS::Field> = witness_openings
        .iter()
        .map(|open| pcs.eval_opening(open, &beta))
        .collect();
    let perms_eval_beta: Vec<PCS::Field> = params
        .extended_permutations
        .iter()
        .take(n_wires_per_gate - 1)
        .map(|open| pcs.eval_opening(open, &beta))
        .collect();

    let g_beta = root.mul(&beta);
    let sigma_eval_g_beta = pcs.eval_opening(&o_sigma, &g_beta);

    challenges.insert_beta(beta).unwrap();

    //  b). build linearization polynomial r_beta(X), and eval at beta
    let witness_polys_eval_beta_as_ref: Vec<&PCS::Field> = witness_polys_eval_beta.iter().collect();
    let perms_eval_beta_as_ref: Vec<&PCS::Field> = perms_eval_beta.iter().collect();
    let o_l = linearization_polynomial_opening::<PCS, CS>(
        params,
        &o_sigma,
        &witness_polys_eval_beta_as_ref[..],
        &perms_eval_beta_as_ref[..],
        &sigma_eval_g_beta,
        &challenges,
    );
    for eval_beta in witness_polys_eval_beta.iter().chain(perms_eval_beta.iter()) {
        transcript.append_field_elem(eval_beta);
    }
    let beta = challenges.get_beta().unwrap();
    let l_eval_beta = pcs.eval_opening(&o_l, &beta);
    transcript.append_field_elem(&sigma_eval_g_beta);
    transcript.append_field_elem(&l_eval_beta);

    // 8. batch eval proofs
    let mut openings: Vec<&PCS::Opening> = witness_openings
        .iter()
        .chain(
            params
                .extended_permutations
                .iter()
                .take(CS::n_wires_per_gate() - 1),
        )
        .collect();
    let o_q_combined = combine_q_polys(&o_q_polys, &beta, n_constraints + 2);
    openings.push(&o_q_combined);
    openings.push(&o_l);
    openings.push(&o_sigma);
    // n_wires_per_gate opening proofs for witness polynomials; n_wires_per_gate-1 opening proofs
    // for the first n_wires_per_gate-1 extended permutations; 1 opening proof for each of [Q(X), L(X)]
    let mut points = vec![*beta; 2 * n_wires_per_gate + 1];
    // One opening proof for Sigma(X) at point g * beta
    points.push(g_beta);
    let (_, batch_eval_proof) = pcs
        .batch_prove_eval(
            transcript,
            &openings[..],
            &points[..],
            n_constraints + 2,
            None,
        )
        .c(d!(PlonkError::ProofError))?;

    // return proof
    Ok(PlonkProof {
        c_witness_polys,
        c_q_polys,
        c_sigma,
        witness_polys_eval_beta,
        sigma_eval_g_beta,
        perms_eval_beta,
        l_eval_beta,
        batch_eval_proof,
    })
}
