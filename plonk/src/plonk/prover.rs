use crate::plonk::transcript::transcript_get_plonk_challenge_u;
use crate::plonk::{
    constraint_system::ConstraintSystem,
    errors::PlonkError,
    helpers::{
        hide_polynomial, pi_poly, r_poly, split_t_and_commit, t_poly, z_poly, PlonkChallenges,
    },
    indexer::{PlonkPK, PlonkPf, PlonkProof},
    transcript::{
        transcript_get_plonk_challenge_alpha, transcript_get_plonk_challenge_beta,
        transcript_get_plonk_challenge_gamma, transcript_get_plonk_challenge_zeta,
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
///     constraint_system::TurboCS,
///     verifier::verifier,
///     prover::prover,
///     indexer::indexer
/// };
/// use zei_plonk::poly_commit::kzg_poly_com::KZGCommitmentScheme;
/// use merlin::Transcript;
/// use rand_chacha::ChaChaRng;
/// use zei_algebra::{prelude::*, bls12_381::BLSScalar};
///
/// let mut prng = ChaChaRng::from_seed([0u8; 32]);
/// let pcs = KZGCommitmentScheme::new(20, &mut prng);
/// let mut cs = TurboCS::new();
///
/// // circuit (x_0 + x_1);
/// let one = BLSScalar::one();
/// let two = one.add(&one);
/// let three = two.add(&one);
/// let var_one = cs.new_variable(one);
/// let var_two = cs.new_variable(two);
/// let var_three = cs.new_variable(three);
/// cs.insert_add_gate(var_one, var_two, var_three);
/// cs.pad();///
///
/// let witness = cs.get_and_clear_witness();
/// let prover_params = indexer(&cs, &pcs).unwrap();
///
/// let proof = {
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
/// let mut transcript = Transcript::new(b"Test");
/// assert!(
///     verifier(&mut transcript, &pcs, &cs, &prover_params.get_verifier_params(), &[], &proof).is_ok()
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
    prover_with_lagrange(prng, transcript, pcs, None, cs, params, witness)
}

/// Prover that uses Lagrange bases
pub fn prover_with_lagrange<
    R: CryptoRng + RngCore,
    PCS: PolyComScheme,
    CS: ConstraintSystem<Field = PCS::Field>,
>(
    prng: &mut R,
    transcript: &mut Transcript,
    pcs: &PCS,
    lagrange_pcs: Option<&PCS>,
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

    let lagrange_pcs = if lagrange_pcs.is_some() {
        if lagrange_pcs.unwrap().max_degree() + 1 == n_constraints {
            lagrange_pcs
        } else {
            None
        }
    } else {
        None
    };

    // Prepare extended witness
    let extended_witness = cs.extend_witness(witness);
    let io = pi_poly::<PCS>(&params, &online_values);

    // 1. build witness polynomials, hide them and commit
    let root = &params.verifier_params.root;
    let n_wires_per_gate = CS::n_wires_per_gate();
    let mut witness_polys = vec![];
    let mut c_witness_polys = vec![];
    if let Some(lagrange_pcs) = lagrange_pcs {
        for i in 0..n_wires_per_gate {
            let f_eval = FpPolynomial::from_coefs(
                extended_witness[i * n_constraints..(i + 1) * n_constraints].to_vec(),
            );
            let mut f = FpPolynomial::ffti(
                root,
                &extended_witness[i * n_constraints..(i + 1) * n_constraints],
                n_constraints,
            );
            let blinds = hide_polynomial(prng, &mut f, 1, n_constraints);
            let c_f = lagrange_pcs
                .commit(&f_eval)
                .c(d!(PlonkError::CommitmentError))?;
            let c_f = pcs.apply_blind_factors(&c_f, &blinds, n_constraints);
            transcript.append_commitment::<PCS::Commitment>(&c_f);
            witness_polys.push(f_eval);
            c_witness_polys.push(c_f);
        }
    } else {
        for i in 0..n_wires_per_gate {
            let mut f = FpPolynomial::ffti(
                root,
                &extended_witness[i * n_constraints..(i + 1) * n_constraints],
                n_constraints,
            );
            let _ = hide_polynomial(prng, &mut f, 1, n_constraints);
            let c_f = pcs.commit(&f).c(d!(PlonkError::CommitmentError))?;
            transcript.append_commitment::<PCS::Commitment>(&c_f);
            witness_polys.push(f);
            c_witness_polys.push(c_f);
        }
    }

    // 2. get challenges gamma and delta
    let gamma = transcript_get_plonk_challenge_beta(transcript, n_constraints);
    let delta = transcript_get_plonk_challenge_gamma(transcript, n_constraints);
    challenges.insert_beta_gamma(gamma, delta).unwrap(); // safe unwrap

    // 3. build sigma, hide it and commit
    let (c_sigma, sigma) = if let Some(lagrange_pcs) = lagrange_pcs {
        let sigma_evals = z_poly::<PCS, CS>(cs, params, &extended_witness, &challenges);
        let mut sigma = FpPolynomial::ffti(
            &params.verifier_params.root,
            &sigma_evals.coefs,
            n_constraints,
        );
        let blinds = hide_polynomial(prng, &mut sigma, 2, n_constraints);
        let c_sigma = lagrange_pcs
            .commit(&sigma_evals)
            .c(d!(PlonkError::CommitmentError))?;
        let c_sigma = pcs.apply_blind_factors(&c_sigma, &blinds, n_constraints);
        transcript.append_commitment::<PCS::Commitment>(&c_sigma);
        (c_sigma, sigma)
    } else {
        let sigma_evals = z_poly::<PCS, CS>(cs, params, &extended_witness, &challenges);
        let mut sigma = FpPolynomial::ffti(
            &params.verifier_params.root,
            &sigma_evals.coefs,
            n_constraints,
        );
        let _ = hide_polynomial(prng, &mut sigma, 2, n_constraints);
        let c_sigma = pcs.commit(&sigma).c(d!(PlonkError::CommitmentError))?;
        transcript.append_commitment::<PCS::Commitment>(&c_sigma);

        (c_sigma, sigma)
    };

    // 4. get challenge alpha
    let alpha = transcript_get_plonk_challenge_alpha(transcript, n_constraints);
    challenges.insert_alpha(alpha).unwrap();

    // 5. build Q, split into `n_wires_per_gate` degree-(N+2) polynomials and commit
    let q = t_poly::<PCS, CS>(cs, params, &witness_polys, &sigma, &challenges, &io).c(d!())?;
    let (c_q_polys, o_q_polys) =
        split_t_and_commit(pcs, &q, n_wires_per_gate, n_constraints + 2).c(d!())?;

    for c_q in c_q_polys.iter() {
        transcript.append_commitment::<PCS::Commitment>(c_q);
    }

    // 6. get challenge beta
    let beta = transcript_get_plonk_challenge_zeta(transcript, n_constraints);
    challenges.insert_zeta(beta).unwrap();

    // 7. a) Evaluate the openings of witness/permutation polynomials at beta, and
    // evaluate the opening of Sigma(X) at point g * beta.
    let witness_polys_eval_beta: Vec<PCS::Field> = witness_polys
        .iter()
        .map(|open| pcs.eval(open, &beta))
        .collect();
    let perms_eval_beta: Vec<PCS::Field> = params
        .s_polys
        .iter()
        .take(n_wires_per_gate - 1)
        .map(|open| pcs.eval(open, &beta))
        .collect();

    let g_beta = root.mul(&beta);
    let sigma_eval_g_beta = pcs.eval(&sigma, &g_beta);

    //  b). build linearization polynomial r_beta(X), and eval at beta
    for eval_beta in witness_polys_eval_beta.iter().chain(perms_eval_beta.iter()) {
        transcript.append_field_elem(eval_beta);
    }
    transcript.append_field_elem(&sigma_eval_g_beta);

    let u = transcript_get_plonk_challenge_u(transcript, cs.size());
    challenges.insert_u(u).unwrap();

    let witness_polys_eval_beta_as_ref: Vec<&PCS::Field> = witness_polys_eval_beta.iter().collect();
    let perms_eval_beta_as_ref: Vec<&PCS::Field> = perms_eval_beta.iter().collect();

    let r_poly = r_poly::<PCS, CS>(
        params,
        &sigma,
        &witness_polys_eval_beta_as_ref[..],
        &perms_eval_beta_as_ref[..],
        &sigma_eval_g_beta,
        &challenges,
        &o_q_polys,
        n_constraints + 2,
    );

    let mut polys_to_open: Vec<&FpPolynomial<PCS::Field>> = witness_polys
        .iter()
        .chain(params.s_polys.iter().take(CS::n_wires_per_gate() - 1))
        .collect();
    polys_to_open.push(&r_poly);

    let beta = challenges.get_zeta().unwrap();

    let eval_proof_1 = pcs
        .batch_prove(transcript, &polys_to_open[..], &beta, n_constraints + 2)
        .c(d!(PlonkError::ProofError))?;

    let eval_proof_2 = pcs
        .prove(transcript, &sigma, &g_beta, n_constraints + 2)
        .c(d!(PlonkError::ProofError))?;

    // return proof
    Ok(PlonkProof {
        cm_w_vec: c_witness_polys,
        cm_t_vec: c_q_polys,
        cm_z: c_sigma,
        w_polys_eval_zeta: witness_polys_eval_beta,
        z_eval_zeta_omega: sigma_eval_g_beta,
        s_polys_eval_zeta: perms_eval_beta,
        opening_witness_zeta: eval_proof_1,
        opening_witness_zeta_omega: eval_proof_2,
    })
}
