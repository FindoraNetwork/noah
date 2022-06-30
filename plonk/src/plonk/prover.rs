use crate::plonk::{
    constraint_system::ConstraintSystem,
    errors::PlonkError,
    helpers::{
        hide_polynomial, pi_poly, r_poly, split_t_and_commit, t_poly, z_poly, PlonkChallenges,
    },
    indexer::{PlonkPK, PlonkPf, PlonkProof},
    transcript::{
        transcript_get_plonk_challenge_alpha, transcript_get_plonk_challenge_beta,
        transcript_get_plonk_challenge_gamma, transcript_get_plonk_challenge_u,
        transcript_get_plonk_challenge_zeta, transcript_init_plonk,
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
    prover_params: &PlonkPK<PCS>,
    w: &[PCS::Field],
) -> Result<PlonkPf<PCS>> {
    if cs.is_verifier_only() {
        return Err(eg!(PlonkError::FuncParamsError));
    }

    let online_values: Vec<PCS::Field> = cs
        .public_vars_witness_indices()
        .iter()
        .map(|index| w[*index])
        .collect();
    // Init transcript
    transcript_init_plonk::<_, PCS::Field>(
        transcript,
        &prover_params.verifier_params,
        &online_values,
    );
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
    let extended_witness = cs.extend_witness(w);
    let pi = pi_poly::<PCS>(&prover_params, &online_values);

    // 1. build witness polynomials, hide them and commit
    let root = &prover_params.verifier_params.root;
    let n_wires_per_gate = CS::n_wires_per_gate();
    let mut w_polys = vec![];
    let mut cm_w_vec = vec![];
    if let Some(lagrange_pcs) = lagrange_pcs {
        for i in 0..n_wires_per_gate {
            let f_eval = FpPolynomial::from_coefs(
                extended_witness[i * n_constraints..(i + 1) * n_constraints].to_vec(),
            );
            let mut f_coefs = FpPolynomial::ffti(
                root,
                &extended_witness[i * n_constraints..(i + 1) * n_constraints],
                n_constraints,
            );
            let blinds = hide_polynomial(prng, &mut f_coefs, 1, n_constraints);
            let cm_w = lagrange_pcs
                .commit(&f_eval)
                .c(d!(PlonkError::CommitmentError))?;
            let cm_w = pcs.apply_blind_factors(&cm_w, &blinds, n_constraints);
            transcript.append_commitment::<PCS::Commitment>(&cm_w);
            w_polys.push(f_coefs);
            cm_w_vec.push(cm_w);
        }
    } else {
        for i in 0..n_wires_per_gate {
            let mut f_coefs = FpPolynomial::ffti(
                root,
                &extended_witness[i * n_constraints..(i + 1) * n_constraints],
                n_constraints,
            );
            let _ = hide_polynomial(prng, &mut f_coefs, 1, n_constraints);
            let cm_w = pcs.commit(&f_coefs).c(d!(PlonkError::CommitmentError))?;
            transcript.append_commitment::<PCS::Commitment>(&cm_w);
            w_polys.push(f_coefs);
            cm_w_vec.push(cm_w);
        }
    }

    // 2. get challenges beta and gamma
    let beta = transcript_get_plonk_challenge_beta(transcript, n_constraints);
    let gamma = transcript_get_plonk_challenge_gamma(transcript, n_constraints);
    challenges.insert_beta_gamma(beta, gamma).unwrap(); // safe unwrap

    // 3. build the z polynomial, hide it and commit
    let (cm_z, z_poly) = if let Some(lagrange_pcs) = lagrange_pcs {
        let z_evals = z_poly::<PCS, CS>(cs, prover_params, &extended_witness, &challenges);
        let mut z_coefs = FpPolynomial::ffti(
            &prover_params.verifier_params.root,
            &z_evals.coefs,
            n_constraints,
        );
        let blinds = hide_polynomial(prng, &mut z_coefs, 2, n_constraints);
        let cm_z = lagrange_pcs
            .commit(&z_evals)
            .c(d!(PlonkError::CommitmentError))?;
        let cm_z = pcs.apply_blind_factors(&cm_z, &blinds, n_constraints);
        transcript.append_commitment::<PCS::Commitment>(&cm_z);
        (cm_z, z_coefs)
    } else {
        let z_evals = z_poly::<PCS, CS>(cs, prover_params, &extended_witness, &challenges);
        let mut z_coefs = FpPolynomial::ffti(
            &prover_params.verifier_params.root,
            &z_evals.coefs,
            n_constraints,
        );
        let _ = hide_polynomial(prng, &mut z_coefs, 2, n_constraints);
        let cm_z = pcs.commit(&z_coefs).c(d!(PlonkError::CommitmentError))?;
        transcript.append_commitment::<PCS::Commitment>(&cm_z);

        (cm_z, z_coefs)
    };

    // 4. get challenge alpha
    let alpha = transcript_get_plonk_challenge_alpha(transcript, n_constraints);
    challenges.insert_alpha(alpha).unwrap();

    // 5. build t, split into `n_wires_per_gate` degree-(N+2) polynomials and commit
    let t_poly =
        t_poly::<PCS, CS>(cs, prover_params, &w_polys, &z_poly, &challenges, &pi).c(d!())?;
    let (cm_t_vec, t_polys) =
        split_t_and_commit(pcs, &t_poly, n_wires_per_gate, n_constraints + 2).c(d!())?;

    for cm_t in cm_t_vec.iter() {
        transcript.append_commitment::<PCS::Commitment>(cm_t);
    }

    // 6. get challenge zeta
    let zeta = transcript_get_plonk_challenge_zeta(transcript, n_constraints);
    challenges.insert_zeta(zeta).unwrap();

    // 7. a) Evaluate the openings of witness/permutation polynomials at \zeta, and
    // evaluate the opening of z(X) at point \omega * \zeta.
    let w_polys_eval_zeta: Vec<PCS::Field> =
        w_polys.iter().map(|poly| pcs.eval(poly, &zeta)).collect();
    let s_polys_eval_zeta: Vec<PCS::Field> = prover_params
        .s_polys
        .iter()
        .take(n_wires_per_gate - 1)
        .map(|poly| pcs.eval(poly, &zeta))
        .collect();

    let zeta_omega = root.mul(&zeta);
    let z_eval_zeta_omega = pcs.eval(&z_poly, &zeta_omega);

    //  b). build the r polynomial, and eval at zeta
    for eval_zeta in w_polys_eval_zeta.iter().chain(s_polys_eval_zeta.iter()) {
        transcript.append_field_elem(eval_zeta);
    }
    transcript.append_field_elem(&z_eval_zeta_omega);

    // 8. get challenge u
    let u = transcript_get_plonk_challenge_u(transcript, cs.size());
    challenges.insert_u(u).unwrap();

    let w_polys_eval_zeta_as_ref: Vec<&PCS::Field> = w_polys_eval_zeta.iter().collect();
    let s_poly_eval_zeta_as_ref: Vec<&PCS::Field> = s_polys_eval_zeta.iter().collect();

    let r_poly = r_poly::<PCS, CS>(
        prover_params,
        &z_poly,
        &w_polys_eval_zeta_as_ref[..],
        &s_poly_eval_zeta_as_ref[..],
        &z_eval_zeta_omega,
        &challenges,
        &t_polys,
        n_constraints + 2,
    );

    let mut polys_to_open: Vec<&FpPolynomial<PCS::Field>> = w_polys
        .iter()
        .chain(
            prover_params
                .s_polys
                .iter()
                .take(CS::n_wires_per_gate() - 1),
        )
        .collect();
    polys_to_open.push(&r_poly);

    let zeta = challenges.get_zeta().unwrap();

    let opening_witness_zeta = pcs
        .batch_prove(transcript, &polys_to_open[..], &zeta, n_constraints + 2)
        .c(d!(PlonkError::ProofError))?;

    let opening_witness_zeta_omega = pcs
        .prove(transcript, &z_poly, &zeta_omega, n_constraints + 2)
        .c(d!(PlonkError::ProofError))?;

    // return proof
    Ok(PlonkProof {
        cm_w_vec,
        cm_t_vec,
        cm_z,
        w_polys_eval_zeta,
        z_eval_zeta_omega,
        s_polys_eval_zeta,
        opening_witness_zeta,
        opening_witness_zeta_omega,
    })
}
