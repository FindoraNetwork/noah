//! This file implements ZK eval for hiding polynomial commitment schemes.
//! Let d be a public degree of the committed polynomial f and z a public point.
//! Let b be the blinding factor hiding the polynomial.
//! The public coin protocol is as follows:
//!   1) Prover samples a random polynomial alpha of degree d, commits to it using blinding b',
//!      evaluate it at z, and send it to verifier.
//!   2) Verifier responds with random field element challenge c
//!   3) Prover replies with response = b*c + b'
//!   4) Prover computes polynomial S(X) = alpha(X) + c * f(X),
//!      verifier derives commitment to X*S(X) with no blinding as
//!      C_XS = C_alpha * C_f^c * Commitment(0; response)^{-1}
//!   5) Prover sends S(z) and a proof for the value z*S(z).
//!   6) Verifier check proof using C_XS and accepts if S(z) - alpha(z) = y*c (in the field)
use crate::poly_commit::{
    field_polynomial::FpPolynomial,
    pcs::{HidingPCS, HomomorphicPolyComElem, PolyComScheme, ShiftPCS},
    transcript::PolyComTranscript,
};
use merlin::Transcript;
use zei_algebra::prelude::*;

const ZK_EVAL_CHALLENGE: &[u8] = b"zk_eval challenge";

/// Initialize the transcript when compute ZK-Eval.
fn init_zk_eval_transcript<PCS: PolyComScheme>(
    transcript: &mut Transcript,
    degree: usize,
    commitment: &PCS::Commitment,
    point: &PCS::Field,
    eval: &PCS::Field,
) {
    transcript.append_message(b"Domain Separator", b"New ZK-Eval Protocol");
    transcript_append_params::<PCS>(transcript, degree, commitment, point, eval);
}

/// Initialize the transcript when compute Non-Hiding Poly ZK-Eval.
fn init_non_hiding_poly_zk_eval_transcript<PCS: PolyComScheme>(
    transcript: &mut Transcript,
    degree: usize,
    commitment: &PCS::Commitment,
    point: &PCS::Field,
    eval: &PCS::Field,
) {
    transcript.append_message(b"Domain Separator", b"New Non-Hiding Poly ZK-Eval Protocol");
    transcript_append_params::<PCS>(transcript, degree, commitment, point, eval);
}

/// Append the params to the transcript.
fn transcript_append_params<PCS: PolyComScheme>(
    transcript: &mut Transcript,
    degree: usize,
    commitment: &PCS::Commitment,
    point: &PCS::Field,
    eval: &PCS::Field,
) {
    transcript.append_message(b"field size", &PCS::Field::get_field_size_le_bytes());
    transcript.append_u64(b"degree", degree as u64);
    transcript.append_commitment::<PCS::Commitment>(commitment);
    transcript.append_field_elem(point);
    transcript.append_field_elem(eval);
}

/// The ZK-Eval proof.
#[derive(Clone)]
pub struct ZKEvalProof<C, P, F> {
    c_alpha: C,
    alpha_eval_z: F,
    response: F,
    s_eval_z: F,
    xs_eval_z_proof: P,
}

/// Define the ZK-Eval proof by given `PolyComScheme`.
pub type ZKEvalPf<PCS> = ZKEvalProof<
    <PCS as PolyComScheme>::Commitment,
    <PCS as PolyComScheme>::EvalProof,
    <PCS as PolyComScheme>::Field,
>;

/// Compute the ZK-Eval Proof.
pub fn prove_zk_eval<R: CryptoRng + RngCore, PCS: PolyComScheme>(
    prng: &mut R,
    transcript: &mut Transcript,
    hpcs: &HidingPCS<'_, PCS>,
    polynomial: &FpPolynomial<PCS::Field>,
    blind: &PCS::Field,
    point: &PCS::Field,
) -> Result<ZKEvalPf<PCS>> {
    let degree = polynomial.degree();
    init_zk_eval_transcript::<PCS>(
        transcript,
        degree,
        &hpcs.commit(polynomial, blind),
        point,
        &polynomial.eval(point),
    );

    let alpha = FpPolynomial::random(prng, degree);
    let alpha_blind = PCS::Field::random(prng);
    let c_alpha = hpcs.commit(&alpha, &alpha_blind);
    let alpha_eval_z = alpha.eval(point);

    transcript.append_commitment::<PCS::Commitment>(&c_alpha);
    transcript.append_field_elem(&alpha_eval_z);

    let c = transcript.get_challenge_field_elem::<PCS::Field>(ZK_EVAL_CHALLENGE);

    let mut response = c.mul(blind);
    response.add_assign(&alpha_blind);

    transcript.append_field_elem(&response);

    // let S = alpha.add(&polynomial.mul_scalar(&c));
    let mut s = polynomial.mul_scalar(&c);
    s.add_assign(&alpha);

    let xs = s.shift(1);
    let (_, open) = hpcs.pcs.commit(xs).unwrap();
    let (xs_eval_z, proof) = hpcs.pcs.prove_eval(transcript, &open, point, 1).c(d!())?; // TODO max degree
    let s_eval_z = s.eval(point);
    let expected = point.mul(&s_eval_z);
    assert_eq!(xs_eval_z, expected);

    transcript.append_field_elem(&s_eval_z);
    transcript.append_eval_proof::<PCS>(&proof);

    Ok(ZKEvalProof {
        c_alpha,
        alpha_eval_z,
        response,
        s_eval_z,
        xs_eval_z_proof: proof,
    })
}

/// Verify the ZK-Eval Proof.
pub fn verify_zk_eval<PCS: PolyComScheme>(
    transcript: &mut Transcript,
    hpcs: &HidingPCS<'_, PCS>,
    degree: usize,
    commitment: &PCS::Commitment,
    point: &PCS::Field,
    eval_value: &PCS::Field,
    proof: &ZKEvalPf<PCS>,
) -> Result<()> {
    init_zk_eval_transcript::<PCS>(transcript, degree, commitment, point, eval_value);

    // 1. first message, append to transcript
    let c_alpha = &proof.c_alpha;
    let alpha_eval_z = &proof.alpha_eval_z;

    transcript.append_commitment::<PCS::Commitment>(&c_alpha);
    transcript.append_field_elem::<PCS::Field>(&alpha_eval_z);

    // 2. compute challenge
    let c = transcript.get_challenge_field_elem::<PCS::Field>(ZK_EVAL_CHALLENGE);

    // 3. append second message to transcript
    let response = &proof.response;
    transcript.append_field_elem(response);
    transcript.append_field_elem(&proof.s_eval_z);
    transcript.append_eval_proof::<PCS>(&proof.xs_eval_z_proof);

    // 4. D0 checks
    // 4.1 C_f^c * C_alpha * com(0; response)
    //     should be a non-hiding commitment to X*S(X) of degree deg(f) + 1 and
    //     should evaluate to z*S(z)
    let zero_poly = FpPolynomial::from_coefs(vec![PCS::Field::zero()]);
    let c_zero = hpcs.commit(&zero_poly, response);
    let derived_c_xs = commitment.exp(&c).op(&c_alpha).op(&c_zero.inv());
    let xs_eval_z = point.mul(&proof.s_eval_z);

    hpcs.pcs
        .verify_eval(
            transcript,
            &derived_c_xs,
            degree + 1,
            point,
            &xs_eval_z,
            &proof.xs_eval_z_proof,
        )
        .c(d!())?;

    // 4.2 check that S(z) - alpha(z) = c*f(z)
    let a = proof.s_eval_z.sub(alpha_eval_z);
    let b = c.sub(eval_value);

    if a == b {
        Ok(())
    } else {
        Err(eg!())
    }
}

/// Compute the Non-Hiding Poly ZK-Eval Proof.
pub fn prove_non_hiding_poly_zk_eval<R: CryptoRng + RngCore, PCS: PolyComScheme>(
    prng: &mut R,
    transcript: &mut Transcript,
    pcs: &PCS,
    polynomial: &FpPolynomial<PCS::Field>,
    point: &PCS::Field,
) -> Result<ZKEvalPf<PCS>> {
    init_non_hiding_poly_zk_eval_transcript::<PCS>(
        transcript,
        polynomial.degree(),
        &pcs.commit(polynomial.clone()).unwrap().0, // FIXME
        point,
        &polynomial.eval(point),
    );
    let hpcs = HidingPCS::new(pcs);
    let blinding = PCS::Field::zero();
    let hidden_polynomial = hpcs.hide_polynomial(polynomial, &blinding);
    prove_zk_eval(
        prng,
        transcript,
        &hpcs,
        &hidden_polynomial,
        &blinding,
        point,
    )
    .c(d!())
}

/// Verify the Non-Hiding Poly ZK-Eval Proof.
pub fn verify_non_hiding_poly_zk_eval<SPCS: ShiftPCS>(
    transcript: &mut Transcript,
    pcs: &SPCS,
    degree: usize,
    commitment: &SPCS::Commitment,
    point: &SPCS::Field,
    eval_value: &SPCS::Field,
    proof: &ZKEvalPf<SPCS>,
) -> Result<()> {
    init_non_hiding_poly_zk_eval_transcript::<SPCS>(
        transcript, degree, commitment, point, eval_value,
    );
    let hpcs = HidingPCS::new(pcs);
    let hiding_commitment = pcs.shift(commitment, 1);
    let eval_value = eval_value.mul(point);

    verify_zk_eval(
        transcript,
        &hpcs,
        degree + 1,
        &hiding_commitment,
        point,
        //&field.mul(point, eval_value),
        &eval_value,
        proof,
    )
    .c(d!())
}
