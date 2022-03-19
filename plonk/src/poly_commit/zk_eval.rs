/*
 This file implements ZK eval for hiding polynomial commitment schemes.
  Let d be a public degree of the committed polynomial f and z a public point. Let b be the blinding factor hiding the polynomial.
 The public coin protocol is as follows:
 1) Prover samples a random polynomial alpha of degree d, commits to it using blinding b',
 evaluate it at z, and send it to verifier.
 2) Verifier responds with random field element challenge c
 3) Prover replies with response = b*c + b'
 4) Prover computes polynomial S(X) = alpha(X) + c * f(X), verifier derives commitment to X*S(X) with no blinding as
 C_XS = C_alpha * C_f^c * Commitment(0; response)^{-1}
 5) Prover sends S(z) and a proof for the value z*S(z).
 6) Verifier check proof using C_XS and accepts if S(z) - alpha(z) = y*c (in the field)
*/

use crate::poly_commit::field_polynomial::FpPolynomial;
use crate::poly_commit::pcs::{HidingPCS, HomomorphicPolyComElem, PolyComScheme, ShiftPCS};
use crate::poly_commit::transcript::PolyComTranscript;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use zei_algebra::{ops::*, traits::Scalar, Zero};

const ZK_EVAL_CHALLENGE: &[u8] = b"zk_eval challenge";

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

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct ZKEvalProof<C, P, F> {
    C_alpha: C,
    alpha_eval_z: F,
    response: F,
    S_eval_z: F,
    XS_eval_z_proof: P,
}

pub type ZKEvalPf<PCS> = ZKEvalProof<
    <PCS as PolyComScheme>::Commitment,
    <PCS as PolyComScheme>::EvalProof,
    <PCS as PolyComScheme>::Field,
>;
#[allow(non_snake_case)]
pub fn prove_zk_eval<R: CryptoRng + RngCore, PCS: PolyComScheme>(
    prng: &mut R,
    transcript: &mut Transcript,
    hpcs: &HidingPCS<PCS>,
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
    let C_alpha = hpcs.commit(&alpha, &alpha_blind);
    let alpha_eval_z = alpha.eval(point);

    transcript.append_commitment::<PCS::Commitment>(&C_alpha);
    transcript.append_field_elem(&alpha_eval_z);

    let c = transcript.get_challenge_field_elem::<PCS::Field>(ZK_EVAL_CHALLENGE);

    let mut response = c.mul(blind);
    response.add_assign(&alpha_blind);

    transcript.append_field_elem(&response);

    // let S = alpha.add(&polynomial.mul_scalar(&c));
    let mut S = polynomial.mul_scalar(&c);
    S.add_assign(&alpha);

    let XS = S.shift(1);
    let (_, open) = hpcs.pcs.commit(XS).unwrap();
    let (XS_eval_z, proof) = hpcs.pcs.prove_eval(transcript, &open, point, 1).c(d!())?; // TODO max degree
    let S_eval_z = S.eval(point);
    let expected = point.mul(&S_eval_z);
    assert_eq!(XS_eval_z, expected);

    transcript.append_field_elem(&S_eval_z);
    transcript.append_eval_proof::<PCS>(&proof);

    Ok(ZKEvalProof {
        C_alpha,
        alpha_eval_z,
        response,
        S_eval_z,
        XS_eval_z_proof: proof,
    })
}

#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub fn verify_zk_eval<PCS: PolyComScheme>(
    transcript: &mut Transcript,
    hpcs: &HidingPCS<PCS>,
    degree: usize,
    commitment: &PCS::Commitment,
    point: &PCS::Field,
    eval_value: &PCS::Field,
    proof: &ZKEvalPf<PCS>,
) -> Result<()> {
    init_zk_eval_transcript::<PCS>(transcript, degree, commitment, point, eval_value);

    // 1. first message, append to transcript
    let C_alpha = &proof.C_alpha;
    let alpha_eval_z = &proof.alpha_eval_z;

    transcript.append_commitment::<PCS::Commitment>(&C_alpha);
    transcript.append_field_elem::<PCS::Field>(&alpha_eval_z);

    // 2. compute challenge
    let c = transcript.get_challenge_field_elem::<PCS::Field>(ZK_EVAL_CHALLENGE);

    // 3. append second message to transcript
    let response = &proof.response;
    transcript.append_field_elem(response);
    transcript.append_field_elem(&proof.S_eval_z);
    transcript.append_eval_proof::<PCS>(&proof.XS_eval_z_proof);

    // 4. D0 checks
    // 4.1 C_f^c * C_alpha * com(0; response) should be a non-hiding commitment to X*S(X) of degree deg(f) + 1
    // and should evaluate to z*S(z)
    let zero_poly = FpPolynomial::from_coefs(vec![PCS::Field::zero()]);
    let C_zero = hpcs.commit(&zero_poly, response);
    let derived_C_XS = commitment.exp(&c).op(&C_alpha).op(&C_zero.inv());
    let XS_eval_z = point.mul(&proof.S_eval_z);

    hpcs.pcs
        .verify_eval(
            transcript,
            &derived_C_XS,
            degree + 1,
            point,
            &XS_eval_z,
            &proof.XS_eval_z_proof,
        )
        .c(d!())?;

    // 4.2 check that S(z) - alpha(z) = c*f(z)
    let a = proof.S_eval_z.sub(alpha_eval_z);
    let b = c.sub(eval_value);

    if a == b {
        Ok(())
    } else {
        Err(eg!())
    }
}

#[allow(non_snake_case)]
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

#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
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

/*
//TODO rebuild this tests
#[cfg(test)]
mod tests {
  use crate::mock_poly_com::MockCommitmentScheme;
  use crate::pcs::HidingPCS;
  use big_numbers::BigNumber;
  use merlin::Transcript;
  use polynomials::fq_polynomial::FqPolynomial;
  use prime_fields::{Fq, PrimeField};
  use rand::SeedableRng;
  use rand_chacha::ChaChaRng;

  #[test]
  fn test_zk_eval() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let poly_com = MockCommitmentScheme::new();
    let hpcs = HidingPCS { pcs: &poly_com };

    let field = Fq::new(BigNumber::from(97));
    //x+x2
    let polynomial = FqPolynomial::from_coefs(&field, vec![field.zero(), field.one(), field.one()]);
    let blind = field.rand_elem(&mut prng);

    let commitment = hpcs.commit(&polynomial, &blind);
    let mut transcript = Transcript::new(b"test");
    let elem = field.rand_elem(&mut prng);
    let value = polynomial.eval(&elem);
    let proof = super::prove_zk_eval(&mut prng,
                                     &mut transcript,
                                     &hpcs,
                                     &field,
                                     &polynomial,
                                     &blind,
                                     &elem).unwrap();

    let mut transcript = Transcript::new(b"test");
    assert!(super::verify_zk_eval(&mut transcript,
                                  &hpcs,
                                  &field,
                                  2,
                                  &commitment,
                                  &elem,
                                  &value,
                                  &proof).is_ok());
  }
}
*/
