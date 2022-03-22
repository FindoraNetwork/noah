use crate::poly_commit::{field_polynomial::FpPolynomial, transcript::PolyComTranscript};
use merlin::Transcript;
use ruc::*;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use zei_algebra::{ops::*, traits::Scalar, One, Zero};

/// The trait for help serialize to bytes,
/// implement by polynomial commitment.
pub trait ToBytes {
    /// Convert to bytes.
    fn to_bytes(&self) -> Vec<u8>;
}

/// The trait for homomorphic polynomial commitment field.
pub trait HomomorphicPolyComElem: ToBytes {
    /// This is the scalar field of the polynomial.
    type Scalar;

    /// Get base (generator) of the group.
    fn get_base() -> Self;

    /// Get identity of the group.
    fn get_identity() -> Self;

    /// Add the underlying polynomials.
    fn op(&self, other: &Self) -> Self;

    /// Add assign the underlying polynomials.
    fn op_assign(&mut self, other: &Self);

    /// Multiply underlying polynomial by scalar `exp` represented
    /// in least significant byte first.
    fn exp(&self, exp: &Self::Scalar) -> Self;

    /// Multiply underlying polynomial by scalar `exp`.
    fn exp_assign(&mut self, exp: &Self::Scalar);

    /// Negates the polynomials coefficients.
    fn inv(&self) -> Self;
}

/// Batch eval proof of polynomial.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone)]
pub struct BatchProofEval<C, E> {
    /// The commitment of batch eval.
    commitment: C,
    /// The eval proof.
    eval_proof: E,
}

/// Batch eval params of polynomial.
pub struct BatchEvalParams<'a, C, F> {
    commitments: &'a [&'a C],
    evals: &'a [F],
}

/// Define the batch eval proof by given `PolyComScheme`.
pub type BatchPfEval<PCS> =
    BatchProofEval<<PCS as PolyComScheme>::Commitment, <PCS as PolyComScheme>::EvalProof>;

/// Define the Option type of batch eval params by given `PolyComScheme`.
pub type OptionParams<'a, PCS> =
    Option<BatchEvalParams<'a, <PCS as PolyComScheme>::Commitment, <PCS as PolyComScheme>::Field>>;

/// Trait for polynomial commitment scheme.
pub trait PolyComScheme: Sized {
    /// Type of prime field.
    type Field: Scalar;

    /// Type of commitment produces, need to implement `HomomorphicPolyComElem`.
    type Commitment: HomomorphicPolyComElem<Scalar = Self::Field>
        + Debug
        + PartialEq
        + Eq
        + Clone
        + Serialize
        + for<'de> Deserialize<'de>;

    /// Type of `EvalProof`.
    type EvalProof: ToBytes + Serialize + for<'de> Deserialize<'de> + Debug + PartialEq + Eq;

    /// Type of `Opening`.
    type Opening: HomomorphicPolyComElem<Scalar = Self::Field> + Debug + PartialEq + Eq + Clone;

    /// Commits to the polynomial, commitment is binding.
    fn commit(
        &self,
        polynomial: FpPolynomial<Self::Field>,
    ) -> Result<(Self::Commitment, Self::Opening)>;

    /// Return the opening of an original commitment of the polynomial.
    fn opening(&self, polynomial: &FpPolynomial<Self::Field>) -> Self::Opening;

    /// Evaluated the polynomial using the commitment opening to it.
    fn eval_opening(&self, opening: &Self::Opening, point: &Self::Field) -> Self::Field;

    /// Computes the commitment of a polynomial given its opening.
    fn commitment_from_opening(&self, opening: &Self::Opening) -> Self::Commitment;

    /// Computes the polynomial from an opening. This is slow as the polynomial is build.
    fn polynomial_from_opening_ref(&self, opening: &Self::Opening) -> FpPolynomial<Self::Field>;

    /// Transforms the opening into a polynomial.
    fn polynomial_from_opening(&self, opening: Self::Opening) -> FpPolynomial<Self::Field>;

    /// Evaluate the polynomial producing a proof for it.
    fn prove_eval(
        &self,
        transcript: &mut Transcript,
        opening: &Self::Opening,
        point: &Self::Field,
        max_degree: usize,
    ) -> Result<(Self::Field, Self::EvalProof)>;

    /// Verify an evaluation proof that polynomial inside commitment
    /// evaluates to `value` on input `point `.
    fn verify_eval(
        &self,
        transcript: &mut Transcript,
        commitment: &Self::Commitment,
        degree: usize,
        point: &Self::Field,
        value: &Self::Field,
        proof: &Self::EvalProof,
    ) -> Result<()>;

    /// Batch proof for polynomial evaluation.
    /// `param` stores the instance parameters to be appended to the transcript.
    /// When `param` is `None`, our function assumes `params` are implicit
    /// in the transcript already.
    fn batch_prove_eval(
        &self,
        transcript: &mut Transcript,
        openings: &[&Self::Opening],
        points: &[Self::Field],
        max_degree: usize,
        params: OptionParams<'_, Self>,
    ) -> Result<(Vec<Self::Field>, BatchPfEval<Self>)> {
        let n = openings.len();
        assert_eq!(n, points.len());
        assert!(n > 0);

        Self::init_pcs_batch_eval_transcript(transcript, max_degree, points, params);

        // 1. Compute quotient Polynomial q(X) = h(X)/z(X), where
        // h(X) = \sum_i \alpha^i * z_i_bar(X) * [fi(X) - fi(xi)]

        // linear combination scalar factor
        let alpha = transcript.get_challenge_field_elem(b"alpha");
        let mut h = FpPolynomial::<Self::Field>::zero();
        let mut c_i = Self::Field::one(); // linear combination first scalar = alpha^0
        let z = FpPolynomial::from_zeroes(points);
        let mut eval_values = vec![];
        let mut z_i_bar_vec = vec![];
        for (open, point) in openings.iter().zip(points) {
            let mut poly = self.polynomial_from_opening_ref(open);
            let eval_value = poly.eval(point);
            eval_values.push(eval_value);
            poly.sub_assign(&FpPolynomial::from_coefs(vec![eval_value]));
            poly.mul_scalar_assign(&c_i);
            let z_i = FpPolynomial::from_zeroes(&[*point]);
            let (z_i_bar, _) = z.div_rem(&z_i);
            h.add_assign(&poly.fast_mul(&z_i_bar));

            c_i.mul_assign(&alpha);
            z_i_bar_vec.push(z_i_bar);
        }

        let (q, rem) = h.div_rem(&z);
        if !rem.is_zero() {
            return Err(eg!());
        }

        let (c_q, o_q) = self.commit(q).c(d!())?;
        transcript.append_commitment::<Self::Commitment>(&c_q);

        // Derive opening of g(X)
        // = sum \alpha^i * z_i_bar(\rho) * (fi(X) - fi(xi)) - q(X) * z(rho)
        // = - z(rho) * q(X)
        //   + sum \alpha^i * z_i_bar(\rho) * fi(X)
        //   - [sum \alpha^i * z_i_bar(\rho) * fi(xi)]
        let rho = transcript.get_challenge_field_elem(b"rho");

        // term `-z(rho) * q(X)`
        let mut g_opening = o_q.inv();
        let z_eval_rho = z.eval(&rho);
        g_opening = g_opening.exp(&z_eval_rho);

        // term `\sum \alpha^i * z_i_bar(\rho) * fi(X)`
        let mut c_i = Self::Field::one(); // alpha^i
        let mut val_sum = Self::Field::zero(); // val_sum = sum f_i(x_i) * alpha^i * z_i_bar(\rho)
        for ((z_i_bar, opening_i), value) in z_i_bar_vec
            .iter()
            .zip(openings.iter())
            .zip(eval_values.iter())
        {
            let mut poly_i = (*(*opening_i)).clone();
            let zi_bar_eval_rho = z_i_bar.eval(&rho);
            let scalar = zi_bar_eval_rho.mul(&c_i);
            poly_i = poly_i.exp(&scalar);
            g_opening = g_opening.op(&poly_i);
            let value_times_scalar = value.mul(&scalar);
            val_sum.add_assign(&value_times_scalar);
            c_i.mul_assign(&alpha);
        }

        // term `-[sum \alpha^i * z_i_bar(\rho) * fi(xi)]`
        let poly_values_sum_opening = self.opening(&FpPolynomial::from_coefs(vec![val_sum]));
        g_opening = g_opening.op(&poly_values_sum_opening.inv());

        let (g_value, g_proof) = self
            .prove_eval(transcript, &g_opening, &rho, max_degree)
            .c(d!())?;
        if !g_value.is_zero() {
            Err(eg!())
        } else {
            Ok((
                eval_values,
                BatchProofEval {
                    commitment: c_q,
                    eval_proof: g_proof,
                },
            ))
        }
    }

    /// Verify batch eval proof.
    /// Optimized according to Sec 4.1 in <https://eprint.iacr.org/2020/081.pdf>
    /// Saves |points| G1 exps
    fn batch_verify_eval(
        &self,
        transcript: &mut Transcript,
        commitments: &[&Self::Commitment],
        max_degree: usize,
        points: &[Self::Field],
        values: &[Self::Field],
        proof: &BatchPfEval<Self>,
        params: OptionParams<'_, Self>,
    ) -> Result<()> {
        Self::init_pcs_batch_eval_transcript(transcript, max_degree, points, params);
        let alpha = transcript.get_challenge_field_elem::<Self::Field>(b"alpha");
        transcript.append_commitment::<Self::Commitment>(&proof.commitment);
        let rho = transcript.get_challenge_field_elem::<Self::Field>(b"rho");

        // 1. z_eval_rho = prod (X - point_i) at X = \rho
        let mut z_eval_rho = Self::Field::one();
        for point in points {
            let aux = rho.sub(point);
            z_eval_rho.mul_assign(&aux)
        }

        // Compute commitment F = com_lc - Com(q(X) * z(\rho)), where
        // com_lc = sum_i alpha^i * z_i_bar(\rho)) * Com((f_i(X) - y_i)
        //        = sum_i alpha^i * z_i_bar(\rho)) * Com(f_i(X))
        //          - Com(sum_i alpha^i * z_i_bar(\rho)) * y_i)
        let mut c_i = Self::Field::one(); // linear combination scalar c_i = alpha^i
        let mut com_lc = Self::Commitment::get_identity();
        let mut val_lc = Self::Field::zero(); // \sum y_i * alpha^i * \z_i_bar(rho)
        for ((point, value), commitment) in points.iter().zip(values).zip(commitments) {
            let rho_minus_point_inv = rho.sub(point).inv().c(d!())?;
            let z_i_bar_eval_rho = z_eval_rho.mul(&rho_minus_point_inv);

            let scalar = z_i_bar_eval_rho.mul(&c_i);

            com_lc = com_lc.op(&commitment.exp(&scalar));

            let value_times_scalar = scalar.mul(value);
            val_lc.add_assign(&value_times_scalar);

            c_i.mul_assign(&alpha);
        }
        let (com, _) = self
            .commit(FpPolynomial::from_coefs(vec![val_lc]))
            .c(d!())?;
        com_lc = com_lc.op(&com.inv());
        // - Com(q(X) * z(\rho))
        let com_z_q = proof.commitment.exp(&z_eval_rho);
        let derived_commitment = com_lc.op(&com_z_q.inv());
        self.verify_eval(
            transcript,
            &derived_commitment,
            max_degree,
            &rho,
            &Self::Field::zero(),
            &proof.eval_proof,
        )
        .c(d!())
    }

    /// Compute the transaction when batch eval.
    fn init_pcs_batch_eval_transcript(
        transcript: &mut Transcript,
        max_degree: usize,
        points: &[Self::Field],
        params: Option<BatchEvalParams<'_, Self::Commitment, Self::Field>>,
    ) {
        transcript.append_message(b"Domain Separator", b"New PCS-Batch-Eval Protocol");
        Self::transcript_append_params(transcript, max_degree, points, params);
    }

    /// Append params to the transaction.
    fn transcript_append_params(
        transcript: &mut Transcript,
        max_degree: usize,
        points: &[Self::Field],
        params: Option<BatchEvalParams<'_, Self::Commitment, Self::Field>>,
    ) {
        transcript.append_message(b"field size", &Self::Field::get_field_size_le_bytes());
        transcript.append_u64(b"max_degree", max_degree as u64);
        for point in points.iter() {
            transcript.append_field_elem(point);
        }
        if let Some(pcs_params) = params {
            for commitment in pcs_params.commitments.iter() {
                transcript.append_commitment::<Self::Commitment>(commitment);
            }
            for value in pcs_params.evals.iter() {
                transcript.append_field_elem(value);
            }
        }
    }

    /// Shrink this to only for verifier use.
    fn shrink_to_verifier_only(&self) -> Result<Self>;
}

/// Uses a binding polynomial commitment scheme and transforms it into
/// a binding and hiding polynomial commitment scheme.
pub struct HidingPCS<'a, PCS> {
    /// A polynomial commitment scheme.
    pub pcs: &'a PCS,
}

impl<PCS: PolyComScheme> HidingPCS<'_, PCS> {
    /// Return by a polynomial commitment scheme.
    pub fn new(pcs: &PCS) -> HidingPCS<'_, PCS> {
        HidingPCS { pcs }
    }

    /// Randomized the polynomial so that commitment of the original
    /// polynomial is binding and hiding.
    pub fn hide_polynomial(
        &self,
        polynomial: &FpPolynomial<PCS::Field>,
        blind: &PCS::Field,
    ) -> FpPolynomial<PCS::Field> {
        let mut coefs = vec![*blind];
        coefs.extend_from_slice(polynomial.get_coefs_ref());
        FpPolynomial::from_coefs(coefs)
    }

    /// Commits to `polynomial` under blinding `blind`.
    pub fn commit(
        &self,
        polynomial: &FpPolynomial<PCS::Field>,
        blind: &PCS::Field,
    ) -> PCS::Commitment {
        let hidden = self.hide_polynomial(polynomial, blind);
        self.pcs.commit(hidden).unwrap().0
    }
}

/// The trait for shift polynomial commitment scheme.
pub trait ShiftPCS: PolyComScheme {
    /// Shift polynomial by one and add blind.
    fn to_hidden(&self, commitment: &Self::Commitment, blind: &Self::Field) -> Self::Commitment;

    /// Shift the underling polynomial by appending low order zero coefficients.
    fn shift(&self, commitment: &Self::Commitment, n: usize) -> Self::Commitment;
}

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use crate::poly_commit::{
        field_polynomial::FpPolynomial,
        kzg_poly_com::KZGCommitmentScheme,
        pcs::{BatchEvalParams, PolyComScheme},
    };
    use merlin::Transcript;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use zei_algebra::{bls12_381::BLSScalar, ops::*, traits::Scalar, One, Zero};

    #[test]
    fn test_pcs_eval() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        let two = one.add(&one);

        let poly = FpPolynomial::from_zeroes(&[zero, one, two]);
        let degree = poly.degree();
        let pcs = KZGCommitmentScheme::new(degree, &mut prng);
        let (com, open) = pcs.commit(poly).unwrap();
        let point = BLSScalar::random(&mut prng);
        let (eval, proof) = {
            let mut transcript = Transcript::new(b"TestPCS");
            pcs.prove_eval(&mut transcript, &open, &point, degree)
                .unwrap()
        };
        assert_eq!(eval, pcs.eval_opening(&open, &point));
        {
            let mut transcript = Transcript::new(b"TestPCS");
            assert!(pcs
                .verify_eval(&mut transcript, &com, degree, &point, &eval, &proof)
                .is_ok());
        }
    }

    #[test]
    fn test_pcs_batch_eval() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        type Field = BLSScalar;
        let zero = Field::zero();
        let one = Field::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let poly1 = FpPolynomial::from_coefs(vec![zero, one, two]);
        let poly2 = FpPolynomial::from_coefs(vec![one, zero, three]);
        let poly3 = FpPolynomial::from_coefs(vec![two, two, two, two]);
        let degree = poly3.degree();
        let pcs = KZGCommitmentScheme::new(degree + 1, &mut prng);
        let (com1, open1) = pcs.commit(poly1).unwrap();
        let (com2, open2) = pcs.commit(poly2).unwrap();
        let (com3, open3) = pcs.commit(poly3).unwrap();
        let point1 = Field::random(&mut prng);
        let point2 = Field::random(&mut prng);
        let point3 = Field::random(&mut prng);
        let points = [point1, point2, point3];
        let (evals, proof) = {
            let mut transcript = Transcript::new(b"TestPCS");
            let params = BatchEvalParams {
                commitments: &[&com1, &com2, &com3],
                evals: &[],
            };
            pcs.batch_prove_eval(
                &mut transcript,
                &[&open1, &open2, &open3],
                &points,
                degree,
                Some(params),
            )
            .unwrap()
        };
        assert_eq!(
            evals,
            vec![
                pcs.eval_opening(&open1, &points[0]),
                pcs.eval_opening(&open2, &points[1]),
                pcs.eval_opening(&open3, &points[2])
            ]
        );
        {
            let mut transcript = Transcript::new(b"TestPCS");
            let params = BatchEvalParams {
                commitments: &[&com1, &com2, &com3],
                evals: &[],
            };
            assert!(pcs
                .batch_verify_eval(
                    &mut transcript,
                    &[&com1, &com2, &com3],
                    degree,
                    &points,
                    &evals,
                    &proof,
                    Some(params)
                )
                .is_ok());
        }
    }

    #[test]
    fn test_pcs_batch_eval_simulate_plonk() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        type Field = BLSScalar;
        let degree = 16;
        let pcs = KZGCommitmentScheme::new(degree + 1, &mut prng);
        let zero = Field::zero();
        let one = Field::one();
        let two = one.add(&one);
        let three = two.add(&one);

        let f1 = FpPolynomial::from_coefs(vec![zero, one, two, two, two, one]);
        let f2 = FpPolynomial::from_coefs(vec![one, zero, three, two, two, one]);
        let f3 = FpPolynomial::from_coefs(vec![two, two, two, two, two, two]);
        let perm1 = FpPolynomial::from_coefs(vec![two, two, two, two]);
        let perm2 = FpPolynomial::from_coefs(vec![two, two, two, two]);
        let Q = FpPolynomial::from_coefs(vec![two; 17]);
        let L = FpPolynomial::from_coefs(vec![two; 6]);
        let Sigma = FpPolynomial::from_coefs(vec![one; 6]);

        let g = two;
        let beta = Field::random(&mut prng);
        let beta_sq = beta.mul(&beta);
        let beta_g = beta.mul(&g);

        let (comf1, openf1) = pcs.commit(f1).unwrap();
        let (comf2, openf2) = pcs.commit(f2).unwrap();
        let (comf3, openf3) = pcs.commit(f3).unwrap();
        let (comperm1, openperm1) = pcs.commit(perm1).unwrap();
        let (comperm2, openperm2) = pcs.commit(perm2).unwrap();
        let (comQ, openQ) = pcs.commit(Q).unwrap();
        let (comL, openL) = pcs.commit(L).unwrap();
        let (comSigma, openSigma) = pcs.commit(Sigma).unwrap();
        let points = [beta, beta_sq, beta, beta, beta, beta, beta, beta_g];
        let (evals, proof) = {
            let mut transcript = Transcript::new(b"TestPCS");
            pcs.batch_prove_eval(
                &mut transcript,
                //&[&f1, &f2, &f3, &perm1, &perm2, &Q, &L, &Sigma],
                &[
                    &openf1, &openf2, &openf3, &openperm1, &openperm2, &openQ, &openL, &openSigma,
                ],
                &points,
                degree,
                None,
            )
            .unwrap()
        };
        assert_eq!(
            evals,
            vec![
                pcs.eval_opening(&openf1, &points[0]),
                pcs.eval_opening(&openf2, &points[1]),
                pcs.eval_opening(&openf3, &points[2]),
                pcs.eval_opening(&openperm1, &points[3]),
                pcs.eval_opening(&openperm2, &points[4]),
                pcs.eval_opening(&openQ, &points[5]),
                pcs.eval_opening(&openL, &points[6]),
                pcs.eval_opening(&openSigma, &points[7])
            ]
        );
        {
            let mut transcript = Transcript::new(b"TestPCS");
            assert!(pcs
                .batch_verify_eval(
                    &mut transcript,
                    &[&comf1, &comf2, &comf3, &comperm1, &comperm2, &comQ, &comL, &comSigma],
                    degree, //Q.degree()
                    &points,
                    &evals,
                    &proof,
                    None
                )
                .is_ok());
        }
    }
}
