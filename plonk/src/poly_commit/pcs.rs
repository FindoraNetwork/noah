use crate::poly_commit::{field_polynomial::FpPolynomial, transcript::PolyComTranscript};
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use zei_algebra::prelude::*;

/// The trait for help serialize to bytes,
/// implement by polynomial commitment.
pub trait ToBytes {
    /// Convert to bytes.
    fn to_bytes(&self) -> Vec<u8>;
}

/// The trait for homomorphic polynomial commitment field.
pub trait HomomorphicPolyComElem: ToBytes + Clone {
    /// This is the scalar field of the polynomial.
    type Scalar;

    /// Get base (generator) of the group.
    fn get_base() -> Self;

    /// Get identity of the group.
    fn get_identity() -> Self;

    /// Add the underlying polynomials.
    fn add(&self, other: &Self) -> Self;

    /// Add assign the underlying polynomials.
    fn add_assign(&mut self, other: &Self);

    /// Subtract the underlying polynomials.
    fn sub(&self, other: &Self) -> Self;

    /// Subtract assign the underlying polynomials.
    fn sub_assign(&mut self, other: &Self);

    /// Multiply underlying polynomial by scalar `exp` represented
    /// in least significant byte first.
    fn mul(&self, exp: &Self::Scalar) -> Self;

    /// Multiply underlying polynomial by scalar `exp`.
    fn mul_assign(&mut self, exp: &Self::Scalar);
}

/// Trait for polynomial commitment scheme.
pub trait PolyComScheme: Sized {
    /// Type of prime field.
    type Field: Scalar + Debug;

    /// Type of commitment produces, need to implement `HomomorphicPolyComElem`.
    type Commitment: HomomorphicPolyComElem<Scalar = Self::Field>
        + Debug
        + PartialEq
        + Eq
        + Clone
        + Serialize
        + for<'de> Deserialize<'de>;

    /// Type of `Opening`.
    type Opening: HomomorphicPolyComElem<Scalar = Self::Field> + Debug + PartialEq + Eq + Clone;

    /// Returns maximal supported degree
    fn max_degree(&self) -> usize;

    /// Commit to the polynomial, commitment is binding.
    fn commit(
        &self,
        polynomial: FpPolynomial<Self::Field>,
    ) -> Result<(Self::Commitment, Self::Opening)>;

    /// Return the opening of an original commitment of the polynomial.
    fn opening(&self, polynomial: &FpPolynomial<Self::Field>) -> Self::Opening;

    /// Evaluate the polynomial using the commitment opening to it.
    fn eval_opening(&self, opening: &Self::Opening, point: &Self::Field) -> Self::Field;

    /// Compute the commitment of a polynomial given its opening.
    fn commitment_from_opening(&self, opening: &Self::Opening) -> Self::Commitment;

    /// Computes the polynomial from an opening. This is slow as the polynomial is build.
    fn polynomial_from_opening_ref(&self, opening: &Self::Opening) -> FpPolynomial<Self::Field>;

    /// Transform the opening into a polynomial.
    fn polynomial_from_opening(&self, opening: Self::Opening) -> FpPolynomial<Self::Field>;

    /// Evaluate the polynomial producing a proof for it.
    fn prove(
        &self,
        transcript: &mut Transcript,
        opening: &Self::Opening,
        point: &Self::Field,
        max_degree: usize,
    ) -> Result<Self::Commitment>;

    /// Verify an evaluation proof that polynomial inside commitment
    /// evaluates to `value` on input `point `.
    fn verify(
        &self,
        transcript: &mut Transcript,
        commitment: &Self::Commitment,
        degree: usize,
        point: &Self::Field,
        value: &Self::Field,
        proof: &Self::Commitment,
    ) -> Result<()>;

    /// Apply blind factors over the vanishing part
    fn apply_blind_factors(
        &self,
        commitment: &Self::Commitment,
        blinds: &[Self::Field],
        zeroing_degree: usize,
    ) -> Self::Commitment;

    /// Batch proof for polynomial evaluation.
    /// `param` stores the instance parameters to be appended to the transcript.
    /// When `param` is `None`, our function assumes `params` are implicit
    /// in the transcript already.
    fn batch_prove(
        &self,
        transcript: &mut Transcript,
        openings: &[&Self::Opening],
        point: &Self::Field,
        max_degree: usize,
    ) -> Result<Self::Commitment> {
        let n = openings.len();
        assert!(n > 0);

        Self::init_pcs_batch_eval_transcript(transcript, max_degree, point);

        // 1. Compute quotient Polynomial q(X) = h(X)/z(X), where
        // h(X) = \sum_i \alpha^i * [fi(X) - fi(xi)]
        let alpha = transcript.get_challenge_field_elem(b"alpha");
        let mut h = FpPolynomial::<Self::Field>::zero();
        let mut c_i = Self::Field::one(); // linear combination first scalar = alpha^0
        let z = FpPolynomial::from_zeroes(&[point.clone()]);

        for open in openings.iter() {
            let mut poly = self.polynomial_from_opening_ref(open);
            let eval_value = poly.eval(point);
            println!("eval_value = {:?}", eval_value);
            poly.sub_assign(&FpPolynomial::from_coefs(vec![eval_value]));
            poly.mul_scalar_assign(&c_i);
            h.add_assign(&poly);
            c_i.mul_assign(&alpha);
        }

        let (q, rem) = h.div_rem(&z);
        if !rem.is_zero() {
            return Err(eg!());
        }

        let (c_q, _) = self.commit(q).c(d!())?;
        Ok(c_q)
    }

    /// Verify a batched proof
    fn batch_verify(
        &self,
        transcript: &mut Transcript,
        commitments: &[&Self::Commitment],
        max_degree: usize,
        point: &Self::Field,
        values: &[Self::Field],
        proof: &Self::Commitment,
    ) -> Result<()> {
        Self::init_pcs_batch_eval_transcript(transcript, max_degree, point);
        let alpha = transcript.get_challenge_field_elem::<Self::Field>(b"alpha");

        // Compute commitment F = com_lc - Com(q(X) * z(\rho)), where
        // com_lc = sum_i alpha^i * z_i_bar(\rho)) * Com((f_i(X) - y_i)
        //        = sum_i alpha^i * z_i_bar(\rho)) * Com(f_i(X))
        //          - Com(sum_i alpha^i * z_i_bar(\rho)) * y_i)
        let mut c_i = Self::Field::one();
        let mut com_lc = Self::Commitment::get_identity();
        let mut val_lc = Self::Field::zero();
        for (value, commitment) in values.iter().zip(commitments) {
            com_lc = com_lc.add(&commitment.mul(&c_i));
            let value_times_scalar = c_i.mul(value);
            val_lc.add_assign(&value_times_scalar);
            c_i.mul_assign(&alpha);
        }
        let (com, _) = self
            .commit(FpPolynomial::from_coefs(vec![val_lc]))
            .c(d!())?;
        com_lc = com_lc.sub(&com);

        self.verify(
            transcript,
            &com_lc,
            max_degree,
            &point,
            &Self::Field::zero(),
            &proof,
        )
        .c(d!())
    }

    /// Compute the transaction when batch eval.
    fn init_pcs_batch_eval_transcript(
        transcript: &mut Transcript,
        max_degree: usize,
        point: &Self::Field,
    ) {
        transcript.append_message(b"Domain Separator", b"New PCS-Batch-Eval Protocol");
        Self::transcript_append_params(transcript, max_degree, point);
    }

    /// Append params to the transaction.
    fn transcript_append_params(
        transcript: &mut Transcript,
        max_degree: usize,
        point: &Self::Field,
    ) {
        transcript.append_message(b"field size", &Self::Field::get_field_size_le_bytes());
        transcript.append_u64(b"max_degree", max_degree as u64);
        transcript.append_field_elem(point);
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

    /// Randomize the polynomial so that commitment of the original
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

    /// Commit to `polynomial` under blinding `blind`.
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
        field_polynomial::FpPolynomial, kzg_poly_com::KZGCommitmentScheme, pcs::PolyComScheme,
    };
    use merlin::Transcript;
    use rand_chacha::ChaChaRng;
    use zei_algebra::{bls12_381::BLSScalar, prelude::*};

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
        let proof = {
            let mut transcript = Transcript::new(b"TestPCS");
            pcs.prove(&mut transcript, &open, &point, degree).unwrap()
        };
        let eval = pcs.eval_opening(&open, &point);
        {
            let mut transcript = Transcript::new(b"TestPCS");
            assert!(pcs
                .verify(&mut transcript, &com, degree, &point, &eval, &proof)
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
        let point = Field::random(&mut prng);
        let proof = {
            let mut transcript = Transcript::new(b"TestPCS");
            pcs.batch_prove(&mut transcript, &[&open1, &open2, &open3], &point, degree)
                .unwrap()
        };
        let evals = vec![
            pcs.eval_opening(&open1, &point),
            pcs.eval_opening(&open2, &point),
            pcs.eval_opening(&open3, &point),
        ];
        {
            let mut transcript = Transcript::new(b"TestPCS");
            assert!(pcs
                .batch_verify(
                    &mut transcript,
                    &[&com1, &com2, &com3],
                    degree,
                    &point,
                    &evals,
                    &proof,
                )
                .is_ok());
        }
    }
}
