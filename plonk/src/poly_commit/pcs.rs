use crate::poly_commit::{field_polynomial::FpPolynomial, transcript::PolyComTranscript};
use merlin::Transcript;
use noah_algebra::{prelude::*, traits::Domain};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// The trait for serialization to bytes
pub trait ToBytes {
    /// Convert to bytes.
    fn to_bytes(&self) -> Vec<u8>;
}

/// The trait for homomorphic polynomial commitment or polynomial.
pub trait HomomorphicPolyComElem: ToBytes + Clone + Sync + Send + Default {
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

    /// Multiply underlying polynomial by scalar `scalar` represented
    /// in least significant byte first.
    fn mul(&self, scalar: &Self::Scalar) -> Self;

    /// Multiply underlying polynomial by scalar `scalar`.
    fn mul_assign(&mut self, scalar: &Self::Scalar);
}

/// Trait for polynomial commitment scheme.
pub trait PolyComScheme: Sized {
    /// Type of prime field.
    type Field: Domain + Debug + Sync + Send;

    /// Type of commitment produces, need to implement `HomomorphicPolyComElem`.
    type Commitment: HomomorphicPolyComElem<Scalar = Self::Field>
        + Debug
        + Default
        + PartialEq
        + Eq
        + Clone
        + Serialize
        + Sync
        + for<'de> Deserialize<'de>;

    /// Return maximal supported degree
    fn max_degree(&self) -> usize;

    /// Commit to the polynomial, commitment is binding.
    fn commit(&self, polynomial: &FpPolynomial<Self::Field>) -> Result<Self::Commitment>;

    /// Evaluate the polynomial using the commitment opening to it.
    fn eval(&self, polynomial: &FpPolynomial<Self::Field>, point: &Self::Field) -> Self::Field;

    /// Evaluate the polynomial producing a proof for it.
    fn prove(
        &self,
        polynomial: &FpPolynomial<Self::Field>,
        point: &Self::Field,
        max_degree: usize,
    ) -> Result<Self::Commitment>;

    /// Verify an evaluation proof that polynomial inside commitment
    /// evaluates to `value` on input `point `.
    fn verify(
        &self,
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
        lagrange_pcs: Option<&Self>,
        polys: &[&FpPolynomial<Self::Field>],
        point: &Self::Field,
        max_degree: usize,
    ) -> Result<Self::Commitment> {
        assert!(polys.len() > 0);

        Self::init_pcs_batch_eval_transcript(transcript, max_degree, point);

        let alpha = transcript.get_challenge_field_elem(b"alpha");
        let mut h = FpPolynomial::<Self::Field>::zero();
        let mut multiplier = Self::Field::one();
        let z = FpPolynomial::from_zeroes(&[point.clone()]);

        for poly in polys.iter() {
            let mut poly = (*poly).clone();
            let eval_value = poly.eval(point);
            poly.sub_assign(&FpPolynomial::from_coefs(vec![eval_value]));
            poly.mul_scalar_assign(&multiplier);
            h.add_assign(&poly);
            multiplier.mul_assign(&alpha);
        }

        let (q, rem) = h.div_rem(&z);
        if !rem.is_zero() {
            return Err(eg!());
        }

        if let Some(lagrange_pcs) = lagrange_pcs {
            let degree = q.degree();
            let mut max_power_of_2 = degree;
            for i in (0..=degree).rev() {
                if (i & (i - 1)) == 0 {
                    max_power_of_2 = i;
                    break;
                }
            }

            let mut blinds = vec![];
            for i in &q.coefs[max_power_of_2..] {
                blinds.push(i.neg());
            }

            let mut new_coefs = q.coefs[..max_power_of_2].to_vec();
            for (i, v) in blinds.iter().enumerate() {
                new_coefs[i] = new_coefs[i] - v;
            }

            let sub_q = FpPolynomial::from_coefs(new_coefs);
            let (_domain, q_eval) = FpPolynomial::fft(&sub_q, max_power_of_2).c(d!())?;
            let q_eval = FpPolynomial::from_coefs(q_eval);

            let cm = lagrange_pcs.commit(&q_eval).c(d!())?;
            Ok(self.apply_blind_factors(&cm, &blinds, max_power_of_2))
        } else {
            self.commit(&q)
        }
    }

    /// Combine multiple commitments into one commitment.
    fn batch(
        &self,
        transcript: &mut Transcript,
        cm_vec: &[&Self::Commitment],
        max_degree: usize,
        point: &Self::Field,
        evals: &[Self::Field],
    ) -> (Self::Commitment, Self::Field) {
        Self::init_pcs_batch_eval_transcript(transcript, max_degree, point);
        let alpha = transcript.get_challenge_field_elem::<Self::Field>(b"alpha");

        let mut multiplier = Self::Field::one();
        let mut cm_combined = Self::Commitment::get_identity();
        let mut eval_combined = Self::Field::zero();
        for (eval, cm) in evals.iter().zip(cm_vec) {
            cm_combined.add_assign(&cm.mul(&multiplier));
            eval_combined.add_assign(&eval.mul(multiplier));
            multiplier.mul_assign(&alpha);
        }
        (cm_combined, eval_combined)
    }

    /// Verify a batched proof.
    fn batch_verify(
        &self,
        transcript: &mut Transcript,
        commitments: &[&Self::Commitment],
        max_degree: usize,
        point: &Self::Field,
        values: &[Self::Field],
        proof: &Self::Commitment,
    ) -> Result<()> {
        let (cm_combined, eval_combined) =
            self.batch(transcript, commitments, max_degree, point, values);

        self.verify(&cm_combined, max_degree, &point, &eval_combined, &proof)
            .c(d!())
    }

    /// Batch verify a list of proofs with different points.
    fn batch_verify_diff_points(
        &self,
        _transcript: &mut Transcript,
        cm_vec: &[Self::Commitment],
        _degree: usize,
        point_vec: &[Self::Field],
        eval_vec: &[Self::Field],
        proof: &[Self::Commitment],
        challenge: &Self::Field,
    ) -> Result<()>;

    /// Initialize the transcript for batch evaluation.
    fn init_pcs_batch_eval_transcript(
        transcript: &mut Transcript,
        max_degree: usize,
        point: &Self::Field,
    ) {
        transcript.append_message(b"Domain Separator", b"New PCS-Batch-Eval Protocol");
        Self::transcript_append_params(transcript, max_degree, point);
    }

    /// Append params to the transcript.
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

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use crate::poly_commit::{
        field_polynomial::FpPolynomial, kzg_poly_com::KZGCommitmentScheme, pcs::PolyComScheme,
    };
    use ark_std::test_rng;
    use merlin::Transcript;
    use noah_algebra::{bls12_381::BLSScalar, prelude::*};

    #[test]
    fn test_pcs_eval() {
        let mut prng = test_rng();
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        let two = one.add(&one);

        let poly = FpPolynomial::from_zeroes(&[zero, one, two]);
        let degree = poly.degree();
        let pcs = KZGCommitmentScheme::new(degree, &mut prng);
        let com = pcs.commit(&poly).unwrap();
        let point = BLSScalar::random(&mut prng);
        let proof = pcs.prove(&poly, &point, degree).unwrap();
        let eval = pcs.eval(&poly, &point);
        assert!(pcs.verify(&com, degree, &point, &eval, &proof).is_ok());
    }

    #[test]
    fn test_pcs_batch_eval() {
        let mut prng = test_rng();
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
        let com1 = pcs.commit(&poly1).unwrap();
        let com2 = pcs.commit(&poly2).unwrap();
        let com3 = pcs.commit(&poly3).unwrap();
        let point = Field::random(&mut prng);
        let proof = {
            let mut transcript = Transcript::new(b"TestPCS");
            pcs.batch_prove(
                &mut transcript,
                None,
                &[&poly1, &poly2, &poly3],
                &point,
                degree,
            )
            .unwrap()
        };
        let evals = vec![
            pcs.eval(&poly1, &point),
            pcs.eval(&poly2, &point),
            pcs.eval(&poly3, &point),
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
