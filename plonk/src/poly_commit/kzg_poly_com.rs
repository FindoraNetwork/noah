use crate::errors::{PlonkError, Result};
use crate::poly_commit::{
    field_polynomial::FpPolynomial,
    pcs::{HomomorphicPolyComElem, PolyComScheme, ToBytes},
};
use merlin::Transcript;
use noah_algebra::bls12_381::BLSPairingEngine;
use noah_algebra::bn254::BN254PairingEngine;
use noah_algebra::{
    prelude::*,
    traits::{Domain, Pairing},
};

/// KZG commitment scheme over the `Group`.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct KZGCommitment<G>(pub G);

impl<'a, G> ToBytes for KZGCommitment<G>
where
    G: Group,
{
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_compressed_bytes()
    }
}

impl<G: Group> HomomorphicPolyComElem<G::ScalarType> for KZGCommitment<G> {
    fn get_base() -> Self {
        KZGCommitment(G::get_base())
    }

    fn get_identity() -> Self {
        KZGCommitment(G::get_identity())
    }

    fn add(&self, other: &Self) -> Self {
        KZGCommitment(self.0.add(&other.0))
    }

    fn add_assign(&mut self, other: &Self) {
        self.0.add_assign(&other.0)
    }

    fn sub(&self, other: &Self) -> Self {
        KZGCommitment(self.0.sub(&other.0))
    }

    fn sub_assign(&mut self, other: &Self) {
        self.0.sub_assign(&other.0)
    }

    fn mul(&self, exp: &G::ScalarType) -> Self {
        KZGCommitment(self.0.mul(exp))
    }

    fn mul_assign(&mut self, exp: &G::ScalarType) {
        self.0.mul_assign(&exp)
    }
}

impl<F: Scalar> ToBytes for FpPolynomial<F> {
    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }
}

impl<F: Domain> HomomorphicPolyComElem<F> for FpPolynomial<F> {
    fn get_base() -> Self {
        unimplemented!()
    }

    fn get_identity() -> Self {
        unimplemented!()
    }

    fn add(&self, other: &Self) -> Self {
        self.add(other)
    }

    fn add_assign(&mut self, other: &Self) {
        self.add_assign(other)
    }

    fn sub(&self, other: &Self) -> Self {
        self.sub(other)
    }

    fn sub_assign(&mut self, other: &Self) {
        self.sub_assign(other)
    }

    fn mul(&self, exp: &F) -> Self {
        self.mul_scalar(exp)
    }

    fn mul_assign(&mut self, exp: &F) {
        self.mul_scalar_assign(exp)
    }
}

/// KZG opening proof.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct KZGOpenProof<G1>(pub G1);

impl<G: Group> ToBytes for KZGOpenProof<G> {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_compressed_bytes()
    }
}

/// KZG commitment scheme about `PairingEngine`.
#[derive(Debug, Serialize, Deserialize)]
pub struct KZGCommitmentScheme<P: Pairing> {
    /// public parameter about G1.
    pub public_parameter_group_1: Vec<P::G1>,
    /// public parameter about G1.
    pub public_parameter_group_2: Vec<P::G2>,
}

impl<P: Pairing> KZGCommitmentScheme<P> {
    /// Create a new instance of a KZG polynomial commitment scheme.
    /// `max_degree` - max degree of the polynomial,
    /// `prng` - pseudo-random generator.
    pub fn new<R: CryptoRng + RngCore>(max_degree: usize, prng: &mut R) -> KZGCommitmentScheme<P> {
        let s = P::ScalarField::random(prng);

        let mut public_parameter_group_1: Vec<P::G1> = Vec::new();

        let mut elem_g1 = P::G1::get_base();

        for _ in 0..=max_degree {
            public_parameter_group_1.push(elem_g1.clone());
            elem_g1 = elem_g1.mul(&s);
        }

        let mut public_parameter_group_2: Vec<P::G2> = Vec::new();
        let elem_g2 = P::G2::get_base();
        public_parameter_group_2.push(elem_g2.clone());
        public_parameter_group_2.push(elem_g2.mul(&s));

        KZGCommitmentScheme {
            public_parameter_group_1,
            public_parameter_group_2,
        }
    }

    /// Serialize the parameters to unchecked bytes.
    pub fn to_unchecked_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![];
        let len_1 = self.public_parameter_group_1.len() as u32;
        let len_2 = self.public_parameter_group_2.len() as u32;
        bytes.extend(len_1.to_le_bytes());
        bytes.extend(len_2.to_le_bytes());

        for i in &self.public_parameter_group_1 {
            bytes.extend(i.to_unchecked_bytes());
        }
        for i in &self.public_parameter_group_2 {
            bytes.extend(i.to_unchecked_bytes());
        }
        Ok(bytes)
    }

    /// Deserialize the parameters from unchecked bytes.
    pub fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(PlonkError::Algebra(AlgebraError::DeserializationError));
        }
        let mut len_1_bytes = [0u8; 4];
        let mut len_2_bytes = [0u8; 4];
        len_1_bytes.copy_from_slice(&bytes[0..4]);
        len_2_bytes.copy_from_slice(&bytes[4..8]);
        let len_1 = u32::from_le_bytes(len_1_bytes) as usize;
        let len_2 = u32::from_le_bytes(len_2_bytes) as usize;
        let n_1 = P::G1::unchecked_size();
        let n_2 = P::G2::unchecked_size();

        let bytes_1 = &bytes[8..];
        let bytes_2 = &bytes[8 + (n_1 * len_1)..];
        let mut p1 = vec![];
        let mut p2 = vec![];

        for i in 0..len_1 {
            p1.push(P::G1::from_unchecked_bytes(
                &bytes_1[n_1 * i..n_1 * (i + 1)],
            )?);
        }

        for i in 0..len_2 {
            p2.push(P::G2::from_unchecked_bytes(
                &bytes_2[n_2 * i..n_2 * (i + 1)],
            )?);
        }

        Ok(Self {
            public_parameter_group_1: p1,
            public_parameter_group_2: p2,
        })
    }
}

impl<P: Pairing> PolyComScheme for KZGCommitmentScheme<P> {
    type Field = P::ScalarField;
    type Commitment = KZGCommitment<P::G1>;

    fn max_degree(&self) -> usize {
        self.public_parameter_group_1.len() - 1
    }

    fn commit(&self, polynomial: &FpPolynomial<Self::Field>) -> Result<Self::Commitment> {
        let coefs = polynomial.get_coefs_ref();

        let degree = polynomial.degree();

        if degree + 1 > self.public_parameter_group_1.len() {
            return Err(PlonkError::DegreeError);
        }

        let coefs_poly_scalar_ref: Vec<&Self::Field> = coefs.iter().collect();
        let pub_param_group_1_as_ref: Vec<&P::G1> = self.public_parameter_group_1[0..degree + 1]
            .iter()
            .collect();

        let commitment_value =
            P::G1::multi_exp(&coefs_poly_scalar_ref[..], &pub_param_group_1_as_ref[..]);

        Ok(KZGCommitment::<P::G1>(commitment_value))
    }

    fn eval(&self, polynomial: &FpPolynomial<Self::Field>, point: &Self::Field) -> Self::Field {
        polynomial.eval(point)
    }

    fn prove(
        &self,
        polynomial: &FpPolynomial<Self::Field>,
        point: &Self::Field,
        max_degree: usize,
    ) -> Result<Self::Commitment> {
        let eval = polynomial.eval(point);

        if polynomial.degree() > max_degree {
            return Err(PlonkError::DegreeError);
        }

        let nominator = polynomial.sub(&FpPolynomial::from_coefs(vec![eval]));
        // f(X) - f(x)

        // Negation must happen in Fq
        let point_neg = point.neg();

        // X - x
        let vanishing_poly = FpPolynomial::from_coefs(vec![point_neg, Self::Field::one()]);
        let (q_poly, r_poly) = nominator.div_rem(&vanishing_poly); // P(X)-P(x) / (X-x)

        if !r_poly.is_zero() {
            return Err(PlonkError::PCSProveEvalError);
        }

        let proof = self.commit(&q_poly).unwrap();
        Ok(proof)
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        _degree: usize,
        point: &Self::Field,
        value: &Self::Field,
        proof: &Self::Commitment,
    ) -> Result<()> {
        let g1_0 = self.public_parameter_group_1[0].clone();
        let g2_0 = self.public_parameter_group_2[0].clone();
        let g2_1 = self.public_parameter_group_2[1].clone();

        let x_minus_point_group_element_group_2 = &g2_1.sub(&g2_0.mul(point));

        let left_pairing_eval = if value.is_zero() {
            P::pairing(&commitment.0, &g2_0)
        } else {
            P::pairing(&commitment.0.sub(&g1_0.mul(value)), &g2_0)
        };

        let right_pairing_eval = P::pairing(&proof.0, &x_minus_point_group_element_group_2);

        if left_pairing_eval == right_pairing_eval {
            Ok(())
        } else {
            Err(PlonkError::PCSProveEvalError)
        }
    }

    fn apply_blind_factors(
        &self,
        commitment: &Self::Commitment,
        blinds: &[Self::Field],
        zeroing_degree: usize,
    ) -> Self::Commitment {
        let mut commitment = commitment.0.clone();
        for (i, blind) in blinds.iter().enumerate() {
            let mut blind = blind.clone();
            commitment = commitment + &(self.public_parameter_group_1[i] * &blind);
            blind = blind.neg();
            commitment = commitment + &(self.public_parameter_group_1[zeroing_degree + i] * &blind);
        }
        KZGCommitment(commitment)
    }

    fn batch_verify_diff_points(
        &self,
        _transcript: &mut Transcript,
        cm_vec: &[Self::Commitment],
        _degree: usize,
        point_vec: &[Self::Field],
        eval_vec: &[Self::Field],
        proofs: &[Self::Commitment],
        challenge: &Self::Field,
    ) -> Result<()> {
        assert!(proofs.len() > 0);
        assert_eq!(proofs.len(), point_vec.len());
        assert_eq!(proofs.len(), eval_vec.len());
        assert_eq!(proofs.len(), cm_vec.len());

        let g1_0 = self.public_parameter_group_1[0].clone();
        let g2_0 = self.public_parameter_group_2[0].clone();
        let g2_1 = self.public_parameter_group_2[1].clone();

        let left_second = g2_1;
        let right_second = g2_0;

        let mut left_first = proofs[0].0.clone();
        let mut right_first = proofs[0].0.mul(&point_vec[0]);
        let mut right_first_val = eval_vec[0].clone();
        let mut right_first_comm = cm_vec[0].0.clone();

        let mut cur_challenge = challenge.clone();
        for i in 1..proofs.len() {
            let new_comm = proofs[i].0.mul(&cur_challenge);

            left_first.add_assign(&new_comm);
            right_first.add_assign(&new_comm.mul(&point_vec[i]));
            right_first_val.add_assign(&eval_vec[i].mul(&cur_challenge));
            right_first_comm.add_assign(&cm_vec[i].0.mul(&cur_challenge));

            cur_challenge.mul_assign(&challenge);
        }
        right_first.sub_assign(&g1_0.mul(&right_first_val));
        right_first.add_assign(&right_first_comm);

        let pairing_eval = P::product_of_pairings(
            &[left_first, right_first.neg()],
            &[left_second, right_second],
        );

        if pairing_eval == P::Gt::get_identity() {
            Ok(())
        } else {
            Err(PlonkError::PCSProveEvalError)
        }
    }

    fn shrink_to_verifier_only(&self) -> Self {
        Self {
            public_parameter_group_1: vec![self.public_parameter_group_1[0].clone()],
            public_parameter_group_2: vec![
                self.public_parameter_group_2[0].clone(),
                self.public_parameter_group_2[1].clone(),
            ],
        }
    }
}

/// KZG commitment scheme over the BLS12-381 curve
pub type KZGCommitmentSchemeBLS = KZGCommitmentScheme<BLSPairingEngine>;

/// KZG commitment scheme over the BN254 curve
pub type KZGCommitmentSchemeBN254 = KZGCommitmentScheme<BN254PairingEngine>;

macro_rules! _test_Kzg_commitment {
    ($scalar:ty, $scheme: ty, $pairing:ty) => {
        #[test]
        fn test_homomorphic_poly_com_elem() {
            let mut prng = test_rng();
            let pcs = <$scheme>::new(20, &mut prng);
            let one = <$scalar>::one();
            let two = one.add(&one);
            let three = two.add(&one);
            let four = three.add(&one);
            let six = three.add(&three);
            let eight = six.add(&two);
            let poly1 = FpPolynomial::from_coefs(vec![two, three, six]);

            let commitment1 = pcs.commit(&poly1).unwrap();

            let poly2 = FpPolynomial::from_coefs(vec![one, eight, four]);

            let commitment2 = pcs.commit(&poly2).unwrap();

            // Add two polynomials
            let poly_sum = poly1.add(&poly2);
            let commitment_sum = pcs.commit(&poly_sum).unwrap();
            let commitment_sum_computed = commitment1.add(&commitment2);
            assert_eq!(commitment_sum, commitment_sum_computed);

            // Multiplying all the coefficients of a polynomial by some value
            let exponent = four.add(&one);
            let poly1_mult_5 = poly1.mul_scalar(&exponent);
            let commitment_poly1_mult_5 = pcs.commit(&poly1_mult_5).unwrap();
            let commitment_poly1_mult_5_hom = commitment1.mul(&exponent);
            assert_eq!(commitment_poly1_mult_5, commitment_poly1_mult_5_hom);
        }

        #[test]
        fn test_public_parameters() {
            let param_size = 5;
            let mut prng = test_rng();
            let kzg_scheme = KZGCommitmentScheme::<$pairing>::new(param_size, &mut prng);
            let g1_power1 = kzg_scheme.public_parameter_group_1[1].clone();
            let g2_power1 = kzg_scheme.public_parameter_group_2[1].clone();

            // Check parameters for G1
            for i in 0..param_size - 1 {
                let elem_first_group_1 = kzg_scheme.public_parameter_group_1[i].clone();
                let elem_next_group_1 = kzg_scheme.public_parameter_group_1[i + 1].clone();
                let elem_next_group_1_target =
                    <$pairing>::pairing(&elem_next_group_1, &<$pairing as Pairing>::G2::get_base());
                let elem_next_group_1_target_recomputed =
                    <$pairing>::pairing(&elem_first_group_1, &g2_power1);
                assert_eq!(
                    elem_next_group_1_target_recomputed,
                    elem_next_group_1_target
                );
            }

            // Check parameters for G2
            let elem_first_group_2 = kzg_scheme.public_parameter_group_2[0].clone();
            let elem_second_group_2 = kzg_scheme.public_parameter_group_2[1].clone();
            let elem_next_group_2_target =
                <$pairing>::pairing(&<$pairing as Pairing>::G1::get_base(), &elem_second_group_2);
            let elem_next_group_2_target_recomputed =
                <$pairing>::pairing(&g1_power1, &elem_first_group_2);

            assert_eq!(
                elem_next_group_2_target_recomputed,
                elem_next_group_2_target
            );
        }

        #[test]
        fn test_generation_of_crs() {
            let n = 1 << 5;
            let mut prng = test_rng();
            let kzg_scheme = KZGCommitmentScheme::<$pairing>::new(n, &mut prng);
            assert_eq!(kzg_scheme.public_parameter_group_1.len(), n + 1);
            assert_eq!(kzg_scheme.public_parameter_group_2.len(), 2);
        }

        #[test]
        fn test_commit() {
            let mut prng = test_rng();
            let pcs = <$scheme>::new(10, &mut prng);
            let one = <$scalar>::one();
            let two = one.add(&one);
            let three = two.add(&one);
            let six = three.add(&three);

            let fq_poly = FpPolynomial::from_coefs(vec![two, three, six]);
            let commitment = pcs.commit(&fq_poly).unwrap();

            let coefs_poly_blsscalar = fq_poly.get_coefs_ref().iter().collect_vec();
            let mut expected_committed_value = <$pairing as Pairing>::G1::get_identity();

            // Doing the multiexp by hand
            for (i, coef) in coefs_poly_blsscalar.iter().enumerate() {
                let g_i = pcs.public_parameter_group_1[i].clone();
                expected_committed_value = expected_committed_value.add(&g_i.mul(&coef));
            }
            assert_eq!(expected_committed_value, commitment.0);
        }

        #[test]
        fn test_eval() {
            let mut prng = test_rng();
            let pcs = <$scheme>::new(10, &mut prng);
            let one = <$scalar>::one();
            let two = one.add(&one);
            let three = two.add(&one);
            let four = three.add(&one);
            let six = three.add(&three);
            let seven = six.add(&one);
            let fq_poly = FpPolynomial::from_coefs(vec![one, two, four]);
            let point = one;
            let max_degree = fq_poly.degree();

            let degree = fq_poly.degree();
            let commitment_value = pcs.commit(&fq_poly).unwrap();

            // Check that an error is returned if the degree of the polynomial exceeds the maximum degree.
            let wrong_max_degree = 1;
            let res = pcs.prove(&fq_poly, &point, wrong_max_degree);
            assert!(res.is_err());

            let proof = pcs.prove(&fq_poly, &point, max_degree).unwrap();

            pcs.verify(&commitment_value, degree, &point, &seven, &proof)
                .unwrap();

            let new_pcs = pcs.shrink_to_verifier_only();
            new_pcs
                .verify(&commitment_value, degree, &point, &seven, &proof)
                .unwrap();

            let wrong_eval = one;
            let res = pcs.verify(&commitment_value, degree, &point, &wrong_eval, &proof);
            assert!(res.is_err());
        }
    };
}
#[cfg(test)]
mod tests_kzg_bls {
    use crate::poly_commit::{
        field_polynomial::FpPolynomial,
        kzg_poly_com::{KZGCommitmentScheme, KZGCommitmentSchemeBLS},
        pcs::{HomomorphicPolyComElem, PolyComScheme},
    };
    use noah_algebra::bls12_381::BLSPairingEngine;
    use noah_algebra::{bls12_381::BLSScalar, prelude::*, traits::Pairing};

    _test_Kzg_commitment!(BLSScalar, KZGCommitmentSchemeBLS, BLSPairingEngine);
}
#[cfg(test)]
mod tests_kzg_bn254 {
    use crate::poly_commit::{
        field_polynomial::FpPolynomial,
        kzg_poly_com::{KZGCommitmentScheme, KZGCommitmentSchemeBN254},
        pcs::{HomomorphicPolyComElem, PolyComScheme},
    };
    use noah_algebra::bn254::{BN254PairingEngine, BN254Scalar};
    use noah_algebra::{prelude::*, traits::Pairing};

    _test_Kzg_commitment!(BN254Scalar, KZGCommitmentSchemeBN254, BN254PairingEngine);
}
