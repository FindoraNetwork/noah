use crate::poly_commit::{
    errors::PolyComSchemeError,
    field_polynomial::FpPolynomial,
    pcs::{HomomorphicPolyComElem, PolyComScheme, ToBytes},
};
use merlin::Transcript;
use noah_algebra::bls12_381::{BLSGt, BLSPairingEngine};
use noah_algebra::{
    bls12_381::{BLSScalar, BLSG1},
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

impl HomomorphicPolyComElem for KZGCommitment<BLSG1> {
    type Scalar = BLSScalar;
    fn get_base() -> Self {
        KZGCommitment(BLSG1::get_base())
    }

    fn get_identity() -> Self {
        KZGCommitment(BLSG1::get_identity())
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

    fn mul(&self, exp: &BLSScalar) -> Self {
        KZGCommitment(self.0.mul(exp))
    }

    fn mul_assign(&mut self, exp: &BLSScalar) {
        self.0.mul_assign(&exp)
    }
}

impl<F: Scalar> ToBytes for FpPolynomial<F> {
    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }
}

impl<F: Domain> HomomorphicPolyComElem for FpPolynomial<F> {
    type Scalar = F;

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
            return Err(eg!(NoahError::DeserializationError));
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

/// KZG commitment scheme over the BLS12-381 curve
pub type KZGCommitmentSchemeBLS = KZGCommitmentScheme<BLSPairingEngine>;

impl<'b> PolyComScheme for KZGCommitmentSchemeBLS {
    type Field = BLSScalar;
    type Commitment = KZGCommitment<BLSG1>;

    fn max_degree(&self) -> usize {
        self.public_parameter_group_1.len() - 1
    }

    fn commit(&self, polynomial: &FpPolynomial<BLSScalar>) -> Result<Self::Commitment> {
        let coefs = polynomial.get_coefs_ref();

        let degree = polynomial.degree();

        if degree + 1 > self.public_parameter_group_1.len() {
            return Err(eg!(PolyComSchemeError::DegreeError));
        }

        let coefs_poly_bls_scalar_ref: Vec<&BLSScalar> = coefs.iter().collect();
        let pub_param_group_1_as_ref: Vec<&BLSG1> = self.public_parameter_group_1[0..degree + 1]
            .iter()
            .collect();

        let commitment_value = BLSG1::multi_exp(
            &coefs_poly_bls_scalar_ref[..],
            &pub_param_group_1_as_ref[..],
        );

        Ok(KZGCommitment(commitment_value))
    }

    fn eval(&self, poly: &FpPolynomial<Self::Field>, point: &Self::Field) -> Self::Field {
        poly.eval(point)
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

    fn prove(
        &self,
        poly: &FpPolynomial<Self::Field>,
        x: &Self::Field,
        max_degree: usize,
    ) -> Result<Self::Commitment> {
        let eval = poly.eval(x);

        if poly.degree() > max_degree {
            println!(
                "polynomial degree = {}, max_degree = {}",
                poly.degree(),
                max_degree
            );
            return Err(eg!(PolyComSchemeError::DegreeError));
        }

        let nominator = poly.sub(&FpPolynomial::from_coefs(vec![eval]));
        // f(X) - f(x)

        // Negation must happen in Fq
        let point_neg = x.neg();

        // X - x
        let vanishing_poly = FpPolynomial::from_coefs(vec![point_neg, Self::Field::one()]);
        let (q_poly, r_poly) = nominator.div_rem(&vanishing_poly); // P(X)-P(x) / (X-x)

        if !r_poly.is_zero() {
            return Err(eg!(PolyComSchemeError::PCSProveEvalError));
        }

        let proof = self.commit(&q_poly).unwrap();
        Ok(proof)
    }

    fn verify(
        &self,
        cm: &Self::Commitment,
        _degree: usize,
        point: &Self::Field,
        eval: &Self::Field,
        proof: &Self::Commitment,
    ) -> Result<()> {
        let g1_0 = self.public_parameter_group_1[0].clone();
        let g2_0 = self.public_parameter_group_2[0].clone();
        let g2_1 = self.public_parameter_group_2[1].clone();

        let x_minus_point_group_element_group_2 = &g2_1.sub(&g2_0.mul(point));

        let left_pairing_eval = if eval.is_zero() {
            BLSPairingEngine::pairing(&cm.0, &g2_0)
        } else {
            BLSPairingEngine::pairing(&cm.0.sub(&g1_0.mul(eval)), &g2_0)
        };

        let right_pairing_eval =
            BLSPairingEngine::pairing(&proof.0, &x_minus_point_group_element_group_2);

        if left_pairing_eval == right_pairing_eval {
            Ok(())
        } else {
            Err(eg!(PolyComSchemeError::PCSProveEvalError))
        }
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

        let pairing_eval = BLSPairingEngine::product_of_pairings(
            &[left_first, right_first.neg()],
            &[left_second, right_second],
        );

        if pairing_eval == BLSGt::get_identity() {
            Ok(())
        } else {
            Err(eg!(PolyComSchemeError::PCSProveEvalError))
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

#[cfg(test)]
mod tests_kzg_impl {
    use crate::poly_commit::{
        field_polynomial::FpPolynomial,
        kzg_poly_com::{KZGCommitmentScheme, KZGCommitmentSchemeBLS},
        pcs::{HomomorphicPolyComElem, PolyComScheme},
    };
    use noah_algebra::bls12_381::BLSPairingEngine;
    use noah_algebra::{
        bls12_381::{BLSScalar, BLSG1},
        prelude::*,
        traits::Pairing,
    };

    fn check_public_parameters_generation<P: Pairing>() {
        let param_size = 5;
        let mut prng = test_rng();
        let kzg_scheme = KZGCommitmentScheme::<P>::new(param_size, &mut prng);
        let g1_power1 = kzg_scheme.public_parameter_group_1[1].clone();
        let g2_power1 = kzg_scheme.public_parameter_group_2[1].clone();

        // Check parameters for G1
        for i in 0..param_size - 1 {
            let elem_first_group_1 = kzg_scheme.public_parameter_group_1[i].clone();
            let elem_next_group_1 = kzg_scheme.public_parameter_group_1[i + 1].clone();
            let elem_next_group_1_target = P::pairing(&elem_next_group_1, &P::G2::get_base());
            let elem_next_group_1_target_recomputed = P::pairing(&elem_first_group_1, &g2_power1);
            assert_eq!(
                elem_next_group_1_target_recomputed,
                elem_next_group_1_target
            );
        }

        // Check parameters for G2
        let elem_first_group_2 = kzg_scheme.public_parameter_group_2[0].clone();
        let elem_second_group_2 = kzg_scheme.public_parameter_group_2[1].clone();
        let elem_next_group_2_target = P::pairing(&P::G1::get_base(), &elem_second_group_2);
        let elem_next_group_2_target_recomputed = P::pairing(&g1_power1, &elem_first_group_2);

        assert_eq!(
            elem_next_group_2_target_recomputed,
            elem_next_group_2_target
        );
    }

    // Check the size of the KZG being generated.
    fn generation_of_crs<P: Pairing>() {
        let n = 1 << 5;
        let mut prng = test_rng();
        let kzg_scheme = KZGCommitmentScheme::<P>::new(n, &mut prng);
        assert_eq!(kzg_scheme.public_parameter_group_1.len(), n + 1);
        assert_eq!(kzg_scheme.public_parameter_group_2.len(), 2);
    }

    #[test]
    fn test_homomorphic_poly_com_elem() {
        let mut prng = test_rng();
        let pcs = KZGCommitmentSchemeBLS::new(20, &mut prng);
        type Field = BLSScalar;
        let one = Field::one();
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
        check_public_parameters_generation::<BLSPairingEngine>();
    }

    #[test]
    fn test_generation_of_crs() {
        generation_of_crs::<BLSPairingEngine>();
    }

    #[test]
    fn test_commit() {
        let mut prng = test_rng();
        let pcs = KZGCommitmentSchemeBLS::new(10, &mut prng);
        type Field = BLSScalar;
        let one = Field::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let six = three.add(&three);

        let fq_poly = FpPolynomial::from_coefs(vec![two, three, six]);
        let commitment = pcs.commit(&fq_poly).unwrap();

        let coefs_poly_blsscalar = fq_poly.get_coefs_ref().iter().collect_vec();
        let mut expected_committed_value = BLSG1::get_identity();

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
        let pcs = KZGCommitmentSchemeBLS::new(10, &mut prng);
        type Field = BLSScalar;
        let one = Field::one();
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

        let res = pcs.verify(&commitment_value, degree, &point, &seven, &proof);
        pnk!(res);

        let new_pcs = pcs.shrink_to_verifier_only().unwrap();
        let res = new_pcs.verify(&commitment_value, degree, &point, &seven, &proof);
        pnk!(res);

        let wrong_eval = one;
        let res = pcs.verify(&commitment_value, degree, &point, &wrong_eval, &proof);
        assert!(res.is_err());
    }
}
