use crate::plonk::{
    constraint_system::ConstraintSystem, errors::PlonkError, helpers::compute_lagrange_constant,
};
use crate::poly_commit::{field_polynomial::FpPolynomial, pcs::PolyComScheme};
use ark_poly::{EvaluationDomain, MixedRadixEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use noah_algebra::{prelude::*, traits::Domain};
use rand_chacha::ChaChaRng;

/// The data structure of a Plonk proof.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone)]
pub struct PlonkProof<C, F> {
    /// The witness polynomial commitments.
    pub cm_w_vec: Vec<C>,
    /// The split quotient polynomial commitments
    pub cm_t_vec: Vec<C>,
    /// The sigma polynomial commitment.
    pub cm_z: C,
    /// The opening of the third preprocessed round key polynomial at \zeta.
    pub prk_3_poly_eval_zeta: F,
    /// The opening of the fourth preprocessed round key polynomial at \zeta.
    pub prk_4_poly_eval_zeta: F,
    /// The openings of witness polynomials at \zeta.
    pub w_polys_eval_zeta: Vec<F>,
    /// The openings of witness polynomials (first three) at \zeta * \omega.
    pub w_polys_eval_zeta_omega: Vec<F>,
    /// The opening of z(X) at point \zeta * \omega.
    pub z_eval_zeta_omega: F,
    /// The openings of permutation polynomials at \zeta.
    pub s_polys_eval_zeta: Vec<F>,
    /// The commitment for the first witness polynomial, for \zeta.
    pub opening_witness_zeta: C,
    /// The commitment for the second witness polynomial, for \zeta\omega.
    pub opening_witness_zeta_omega: C,
}

/// The type of the Plonk proof with a specific polynomial commitment scheme.
pub type PlonkPf<PCS> =
    PlonkProof<<PCS as PolyComScheme>::Commitment, <PCS as PolyComScheme>::Field>;

/// Plonk prover parameters.
#[derive(Debug, Serialize, Deserialize)]
pub struct PlonkProverParams<O, C, F> {
    /// The polynomials of the selectors.
    pub q_polys: Vec<O>,
    /// The polynomials of perm1, perm2, ..., perm_{n_wires_per_gate}.
    pub s_polys: Vec<O>,
    /// The polynomial for boolean constraints.
    pub qb_poly: O,
    /// The four polynomials for the Anemoi/Jive constraints.
    pub q_prk_polys: Vec<O>,
    /// The Plonk verifier parameters.
    pub verifier_params: PlonkVerifierParams<C, F>,
    /// The elements of the group.
    pub group: Vec<F>,
    /// The evaluation domain for computing the quotient polynomial.
    pub coset_quotient: Vec<F>,
    /// The evaluation domain of size m.
    pub domain_m: Vec<u8>,
    /// First lagrange basis.
    pub l1_coefs: FpPolynomial<F>,
    /// The l1's FFT of the polynomial of unity root set.
    pub l1_coset_evals: Vec<F>,
    /// Initialize [one.neg, zero, zero, ... zero, one] polynomial.
    pub z_h_coefs: FpPolynomial<F>,
    /// The z_h's FFT of the polynomial of unity root set.
    pub z_h_inv_coset_evals: Vec<F>,
    /// The selector polynomials' FFT of the polynomial of unity root set.
    pub q_coset_evals: Vec<Vec<F>>,
    /// The permutation polynomials' FFT of the polynomial of unity root set.
    pub s_coset_evals: Vec<Vec<F>>,
    /// The boolean constraint polynomial's FFT of the polynomial of unity root set.
    pub qb_coset_eval: Vec<F>,
    /// The Anemoi/Jive polynomials' FFT of the polynomial of unity root set.
    pub q_prk_coset_evals: Vec<Vec<F>>,
}

/// Prover parameters over a particular polynomial commitment scheme.
pub type PlonkPK<PCS> = PlonkProverParams<
    FpPolynomial<<PCS as PolyComScheme>::Field>,
    <PCS as PolyComScheme>::Commitment,
    <PCS as PolyComScheme>::Field,
>;

impl<O, C, F> PlonkProverParams<O, C, F> {
    /// Return the verifier parameters.
    pub fn get_verifier_params(self) -> PlonkVerifierParams<C, F> {
        self.verifier_params
    }

    /// Return a reference of verifier parameters.
    pub fn get_verifier_params_ref(&self) -> &PlonkVerifierParams<C, F> {
        &self.verifier_params
    }
}

/// Plonk verifier parameters.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PlonkVerifierParams<C, F> {
    /// The commitments of the selectors.
    pub cm_q_vec: Vec<C>,
    /// The commitments of perm1, perm2, ..., perm_{n_wires_per_gate}.
    pub cm_s_vec: Vec<C>,
    /// The commitment of the boolean selector.
    pub cm_qb: C,
    /// The commitments of the preprocessed round key selectors.
    pub cm_prk_vec: Vec<C>,
    /// the Anemoi generator.
    pub anemoi_generator: F,
    /// the Anemoi generator's inverse.
    pub anemoi_generator_inv: F,
    /// `n_wires_per_gate` different quadratic non-residue in F_q-{0}.
    pub k: Vec<F>,
    /// The primitive evaluation domain.
    pub domain: Vec<u8>,
    /// The size of constraint system.
    pub cs_size: usize,
    /// The public constrain variables indices.
    pub public_vars_constraint_indices: Vec<usize>,
    /// The constrain lagrange base by public constrain variables.
    pub lagrange_constants: Vec<F>,
}

/// Define the PLONK verifier params by given `PolyComScheme`.
pub type PlonkVK<PCS> =
    PlonkVerifierParams<<PCS as PolyComScheme>::Commitment, <PCS as PolyComScheme>::Field>;

/// Perform deserialization, then return domain and root(a generator of the subgroup).
pub fn get_domain_and_root<PCS: PolyComScheme>(
    domain: &[u8],
) -> (
    MixedRadixEvaluationDomain<<<PCS as PolyComScheme>::Field as Domain>::Field>,
    PCS::Field,
) {
    let reader = ark_std::io::BufReader::new(domain);
    let domain = MixedRadixEvaluationDomain::deserialize_unchecked(reader).unwrap();
    let root = PCS::Field::from_field(domain.group_gen);
    (domain, root)
}

/// Convert the domain to bytes in the compressed representation.
fn compress_domain<PCS: PolyComScheme>(
    domain: &MixedRadixEvaluationDomain<<<PCS as PolyComScheme>::Field as Domain>::Field>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    domain.serialize_unchecked(&mut buf).unwrap();
    buf
}

/// Encode the permutation value, from an index to a group element.
pub fn encode_perm_to_group<F: Scalar>(group: &[F], perm: &[usize], k: &[F]) -> Vec<F> {
    let n = group.len();
    perm.iter()
        .map(|pi| {
            for (i, ki) in k.iter().enumerate().skip(1) {
                if *pi < (i + 1) * n && *pi >= i * n {
                    return ki.mul(&group[pi % n]);
                }
            }
            group[pi % n]
        })
        .collect()
}

/// Find `n_wires_per_gate - 1` different quadratic non-residue in F_q-{0}.
pub fn choose_ks<R: CryptoRng + RngCore, F: Scalar>(
    prng: &mut R,
    n_wires_per_gate: usize,
) -> Vec<F> {
    let mut k = vec![F::one()];
    let exp = { u64_limbs_from_bytes(&F::field_size_minus_one_half()) };

    for _ in 1..n_wires_per_gate {
        loop {
            let ki = F::random(prng);
            if ki == F::zero() {
                continue;
            }
            if k.iter().all(|x| x != &ki) && ki.pow(&exp) != F::one() {
                k.push(ki);
                break;
            }
        }
    }
    k
}

/// Run the Plonk indexer.
/// Before invoking indexer function, the constraint system `cs` should pad the number of
/// constraints to a power of two.
pub fn indexer<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    cs: &CS,
    pcs: &PCS,
) -> Result<PlonkPK<PCS>> {
    indexer_with_lagrange(cs, pcs, None, None)
}

/// The Plonk indexer that leverages Lagrange bases
pub fn indexer_with_lagrange<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    cs: &CS,
    pcs: &PCS,
    lagrange_pcs: Option<&PCS>,
    verifier_params: Option<PlonkVK<PCS>>,
) -> Result<PlonkPK<PCS>> {
    let no_verifier = verifier_params.is_none();

    // It's okay to choose a fixed seed to generate quadratic non-residue.
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let n_wires_per_gate = CS::n_wires_per_gate();
    let n = cs.size();
    let m = cs.quot_eval_dom_size();
    let factor = m / n;
    if n * factor != m {
        return Err(eg!(PlonkError::SetupError));
    }
    let lagrange_pcs = if lagrange_pcs.is_some() && lagrange_pcs.unwrap().max_degree() + 1 == n {
        lagrange_pcs
    } else {
        None
    };

    let domain =
        FpPolynomial::<PCS::Field>::evaluation_domain(n).c(d!(PlonkError::GroupNotFound(n)))?;
    let domain_m =
        FpPolynomial::<PCS::Field>::evaluation_domain(m).c(d!(PlonkError::GroupNotFound(m)))?;
    let group = domain
        .elements()
        .into_iter()
        .map(|x| PCS::Field::from_field(x))
        .collect::<Vec<_>>();
    let k = choose_ks::<_, PCS::Field>(&mut prng, n_wires_per_gate);
    let coset_quotient = domain_m
        .elements()
        .into_iter()
        .map(|x| k[1].mul(&PCS::Field::from_field(x)))
        .collect();

    let commit = |coefs: Vec<PCS::Field>,
                  polynomial: &FpPolynomial<PCS::Field>|
     -> Result<PCS::Commitment> {
        if let Some(lagrange_pcs) = lagrange_pcs {
            let s_evals = FpPolynomial::from_coefs(coefs);
            let cm = lagrange_pcs
                .commit(&s_evals)
                .c(d!(PlonkError::SetupError))?;
            Ok(cm)
        } else {
            let cm = pcs.commit(&polynomial).c(d!(PlonkError::SetupError))?;
            Ok(cm)
        }
    };

    // Step 1: compute permutation polynomials and commit them.
    let raw_perm = cs.compute_permutation();
    let mut encoded_perm = Vec::with_capacity(n_wires_per_gate * n);
    for i in 0..n_wires_per_gate {
        encoded_perm.extend(encode_perm_to_group(
            &group,
            &raw_perm[i * n..(i + 1) * n],
            &k,
        ));
    }
    let mut s_coset_evals = vec![vec![]; n_wires_per_gate];
    let mut s_polys = vec![];
    let mut cm_s_vec = vec![];
    for i in 0..n_wires_per_gate {
        let s_coefs = FpPolynomial::ifft_with_domain(&domain, &encoded_perm[i * n..(i + 1) * n]);

        s_coset_evals[i].extend(s_coefs.coset_fft_with_domain(&domain_m, &k[1]));

        if no_verifier {
            let cm_s = commit(encoded_perm[i * n..(i + 1) * n].to_vec(), &s_coefs)?;
            cm_s_vec.push(cm_s);
        }

        s_polys.push(s_coefs);
    }

    // Step 2: compute selector polynomials and commit them.
    let mut q_coset_evals = vec![vec![]; cs.num_selectors()];
    let mut q_polys = vec![];
    let mut cm_q_vec = vec![];
    for (i, q_coset_eval) in q_coset_evals.iter_mut().enumerate() {
        let q_coefs = FpPolynomial::ifft_with_domain(&domain, cs.selector(i)?);
        q_coset_eval.extend(q_coefs.coset_fft_with_domain(&domain_m, &k[1]));

        if no_verifier {
            let cm_q = commit(cs.selector(i)?.to_vec(), &q_coefs)?;
            cm_q_vec.push(cm_q);
        }
        q_polys.push(q_coefs);
    }

    // Step 3: precompute two helper functions, L1 and Z_H.
    let mut l1_evals = FpPolynomial::from_coefs(vec![PCS::Field::zero(); group.len()]);
    l1_evals.coefs[0] = PCS::Field::from(n as u32); // X^n - 1 = (X - 1) (X^{n-1} + X^{n-2} + ... + 1)
    let l1_coefs = FpPolynomial::ifft_with_domain(&domain, &l1_evals.coefs);
    let l1_coset_evals = l1_coefs.coset_fft_with_domain(&domain_m, &k[1]);

    let z_h_coefs = {
        let mut v = vec![PCS::Field::zero(); n + 1];
        v[0] = PCS::Field::one().neg();
        v[n] = PCS::Field::one();
        FpPolynomial::from_coefs(v)
    };
    let z_h_inv_coset_evals = z_h_coefs
        .coset_fft_with_domain(&domain_m, &k[1])
        .into_iter()
        .map(|x| x.inv().unwrap())
        .collect();

    // Step 4: compute the Lagrange interpolation constants.
    let mut lagrange_constants = vec![];
    if no_verifier {
        for constraint_index in cs.public_vars_constraint_indices().iter() {
            lagrange_constants.push(compute_lagrange_constant(&group, *constraint_index));
        }
    }

    // Step 5: commit `boolean_constraint_indices`.
    let (qb_coset_eval, qb_poly, cm_qb) = {
        let mut qb = vec![PCS::Field::zero(); n];
        for i in cs.boolean_constraint_indices().iter() {
            qb[*i] = PCS::Field::one();
        }
        let qb_coef = FpPolynomial::ifft_with_domain(&domain, &qb);
        let qb_coset_eval = qb_coef.coset_fft_with_domain(&domain_m, &k[1]);

        let cm_qb = if no_verifier {
            commit(qb, &qb_coef)?
        } else {
            Default::default()
        };

        (qb_coset_eval, qb_coef, cm_qb)
    };

    // Step 6: commit `anemoi_constraints_indices`
    let (q_prk_coset_evals, q_prk_polys, cm_prk_vec) = {
        let q_prk_evals = cs.compute_anemoi_jive_selectors().to_vec();

        let q_prk_polys: Vec<FpPolynomial<PCS::Field>> = q_prk_evals
            .iter()
            .map(|p| FpPolynomial::ifft_with_domain(&domain, &p))
            .collect::<Vec<FpPolynomial<PCS::Field>>>();

        let q_prk_coset_evals = q_prk_polys
            .iter()
            .map(|p| p.coset_fft_with_domain(&domain_m, &k[1]))
            .collect::<Vec<Vec<PCS::Field>>>();

        let cm_prk_vec: Vec<PCS::Commitment> = if no_verifier {
            q_prk_evals
                .into_iter()
                .zip(q_prk_polys.iter())
                .map(|(q_prk_eval, q_prk_poly)| commit(q_prk_eval, q_prk_poly))
                .collect::<Result<_>>()?
        } else {
            vec![]
        };

        (q_prk_coset_evals, q_prk_polys, cm_prk_vec)
    };

    let verifier_params = if let Some(verifier) = verifier_params {
        verifier
    } else {
        let (anemoi_generator, anemoi_generator_inv) = cs.get_anemoi_parameters()?;
        PlonkVerifierParams {
            cm_q_vec,
            cm_s_vec,
            cm_qb,
            cm_prk_vec,
            anemoi_generator,
            anemoi_generator_inv,
            k,
            domain: compress_domain::<PCS>(&domain),
            cs_size: n,
            public_vars_constraint_indices: cs.public_vars_constraint_indices().to_vec(),
            lagrange_constants,
        }
    };

    Ok(PlonkProverParams {
        q_polys,
        s_polys,
        qb_poly,
        q_prk_polys,
        verifier_params,
        group,
        coset_quotient,
        domain_m: compress_domain::<PCS>(&domain_m),
        l1_coefs,
        l1_coset_evals,
        z_h_coefs,
        z_h_inv_coset_evals,
        q_coset_evals,
        s_coset_evals,
        qb_coset_eval,
        q_prk_coset_evals,
    })
}

#[cfg(test)]
mod test {
    use crate::plonk::indexer::choose_ks;
    use noah_algebra::{bls12_381::BLSScalar, prelude::*};

    type F = BLSScalar;

    #[test]
    fn test_choose_ks() {
        let mut prng = test_rng();
        let m = 8;
        let k = choose_ks::<_, F>(&mut prng, m);
        let exp = u64_limbs_from_bytes(&F::field_size_minus_one_half());
        assert_eq!(k[0], F::one());
        assert!(k.iter().skip(1).all(|x| *x != F::zero()));
        assert!(k.iter().skip(1).all(|x| x.pow(&exp) != F::one()));
        for i in 1..m {
            for j in 0..i {
                assert_ne!(k[i], k[j]);
            }
        }
    }
}
