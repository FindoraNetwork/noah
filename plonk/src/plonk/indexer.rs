use crate::plonk::{
    constraint_system::ConstraintSystem,
    errors::PlonkError,
    helpers::{build_group, compute_lagrange_constant},
};
use crate::poly_commit::{
    field_polynomial::{primitive_nth_root_of_unity, FpPolynomial},
    pcs::PolyComScheme,
};
use rand_chacha::ChaChaRng;
use zei_algebra::prelude::*;

/// A PlonkProof is generic on the polynomial commitment scheme, PCS.
/// PCS is generic in the commitment group C, the eval proof type E,
/// and Field elements F.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone)]
pub struct PlonkProof<C, F> {
    /// the witness polynomial commitments.
    pub(crate) w_polys: Vec<C>,
    /// the split quotient polynomial commitments
    pub(crate) t_polys: Vec<C>,
    /// the sigma polynomial commitment.
    pub(crate) c_sigma: C,
    /// the openings of witness polynomials at beta.
    pub(crate) witness_polys_eval_beta: Vec<F>,
    /// the opening of Sigma(X) at point g * beta.
    pub(crate) sigma_eval_g_beta: F,
    /// the openings of permutation polynomials at beta.
    pub(crate) perms_eval_beta: Vec<F>,
    /// The commitment for the first witness polynomial, for \zeta.
    pub(crate) eval_proof_1: C,
    /// The commitment for the second witness polynomial, for \zeta\omega.
    pub(crate) eval_proof_2: C,
}

/// Define the PLONK proof by given `PolyComScheme`.
pub type PlonkPf<PCS> =
    PlonkProof<<PCS as PolyComScheme>::Commitment, <PCS as PolyComScheme>::Field>;

/// Prover parameters.
#[derive(Debug, Serialize, Deserialize)]
pub struct PlonkProverParams<O, C, F> {
    /// the polynomials of the selectors.
    pub(crate) selector_polynomials: Vec<O>,
    /// the polynomials of perm1, perm2, ..., perm_{n_wires_per_gate}.
    pub(crate) permutation_polynomials: Vec<O>,
    /// the verifier parameters.
    pub(crate) verifier_params: PlonkVerifierParams<C, F>,
    pub(crate) group: Vec<F>,
    /// The evaluation domain for computing the quotient polynomial.
    pub(crate) coset_quotient: Vec<F>,
    pub(crate) root_m: F,
    /// first lagrange basis.
    pub(crate) l1_coefs: FpPolynomial<F>,
    /// the l1's DFT of the polynomial of unity root set.
    pub(crate) l1_coset_evals: Vec<F>,
    /// initialize [one.neg, zero, zero, ... zero, one] polynomial.
    pub(crate) z_h: FpPolynomial<F>,
    /// the z_h's FFT of the polynomial of unity root set.
    pub(crate) z_h_inv_coset_evals: Vec<F>,
    /// the selector polynomials' FFT of the polynomial of unity root set.
    pub(crate) selector_coset_evals: Vec<Vec<F>>,
    /// the permutation polynomials' FFT of the polynomial of unity root set.
    pub(crate) permutation_coset_evals: Vec<Vec<F>>,
}

/// Prover parameters over a particular polynomial commitment scheme.
pub type PlonkPK<PCS> = PlonkProverParams<
    <PCS as PolyComScheme>::Opening,
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

/// Verifier parameters.
#[derive(Debug, Serialize, Deserialize)]
pub struct PlonkVerifierParams<C, F> {
    /// the commitments of the selectors.
    pub(crate) selector_commitments: Vec<C>,
    /// the commitments of perm1, perm2, ..., perm_{n_wires_per_gate}.
    pub(crate) permutation_commitments: Vec<C>,
    /// `n_wires_per_gate` different quadratic non-residue in F_q-{0}.
    pub(crate) k: Vec<F>,
    /// a primitive n-th root of unity.
    pub(crate) root: F,
    /// the size of constraint system.
    pub(crate) cs_size: usize,
    /// the public constrain variables indices.
    pub(crate) public_vars_constraint_indices: Vec<usize>,
    /// the constrain lagrange base by public constrain variables.
    pub(crate) lagrange_constants: Vec<F>,
}

/// Define the PLONK verifier params by given `PolyComScheme`.
pub type PlonkVK<PCS> =
    PlonkVerifierParams<<PCS as PolyComScheme>::Commitment, <PCS as PolyComScheme>::Field>;

/// Encode the permutation value, from an index to a field element.
pub fn perm_values<F: Scalar>(group: &[F], perm: &[usize], k: &[F]) -> Vec<F> {
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

/// Compute `n_wires_per_gate` different quadratic non-residue in F_q-{0}.
pub fn choose_ks<R: CryptoRng + RngCore, F: Scalar>(
    prng: &mut R,
    n_wires_per_gate: usize,
) -> Vec<F> {
    let mut k = vec![F::one()];
    let q_minus_1_half_lsf = F::field_size_minus_one_half();
    let q_minus_1_half_u64_lims_le = u64_lsf_from_bytes(&q_minus_1_half_lsf);

    for _ in 1..n_wires_per_gate {
        loop {
            let ki = F::random(prng);
            if ki == F::zero() {
                continue;
            }
            if k.iter().all(|x| x != &ki) && ki.pow(&q_minus_1_half_u64_lims_le) != F::one() {
                k.push(ki);
                break;
            }
        }
    }
    k
}

/// Precompute the prover parameters.
/// Before invoking preprocess_prover(), the constraint system `cs` should pad the number of
/// constraints to a power of two.
///
pub fn indexer<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    cs: &CS,
    pcs: &PCS,
) -> Result<PlonkPK<PCS>> {
    indexer_with_lagrange(cs, pcs, None)
}

/// Indexer that uses Lagrange bases
pub fn indexer_with_lagrange<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    cs: &CS,
    pcs: &PCS,
    lagrange_pcs: Option<&PCS>,
) -> Result<PlonkPK<PCS>> {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let n_wires_per_gate = CS::n_wires_per_gate();
    let n = cs.size();
    let m = cs.quot_eval_dom_size();
    let factor = m / n;
    if n * factor != m {
        return Err(eg!(PlonkError::SetupError));
    }
    let lagrange_pcs = if lagrange_pcs.is_some() {
        if lagrange_pcs.unwrap().max_degree() + 1 == n {
            lagrange_pcs
        } else {
            None
        }
    } else {
        None
    };
    let root_m =
        primitive_nth_root_of_unity::<PCS::Field>(m).c(d!(PlonkError::GroupNotFound(m)))?;
    let group_m = build_group(&root_m, m)?;
    let root = group_m[factor % m];
    let group = build_group(&root, n)?;
    let k = choose_ks::<_, PCS::Field>(&mut prng, n_wires_per_gate);
    let coset_quotient = group_m.iter().map(|x| k[1].mul(x)).collect();

    // Step 1: compute permutation polynomials and commit them.

    let raw_permutation = cs.compute_permutation();
    let mut encoded_permutation = Vec::with_capacity(n_wires_per_gate * n);
    for i in 0..n_wires_per_gate {
        encoded_permutation.extend(perm_values(
            &group,
            &raw_permutation[i * n..(i + 1) * n],
            &k,
        ));
    }
    let mut permutation_coset_evals = vec![vec![]; n_wires_per_gate];
    let mut permutation_polynomials = vec![];
    let mut permutation_commitments = vec![];

    if let Some(lagrange_pcs) = lagrange_pcs {
        for i in 0..n_wires_per_gate {
            let perm_evals =
                FpPolynomial::from_coefs(encoded_permutation[i * n..(i + 1) * n].to_vec());
            let perm_coefs = FpPolynomial::ffti(&root, &encoded_permutation[i * n..(i + 1) * n], n);

            permutation_coset_evals[i]
                .extend(perm_coefs.coset_fft_with_unity_root(&root_m, m, &k[1]));

            let (c_perm, _) = lagrange_pcs
                .commit(perm_evals)
                .c(d!(PlonkError::SetupError))?;
            permutation_commitments.push(c_perm);

            let o_perm = pcs.opening(&perm_coefs);
            permutation_polynomials.push(o_perm);
        }
    } else {
        for i in 0..n_wires_per_gate {
            let perm_coefs = FpPolynomial::ffti(&root, &encoded_permutation[i * n..(i + 1) * n], n);

            permutation_coset_evals[i]
                .extend(perm_coefs.coset_fft_with_unity_root(&root_m, m, &k[1]));

            let (c_perm, o_perm) = pcs.commit(perm_coefs).c(d!(PlonkError::SetupError))?;
            permutation_polynomials.push(o_perm);
            permutation_commitments.push(c_perm);
        }
    }

    let mut selector_coset_evals = vec![vec![]; cs.num_selectors()];
    let mut selector_polynomials = vec![];
    let mut selector_commitments = vec![];
    if let Some(lagrange_pcs) = lagrange_pcs {
        for (i, selector_coset_evals) in selector_coset_evals.iter_mut().enumerate() {
            let q_evals = FpPolynomial::from_coefs(cs.selector(i)?.to_vec());
            let q_coefs = FpPolynomial::ffti(&root, cs.selector(i)?, n);
            selector_coset_evals.extend(q_coefs.coset_fft_with_unity_root(&root_m, m, &k[1]));

            let (c_q, _) = lagrange_pcs.commit(q_evals).c(d!(PlonkError::SetupError))?;
            selector_commitments.push(c_q);

            let o_q = pcs.opening(&q_coefs);
            selector_polynomials.push(o_q);
        }
    } else {
        for (i, selector_coset_evals) in selector_coset_evals.iter_mut().enumerate() {
            let q = FpPolynomial::ffti(&root, cs.selector(i)?, n);
            selector_coset_evals.extend(q.coset_fft_with_unity_root(&root_m, m, &k[1]));

            let (c_q, o_q) = pcs.commit(q).c(d!(PlonkError::SetupError))?;
            selector_polynomials.push(o_q);
            selector_commitments.push(c_q);
        }
    }

    // Step 2: precompute two helper functions, L1 and Z_H.
    let mut l1_evals = FpPolynomial::from_coefs(vec![PCS::Field::zero(); group.len()]);
    l1_evals.coefs[0] = PCS::Field::from(n as u32); // X^n - 1 = (X - 1) (X^{n-1} + X^{n-2} + ... + 1)
    let l1_coefs = FpPolynomial::ffti(&root, &l1_evals.coefs, n);
    let l1_coset_evals = l1_coefs.coset_fft_with_unity_root(&root_m, m, &k[1]);

    let mut z_h_coefs = vec![PCS::Field::zero(); n + 1];
    z_h_coefs[0] = PCS::Field::one().neg();
    z_h_coefs[n] = PCS::Field::one();
    let z_h = FpPolynomial::from_coefs(z_h_coefs);
    let z_h_inv_coset_evals = z_h
        .coset_fft_with_unity_root(&root_m, m, &k[1])
        .into_iter()
        .map(|x| x.inv().unwrap())
        .collect();

    // Step 3: compute the Lagrange interpolation constants.
    let mut lagrange_constants = vec![];
    for constraint_index in cs.public_vars_constraint_indices().iter() {
        lagrange_constants.push(compute_lagrange_constant(&group, *constraint_index));
    }

    let verifier_params = PlonkVerifierParams {
        selector_commitments,
        permutation_commitments,
        k,
        root,
        cs_size: n,
        public_vars_constraint_indices: cs.public_vars_constraint_indices().to_vec(),
        lagrange_constants,
    };

    Ok(PlonkProverParams {
        selector_polynomials,
        permutation_polynomials,
        verifier_params,
        group,
        coset_quotient,
        root_m,
        l1_coefs,
        l1_coset_evals,
        z_h,
        z_h_inv_coset_evals,
        selector_coset_evals,
        permutation_coset_evals,
    })
}

#[cfg(test)]
mod test {
    use crate::plonk::indexer::choose_ks;
    use rand_chacha::ChaChaRng;
    use zei_algebra::{bls12_381::BLSScalar, prelude::*};

    type F = BLSScalar;

    #[test]
    fn test_choose_ks() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let m = 8;
        let k = choose_ks::<_, F>(&mut prng, m);
        let q_minus_one_half = F::field_size_minus_one_half();
        let q_minus_one_half_u64 = u64_lsf_from_bytes(&q_minus_one_half);
        assert_eq!(k[0], F::one());
        assert!(k.iter().skip(1).all(|x| *x != F::zero()));
        assert!(k
            .iter()
            .skip(1)
            .all(|x| x.pow(&q_minus_one_half_u64) != F::one()));
        for i in 1..m {
            for j in 0..i {
                assert_ne!(k[i], k[j]);
            }
        }
    }
}
