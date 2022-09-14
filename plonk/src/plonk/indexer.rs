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

/// The data structure of a Plonk proof.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone)]
pub struct PlonkProof<C, F> {
    /// the witness polynomial commitments.
    pub cm_w_vec: Vec<C>,
    /// the split quotient polynomial commitments
    pub cm_t_vec: Vec<C>,
    /// the sigma polynomial commitment.
    pub cm_z: C,
    /// the openings of witness polynomials at \zeta.
    pub w_polys_eval_zeta: Vec<F>,
    /// the opening of z(X) at point \zeta * \omega.
    pub z_eval_zeta_omega: F,
    /// the openings of permutation polynomials at \zeta.
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
    /// the polynomials of the selectors.
    pub q_polys: Vec<O>,
    /// the polynomials of perm1, perm2, ..., perm_{n_wires_per_gate}.
    pub s_polys: Vec<O>,
    /// the polynomial for boolean constraints.
    pub qb_poly: O,
    /// the Plonk verifier parameters.
    pub verifier_params: PlonkVerifierParams<C, F>,
    /// the elements of the group.
    pub group: Vec<F>,
    /// The evaluation domain for computing the quotient polynomial.
    pub coset_quotient: Vec<F>,
    /// The root for the domain of size m.
    pub root_m: F,
    /// first lagrange basis.
    pub l1_coefs: FpPolynomial<F>,
    /// the l1's FFT of the polynomial of unity root set.
    pub l1_coset_evals: Vec<F>,
    /// initialize [one.neg, zero, zero, ... zero, one] polynomial.
    pub z_h_coefs: FpPolynomial<F>,
    /// the z_h's FFT of the polynomial of unity root set.
    pub z_h_inv_coset_evals: Vec<F>,
    /// the selector polynomials' FFT of the polynomial of unity root set.
    pub q_coset_evals: Vec<Vec<F>>,
    /// the permutation polynomials' FFT of the polynomial of unity root set.
    pub s_coset_evals: Vec<Vec<F>>,
    /// the boolean constraint polynomial's FFT of the polynomial of unity root set.
    pub qb_coset_eval: Vec<F>,
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
#[derive(Debug, Serialize, Deserialize)]
pub struct PlonkVerifierParams<C, F> {
    /// the commitments of the selectors.
    pub cm_q_vec: Vec<C>,
    /// the commitments of perm1, perm2, ..., perm_{n_wires_per_gate}.
    pub cm_s_vec: Vec<C>,
    /// the commitment of the boolean selector.
    pub cm_qb: C,
    /// `n_wires_per_gate` different quadratic non-residue in F_q-{0}.
    pub k: Vec<F>,
    /// a primitive n-th root of unity.
    pub root: F,
    /// the size of constraint system.
    pub cs_size: usize,
    /// the public constrain variables indices.
    pub public_vars_constraint_indices: Vec<usize>,
    /// the constrain lagrange base by public constrain variables.
    pub lagrange_constants: Vec<F>,
}

/// Define the PLONK verifier params by given `PolyComScheme`.
pub type PlonkVK<PCS> =
    PlonkVerifierParams<<PCS as PolyComScheme>::Commitment, <PCS as PolyComScheme>::Field>;

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
/// Before invoking index(), the constraint system `cs` should pad the number of
/// constraints to a power of two.
///
pub fn indexer<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    cs: &CS,
    pcs: &PCS,
) -> Result<PlonkPK<PCS>> {
    indexer_with_lagrange(cs, pcs, None)
}

/// The Plonk indexer that leverages Lagrange bases
pub fn indexer_with_lagrange<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    cs: &CS,
    pcs: &PCS,
    lagrange_pcs: Option<&PCS>,
) -> Result<PlonkPK<PCS>> {
    // It's okay to choose a fixed seed to generate quadratic non-residue.
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

    if let Some(lagrange_pcs) = lagrange_pcs {
        for i in 0..n_wires_per_gate {
            let s_evals = FpPolynomial::from_coefs(encoded_perm[i * n..(i + 1) * n].to_vec());
            let s_coefs = FpPolynomial::ffti(&root, &encoded_perm[i * n..(i + 1) * n], n);

            s_coset_evals[i].extend(s_coefs.coset_fft_with_unity_root(&root_m, m, &k[1]));

            let cm_s = lagrange_pcs
                .commit(&s_evals)
                .c(d!(PlonkError::SetupError))?;
            cm_s_vec.push(cm_s);
            s_polys.push(s_coefs);
        }
    } else {
        for i in 0..n_wires_per_gate {
            let s_coefs = FpPolynomial::ffti(&root, &encoded_perm[i * n..(i + 1) * n], n);

            s_coset_evals[i].extend(s_coefs.coset_fft_with_unity_root(&root_m, m, &k[1]));

            let cm_s = pcs.commit(&s_coefs).c(d!(PlonkError::SetupError))?;
            s_polys.push(s_coefs);
            cm_s_vec.push(cm_s);
        }
    }

    let mut q_coset_evals = vec![vec![]; cs.num_selectors()];
    let mut q_polys = vec![];
    let mut cm_q_vec = vec![];
    if let Some(lagrange_pcs) = lagrange_pcs {
        for (i, q_coset_eval) in q_coset_evals.iter_mut().enumerate() {
            let q_evals = FpPolynomial::from_coefs(cs.selector(i)?.to_vec());
            let q_coefs = FpPolynomial::ffti(&root, cs.selector(i)?, n);
            q_coset_eval.extend(q_coefs.coset_fft_with_unity_root(&root_m, m, &k[1]));

            let cm_q = lagrange_pcs
                .commit(&q_evals)
                .c(d!(PlonkError::SetupError))?;
            cm_q_vec.push(cm_q);
            q_polys.push(q_coefs);
        }
    } else {
        for (i, q_coset_eval) in q_coset_evals.iter_mut().enumerate() {
            let q_coefs = FpPolynomial::ffti(&root, cs.selector(i)?, n);
            q_coset_eval.extend(q_coefs.coset_fft_with_unity_root(&root_m, m, &k[1]));

            let cm_q = pcs.commit(&q_coefs).c(d!(PlonkError::SetupError))?;
            cm_q_vec.push(cm_q);
            q_polys.push(q_coefs);
        }
    }

    // Step 2: precompute two helper functions, L1 and Z_H.
    let mut l1_evals = FpPolynomial::from_coefs(vec![PCS::Field::zero(); group.len()]);
    l1_evals.coefs[0] = PCS::Field::from(n as u32); // X^n - 1 = (X - 1) (X^{n-1} + X^{n-2} + ... + 1)
    let l1_coefs = FpPolynomial::ffti(&root, &l1_evals.coefs, n);
    let l1_coset_evals = l1_coefs.coset_fft_with_unity_root(&root_m, m, &k[1]);

    let z_h_coefs = {
        let mut v = vec![PCS::Field::zero(); n + 1];
        v[0] = PCS::Field::one().neg();
        v[n] = PCS::Field::one();
        FpPolynomial::from_coefs(v)
    };
    let z_h_inv_coset_evals = z_h_coefs
        .coset_fft_with_unity_root(&root_m, m, &k[1])
        .into_iter()
        .map(|x| x.inv().unwrap())
        .collect();

    // Step 3: compute the Lagrange interpolation constants.
    let mut lagrange_constants = vec![];
    for constraint_index in cs.public_vars_constraint_indices().iter() {
        lagrange_constants.push(compute_lagrange_constant(&group, *constraint_index));
    }

    // Step 4: commit `boolean_constraint_indices`.
    let (qb_coset_eval, qb_poly, cm_qb) = if let Some(lagrange_pcs) = lagrange_pcs {
        let mut qb = vec![PCS::Field::zero(); n];
        for i in cs.boolean_constraint_indices().iter() {
            qb[*i] = PCS::Field::one();
        }
        let qb_coef = FpPolynomial::ffti(&root, &qb, n);
        let qb_eval = FpPolynomial::from_coefs(qb);
        let qb_coset_eval = qb_coef.coset_fft_with_unity_root(&root_m, m, &k[1]);

        let cm_qb = lagrange_pcs
            .commit(&qb_eval)
            .c(d!(PlonkError::SetupError))?;

        (qb_coset_eval, qb_coef, cm_qb)
    } else {
        let mut qb = vec![PCS::Field::zero(); n];
        for i in cs.boolean_constraint_indices().iter() {
            qb[*i] = PCS::Field::one();
        }
        let qb_coef = FpPolynomial::ffti(&root, &qb, n);
        let qb_coset_eval = qb_coef.coset_fft_with_unity_root(&root_m, m, &k[1]);

        let cm_qb = pcs.commit(&qb_coef).c(d!(PlonkError::SetupError))?;

        (qb_coset_eval, qb_coef, cm_qb)
    };

    let verifier_params = PlonkVerifierParams {
        cm_q_vec,
        cm_s_vec,
        cm_qb,
        k,
        root,
        cs_size: n,
        public_vars_constraint_indices: cs.public_vars_constraint_indices().to_vec(),
        lagrange_constants,
    };

    Ok(PlonkProverParams {
        q_polys,
        s_polys,
        qb_poly,
        verifier_params,
        group,
        coset_quotient,
        root_m,
        l1_coefs,
        l1_coset_evals,
        z_h_coefs,
        z_h_inv_coset_evals,
        q_coset_evals,
        s_coset_evals,
        qb_coset_eval,
    })
}

#[cfg(test)]
mod test {
    use crate::plonk::indexer::choose_ks;
    use ark_std::test_rng;
    use zei_algebra::{bls12_381::BLSScalar, prelude::*};

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
