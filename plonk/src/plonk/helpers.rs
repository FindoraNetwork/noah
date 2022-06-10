use crate::plonk::{
    constraint_system::ConstraintSystem,
    errors::PlonkError,
    setup::{PlonkPK, PlonkPf, PlonkVK},
};
use crate::poly_commit::{
    field_polynomial::FpPolynomial,
    pcs::{HomomorphicPolyComElem, PolyComScheme},
};
use std::cmp::min;
use zei_algebra::prelude::*;

/// Build the base group.
pub(super) fn build_group<F: Scalar>(generator: &F, max_elems: usize) -> Result<Vec<F>> {
    let mut elems = vec![F::one()];
    let mut current_root = *generator;
    let mut n = 1;
    while current_root != F::one() {
        if n == max_elems {
            return Err(eg!(PlonkError::GroupNotFound(max_elems)));
        }
        elems.push(current_root);
        current_root.mul_assign(&generator);
        n += 1;
    }
    Ok(elems)
}

/// The PLONK challenges values.
#[derive(Default)]
pub(super) struct PlonkChallenges<F> {
    challenges: Vec<F>,
}

impl<F: Scalar> PlonkChallenges<F> {
    /// Create a challenges with capacity 4.
    pub(super) fn new() -> PlonkChallenges<F> {
        PlonkChallenges {
            challenges: Vec::with_capacity(4),
        }
    }

    /// Insert Gamma and Delta.
    pub(super) fn insert_gamma_delta(&mut self, gamma: F, delta: F) -> Result<()> {
        if self.challenges.is_empty() {
            self.challenges.push(gamma);
            self.challenges.push(delta);
            Ok(())
        } else {
            Err(eg!())
        }
    }

    /// Insert Alpha.
    pub(super) fn insert_alpha(&mut self, alpha: F) -> Result<()> {
        if self.challenges.len() == 2 {
            self.challenges.push(alpha);
            Ok(())
        } else {
            Err(eg!())
        }
    }

    /// Insert Beta.
    pub(super) fn insert_beta(&mut self, beta: F) -> Result<()> {
        if self.challenges.len() == 3 {
            self.challenges.push(beta);
            Ok(())
        } else {
            Err(eg!())
        }
    }

    /// Insert u.
    pub(super) fn insert_u(&mut self, u: F) -> Result<()> {
        if self.challenges.len() == 4 {
            self.challenges.push(u);
            Ok(())
        } else {
            Err(eg!())
        }
    }

    /// Return the Gamme and Delta value.
    pub(super) fn get_gamma_delta(&self) -> Result<(&F, &F)> {
        if self.challenges.len() > 1 {
            Ok((&self.challenges[0], &self.challenges[1]))
        } else {
            Err(eg!())
        }
    }

    /// Return the Alpha value.
    pub(super) fn get_alpha(&self) -> Result<&F> {
        if self.challenges.len() > 2 {
            Ok(&self.challenges[2])
        } else {
            Err(eg!())
        }
    }

    /// Return the Beta value.
    pub(super) fn get_beta(&self) -> Result<&F> {
        if self.challenges.len() > 3 {
            Ok(&self.challenges[3])
        } else {
            Err(eg!())
        }
    }

    /// Return the u value
    pub(super) fn get_u(&self) -> Result<&F> {
        if self.challenges.len() > 4 {
            Ok(&self.challenges[4])
        } else {
            Err(eg!())
        }
    }
}

/// Return the public variables polynomial.
pub(super) fn public_vars_polynomial<PCS: PolyComScheme>(
    params: &PlonkPK<PCS>,
    public_vars: &[PCS::Field],
) -> FpPolynomial<PCS::Field> {
    let mut y = Vec::with_capacity(params.verifier_params.cs_size);
    for (i, _) in params.group.iter().enumerate() {
        if let Some((pos, _)) = params
            .verifier_params
            .public_vars_constraint_indices
            .iter()
            .find_position(|&&x| x == i)
        {
            y.push(public_vars[pos])
        } else {
            y.push(PCS::Field::zero());
        }
    }

    FpPolynomial::ffti(
        &params.verifier_params.root,
        &y,
        params.verifier_params.cs_size,
    )
}

/// Add a random degree `num_hide_points`+`zeroing_degree` polynomial
/// that vanishes on X^{zeroing_degree} -1. Goal is to randomize
/// `polynomial` maintaining output values for elements in a sub group
/// of order N. Eg, when num_hide_points is 1, then it adds
/// (r1 + r2*X) * (X^zeroing_degree - 1) to `polynomial.
pub(super) fn hide_polynomial<R: CryptoRng + RngCore, F: Scalar>(
    prng: &mut R,
    polynomial: &mut FpPolynomial<F>,
    num_hide_points: usize,
    zeroing_degree: usize,
) -> Vec<F> {
    let mut blinds = Vec::new();
    for i in 0..num_hide_points + 1 {
        let mut blind = F::random(prng);
        blinds.push(blind);
        polynomial.add_coef_assign(&blind, i);
        blind = blind.neg();
        polynomial.add_coef_assign(&blind, zeroing_degree + i);
    }
    blinds
}

/// Build polynomial Sigma, by interpolating
/// \Sigma(g^{i+1}) = \Sigma(g^i)\prod_{j=1}^{n_wires_per_gate}(fj(g^i)
/// + \gamma*k_j*g^i +\delta)/(fj(g^i) + \gamma*perm_j(g^i) +\delta)
/// and setting \Sigma(1) = 1 for the base case
pub(super) fn sigma_polynomial_evals<
    PCS: PolyComScheme,
    CS: ConstraintSystem<Field = PCS::Field>,
>(
    cs: &CS,
    params: &PlonkPK<PCS>,
    witness: &[PCS::Field],
    challenges: &PlonkChallenges<PCS::Field>,
) -> FpPolynomial<PCS::Field> {
    let n_wires_per_gate = CS::n_wires_per_gate();
    let (gamma, delta) = challenges.get_gamma_delta().unwrap();
    let mut sigma_values = vec![];
    let perm = cs.compute_permutation();
    let n_constraints = witness.len() / n_wires_per_gate;
    let mut prev = PCS::Field::one();
    sigma_values.push(PCS::Field::one());
    let group = &params.group[..];

    // computes permutation values
    let p_of_x =
        |perm_value: usize, n: usize, group: &[PCS::Field], k: &[PCS::Field]| -> PCS::Field {
            for (i, ki) in k.iter().enumerate().skip(1) {
                if perm_value < (i + 1) * n && perm_value >= i * n {
                    return ki.mul(&group[perm_value % n]);
                }
            }
            k[0].mul(&group[perm_value])
        };

    let k = &params.verifier_params.k;
    for i in 0..n_constraints - 1 {
        // 1. a = prod_{j=1..n_wires_per_gate}(fj(g^i) + \gamma*k_j*g^i +\delta)
        // 2. b = prod_{j=1..n_wires_per_gate}(fj(g^i) + \gamma*permj(g^i) +\delta)
        let mut a = PCS::Field::one();
        let mut b = PCS::Field::one();
        for j in 0..n_wires_per_gate {
            let k_x = k[j].mul(&group[i]);
            let f_x = &witness[j * n_constraints + i];
            let f_plus_gamma_id_plus_delta = &f_x.add(delta).add(&gamma.mul(&k_x));
            a.mul_assign(&f_plus_gamma_id_plus_delta);

            let p_x = p_of_x(perm[j * n_constraints + i], n_constraints, group, k);
            let f_plus_gamma_perm_plus_delta = f_x.add(delta).add(&gamma.mul(&p_x));
            b.mul_assign(&f_plus_gamma_perm_plus_delta);
        }

        // save \Sigma(g^{i+1}) = \Sigma(g^i)* a / b
        let b_inv = b.inv().unwrap();
        prev.mul_assign(&a.mul(&b_inv));
        sigma_values.push(prev);
    }
    // interpolate polynomial
    FpPolynomial::from_coefs(sigma_values)
}

/// Computes PLONK's quotient polynomial.
/// To compute Q(X), we first get the evaluations of Q(X) on a set H' where |H'| > deg(Q(X)),
/// then we recover the coefficients of Q(X) using an inverse FFT.
/// To evaluate Q(X) at a point z \in H', we need to obtain the values of
/// 1. Evaluations of witness polynomials at point z: {fj(z)}_{j=1..n_wires_per_gate}.
/// 2. Evaluations of sigma polynomials at point z and g*z: Sigma(z), Sigma(g*z).
/// 3. The evaluation of the IO polynomial at point z: IO(z).
/// And we need to precompute the values of
/// 1. Evaluations of selector polynomials at point z: {qj(z)}.
/// 2. Evaluations of permutation polynomials at point z: {perm_j(z)}_{j=1..n_wires_per_gate}.
/// 3. The evaluation of Z_H^{-1}(z), where Z_H(X) is the vanishing polynomial of H.
/// Then Q(z) is evaluated as
/// Q(z) = P(z) * Z_H^{-1}(z), for P(z)=
///     constraint_equation({fj(z)}, {qj(z)}, IO(z))
///   + alpha * \Sigma(z)\prod_j (fj(z) + gamma * kj * z + delta)
///   - alpha * \Sigma(g*z)\prod_j (fj(z) + gamma * perm_j(z) + delta)
///   + alpha^2 (Sigma(z) - 1) * (z^n - 1) / (z - 1).
///
/// To guarantee that Z_H^{-1}(z) is well-defined for any z \in H', we have to make sure
/// z \notin H, hence we choose H' to be a set that does not overlap with H. In particular,
/// we define
/// H'' := <g> where |H''| = m > deg(Q(X)),
/// H := <g^{m/n}> and thus |H| = n,
/// H' := k[1] * H'' where k[1] is a generator of Fq-{0}.
/// Thus |H'| > deg(Q(X)) and H' does not overlap with H.
///
/// The algorithm takes (n_wires_per_gate+2) deg-m ffts to compute the evaluations of
/// ({fj(X)}, IO(X), Sigma(X)}), O(m) ops to evaluate {Q(z)}_{z\in H'}, and 1 deg-m
/// ifft to recover Q(X).
pub(super) fn quotient_polynomial<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    cs: &CS,
    params: &PlonkPK<PCS>,
    witness_polys: &[FpPolynomial<PCS::Field>],
    sigma: &FpPolynomial<PCS::Field>,
    challenges: &PlonkChallenges<PCS::Field>,
    io: &FpPolynomial<PCS::Field>,
) -> Result<FpPolynomial<PCS::Field>> {
    let n = cs.size();
    let m = cs.quot_eval_dom_size();
    let factor = m / n;
    if n * factor != m {
        return Err(eg!(PlonkError::SetupError));
    }
    let root_m = &params.root_m;
    let k = &params.verifier_params.k;

    // Compute the evaluations of witness/IO/Sigma polynomials on the coset k[1] * <root_m>.
    let witness_polys_coset_evals: Vec<Vec<PCS::Field>> = witness_polys
        .iter()
        .map(|poly| poly.coset_fft_with_unity_root(root_m, m, &k[1]))
        .collect();
    let io_coset_evals = io.coset_fft_with_unity_root(root_m, m, &k[1]);
    let sigma_coset_evals = sigma.coset_fft_with_unity_root(root_m, m, &k[1]);

    // Compute the evaluations of the quotient polynomial on the coset.
    let (gamma, delta) = challenges.get_gamma_delta().unwrap();
    let alpha = challenges.get_alpha().unwrap();
    let alpha_sq = alpha.mul(alpha);
    let mut quot_coset_evals = vec![];

    for point in 0..m {
        let wire_vals: Vec<&PCS::Field> = witness_polys_coset_evals
            .iter()
            .map(|poly_coset_evals| &poly_coset_evals[point])
            .collect();
        let sel_vals: Vec<&PCS::Field> = params
            .selectors_coset_evals
            .iter()
            .map(|poly_coset_evals| &poly_coset_evals[point])
            .collect();
        let term1 = CS::eval_gate_func(&wire_vals, &sel_vals, &io_coset_evals[point])?;

        // alpha * [\Sigma(X)\prod_j (fj(X) + gamma * kj * X + delta)]
        let mut term2 = alpha.mul(&sigma_coset_evals[point]);
        for j in 0..CS::n_wires_per_gate() {
            let tmp = witness_polys_coset_evals[j][point]
                .add(delta)
                .add(&gamma.mul(&k[j].mul(&params.coset_quot[point])));
            term2.mul_assign(&tmp);
        }

        // alpha * [\Sigma(g*X)\prod_j (fj(X) + gamma * perm_j(X) + delta)]
        let mut term3 = alpha.mul(&sigma_coset_evals[(point + factor) % m]);
        for (w_poly_coset_evals, perm_coset_evals) in witness_polys_coset_evals
            .iter()
            .zip(params.perms_coset_evals.iter())
        {
            let tmp = &w_poly_coset_evals[point]
                .add(delta)
                .add(&gamma.mul(&perm_coset_evals[point]));
            term3.mul_assign(&tmp);
        }

        // alpha^2 * (Sigma(X) - 1) * L_1(X)
        let term4 = alpha_sq
            .mul(&params.l1_coset_evals[point])
            .mul(&sigma_coset_evals[point].sub(&PCS::Field::one()));

        let numerator = term1.add(&term2).add(&term4.sub(&term3));
        quot_coset_evals.push(numerator.mul(&params.z_h_inv_coset_evals[point]));
    }

    let k_inv = k[1].inv().c(d!(PlonkError::DivisionByZero))?;
    Ok(FpPolynomial::coset_ffti(
        root_m,
        &quot_coset_evals,
        &k_inv,
        m,
    ))
}

/// Compute linearization polynomial opening/commitment.
/// Denote cs.eval_selector_multipliers(f1(beta), .., f_{n_wires_per_gate}(beta))
///   = (w1, .., w_{n_selectors}).
/// Denote the selector polynomials [q1(X), ..., q_{n_selectors}(X)].
/// Denote the selector polynomials commitments [C_q1(X), ..., C_q_{n_selectors}(X)].
/// The opening:
///  L(X) = sum_{i=1..n_selectors} wi * qi(X)
///       + \Sigma(X) [alpha * prod_j (fj(beta) + gamma * kj * beta + delta) + alpha^2 * L1(beta)]
///       - perm_{n_wires_per_gate}(X) [alpha * \Sigma(g*beta) * gamma
///         * prod_{j=1..n_wires_per_gate-1}(fj(beta) + gamma * perm_j(beta) + delta)]
/// The commitment:
///  C_L(X) = sum_{i=1..n_selectors} wi * qi(X)
///       + C_\Sigma(X) [alpha * prod_j (fj(beta) + gamma * kj * beta + delta)
///                      + alpha^2 * L1(beta)]
///       - C_perm_{n_wires_per_gate}(X) [alpha * \Sigma(g*beta) * gamma
///         * prod_{j=1..n_wires_per_gate-1}(fj(beta) + gamma * perm_j(beta) + delta)]
#[allow(clippy::too_many_arguments)]
fn linearization<F: Scalar, PCSType: HomomorphicPolyComElem<Scalar = F>>(
    wires: &[F],
    n: usize,
    selectors: &[PCSType],
    k: &[F],
    last_extended_perm: &PCSType,
    sigma: &PCSType,
    witness_polys_eval_beta: &[&F],
    perms_eval_beta: &[&F],
    sigma_eval_g_beta: &F,
    challenges: &PlonkChallenges<F>,
    q_polys: &[PCSType],
    n_q_polys: usize,
) -> PCSType {
    let (gamma, delta) = challenges.get_gamma_delta().unwrap();
    let alpha = challenges.get_alpha().unwrap();
    let beta = challenges.get_beta().unwrap();

    // 1. sum_{i=1..n_selectors} wi * qi(X)
    let mut l = selectors[0].mul(&wires[0]);
    for i in 1..selectors.len() {
        l.add_assign(&selectors[i].mul(&wires[i]));
    }

    // 2. \Sigma(X) [ alpha * prod_{j=1..n_wires_per_gate} (fj(beta) + gamma * kj * beta + delta)
    //              + alpha^2 * L1(beta)]
    let sigma_scalar = compute_sigma_scalar_in_l(n, witness_polys_eval_beta, k, challenges);
    l.add_assign(&sigma.mul(&sigma_scalar));

    // 3. - perm_{n_wires_per_gate}(X) [alpha * \Sigma(g*beta) * gamma
    //    * prod_{j=1..n_wires_per_gate-1}(fj(beta) + gamma * perm_j(beta) + delta)]
    let mut b = alpha.mul(&sigma_eval_g_beta.mul(gamma));
    for i in 0..witness_polys_eval_beta.len() - 1 {
        let bi = witness_polys_eval_beta[i]
            .add(&gamma.mul(perms_eval_beta[i]))
            .add(delta);
        b.mul_assign(&bi);
    }
    l.sub_assign(&last_extended_perm.mul(&b));

    let mut z_h_eval_beta = beta.pow(&[n as u64]);
    z_h_eval_beta.sub_assign(&F::one());

    // 4. subtract the combined q polynomial
    // Given value \beta, and homomorphic polynomial commitments/openings {qi(X)}_{i=0..m-1},
    // compute \sum_{i=0..m-1} \beta^{i*n} * qi(X)
    let factor = beta.pow(&[n_q_polys as u64]);
    let mut exponent = z_h_eval_beta * factor;
    let mut q_poly_combined = q_polys[0].clone().mul(&z_h_eval_beta);
    for q_poly in q_polys.iter().skip(1) {
        q_poly_combined.add_assign(&q_poly.mul(&exponent));
        exponent.mul_assign(&factor);
    }
    l.sub_assign(&q_poly_combined);
    l
}

/// Open the linearization_polynomial.
pub(super) fn linearization_polynomial_opening<
    PCS: PolyComScheme,
    CS: ConstraintSystem<Field = PCS::Field>,
>(
    params: &PlonkPK<PCS>,
    sigma: &PCS::Opening,
    witness_polys_eval_beta: &[&PCS::Field],
    perms_eval_beta: &[&PCS::Field],
    sigma_eval_g_beta: &PCS::Field,
    challenges: &PlonkChallenges<PCS::Field>,
    q_polys: &[PCS::Opening],
    n_q_polys: usize,
) -> PCS::Opening {
    let w = CS::eval_selector_multipliers(witness_polys_eval_beta).unwrap(); // safe unwrap
    linearization::<PCS::Field, PCS::Opening>(
        &w,
        params.group.len(),
        &params.selectors,
        &params.verifier_params.k,
        &params.extended_permutations[CS::n_wires_per_gate() - 1],
        sigma,
        witness_polys_eval_beta,
        perms_eval_beta,
        sigma_eval_g_beta,
        challenges,
        q_polys,
        n_q_polys,
    )
}

/// Commit the linearization_polynomial.
pub(super) fn linearization_commitment<
    PCS: PolyComScheme,
    CS: ConstraintSystem<Field = PCS::Field>,
>(
    params: &PlonkVK<PCS>,
    c_sigma: &PCS::Commitment,
    witness_polys_eval_beta: &[&PCS::Field],
    perms_eval_beta: &[&PCS::Field],
    sigma_eval_g_beta: &PCS::Field,
    challenges: &PlonkChallenges<PCS::Field>,
    q_polys: &[PCS::Commitment],
    n_q_polys: usize,
) -> PCS::Commitment {
    let w = CS::eval_selector_multipliers(witness_polys_eval_beta).unwrap(); // safe unwrap
    linearization::<PCS::Field, PCS::Commitment>(
        &w,
        params.cs_size,
        &params.selectors,
        &params.k,
        &params.extended_permutations[CS::n_wires_per_gate() - 1],
        c_sigma,
        witness_polys_eval_beta,
        perms_eval_beta,
        sigma_eval_g_beta,
        challenges,
        q_polys,
        n_q_polys,
    )
}

/// Compute sum_{i=1}^\ell w_i L_j(X), where j is the constraint
/// index for the i-th public value. L_j(X) = (X^n-1) / (X - g^j) is
/// the j-th lagrange base (zero for every X= g^i, except when i ==j)
pub(super) fn eval_public_var_poly<PCS: PolyComScheme>(
    params: &PlonkVK<PCS>,
    public_values: &[PCS::Field],
    eval_point: &PCS::Field,
) -> PCS::Field {
    let mut eval = PCS::Field::zero();
    // (X^n -1) lagrange numerator
    let x_to_n = eval_point.pow(&[params.cs_size as u64]);
    let num = x_to_n.sub(&PCS::Field::one());
    for ((constraint_index, public_value), lagrange_constant) in params
        .public_vars_constraint_indices
        .iter()
        .zip(public_values)
        .zip(params.lagrange_constants.iter())
    {
        // X - g^j j-th lagrange denominator
        let root_to_j = params.root.pow(&[*constraint_index as u64]);
        let den = eval_point.sub(&root_to_j);
        let den_inv = den.inv().unwrap();
        let lagrange_i = lagrange_constant.mul(&num.mul(&den_inv));
        eval.add_assign(&lagrange_i.mul(public_value));
    }
    eval
}

/// Compute constant c_j such that 1=c_j*prod_{i != j} (g^j - g^i).
/// In such case, j-th lagrange base can be represented
/// by L_j(X) = c_j (X^n-1)/(X-g^j)
pub(super) fn compute_lagrange_constant<F: Scalar>(group: &[F], base_index: usize) -> F {
    let mut constant_inv = F::one();
    for (i, elem) in group.iter().enumerate() {
        if i == base_index {
            continue;
        }
        constant_inv.mul_assign(&group[base_index].sub(elem));
    }
    constant_inv.inv().unwrap()
}

/// compute the scalar factor of \Sigma(X) in linearization polynomial
/// L(X): prod(fi(\beta) + \gamma * k_i * \beta + delta)*\alpha
///       + (\beta^n-1) / (\beta-1) * \alpha^2
fn compute_sigma_scalar_in_l<F: Scalar>(
    n: usize,
    witness_polys_eval_beta: &[&F],
    k: &[F],
    challenges: &PlonkChallenges<F>,
) -> F {
    let n_wires_per_gate = witness_polys_eval_beta.len();
    let (gamma, delta) = challenges.get_gamma_delta().unwrap();
    let alpha = challenges.get_alpha().unwrap();
    let beta = challenges.get_beta().unwrap();
    // 1. alpha * prod_{i=1..n_wires_per_gate}(fi(\beta) + \gamma * k_i * \beta + delta)
    let gamma_beta = gamma.mul(beta);
    let mut a = *alpha;
    for i in 0..n_wires_per_gate {
        let ai = witness_polys_eval_beta[i]
            .add(&k[i].mul(&gamma_beta))
            .add(delta);
        a.mul_assign(&ai);
    }

    // 2. alpha^2*(beta^n - 1) / (beta - 1)
    let alpha_sq = alpha.mul(alpha);
    let beta_pow_n = beta.pow(&[n as u64]);
    let l1_eval_beta = beta_pow_n
        .sub(&F::one())
        .mul(&beta.sub(&F::one()).inv().unwrap());
    let c = l1_eval_beta.mul(&alpha_sq);

    a.add(&c)
}

/// derive Q(beta) such that P(\beta) - Q(beta)*Z_H(beta) = 0
/// That is Q(beta) = P(\beta)/Z_H(beta) =
///  (L(\beta) + PI(\beta) - alpha * \Sigma(g * beta)
///     * prod_{i=1..n_wires_per_gate-1}(fi(beta) + gamma * permi(beta) + delta)
///     * (f_{n_wires_per_gate}(beta) + delta)
///     - alpha^2 *(\beta^n - 1) / (\beta - 1) ) / (\beta^n - 1)
pub(super) fn derive_q_eval_beta<PCS: PolyComScheme>(
    params: &PlonkVK<PCS>,
    proof: &PlonkPf<PCS>,
    challenges: &PlonkChallenges<PCS::Field>,
    public_vars_eval_beta: &PCS::Field,
) -> PCS::Field {
    let beta = challenges.get_beta().unwrap();
    let alpha = challenges.get_alpha().unwrap();
    let (gamma, delta) = challenges.get_gamma_delta().unwrap();

    let term0 = public_vars_eval_beta;
    let mut term1 = alpha.mul(&proof.sigma_eval_g_beta);
    let n_wires_per_gate = &proof.witness_polys_eval_beta.len();
    for i in 0..n_wires_per_gate - 1 {
        let b = proof.witness_polys_eval_beta[i]
            .add(&gamma.mul(&proof.perms_eval_beta[i]))
            .add(delta);
        term1.mul_assign(&b);
    }
    term1.mul_assign(&proof.witness_polys_eval_beta[n_wires_per_gate - 1].add(delta));

    let one = PCS::Field::one();
    let beta_n = beta.pow(&[params.cs_size as u64]);
    let z_h_eval_beta = beta_n.sub(&one);
    let beta_minus_one = beta.sub(&one);
    let first_lagrange_eval_beta = z_h_eval_beta.mul(beta_minus_one.inv().unwrap());
    let term2 = first_lagrange_eval_beta.mul(alpha.mul(alpha));

    let term1_plus_term2 = term1.add(&term2);
    term1_plus_term2.sub(&term0)
}

/// Split the quotient polynomial into `n_wires_per_gate` degree-`n` polynomials and commit.
#[allow(clippy::type_complexity)]
pub(crate) fn split_q_and_commit<PCS: PolyComScheme>(
    pcs: &PCS,
    q: &FpPolynomial<PCS::Field>,
    n_wires_per_gate: usize,
    n: usize,
) -> Result<(Vec<PCS::Commitment>, Vec<PCS::Opening>)> {
    let mut c_q_polys = vec![];
    let mut o_q_polys = vec![];
    let coefs_len = q.get_coefs_ref().len();

    for i in 0..n_wires_per_gate {
        let coefs_start = i * n;
        let coefs_end = if i == n_wires_per_gate - 1 {
            coefs_len
        } else {
            (i + 1) * n
        };
        let coefs = if coefs_start < coefs_len {
            q.get_coefs_ref()[coefs_start..min(coefs_len, coefs_end)].to_vec()
        } else {
            vec![]
        };
        let q_poly = FpPolynomial::from_coefs(coefs);
        let (c_q, o_q) = pcs.commit(q_poly).c(d!(PlonkError::CommitmentError))?;
        c_q_polys.push(c_q);
        o_q_polys.push(o_q);
    }

    Ok((c_q_polys, o_q_polys))
}

#[cfg(test)]
mod test {
    use crate::plonk::{
        constraint_system::TurboConstraintSystem,
        helpers::{sigma_polynomial_evals, PlonkChallenges},
        setup::preprocess_prover,
    };
    use crate::poly_commit::kzg_poly_com::{KZGCommitmentScheme, KZGCommitmentSchemeBLS};
    use rand_chacha::ChaChaRng;
    use zei_algebra::{bls12_381::BLSScalar, prelude::*};

    type F = BLSScalar;

    #[test]
    fn test_sigma_polynomial() {
        let mut cs = TurboConstraintSystem::new();

        let zero = F::zero();
        let one = F::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = three.add(&one);
        let five = four.add(&one);
        let six = five.add(&one);

        let witness = [one, three, five, four, two, two, two, six, three];
        cs.add_variables(&witness);

        cs.insert_add_gate(0, 4, 1);
        cs.insert_add_gate(1, 4, 2);
        cs.insert_add_gate(2, 4, 6);
        cs.insert_add_gate(3, 5, 7);
        cs.pad();

        let mut prng = ChaChaRng::from_seed([0_u8; 32]);
        let pcs = KZGCommitmentScheme::new(20, &mut prng);
        let params = preprocess_prover(&cs, &pcs, [0u8; 32]).unwrap();

        let mut challenges = PlonkChallenges::<F>::new();
        challenges.insert_gamma_delta(one, zero).unwrap();
        let q = sigma_polynomial_evals::<KZGCommitmentSchemeBLS, TurboConstraintSystem<F>>(
            &cs,
            &params,
            &witness[..],
            &challenges,
        );

        let q0 = q.coefs[0];
        assert_eq!(q0, one);
    }
}
