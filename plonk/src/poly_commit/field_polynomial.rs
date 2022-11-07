use ark_poly::{EvaluationDomain, MixedRadixEvaluationDomain};
use noah_algebra::{prelude::*, traits::Domain};

#[cfg(feature = "parallel")]
use rayon::prelude::{IntoParallelRefMutIterator, ParallelIterator};

/// Field polynomial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FpPolynomial<F> {
    /// Coefficients (or evaluations) of the polynomial
    pub coefs: Vec<F>,
}

impl<F: Domain> FpPolynomial<F> {
    /// Return the polynomial coefs reference.
    pub fn get_coefs_ref(&self) -> &[F] {
        self.coefs.as_slice()
    }

    /// Return the little-endian byte representations of the field size
    pub fn get_field_size(&self) -> Vec<u8> {
        F::get_field_size_le_bytes()
    }

    /// Return the constant zero polynomial
    /// # Example
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One};
    /// let poly = FpPolynomial::<BLSScalar>::zero();
    /// let zero = BLSScalar::zero();
    /// assert_eq!(poly.degree(), 0);
    /// assert_eq!(poly.eval(&zero), zero);
    /// assert_eq!(poly.eval(&BLSScalar::one()), zero);
    /// ```
    pub fn zero() -> Self {
        Self::from_coefs(vec![F::zero()])
    }

    /// Return the constant one polynomial
    /// # Example
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One};
    /// let poly = FpPolynomial::<BLSScalar>::one();
    /// let one = BLSScalar::one();
    /// assert_eq!(poly.degree(), 0);
    /// assert_eq!(poly.eval(&one), one);
    /// assert_eq!(poly.eval(&BLSScalar::zero()), one);
    /// ```
    pub fn one() -> Self {
        Self::from_coefs(vec![F::one()])
    }

    /// Build a polynomial from the coefficient vector, low-order coefficient first.
    /// High-order zero coefficient are trimmed.
    /// # Example
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let five = two.add(&two).add(&one);
    /// let coefs = vec![one, zero, one];
    /// let poly = FpPolynomial::from_coefs(coefs);
    /// assert_eq!(poly.degree(), 2);
    /// assert_eq!(poly.eval(&zero), one);
    /// assert_eq!(poly.eval(&one), two);
    /// assert_eq!(poly.eval(&two), five);
    /// let coefs2 = vec![one, zero, one, zero, zero, zero];
    /// let poly2 = FpPolynomial::from_coefs(coefs2);
    /// assert_eq!(poly2.degree(), 2);
    /// assert_eq!(poly, poly2);
    /// ```
    pub fn from_coefs(coefs: Vec<F>) -> Self {
        let mut p = FpPolynomial { coefs };
        p.trim_coefs();
        p
    }

    /// Build a polynomial from its zeroes/roots.
    /// # Example
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let five = two.add(&two).add(&one);
    /// let zeroes = [one, zero, five, two];
    /// let poly = FpPolynomial::from_zeroes(&zeroes[..]);
    /// assert_eq!(poly.degree(), 4);
    /// assert_eq!(poly.eval(&zero), zero);
    /// assert_eq!(poly.eval(&one), zero);
    /// assert_eq!(poly.eval(&two), zero);
    /// assert_eq!(poly.eval(&five), zero);
    /// ```
    pub fn from_zeroes(zeroes: &[F]) -> Self {
        let roots_ref: Vec<&F> = zeroes.iter().collect();
        Self::from_zeroes_ref(&roots_ref[..])
    }

    /// Build a polynomial from its zeroes/roots given as reference.
    pub fn from_zeroes_ref(zeroes: &[&F]) -> Self {
        let mut r = Self::one();
        for root in zeroes.iter() {
            let mut p = r.clone();
            r.coefs.insert(0, F::zero()); // multiply by X
            p.mul_scalar_assign(*root); // x_0 * r
            r.sub_assign(&p); // r = r * (X - x_0)
        }
        r.trim_coefs();
        r
    }

    /// Return a polynomial of `degree` + 1 uniformly random coefficients. Note that for each
    /// coffiecient with probability 1/q is zero, and hence the degree could be less than `degree`
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::prelude::*;
    /// use rand::thread_rng;
    /// let poly = FpPolynomial::<BLSScalar>::random(&mut thread_rng(), 10);
    /// assert!(poly.degree() <= 10)
    /// ```
    pub fn random<R: CryptoRng + RngCore>(prng: &mut R, degree: usize) -> FpPolynomial<F> {
        let mut coefs = Vec::with_capacity(degree + 1);
        for _ in 0..degree + 1 {
            coefs.push(F::random(prng));
        }
        Self::from_coefs(coefs)
    }

    /// Remove high degree zero-coefficients
    fn trim_coefs(&mut self) {
        while self.coefs.len() > 1 && self.coefs.last().unwrap().is_zero() {
            // safe unwrap
            self.coefs.pop().unwrap(); // safe unwrap
        }
    }

    /// Return degree of the polynomial
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One};
    /// let poly = FpPolynomial::<BLSScalar>::from_coefs(vec![BLSScalar::one(); 10]);
    /// assert_eq!(poly.degree(), 9);
    /// let poly = FpPolynomial::<BLSScalar>::from_coefs(vec![BLSScalar::zero(); 10]);
    /// assert_eq!(poly.degree(), 0)
    /// ```
    pub fn degree(&self) -> usize {
        if self.coefs.len() == 0 {
            0
        } else {
            self.coefs.len() - 1
        }
    }

    /// Test if polynomial is the zero polynomial.
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One};
    /// let poly = FpPolynomial::<BLSScalar>::from_coefs(vec![BLSScalar::one(); 10]);
    /// assert!(!poly.is_zero());
    /// let poly = FpPolynomial::<BLSScalar>::from_coefs(vec![BLSScalar::zero(); 10]);
    /// assert!(poly.is_zero())
    /// ```
    pub fn is_zero(&self) -> bool {
        self.degree() == 0 && self.coefs[0].is_zero()
    }

    /// Evaluate a polynomial on a point.
    pub fn eval(&self, point: &F) -> F {
        let mut result = F::zero();
        let mut variable = F::one();
        let num_coefs = self.coefs.len();
        for coef in self.coefs[0..num_coefs].iter() {
            let mut a = variable;
            a.mul_assign(coef);
            result.add_assign(&a);
            variable.mul_assign(point);
        }
        result
    }

    /// Add another polynomial to self.
    pub fn add_assign(&mut self, other: &Self) {
        for (self_coef, other_coef) in self.coefs.iter_mut().zip(other.coefs.iter()) {
            self_coef.add_assign(other_coef);
        }
        let n = self.coefs.len();
        if n < other.coefs.len() {
            for other_coef in other.coefs[n..].iter() {
                self.coefs.push(*other_coef);
            }
        }
        self.trim_coefs();
    }

    /// Add with another polynomial, producing a new polynomial.
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let three = two.add(&one);
    /// let poly1 = FpPolynomial::from_coefs(vec![zero, one, two, three]);
    /// let poly2 = FpPolynomial::from_coefs(vec![three, two, one, zero, one]);
    /// let poly_add = poly1.add(&poly2);
    /// let poly_add2 = poly2.add(&poly1);
    /// assert_eq!(poly_add, poly_add2);
    /// let poly_expected = FpPolynomial::from_coefs(vec![three, three, three, three, one]);
    /// assert_eq!(poly_add, poly_expected);
    /// ```
    pub fn add(&self, other: &Self) -> Self {
        let mut new = self.clone();
        new.add_assign(other);
        new
    }

    /// Subtracts another polynomial from self.
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let three = two.add(&one);
    /// let mut poly1 = FpPolynomial::from_coefs(vec![three, three, two, one]);
    /// let poly2 = FpPolynomial::from_coefs(vec![three, two, one, one]);
    /// poly1.sub_assign(&poly2);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// assert_eq!(poly1, poly_expected);
    ///  // second polynomial is of lower degree
    /// let mut poly1 = FpPolynomial::from_coefs(vec![three, three, two, one]);
    /// let poly2 = FpPolynomial::from_coefs(vec![three, two, one]);
    /// poly1.sub_assign(&poly2);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, one, one, one]);
    /// assert_eq!(poly1, poly_expected);
    ///  // first polynomial is of lower degree
    /// let mut poly1 = FpPolynomial::from_coefs(vec![three, three, two]);
    /// let poly2 = FpPolynomial::from_coefs(vec![three, two, one, one]);
    /// poly1.sub_assign(&poly2);
    /// let mut minus_one = one.neg();
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, one, one, minus_one]);
    /// assert_eq!(poly1, poly_expected);
    /// ```
    pub fn sub_assign(&mut self, other: &Self) {
        for (self_coef, other_coef) in self.coefs.iter_mut().zip(other.coefs.iter()) {
            self_coef.sub_assign(other_coef);
        }
        let n = self.coefs.len();
        if other.coefs.len() > n {
            for other_coef in other.coefs[n..].iter() {
                self.coefs.push(other_coef.neg());
            }
        }
        self.trim_coefs();
    }

    /// Subtract another polynomial from self, producing a new polynomial.
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let three = two.add(&one);
    /// let poly1 = FpPolynomial::from_coefs(vec![three, three, two, one]);
    /// let poly2 = FpPolynomial::from_coefs(vec![three, two, one, one]);
    /// let poly_sub = poly1.sub(&poly2);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// assert_eq!(poly_sub, poly_expected);
    /// ```
    pub fn sub(&self, other: &Self) -> Self {
        let mut new = self.clone();
        new.sub_assign(other);
        new
    }

    /// Negate the coefficients.
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let minus_one = one.neg();
    /// let mut poly = FpPolynomial::from_coefs(vec![zero, one]);
    /// poly.neg_assign();
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, minus_one]);
    /// assert_eq!(poly, poly_expected);
    /// ```
    pub fn neg_assign(&mut self) {
        let minus_one = F::one().neg();
        self.mul_scalar_assign(&minus_one);
    }

    /// negate the coefficients.
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let minus_one = one.neg();
    /// let poly = FpPolynomial::from_coefs(vec![zero, one]);
    /// let negated  = poly.neg();
    /// let expected = FpPolynomial::from_coefs(vec![zero, minus_one]);
    /// assert_eq!(negated, expected);
    /// ```
    pub fn neg(&self) -> Self {
        let mut new = self.clone();
        new.neg_assign();
        new
    }

    /// Add `coef` to the coefficient of order `order`.
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let mut two = one;
    /// two.add_assign(&one);
    /// let mut poly = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// poly.add_coef_assign(&one, 1);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, two, one]);
    /// assert_eq!(poly, poly_expected);
    /// poly.add_coef_assign(&one, 3);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, two, one, one]);
    /// let mut minus_one = one.neg();
    /// poly.add_coef_assign(&minus_one, 3);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, two, one]);
    /// assert_eq!(poly, poly_expected);
    /// ```
    pub fn add_coef_assign(&mut self, coef: &F, order: usize) {
        while self.degree() < order {
            self.coefs.push(F::zero());
        }
        self.coefs[order].add_assign(coef);
        self.trim_coefs();
    }

    /// Multiply polynomial by a constant scalar.
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let mut poly = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// poly.mul_scalar_assign(&two);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, two, two]);
    /// // multiply y zero
    /// assert_eq!(poly, poly_expected);
    /// poly.mul_scalar_assign(&zero);
    /// assert!(poly.is_zero());
    /// ```
    pub fn mul_scalar_assign(&mut self, scalar: &F) {
        #[cfg(not(feature = "parallel"))]
        {
            for coef in self.coefs.iter_mut() {
                coef.mul_assign(scalar)
            }
        }
        #[cfg(feature = "parallel")]
        {
            self.coefs
                .par_iter_mut()
                .for_each(|coef| coef.mul_assign(scalar));
        }
        self.trim_coefs();
    }

    /// Multiply polynomial by a constant scalar into a new polynomial.
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let mut poly = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// let new = poly.mul_scalar(&two);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, two, two]);
    /// assert_eq!(new, poly_expected);
    /// ```
    pub fn mul_scalar(&self, scalar: &F) -> Self {
        let mut new = self.clone();
        new.mul_scalar_assign(scalar);
        new
    }

    /// Multiply the polynomial variable by a scalar.
    /// mul_var(\sum a_i X^i, b) = \sum a_i b^i X^i
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let four = two.add(&two);
    /// let mut poly = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// poly.mul_var_assign(&two);
    /// let expected = FpPolynomial::from_coefs(vec![zero, two, four]);
    /// assert_eq!(poly, expected);
    /// ```
    pub fn mul_var_assign(&mut self, scalar: &F) {
        let mut r = F::one();
        for coefs in self.coefs.iter_mut() {
            coefs.mul_assign(&r);
            r.mul_assign(scalar);
        }
        self.trim_coefs();
    }

    /// Multiply polynomial variable by a scalar
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let four = two.add(&two);
    /// let mut poly = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// let result = poly.mul_var(&two);
    /// let expected = FpPolynomial::from_coefs(vec![zero, two, four]);
    /// assert_eq!(result, expected);
    /// ```
    pub fn mul_var(&self, scalar: &F) -> Self {
        let mut new = self.clone();
        new.mul_var_assign(scalar);
        new
    }

    /// Divide polynomial to produce the quotient and remainder polynomials.
    /// # Example:
    /// ```
    /// use noah_plonk::poly_commit::field_polynomial::FpPolynomial;
    /// use noah_algebra::bls12_381::BLSScalar;
    /// use noah_algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let mut poly = FpPolynomial::from_coefs(vec![one, one, one]);
    /// let mut divisor = FpPolynomial::from_coefs(vec![one, one]);
    /// let expected_quo = FpPolynomial::from_coefs(vec![zero, one]);
    /// let expected_rem = FpPolynomial::from_coefs(vec![one]);
    /// let (q, r) = poly.div_rem(&divisor);
    /// assert_eq!(q, expected_quo);
    /// assert_eq!(r, expected_rem);
    /// ```
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        let k = self.coefs.len();
        let l = divisor.coefs.len();
        if l > k {
            return (Self::zero(), self.clone());
        }
        let divisor_coefs = &divisor.coefs[..];
        let bl_inv = divisor_coefs.last().unwrap().clone().inv().unwrap();
        let mut rem = self.coefs.clone();
        let mut quo: Vec<F> = (0..k - l + 1).map(|_| F::zero()).collect();
        for i in (0..(k - l + 1)).rev() {
            let mut qi = bl_inv;
            qi.mul_assign(&rem[i + l - 1]);
            for j in 0..l {
                let mut a = qi;
                a.mul_assign(&divisor_coefs[j]);
                rem[i + j].sub_assign(&a);
            }
            quo[i] = qi;
        }
        for _ in 0..k - l + 1 {
            rem.pop();
        }
        if rem.is_empty() {
            rem.push(F::zero());
        }
        let mut q = FpPolynomial::from_coefs(quo);
        q.trim_coefs();
        let mut r = FpPolynomial::from_coefs(rem);
        r.trim_coefs();
        (q, r)
    }

    /// Construct a domain for evaluations of a polynomial having `num_coeffs` coefficients,
    /// where `num_coeffs` is with the form 2^k or 3 * 2^k.
    pub fn evaluation_domain(num_coeffs: usize) -> Option<MixedRadixEvaluationDomain<F::Field>> {
        assert!(
            num_coeffs.is_power_of_two()
                || ((num_coeffs % 3 == 0) && (num_coeffs / 3).is_power_of_two())
        );
        MixedRadixEvaluationDomain::<F::Field>::new(num_coeffs)
    }

    /// Compute the FFT of the polynomial, the parameter `num_coeffs` is with the form 2^k or 3 * 2^k.
    pub fn fft(&self, num_coeffs: usize) -> Option<(MixedRadixEvaluationDomain<F::Field>, Vec<F>)> {
        assert!(num_coeffs > self.degree());
        let domain = Self::evaluation_domain(num_coeffs)?;
        let values = self.fft_with_domain(&domain);
        Some((domain, values))
    }

    /// Compute the FFT of the polynomial with the given domain.
    pub fn fft_with_domain(&self, domain: &MixedRadixEvaluationDomain<F::Field>) -> Vec<F> {
        assert!(domain.size > self.degree() as u64);
        let coefs = self
            .coefs
            .iter()
            .map(|coef| coef.get_field())
            .collect::<Vec<F::Field>>();

        let values = domain.fft(&coefs);
        values.iter().map(|x| F::from_field(*x)).collect()
    }

    /// Compute the FFT of the polynomial on the set k * <root>.
    pub fn coset_fft_with_domain(
        &self,
        domain: &MixedRadixEvaluationDomain<F::Field>,
        k: &F,
    ) -> Vec<F> {
        self.mul_var(k).fft_with_domain(&domain)
    }

    /// Compute the polynomial given its evaluation values and domain.
    pub fn ifft_with_domain(domain: &MixedRadixEvaluationDomain<F::Field>, values: &[F]) -> Self {
        let values = values
            .iter()
            .map(|value| value.get_field())
            .collect::<Vec<F::Field>>();

        let coefs = domain.ifft(&values);
        let coefs = coefs.iter().map(|coef| F::from_field(*coef)).collect();
        Self::from_coefs(coefs)
    }

    /// Compute the polynomial given its evaluation values at a coset k * H,
    /// where H is evaluation domain and k_inv is the inverse of k.
    pub fn coset_ifft_with_domain(
        domain: &MixedRadixEvaluationDomain<F::Field>,
        values: &[F],
        k_inv: &F,
    ) -> Self {
        Self::ifft_with_domain(domain, values).mul_var(k_inv)
    }
}

#[cfg(test)]
mod test {
    use crate::poly_commit::field_polynomial::FpPolynomial;
    use ark_poly::MixedRadixEvaluationDomain;
    use noah_algebra::{bls12_381::BLSScalar, prelude::*, traits::Domain};

    #[test]
    fn from_zeroes() {
        let n = 10;
        let mut zeroes = vec![];
        let mut prng = test_rng();
        for _ in 0..n {
            zeroes.push(BLSScalar::random(&mut prng));
        }
        let poly = FpPolynomial::from_zeroes(&zeroes[..]);
        for root in zeroes.iter() {
            assert_eq!(BLSScalar::zero(), poly.eval(root));
        }

        let zeroes_ref: Vec<&BLSScalar> = zeroes.iter().collect();
        let poly = FpPolynomial::from_zeroes_ref(&zeroes_ref);
        for root in zeroes.iter() {
            assert_eq!(BLSScalar::zero(), poly.eval(root));
        }
    }

    fn check_fft<F: Domain>(
        poly: &FpPolynomial<F>,
        domain: &MixedRadixEvaluationDomain<F::Field>,
        fft: &[F],
    ) -> bool {
        assert!(
            fft.len().is_power_of_two()
                || ((fft.len() % 3 == 0) && (fft.len() / 3).is_power_of_two())
        );

        let mut omega = F::one().get_field();
        for fft_elem in fft {
            if *fft_elem != poly.eval(&F::from_field(omega)) {
                return false;
            }
            omega.mul_assign(&domain.group_gen)
        }
        true
    }

    #[test]
    fn test_fft() {
        let mut prng = test_rng();
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();

        let polynomial = FpPolynomial::from_coefs(vec![one]);
        let (domian, fft) = polynomial.fft(1).unwrap();
        assert!(check_fft(&polynomial, &domian, &fft));

        let polynomial = FpPolynomial::from_coefs(vec![one, one]);
        let (domian, fft) = polynomial.fft(2).unwrap();
        assert!(check_fft(&polynomial, &domian, &fft));

        let polynomial = FpPolynomial::from_coefs(vec![one, zero]);
        let (domian, fft) = polynomial.fft(2).unwrap();
        assert!(check_fft(&polynomial, &domian, &fft));

        let polynomial = FpPolynomial::from_coefs(vec![zero, one]);
        let (domian, fft) = polynomial.fft(2).unwrap();
        assert!(check_fft(&polynomial, &domian, &fft));

        let polynomial = FpPolynomial::from_coefs(vec![zero, one, one]);
        let (domian, fft) = polynomial.fft(3).unwrap();
        assert!(check_fft(&polynomial, &domian, &fft));

        let ffti_polynomial = FpPolynomial::ifft_with_domain(&domian, &fft);
        assert_eq!(ffti_polynomial, polynomial);

        let mut coefs = vec![];
        for _ in 0..16 {
            coefs.push(BLSScalar::random(&mut prng));
        }
        let polynomial = FpPolynomial::from_coefs(coefs);
        let (domian, fft) = polynomial.fft(16).unwrap();
        let ffti_polynomial = FpPolynomial::ifft_with_domain(&domian, &fft);
        assert_eq!(ffti_polynomial, polynomial);

        let mut coefs = vec![];
        for _ in 0..32 {
            coefs.push(BLSScalar::random(&mut prng));
        }
        let polynomial = FpPolynomial::from_coefs(coefs);
        let (domian, fft) = polynomial.fft(32).unwrap();
        let ffti_polynomial = FpPolynomial::ifft_with_domain(&domian, &fft);
        assert_eq!(ffti_polynomial, polynomial);

        let mut coefs = vec![];
        for _ in 0..3 {
            coefs.push(BLSScalar::random(&mut prng));
        }
        let polynomial = FpPolynomial::from_coefs(coefs);
        let (domian, fft) = polynomial.fft(3).unwrap();
        let ffti_polynomial = FpPolynomial::ifft_with_domain(&domian, &fft);
        assert_eq!(ffti_polynomial, polynomial);

        let mut coefs = vec![];
        for _ in 0..48 {
            coefs.push(BLSScalar::random(&mut prng));
        }
        let polynomial = FpPolynomial::from_coefs(coefs);
        let (domian, fft) = polynomial.fft(48).unwrap();
        let ffti_polynomial = FpPolynomial::ifft_with_domain(&domian, &fft);
        assert_eq!(ffti_polynomial, polynomial);
    }
}
