use algebra::{ops::*, traits::Scalar, Zero};
use num_bigint::{BigUint, ToBigUint};
use num_integer::Integer;
use rand::{CryptoRng, RngCore};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FpPolynomial<F> {
    pub(crate) coefs: Vec<F>,
}

impl<F> FpPolynomial<F> {
    pub fn get_coefs_ref(&self) -> &[F] {
        self.coefs.as_slice()
    }
}

impl<F: Scalar> FpPolynomial<F> {
    pub fn get_field_size(&self) -> Vec<u8> {
        F::get_field_size_le_bytes()
    }

    /// Returns the always zero polynomial
    /// # Example
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One};
    /// let poly = FpPolynomial::<BLSScalar>::zero();
    /// let zero = BLSScalar::zero();
    /// assert_eq!(poly.degree(), 0);
    /// assert_eq!(poly.eval(&zero), zero);
    /// assert_eq!(poly.eval(&BLSScalar::one()), zero);
    /// ```
    pub fn zero() -> Self {
        Self::from_coefs(vec![F::zero()])
    }

    /// Returns the always one polynomial
    /// # Example
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One};
    /// let poly = FpPolynomial::<BLSScalar>::one();
    /// let one = BLSScalar::one();
    /// assert_eq!(poly.degree(), 0);
    /// assert_eq!(poly.eval(&one), one);
    /// assert_eq!(poly.eval(&BLSScalar::zero()), one);
    /// ```
    pub fn one() -> Self {
        Self::from_coefs(vec![F::one()])
    }

    /// Builds a polynomial from the coefficient vector, low-order coefficient first.
    /// High-order zero coefficient are trimmed
    /// # Example
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// Builds a polynomial from its zeroes/roots.
    /// # Example
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// Builds a polynomial from its zeroes/roots given as reference.
    /// # Example
    /// see from_zeroes
    pub fn from_zeroes_ref(zeroes: &[&F]) -> Self {
        let mut r = Self::one();
        for root in zeroes.iter() {
            let mut p = r.clone();
            r.shift_assign(1); // multiply by X
            p.mul_scalar_assign(*root); // x_0 * r
            r.sub_assign(&p); // r = r*(X - x_0)
        }
        r.trim_coefs();
        r
    }

    /// Returns None if x is repeated
    /// Returns `Some(poly)` where `poly(x[i]) = y[i]`
    /// Returns `Some(0)` if `x.len() == 0`
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let five = two.add(&two).add(&one);
    /// let x = [zero, one, two, five];
    /// let y = [five, five, one, two];
    /// let poly = FpPolynomial::from_interpolation(&x, &y).unwrap();
    /// assert_eq!(poly.degree(), 3);
    /// assert_eq!(poly.eval(&zero), five);
    /// assert_eq!(poly.eval(&one), five);
    /// assert_eq!(poly.eval(&two), one);
    /// assert_eq!(poly.eval(&five), two);
    /// let x = [zero, one, two, two];
    /// let y = [five, five, one, two];
    /// let poly_option = FpPolynomial::from_interpolation(&x, &y);
    /// assert!(poly_option.is_none());
    /// ```
    pub fn from_interpolation(x: &[F], y: &[F]) -> Option<Self> {
        assert_eq!(x.len(), y.len());
        let n = x.len();
        if n == 0 {
            return Some(Self::zero());
        }

        let mut poly = Self::zero();
        for (i, y_i) in y.iter().enumerate() {
            let mut lagrange_i = Self::lagrange_ith_base(x, i)?;
            lagrange_i.mul_scalar_assign(y_i);
            poly.add_assign(&lagrange_i);
        }
        poly.trim_coefs();
        Some(poly)
    }

    /// Returns a polynomial of `degree` + 1 uniformly random coefficients. Note that for each
    /// coffiecient with probability
    /// 1/q is zero, and hence the degree could be less than `degree`
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// Removes high degree zero-coefficients
    fn trim_coefs(&mut self) {
        while self.coefs.len() > 1 && self.coefs.last().unwrap().is_zero() {
            // safe unwrap
            self.coefs.pop().unwrap(); // safe unwrap
        }
    }

    /// Returns degree of the polynomial
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One};
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

    /// Tests if polynomial is the zero polynomial
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One};
    /// let poly = FpPolynomial::<BLSScalar>::from_coefs(vec![BLSScalar::one(); 10]);
    /// assert!(!poly.is_zero());
    /// let poly = FpPolynomial::<BLSScalar>::from_coefs(vec![BLSScalar::zero(); 10]);
    /// assert!(poly.is_zero())
    /// ```
    pub fn is_zero(&self) -> bool {
        self.degree() == 0 && self.coefs[0].is_zero()
    }

    /// Evaluate a polynomial on a point
    /// Tests if polynomial is the zero polynomial
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let five = two.add(&two).add(&one);
    /// let x = [zero, one, two, five];
    /// let y = [five, five, one, two];
    /// let poly = FpPolynomial::from_interpolation(&x, &y).unwrap();
    /// assert_eq!(poly.eval(&zero), five);
    /// assert_eq!(poly.eval(&one), five);
    /// assert_eq!(poly.eval(&two), one);
    /// assert_eq!(poly.eval(&five), two);
    /// ```
    pub fn eval(&self, point: &F) -> F {
        let mut result = F::zero();
        let mut variable = F::one();
        let num_coefs = self.coefs.len();
        for coef in self.coefs[0..num_coefs - 1].iter() {
            let mut a = variable;
            a.mul_assign(coef);
            result.add_assign(&a);
            variable.mul_assign(point);
        }
        let last_coef = &self.coefs.last().unwrap();
        let mut a = variable;
        a.mul_assign(*last_coef);
        result.add_assign(&a);
        result
    }

    /// Add another polynomial to self
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let three = two.add(&one);
    /// let x = [zero, one, two, three];
    /// let y1 = [zero, one, two, three];
    /// let mut poly1 = FpPolynomial::from_interpolation(&x, &y1).unwrap();
    /// let y2 = [three, two, one, zero];
    /// let poly2 = FpPolynomial::from_interpolation(&x, &y2).unwrap();
    /// poly1.add_assign(&poly2);
    /// let y_expected = [three, three, three, three];
    /// let poly_expected = FpPolynomial::from_interpolation(&x, &y_expected).unwrap();
    /// assert_eq!(poly1, poly_expected);
    /// // first polynomial is of lower degree
    /// let mut poly1 = FpPolynomial::from_coefs(vec![one, one]);
    /// let poly2 = FpPolynomial::from_coefs(vec![one, one, one]);
    /// poly1.add_assign(&poly2);
    /// let expected = FpPolynomial::from_coefs(vec![two, two, one]);
    /// assert_eq!(poly1, expected);
    /// // second polynomial is of lower degree
    /// let mut poly1 = FpPolynomial::from_coefs(vec![one, one, one]);
    /// let poly2 = FpPolynomial::from_coefs(vec![one, one]);
    /// poly1.add_assign(&poly2);
    /// let expected = FpPolynomial::from_coefs(vec![two, two, one]);
    /// assert_eq!(poly1, expected);
    /// ```
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

    /// Add with another polynomial, producing a new polynomial
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// Subtracts another polynomial from self
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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
                let c = other_coef.neg();
                self.coefs.push(c);
            }
        }
        self.trim_coefs();
    }

    /// Subtract another polynomial from self, producing a new polynomial
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// Negate the coefficients
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// negate the coefficients
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// Compute product of self with another polynomial, producing a new polynomial
    /// O(self.degree * other.degree) naive algorithm. For FFT based implementation use fast_mul function
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let poly1 = FpPolynomial::from_coefs(vec![zero, one]);
    /// let poly2 = FpPolynomial::from_coefs(vec![one, one]);
    /// let poly_mul = poly1.naive_mul(&poly2);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// assert_eq!(poly_mul, poly_expected);
    /// ```
    pub fn naive_mul(&self, other: &Self) -> Self {
        let mut new = Self::zero();
        for (i, other_coefs) in other.coefs.iter().enumerate() {
            let mut shifted_i = self.shift(i); // multiply by X^i
            shifted_i.mul_scalar_assign(other_coefs);
            new.add_assign(&shifted_i);
        }
        new
    }

    /// Compute product of self with another polynomial, producing a new polynomial
    /// O(n log n) algorithm using FFT
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let poly1 = FpPolynomial::from_coefs(vec![zero, one]);
    /// let poly2 = FpPolynomial::from_coefs(vec![one, one]);
    /// let poly_mul = poly1.fast_mul(&poly2);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// assert_eq!(poly_mul, poly_expected);
    /// ```
    pub fn fast_mul(&self, other: &Self) -> Self {
        let n = (self.degree() + other.degree() + 1).next_power_of_two();
        let (mut self_evals, root) = self.fft(n).unwrap();
        let other_evals = other.fft_with_unity_root(&root, n);
        for (self_eval, other_eval) in self_evals.iter_mut().zip(other_evals.iter()) {
            self_eval.mul_assign(other_eval);
        }
        Self::ffti(&root, &self_evals)
    }

    /// Add `coef` to the coefficient of order `order`
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// Multiply the coefficient of order `order` by `coef`
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let mut poly = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// poly.mul_coef_assign(&two, 1);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, two, one]);
    /// assert_eq!(poly, poly_expected);
    /// poly.mul_coef_assign(&two, 3);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, two, one]);
    /// assert_eq!(poly, poly_expected);
    /// ```
    pub fn mul_coef_assign(&mut self, coef: &F, order: usize) {
        while self.degree() < order {
            self.coefs.push(F::zero());
        }
        self.coefs[order].mul_assign(coef);
        self.trim_coefs();
    }

    /// Append coefficients, increasing the degree by `coef.len()`
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let mut poly = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// let extra_coefs = [two, two];
    /// poly.append_coefs_assign(&extra_coefs);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, one, one, two, two]);
    /// assert_eq!(poly, poly_expected);
    /// ```
    pub fn append_coefs_assign(&mut self, coef: &[F]) {
        self.coefs.extend_from_slice(coef);
        self.trim_coefs();
    }

    /// Multiply polynomial by X^n
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let mut poly = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// poly.shift_assign(3);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, zero, zero, zero, one, one]);
    /// assert_eq!(poly, poly_expected);
    /// ```
    pub fn shift_assign(&mut self, n: usize) {
        let mut new_coefs = Vec::with_capacity(n + self.coefs.len());
        new_coefs.extend(vec![F::zero(); n]);
        new_coefs.append(&mut self.coefs);
        self.coefs = new_coefs
    }

    /// Multiply polynomial by X^n into a new polynomial
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let poly = FpPolynomial::from_coefs(vec![zero, one, one]);
    /// let shifted = poly.shift(3);
    /// let poly_expected = FpPolynomial::from_coefs(vec![zero, zero, zero, zero, one, one]);
    /// assert_eq!(shifted, poly_expected);
    /// ```
    pub fn shift(&self, n: usize) -> Self {
        let mut new = self.clone();
        new.shift_assign(n);
        new
    }

    /// Multiply polynomial by a constant scalar
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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
        for coef in self.coefs.iter_mut() {
            coef.mul_assign(scalar)
        }
        self.trim_coefs();
    }

    /// Multiply polynomial by a constant scalar into a new polynomial
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// Multiply the polynomial variable by a scalar
    /// mul_var(\sum a_i X^i, b) = \sum a_i b^i X^i
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// Multiply polynomial's variable by a scalar
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// divide polynomial producing quotient and remainder polynomial
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
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

    /// Compute polynomial with another polynomials f.compose(inner)(x) = f(inner(x))
    /// # Example:
    /// ```
    /// use poly_iops::polynomials::field_polynomial::FpPolynomial;
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::{Zero, One, ops::*};
    /// let zero = BLSScalar::zero();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let three = two.add(&one);
    /// let mut outer = FpPolynomial::from_coefs(vec![zero, one, one]); // x + x^2
    /// let mut inner = FpPolynomial::from_coefs(vec![one, one]); // 1 + x
    /// let expected = FpPolynomial::from_coefs(vec![two, three, one]); // (1+x) + (1+x)^2 = 2 + 3x + x^2
    /// let composed = outer.compose(&inner);
    /// assert_eq!(composed, expected);
    /// ```
    pub fn compose(&self, inner: &Self) -> Self {
        let mut r = Self::zero();
        let mut prev = Self::one();
        for a_i in self.coefs.iter() {
            let poly_i = prev.mul_scalar(a_i);
            r.add_assign(&poly_i);
            prev = prev.fast_mul(inner);
        }
        r
    }

    /// Compute the DFT of the polynomial, return DFT and primitive the roof of unity used
    /// n is with the form 2^k or 3 * 2^k
    pub fn fft(&self, num_points: usize) -> Option<(Vec<F>, F)> {
        assert!(
            num_points.is_power_of_two()
                || ((num_points % 3 == 0) && (num_points / 3).is_power_of_two())
        );
        let root = primitive_nth_root_of_unity(num_points)?;
        Some((self.fft_with_unity_root(&root, num_points), root))
    }

    /// Compute the DFT of the polynomial using given n-th root of unity
    /// n is with the form 2^k or 3 * 2^k
    pub fn fft_with_unity_root(&self, root: &F, num_points: usize) -> Vec<F> {
        assert!(
            num_points.is_power_of_two()
                || ((num_points % 3 == 0) && (num_points / 3).is_power_of_two())
        );
        let mut coefs: Vec<&F> = self.coefs.iter().collect();
        let zero = F::zero();
        if num_points + 1 > self.degree() {
            let dummy = vec![&zero; num_points - self.degree() - 1];
            coefs.extend(dummy);
        }
        recursive_fft(&coefs, &root)
    }

    /// Compute the DFT of the polynomial on the set k * <root>.
    pub fn coset_fft_with_unity_root(&self, root: &F, num_points: usize, k: &F) -> Vec<F> {
        self.mul_var(k).fft_with_unity_root(root, num_points)
    }

    /// Compute the polynomial given its evaluation values at the n n-th root of unity given a primitive n-th root of unity
    pub fn ffti(root: &F, values: &[F]) -> Self {
        let values: Vec<&F> = values.iter().collect();
        let coefs = recursive_ifft(&values, root);
        Self::from_coefs(coefs)
    }

    /// Compute the polynomial given its evaluation values at a coset k * H, where H are n n-th
    /// root of unities and k_inv is the inverse of k.
    pub fn coset_ffti(root: &F, values: &[F], k_inv: &F) -> Self {
        Self::ffti(root, values).mul_var(k_inv)
    }

    pub fn lagrange_ith_base(points: &[F], i: usize) -> Option<Self> {
        if i >= points.len() {
            return None;
        }
        let mut divisor = F::one();
        let x_i = &points[i];
        for (index, point) in points.iter().enumerate() {
            if index == i {
                continue;
            }
            let c = x_i.sub(point);
            divisor.mul_assign(&c);
        }

        let points_skip_i: Vec<&F> = points
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, v)| v)
            .collect();
        let mut result = Self::from_zeroes_ref(points_skip_i.as_slice());
        let inv = divisor.inv().ok();
        inv.as_ref().map(|inv| {
            result.mul_scalar_assign(inv);
            result
        })
    }
}

/// given the coefs of a polynomial and a primitive n-th root of unity for field, compute its DFT
/// n is with the form 2^k or 3 * 2^k
fn recursive_fft<F: Scalar>(coefs: &[&F], root: &F) -> Vec<F> {
    let n = coefs.len();
    assert!(n.is_power_of_two() || ((n % 3 == 0) && (n / 3).is_power_of_two()));
    if n == 1 {
        return vec![*coefs[0]];
    }
    let root_sq = root.mul(root);
    if n == 3 {
        let root_quad = root_sq.mul(&root_sq);

        let mut a0 = coefs[0].add(coefs[1]);
        a0.add_assign(coefs[2]);

        let c1_times_root = coefs[1].mul(root);
        let c2_times_root_sq = coefs[2].mul(&root_sq);
        let mut a1 = coefs[0].add(&c1_times_root);
        a1.add_assign(&c2_times_root_sq);

        let c1_times_root_sq = coefs[1].mul(&root_sq);
        let c2_times_root_quad = coefs[2].mul(&root_quad);
        let mut a2 = coefs[0].add(&c1_times_root_sq);
        a2.add_assign(&c2_times_root_quad);

        return vec![a0, a1, a2];
    }
    let even: Vec<&F> = coefs
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 2 == 0)
        .map(|(_, c)| *c)
        .collect();
    let odd: Vec<&F> = coefs
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, c)| *c)
        .collect();

    let y_even = recursive_fft(&even, &root_sq);
    let y_odd = recursive_fft(&odd, &root_sq);

    let mut omega = F::one();
    let mut dft = vec![F::zero(); n];
    for (i, (e, o)) in y_even.iter().zip(y_odd.iter()).enumerate() {
        let omega_o = omega.mul(o);
        dft[i] = e.add(&omega_o);
        dft[n / 2 + i] = e.sub(&omega_o);
        omega.mul_assign(root);
    }
    dft
}

pub fn primitive_nth_root_of_unity<F: Scalar>(num_points: usize) -> Option<F> {
    let q_minus_one = BigUint::from_bytes_le(F::get_field_size_le_bytes().as_slice()).sub(1u64);
    let (exp, r) = q_minus_one.div_rem(&num_points.to_biguint().unwrap());
    if !r.is_zero() {
        None
    } else {
        let g = F::multiplicative_generator();
        let exp_u32_limbs = exp.to_u32_digits();
        let exp_u64_limbs = u32_limbs_to_u64_limbs(exp_u32_limbs.as_slice());
        Some(g.pow(&exp_u64_limbs[..]))
    }
}

fn u32_limbs_to_u64_limbs(s: &[u32]) -> Vec<u64> {
    let mut u64_limbs = vec![];
    let mut even_limb = 0u64;
    for (i, u32_limb) in s.iter().enumerate() {
        if i % 2 == 0 {
            even_limb = (*u32_limb) as u64;
        } else {
            u64_limbs.push(even_limb + ((*u32_limb as u64) << 32));
            even_limb = 0u64;
        }
    }
    if even_limb != 0 {
        u64_limbs.push(even_limb);
    }
    u64_limbs
}

/// given the the values of a polynomial at the n n-th root of unity, and a primitive n-th root of unity
/// if computes its coefficients.
/// n is with the form 2^k or 3 * 2^k
pub fn recursive_ifft<F: Scalar>(values: &[&F], root: &F) -> Vec<F> {
    let n = values.len();
    assert!(n.is_power_of_two() || ((n % 3 == 0) && (n / 3).is_power_of_two()));
    let root_inv = root.pow(&[(n - 1) as u64]);
    let n = F::from(n as u64);
    let n_inv = n.inv().unwrap();
    recursive_fft(values, &root_inv)
        .into_iter()
        .map(|x| {
            let mut a = n_inv;
            a.mul_assign(&x);
            a
        })
        .collect()
}

#[cfg(test)]
mod test {
    use crate::polynomials::field_polynomial::FpPolynomial;
    use algebra::{bls12_381::BLSScalar, ops::*, traits::Scalar, One, Zero};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn from_zeroes() {
        let n = 10;
        let mut zeroes = vec![];
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
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

    #[test]
    fn from_interpolation() {
        let n = 10;
        let mut y = vec![];
        let mut x = vec![];
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        for _ in 0..n {
            x.push(BLSScalar::random(&mut prng));
            y.push(BLSScalar::random(&mut prng));
        }
        let poly = FpPolynomial::from_interpolation(x.as_slice(), y.as_slice()).unwrap();
        for (x, y) in x.iter().zip(y.iter()) {
            let z = poly.eval(x);
            assert_eq!(*y, z);
        }
    }

    fn check_dft<F: Scalar>(poly: &FpPolynomial<F>, root: &F, dft: &[F]) -> bool {
        let mut omega = F::one();
        if !dft.len().is_power_of_two() {
            return false;
        }
        if (dft.len() % 3 == 0) && !(dft.len() / 3).is_power_of_two() {
            return false;
        }
        for fft_elem in dft {
            if *fft_elem != poly.eval(&omega) {
                return false;
            }
            omega.mul_assign(root);
        }
        true
    }

    #[test]
    fn test_fft() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = two.add(&two);

        let polynomial = FpPolynomial::from_coefs(vec![one]);
        let (dft, root) = polynomial.fft(1).unwrap();
        check_dft(&polynomial, &root, &dft);

        let polynomial = FpPolynomial::from_coefs(vec![one, one]);
        let (dft, root) = polynomial.fft(2).unwrap();
        check_dft(&polynomial, &root, &dft);

        let polynomial = FpPolynomial::from_coefs(vec![one, zero]);
        let (dft, root) = polynomial.fft(2).unwrap();
        check_dft(&polynomial, &root, &dft);

        let polynomial = FpPolynomial::from_coefs(vec![zero, one]);
        let (dft, root) = polynomial.fft(2).unwrap();
        check_dft(&polynomial, &root, &dft);

        let polynomial = FpPolynomial::from_coefs(vec![zero, one, one]);
        let (dft, root) = polynomial.fft(3).unwrap();
        check_dft(&polynomial, &root, &dft);

        let root = super::primitive_nth_root_of_unity(4).unwrap();
        let polynomial = FpPolynomial::from_coefs(vec![one, two, three, four]);
        let dft = polynomial.fft_with_unity_root(&root, 4);
        check_dft(&polynomial, &root, &dft);

        let ffti_polynomial = FpPolynomial::ffti(&root, &dft);
        assert_eq!(ffti_polynomial, polynomial);

        let mut coefs = vec![];
        for _ in 0..16 {
            coefs.push(BLSScalar::random(&mut prng));
        }
        let polynomial = FpPolynomial::from_coefs(coefs);
        let (dft, root) = polynomial.fft(16).unwrap();
        let ffti_polynomial = FpPolynomial::ffti(&root, &dft);
        assert_eq!(ffti_polynomial, polynomial);

        let mut coefs = vec![];
        for _ in 0..32 {
            coefs.push(BLSScalar::random(&mut prng));
        }
        let polynomial = FpPolynomial::from_coefs(coefs);
        let (dft, root) = polynomial.fft(32).unwrap();
        let ffti_polynomial = FpPolynomial::ffti(&root, &dft);
        assert_eq!(ffti_polynomial, polynomial);

        let mut coefs = vec![];
        for _ in 0..3 {
            coefs.push(BLSScalar::random(&mut prng));
        }
        let polynomial = FpPolynomial::from_coefs(coefs);
        let (dft, root) = polynomial.fft(3).unwrap();
        let ffti_polynomial = FpPolynomial::ffti(&root, &dft);
        assert_eq!(ffti_polynomial, polynomial);

        let mut coefs = vec![];
        for _ in 0..48 {
            coefs.push(BLSScalar::random(&mut prng));
        }
        let polynomial = FpPolynomial::from_coefs(coefs);
        let (dft, root) = polynomial.fft(48).unwrap();
        let ffti_polynomial = FpPolynomial::ffti(&root, &dft);
        assert_eq!(ffti_polynomial, polynomial);
    }

    #[test]
    fn test_fast_mul() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let n = 7;
        let mut coefs = vec![];
        for _ in 0..n {
            coefs.push(BLSScalar::random(&mut prng));
        }
        let polynomial1 = FpPolynomial::<BLSScalar>::from_coefs(coefs);

        let mut coefs2 = vec![];
        for _ in 0..n {
            coefs2.push(BLSScalar::random(&mut prng));
        }
        let polynomial2 = FpPolynomial::<BLSScalar>::from_coefs(coefs2);
        let mul = polynomial1.naive_mul(&polynomial2);
        let fast_mul = polynomial1.fast_mul(&polynomial2);

        assert_eq!(mul, fast_mul);

        for _ in 0..2 * n {
            let elem = BLSScalar::random(&mut prng);
            let mut a = polynomial1.eval(&elem);
            a.mul_assign(&polynomial2.eval(&elem));
            let b = mul.eval(&elem);
            let c = fast_mul.eval(&elem);
            assert_eq!(b, c);
            assert_eq!(a, b);
        }
    }
}
