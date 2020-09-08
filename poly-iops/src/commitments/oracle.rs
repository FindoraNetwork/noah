use crate::polynomials::field_polynomial::FpPolynomial;
use algebra::groups::Scalar;

pub trait PolynomialOracle {
  type Field: Scalar;
  fn eval(&self, point: &Self::Field) -> Self::Field;
}

pub struct NaiveOracle<F> {
  poly: FpPolynomial<F>,
}

impl<F> NaiveOracle<F> {
  pub fn new(poly: FpPolynomial<F>) -> NaiveOracle<F> {
    NaiveOracle { poly }
  }
}

impl<F: Scalar> PolynomialOracle for NaiveOracle<F> {
  type Field = F;
  fn eval(&self, point: &F) -> F {
    self.poly.eval(point)
  }
}
