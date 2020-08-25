use crate::groups::Group;
use crate::groups::Scalar;

pub trait Pairing {
  type ScalarField: Scalar;
  type G1: Group<Self::ScalarField>;
  type G2: Group<Self::ScalarField>;
  type Gt: Group<Self::ScalarField>;
  fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt;
}
