use crate::groups::{Group /*GroupArithmetic*/ };
use crate::groups::Scalar;
//use crate::crypto::sigma::SigmaTranscript;
//use crate::errors::AlgebraError;
//use merlin::Transcript;

pub trait Pairing {
  type ScalarField: Scalar;
  type G1: Group<S = Self::ScalarField>;
  type G2: Group<S = Self::ScalarField>;
  type Gt: Group<S = Self::ScalarField>;
  fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt;
}
