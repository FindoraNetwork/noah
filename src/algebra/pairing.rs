use super::groups::Group;
use crate::algebra::groups::Scalar;

pub trait PairingTargetGroup: PartialEq {
  type ScalarField: Scalar;
  type G1: Group;
  type G2: Group;
  fn pairing(a: &Self::G1, b: &Self::G2) -> Self;
  fn scalar_mul(&self, a: &Self::ScalarField) -> Self;
  fn add(&self, other: &Self) -> Self;
  fn get_identity() -> Self;
}
