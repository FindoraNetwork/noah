use super::groups::Group;

pub trait PairingTargetGroup<S>: PartialEq {
  type G1: Group<S>;
  type G2: Group<S>;
  fn pairing(a: &Self::G1, b: &Self::G2) -> Self;
  fn scalar_mul(&self, a: &S) -> Self;
  fn add(&self, other: &Self) -> Self;
  fn get_identity() -> Self;
}
