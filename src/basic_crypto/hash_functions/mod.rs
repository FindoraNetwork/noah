pub mod mimc;

pub trait MTHash<S> {
  fn new(level: usize) -> Self;
  fn digest(&self, values: &[&S]) -> S;
  fn digest_root(&self, size: usize, values: &[&S]) -> S;
}
