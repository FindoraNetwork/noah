pub mod rescue;
pub mod rescue_bls12_381;

pub trait MTHash {
    type S;
    fn new(level: usize) -> Self;
    fn digest(&self, values: &[&Self::S]) -> Self::S;
    fn digest_root(&self, size: usize, values: &[&Self::S]) -> Self::S;
}
