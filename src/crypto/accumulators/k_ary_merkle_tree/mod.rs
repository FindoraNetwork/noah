use crate::errors::ZeiError;
use curve25519_dalek::scalar::Scalar;
use digest::Digest;
use itertools::Itertools;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::fmt::Debug;
use std::string::ToString;

#[derive(Debug, Clone)]
pub struct KMerkleNode<S> {
  pub(crate) value: S,
  children: Vec<KMerkleNode<S>>,
}

#[derive(Debug)]
pub struct KMerkleTree<S> {
  pub root: KMerkleNode<S>,
  pub size: usize,
  pub k: usize, // Arity of the Merkle tree
}

#[derive(Debug)]
pub struct KMerkleRoot<S> {
  pub value: S,
  pub size: usize,
}

impl<S: Copy> KMerkleTree<S> {
  pub fn get_root(&self) -> KMerkleRoot<S> {
    KMerkleRoot { value: self.root.value,
                  size: self.size }
  }
}

pub trait MTHash<S> {
  fn new(level: usize) -> Self;
  fn digest(&self, values: &[&S]) -> S;
  fn digest_root(&self, size: usize, values: &[&S]) -> S;
}

pub fn mt_build<S, H>(elements: &[S], k: usize) -> Result<KMerkleTree<S>, ZeiError>
  where S: Copy + PartialEq + Eq + Debug,
        H: MTHash<S>
{
  // TODO replace by !is_power_of_k
  // if !is_power_two(elements.len()) {
  //   return Err(ZeiError::ParameterError);
  // }

  let tree = KMerkleTree { root: create_k_merkle_node::<S, H>(elements, 0, k),
                           size: elements.len(),
                           k };
  Ok(tree)
}

fn create_k_merkle_node<S: Copy + Debug, H: MTHash<S>>(elements: &[S],
                                                       level: usize,
                                                       k: usize)
                                                       -> KMerkleNode<S> {
  let len = elements.len();
  if elements.len() == 1 {
    return KMerkleNode { children: vec![],
                         value: elements[0] };
  }

  let mut k_merkle_nodes: Vec<KMerkleNode<S>> = vec![];
  let slice_length = len / k;
  for i in 0..k {
    let k_merkle_node = create_k_merkle_node::<_, H>(&elements
                                                       [i * slice_length..(i + 1) * slice_length],
                                                     level + 1,
                                                     k);
    k_merkle_nodes.push(k_merkle_node);
  }

  let hash = H::new(level);

  let values_vec: Vec<S> = k_merkle_nodes.clone()
                                         .into_iter()
                                         .map(|v| v.value)
                                         .collect();

  let value: S = match level {
    0 => hash.digest_root(elements.len(),
                          values_vec.iter().map(|v| v).collect_vec().as_slice()),
    _ => hash.digest(values_vec.iter().map(|v| v).collect_vec().as_slice()),
  };

  KMerkleNode { children: k_merkle_nodes,
                value }
}

pub struct MiMCHash {
  c: [Scalar; MIMC_ROUNDS],
}
const MIMC_ROUNDS: usize = 159;

impl MTHash<Scalar> for MiMCHash {
  fn new(level: usize) -> MiMCHash {
    MiMCHash { c: compute_mimc_constants(level) }
  }
  fn digest(&self, values: &[&Scalar]) -> Scalar {
    let mut sa = Scalar::from(0u8);
    let mut sc = Scalar::from(0u8);
    for value in values.iter() {
      let x = mimc_feistel(&(*value + sa), &sc, &self.c[..]);
      sa = x.0;
      sc = x.1;
    }
    sa
  }

  fn digest_root(&self, size: usize, values: &[&Scalar]) -> Scalar {
    let x = Scalar::from(size as u64);
    let mut vec = Vec::with_capacity(values.len() + 1);
    vec.push(&x);
    vec.extend_from_slice(values);
    self.digest(&vec[..])
  }
}

pub(crate) fn mimc_f(s: &Scalar, c: &Scalar) -> Scalar {
  let x = s + c;
  let x2 = x * x;
  (x2 * x2) * x
}

#[allow(clippy::needless_range_loop)]
pub(crate) fn compute_mimc_constants(level: usize) -> [Scalar; MIMC_ROUNDS] {
  let mut c = [Scalar::from(0u32); MIMC_ROUNDS];
  let mut hash = sha2::Sha256::new();
  hash.input(level.to_string());
  let mut seed = [0u8; 32];
  seed.copy_from_slice(&hash.result()[..]);
  let mut prng = ChaChaRng::from_seed(seed);
  for i in 1..MIMC_ROUNDS - 1 {
    c[i] = Scalar::random(&mut prng);
  }
  c
}

pub(crate) fn mimc_feistel(left: &Scalar, right: &Scalar, c: &[Scalar]) -> (Scalar, Scalar) {
  let mut xl = *left;
  let mut xr = *right;
  for ci in c {
    let aux = xl;
    xl = xr + mimc_f(&xl, ci);
    xr = aux;
  }
  (xl, xr)
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn test_mt() {
    let mut elements = vec![];
    let size = 32;
    for i in 0..size {
      elements.push(Scalar::from(i as u64));
    }
    let merkle_tree = mt_build::<Scalar, MiMCHash>(&elements[..], 2).unwrap();

    // The root is equal to the root computed with a standard binary merkle tree as we chose k=2
    let merkle_root = merkle_tree.get_root();
    let bytes_root: [u8; 32] = [100, 244, 200, 168, 101, 74, 28, 49, 202, 11, 7, 134, 182, 158,
                                209, 220, 59, 192, 249, 1, 155, 208, 188, 51, 93, 156, 34, 192,
                                74, 200, 104, 4];

    assert_eq!(&bytes_root, merkle_root.value.as_bytes());
  }
}
