use crate::basic_crypto::hash_functions::MTHash;
use crate::errors::ZeiError;
use itertools::Itertools;
use std::fmt::Debug;

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

#[cfg(test)]
mod test {
  use super::*;
  use crate::basic_crypto::hash_functions::mimc::MiMCHash;
  use curve25519_dalek::scalar::Scalar;

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
