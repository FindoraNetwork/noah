use crate::basic_crypto::hash_functions::MTHash;
use crate::errors::ZeiError;
use itertools::Itertools;
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct KMerkleNode<S> {
  pub(crate) value: S,
  children: Vec<KMerkleNode<S>>,
  pub k: usize, // Arity of the Merkle tree
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

type PathPosition = usize;

/// Returns true if n is a power of k, false otherwise
fn is_power_of_k(k: usize, n: usize) -> bool {
  if k == 1 {
    return n == 1;
  }
  let mut pow = 1;
  while pow < n {
    pow *= k;
  }
  pow == n
}

/// Builds a k-ary Merkle tree from a set of elements
/// * `elements` - elements to be placed at the leaves of the tree. The number of elements must be a power of k.
/// * `k` - number of children of each node
/// * `returns` Merkle tree data structure or an error
pub fn k_mt_build<S, H>(elements: &[S], k: usize) -> Result<KMerkleTree<S>, ZeiError>
  where S: Copy + PartialEq + Eq + Debug,
        H: MTHash<S>
{
  if !is_power_of_k(k, elements.len()) {
    return Err(ZeiError::ParameterError);
  }

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
                         value: elements[0],
                         k };
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
                value,
                k }
}

type KMTProof<S> = Vec<(PathPosition, Vec<S>)>;

/// Computes a proof (merkle path) for a leaf of the tree
/// * `tree` - merkle tree data structure
/// * `index` - location of the leaf, 0 being the index of the most left one
/// * `returns` - the value of the root node and the proof
pub fn kmt_prove<S>(tree: &KMerkleTree<S>, index: usize) -> Result<(S, KMTProof<S>), ZeiError>
  where S: Copy + PartialEq + Eq + Debug
{
  if index >= tree.size {
    return Err(ZeiError::ParameterError);
  }
  Ok(prove_node::<S>(&tree.root, index, tree.size))
}

fn prove_node<S: Copy + PartialEq + Eq + Debug>(node: &KMerkleNode<S>,
                                                index: usize,
                                                size: usize)
                                                -> (S, KMTProof<S>) {
  if node.children.is_empty() {
    return (node.value, vec![]);
  }

  let k = node.k;
  let new_size = size / k;
  let position = index / new_size;
  let new_index = index % new_size;
  let next_node = node.children.get(position).unwrap();

  let (elem, mut v) = prove_node(next_node, new_index, new_size);

  let mut vec_to_store = vec![];
  for i in 0..k {
    if i != position {
      vec_to_store.push(node.children.get(i).unwrap().value);
    }
  }

  v.push((position, vec_to_store));
  (elem, v)
}

#[allow(clippy::ptr_arg)]
/// Verifies a merkle proof for an element against a merkle root
/// `root` - hash value of the root of some merkle tree
/// `element` - element to be tested
/// `proof` - proof that the element is a leaf of the merkle tree defined by its root.
/// `returns` Ok() if the verification is successful, an error otherwise
pub fn kmt_verify<S, H>(root: &KMerkleRoot<S>,
                        element: &S,
                        proof: &KMTProof<S>)
                        -> Result<(), ZeiError>
  where S: Copy + PartialEq + Eq,
        H: MTHash<S>
{
  let mut prev = *element;
  let mut level = proof.len();
  for (pos, siblings) in proof[..proof.len() - 1].iter() {
    let hasher = H::new(level - 1);

    let mut v_to_hash = vec![];
    let mut siblings_left = siblings[0..*pos].to_vec();
    let mut siblings_right = siblings[*pos..].to_vec();
    v_to_hash.append(&mut siblings_left);
    v_to_hash.push(prev);
    v_to_hash.append(&mut siblings_right);
    let v_to_hash = v_to_hash.iter().map(|v| v).collect_vec();
    prev = hasher.digest(v_to_hash.as_slice());

    level -= 1;
  }
  let hasher = H::new(0);
  let pos = &proof[proof.len() - 1].0;
  let siblings = &proof[proof.len() - 1].1;

  let mut v_to_hash = vec![];
  let mut siblings_left = siblings[0..*pos].to_vec();
  let mut siblings_right = siblings[*pos..].to_vec();
  v_to_hash.append(&mut siblings_left);
  v_to_hash.push(prev);
  v_to_hash.append(&mut siblings_right);
  let v_to_hash = v_to_hash.iter().map(|v| v).collect_vec();
  let computed_root = hasher.digest_root(root.size, v_to_hash.as_slice());

  if computed_root == root.value {
    Ok(())
  } else {
    Err(ZeiError::MerkleTreeVerificationError)
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use crate::basic_crypto::hash_functions::mimc::MiMCHash;
  use crate::crypto::merkle_tree::binary_merkle_tree::mt_build;
  use curve25519_dalek::scalar::Scalar;

  #[test]
  fn root_computation() {
    let mut elements = vec![];
    let size = 32;
    for i in 0..size {
      elements.push(Scalar::from(i as u64));
    }
    let k_merkle_tree = k_mt_build::<Scalar, MiMCHash>(&elements[..], 2).unwrap();

    // The root is equal to the root computed with a standard binary merkle tree as we chose k=2
    let k_merkle_root = k_merkle_tree.get_root();
    let binary_merkle_tree = mt_build::<Scalar, MiMCHash>(&elements[..]).unwrap();
    let binary_merkle_root = binary_merkle_tree.get_root();
    assert_eq!(k_merkle_root.value, binary_merkle_root.value);

    // Compute the root of a 3-ary merkle tree
    let mut elements = vec![];
    let size = 27;
    for i in 0..size {
      elements.push(Scalar::from(i as u64));
    }
    let k_merkle_tree = k_mt_build::<Scalar, MiMCHash>(&elements[..], 3).unwrap();
    let k_merkle_root = k_merkle_tree.get_root();
    let k_merkle_root_bytes_expected: [u8; 32] =
      [131, 67, 191, 251, 189, 176, 78, 250, 36, 176, 46, 156, 15, 60, 78, 245, 211, 223, 183,
       127, 173, 76, 54, 75, 131, 216, 238, 50, 52, 25, 242, 11];
    assert_eq!(k_merkle_root.value.as_bytes(),
               &k_merkle_root_bytes_expected);

    // Fails if the size of the input is not a power of k
    let k = 3;
    let not_a_power_of_3 = 30;
    let elements = vec![Scalar::from(0 as u64); not_a_power_of_3];
    let k_merkle_tree = k_mt_build::<Scalar, MiMCHash>(&elements[..], k);
    assert!(k_merkle_tree.is_err());
  }

  #[test]
  fn prove_and_verify() {
    let mut elements = vec![];
    let k = 3;
    let size = 27;
    for i in 0..size {
      elements.push(Scalar::from(i as u64));
    }
    let k_merkle_tree = k_mt_build::<Scalar, MiMCHash>(&elements[..], k).unwrap();
    let mut k_merkle_root = k_merkle_tree.get_root();

    for i in 0..size {
      let (e, proof) = kmt_prove::<Scalar>(&k_merkle_tree, i).unwrap();

      let b = kmt_verify::<Scalar, MiMCHash>(&k_merkle_root, &e, &proof);
      assert_eq!(true, b.is_ok());

      let b = kmt_verify::<Scalar, MiMCHash>(&k_merkle_root, &(e + Scalar::from(1u8)), &proof);
      assert_eq!(false, b.is_ok());

      k_merkle_root.size = size * 2;
      let b = kmt_verify::<Scalar, MiMCHash>(&k_merkle_root, &e, &proof);
      assert_eq!(false, b.is_ok());

      k_merkle_root.size = size;
    }
  }
}
