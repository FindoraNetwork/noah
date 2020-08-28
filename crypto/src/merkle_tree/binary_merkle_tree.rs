use crate::basics::hash_functions::MTHash;
use std::fmt::Debug;
use utils::errors::ZeiError;

pub enum PathDirection {
  LEFT,
  RIGHT,
}

#[derive(Debug)]
pub struct MerkleNode<S> {
  pub(crate) value: S,
  pub(crate) left: Option<Box<MerkleNode<S>>>,
  pub(crate) right: Option<Box<MerkleNode<S>>>,
}

#[derive(Debug)]
pub struct MerkleTree<S> {
  pub root: MerkleNode<S>,
  pub size: usize,
}

#[derive(Debug)]
pub struct MerkleRoot<S> {
  pub value: S,
  pub size: usize,
}

impl<S: Copy> MerkleTree<S> {
  pub fn get_root(&self) -> MerkleRoot<S> {
    MerkleRoot { value: self.root.value,
                 size: self.size }
  }
}

/// Builds a binary Merkle tree from a set of elements
/// * `elements` - elements to be placed at the leaves of the tree. The number of elements must be a power of 2.
/// * `returns` Merkle tree data structure or an error
pub fn mt_build<Sc, H>(elements: &[Sc]) -> Result<MerkleTree<Sc>, ZeiError>
  where Sc: Copy + PartialEq + Eq + Debug,
        H: MTHash<S = Sc>
{
  if !is_power_two(elements.len()) {
    return Err(ZeiError::ParameterError);
  }

  let tree = MerkleTree { root: create_merkle_node::<Sc, H>(elements, 0),
                          size: elements.len() };
  Ok(tree)
}

/// Computes a proof (merkle path) for a leaf of the tree
/// * `tree` - merkle tree data structure
/// * `index` - location of the leaf, 0 being the index of the most left one
/// * `returns` - the value of the root node and the proof
pub fn mt_prove<S>(tree: &MerkleTree<S>,
                   index: usize)
                   -> Result<(S, Vec<(PathDirection, S)>), ZeiError>
  where S: Copy + PartialEq + Eq + Debug
{
  if index >= tree.size {
    return Err(ZeiError::ParameterError);
  }
  Ok(prove_node::<S>(&tree.root, index, tree.size))
}

/// Verifies a merkle proof for an element against a merkle root
/// `root` - hash value of the root of some merkle tree
/// `element` - element to be tested
/// `proof` - proof that the element is a leaf of the merkle tree defined by its root.
/// `returns` Ok() if the verification is successful, an error otherwise
pub fn mt_verify<S, H>(root: &MerkleRoot<S>,
                       element: &S,
                       path: &[(PathDirection, S)])
                       -> Result<(), ZeiError>
  where S: Copy + PartialEq + Eq,
        H: MTHash<S = S>
{
  let mut prev = *element;
  let mut level = path.len();
  for (b, sibling) in path[..path.len() - 1].iter() {
    let hasher = H::new(level - 1);
    prev = match *b {
      PathDirection::RIGHT => hasher.digest(&[sibling, &prev]),
      PathDirection::LEFT => hasher.digest(&[&prev, sibling]),
    };
    level -= 1;
  }
  let hasher = H::new(0);
  let sibling = &path[path.len() - 1].1;
  let computed_root = match path[path.len() - 1].0 {
    PathDirection::RIGHT => hasher.digest_root(root.size, &[sibling, &prev]),
    PathDirection::LEFT => hasher.digest_root(root.size, &[&prev, sibling]),
  };

  if computed_root == root.value {
    Ok(())
  } else {
    Err(ZeiError::MerkleTreeVerificationError)
  }
}

fn create_merkle_node<S: Copy + Debug, H: MTHash<S = S>>(elements: &[S],
                                                         level: usize)
                                                         -> MerkleNode<S> {
  let len = elements.len();
  if elements.len() == 1 {
    return MerkleNode { left: None,
                        right: None,
                        value: elements[0] };
  }
  let left = create_merkle_node::<_, H>(&elements[0..len / 2], level + 1);
  let right = create_merkle_node::<_, H>(&elements[len / 2..], level + 1);

  //let value = mimc_hash(level, &left.value, &right.value);
  let hash = H::new(level);
  let value = match level {
    0 => hash.digest_root(elements.len(), &[&left.value, &right.value]),
    _ => hash.digest(&[&left.value, &right.value]),
  };

  MerkleNode { left: Some(Box::new(left)),
               right: Some(Box::new(right)),
               value }
}

/// Computes the authentication path for a  node corresponding to an index
/// Note: we assume the tree is complete
/// * `node` - root node corresponding to the whole tree
/// * `index` - index of the leaf for which we want to compute the authentication path (from left to right)
/// * size - number of leaves of the whole tree
fn prove_node<S: Copy + PartialEq + Eq + Debug>(node: &MerkleNode<S>,
                                                index: usize,
                                                size: usize)
                                                -> (S, Vec<(PathDirection, S)>) {
  if node.left.is_none() {
    return (node.value, vec![]);
  }

  // From now one the unwrap are safe as we assume the tree is complete.
  if index < size / 2 {
    let (elem, mut v) = prove_node(node.left.as_ref().unwrap().as_ref(), index, size / 2);
    v.push((PathDirection::LEFT, node.right.as_ref().unwrap().value));
    return (elem, v);
  }
  let (elem, mut v) = prove_node(node.right.as_ref().unwrap().as_ref(),
                                 index - size / 2,
                                 size / 2);
  v.push((PathDirection::RIGHT, node.left.as_ref().unwrap().value));
  (elem, v)
}

fn is_power_two(n: usize) -> bool {
  (n != 0) && ((n & (n - 1)) == 0)
}

#[cfg(test)]
mod test {
  use super::*;
  use crate::basics::hash_functions::mimc::MiMCHash;
  use algebra::groups::Scalar as _;
  use algebra::ristretto::RistrettoScalar as Scalar;

  #[test]
  fn test_mt() {
    let mut elements = vec![];
    let size = 32usize;
    for i in 0..size {
      elements.push(Scalar::from_u64(i as u64));
    }
    let merkle_tree = mt_build::<Scalar, MiMCHash>(&elements[..]).unwrap();

    let mut merkle_root = merkle_tree.get_root();

    for i in 0..size {
      let (e, path) = mt_prove::<Scalar>(&merkle_tree, i).unwrap();
      let b = mt_verify::<Scalar, MiMCHash>(&merkle_root, &e, &path[..]);
      assert_eq!(true, b.is_ok());

      let b = mt_verify::<Scalar, MiMCHash>(&merkle_root, &e.add(&Scalar::from_u32(1)), &path[..]);
      assert_eq!(false, b.is_ok());

      merkle_root.size = size * 2;
      let b = mt_verify::<Scalar, MiMCHash>(&merkle_root, &e, &path[..]);
      assert_eq!(false, b.is_ok());

      merkle_root.size = size as usize;
    }
  }
}
