use algebra::bls12_381::BLSScalar;
use algebra::jubjub::{JubjubGroup, JubjubScalar};

pub type Nullifier = BLSScalar;
pub type Commitment = BLSScalar;
pub type BlindFactor = BLSScalar;

#[derive(Debug)]
pub struct AXfrSecKey(pub(crate) JubjubScalar);
#[derive(Debug, Eq, PartialEq)]
pub struct AXfrPubKey(pub(crate) JubjubGroup);

/// A Merkle tree node which consists of the following:
/// * `siblings1` - the 1st sibling of the tree node
/// * `siblings2` - the 2nd sibling of the tree node
/// * `is_left_child` - indicates whether the tree node is the left child of its parent
/// * `is_right_child` - indicates whether the tree node is the right child of its parent
#[derive(Debug, Clone)]
pub struct MTNode {
  pub siblings1: BLSScalar,
  pub siblings2: BLSScalar,
  pub is_left_child: u8,
  pub is_right_child: u8,
}

/// An authentication path of a ternary Merkle tree.
#[derive(Debug)]
pub struct MTPath {
  pub nodes: Vec<MTNode>,
}

impl MTPath {
  pub fn new(nodes: Vec<MTNode>) -> Self {
    Self { nodes }
  }
}
