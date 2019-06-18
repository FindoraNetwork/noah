use crate::errors::ZeiError;
use curve25519_dalek::scalar::Scalar;
use digest::Digest;
use rand_chacha::ChaChaRng;
use rand::SeedableRng;
use std::string::ToString;
use std::fmt::Debug;

pub enum PathDirection{
    LEFT,
    RIGHT,
}

#[derive(Debug)]
pub struct MerkleNode<S>{
    pub(crate) value: S,
    pub(crate) left: Option<Box<MerkleNode<S>>>,
    pub(crate) right: Option<Box<MerkleNode<S>>>
}

#[derive(Debug)]
pub struct MerkleTree<S>{
    pub root: MerkleNode<S>,
    pub size: usize,
}

#[derive(Debug)]
pub struct MerkleRoot<S>{
    pub value: S,
    pub size: usize,
}

pub trait MTHash<S>{
    fn new(level: usize) -> Self;
    fn digest(&self, values: &[&S]) -> S;
    fn digest_root(&self, size: usize, values: &[&S]) -> S;
}

pub fn mt_build<S,H>(elements: &[S]) -> Result<(MerkleTree<S>, MerkleRoot<S>), ZeiError>
    where S: Copy + PartialEq + Eq + Debug, H: MTHash<S>
{
    if ! is_power_two(elements.len()){
        return Err(ZeiError::ParameterError);
    }

    let tree = MerkleTree{
        root: create_merkle_node::<S,H>(elements, 0),
        size: elements.len()
    };
    let root = MerkleRoot{
        value: tree.root.value,
        size:  tree.size,
    };
    Ok((tree, root))
}


pub fn mt_prove<S>(tree: &MerkleTree<S>, index: usize) -> (S, Vec<(PathDirection, S)>)
    where S: Copy + PartialEq + Eq + Debug
{
    prove_node::<S>(&tree.root, index, tree.size)
}

pub fn mt_verify<S, H>(root: &MerkleRoot<S>, element: &S, path: &[(PathDirection, S)]) -> bool
    where S: Copy  + PartialEq + Eq, H: MTHash<S>
{
    let mut prev = *element;
    let mut level = path.len();
    for (b,sibling) in path[..path.len()-1].iter(){
        let hasher = H::new(level - 1);
        prev = match *b {
            PathDirection::RIGHT => hasher.digest(&[sibling, &prev]),
            PathDirection::LEFT  => hasher.digest(&[&prev, sibling]),
        };
        level = level -1;
    }
    let hasher = H::new(0);
    let sibling = &path[path.len() - 1].1;
    let computed_root = match path[path.len() - 1].0{
        PathDirection::RIGHT =>  hasher.digest_root(root.size, &[sibling, &prev]),
        PathDirection::LEFT => hasher.digest_root(root.size, &[&prev, sibling]),
    };

    computed_root == root.value
}

fn create_merkle_node<S: Copy + Debug, H: MTHash<S>>(elements: &[S], level: usize) -> MerkleNode<S>{
    let len = elements.len();
    if elements.len() == 1 {
        return MerkleNode{
            left: None,
            right: None,
            value: elements[0],
        }
    }
    let left = create_merkle_node::<_, H>(&elements[0..len/2], level + 1);
    let right = create_merkle_node::<_, H>(&elements[len/2..], level + 1);

    //let value = mimc_hash(level, &left.value, &right.value);
    let hash = H::new(level);
    let value = match level{
        0 => hash.digest_root(elements.len(), &[&left.value, &right.value]),
        _ => hash.digest(&[&left.value, &right.value]),
    };

    MerkleNode{
        left: Some(Box::new(left)),
        right: Some(Box::new(right)),
        value
    }
}

fn prove_node<S: Copy + PartialEq + Eq + Debug>(node: &MerkleNode<S>, index: usize, size: usize) -> (S, Vec<(PathDirection, S)>){
    if node.left.is_none(){
        return (node.value, vec![]);
    }
    if index < size/2 {
        let (elem, mut v) = prove_node(node.left.as_ref().unwrap().as_ref() , index, size/2);
        v.push((PathDirection::LEFT, node.right.as_ref().unwrap().value));
        return (elem, v);
    }
    let (elem, mut v) = prove_node(node.right.as_ref().unwrap().as_ref() , index/2, size/2);
    v.push((PathDirection::RIGHT, node.left.as_ref().unwrap().value));
    (elem, v)
}

fn is_power_two(n: usize) -> bool{
    (n != 0) && ((n & (n-1)) == 0)
}

pub struct MiMCHash{
    c: [Scalar; MIMC_ROUNDS],
}
const MIMC_ROUNDS: usize = 159;

impl MTHash<Scalar> for MiMCHash{
    fn new(level: usize) -> MiMCHash{
        MiMCHash{
            c: compute_mimc_constants(level),
        }
    }
    fn digest(&self, values:&[&Scalar]) -> Scalar{
        let mut sa = Scalar::from(0u8);
        let mut sc = Scalar::from(0u8);
        for value in values.iter() {
            let x = mimc_feistel(&(*value + &sa), &sc, &self.c[..]);
            sa = x.0;
            sc = x.1;
        }
        sa
    }

    fn digest_root(&self, size: usize, values:&[&Scalar]) -> Scalar{
        let x = Scalar::from(size as u64);
        let mut vec = Vec::with_capacity(values.len() + 1);
        vec.push(&x);
        vec.extend_from_slice(values);
        self.digest(&vec[..])
    }
}

pub(crate) fn mimc_f(s: &Scalar, c: &Scalar) -> Scalar{
    let x = s + c;
    let x2 = x*x;
    return (x2 * x2) * x;
}


pub(crate) fn compute_mimc_constants(level: usize) -> [Scalar; MIMC_ROUNDS]{
    let mut c = [Scalar::from(0u32); MIMC_ROUNDS];
    let mut hash = sha2::Sha256::new();
    hash.input( level.to_string());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash.result()[..]);
    let mut prng = ChaChaRng::from_seed(seed);
    for i in 1..MIMC_ROUNDS-1{
        c[i] = Scalar::random(&mut prng);
    }
    c
}

pub(crate) fn mimc_feistel(left: &Scalar, right: &Scalar, c: &[Scalar]) -> (Scalar, Scalar){
    let mut xl = left.clone();
    let mut xr = right.clone();
    for ci in c{
        let aux = xl.clone();
        xl = xr + mimc_f(&xl,ci);
        xr = aux;
    }
    (xl,xr)
}

#[cfg(test)]
mod test{
    use super::*;

    #[test]
    fn test_mt(){

        let mut elements = vec![];
        let size = 32;
        for i in 0..size{
            elements.push(Scalar::from(i as u64));
        }
        let (merkle_tree, mut merkle_root) = mt_build::<Scalar, MiMCHash>(&elements[..]).unwrap();

        for i in 0..size{
            let (e, path) = mt_prove::<Scalar>(&merkle_tree, i);
            let b = mt_verify::<Scalar, MiMCHash>(&merkle_root, &e, &path[..]);
            assert_eq!(true,b);

            let b = mt_verify::<Scalar, MiMCHash>(&merkle_root, &(e+Scalar::from(1u8)), &path[..]);
            assert_eq!(false,b);

            merkle_root.size = size * 2;
            let b = mt_verify::<Scalar, MiMCHash>(&merkle_root, &e, &path[..]);
            assert_eq!(false,b);

            merkle_root.size = size;
        }
    }
}
