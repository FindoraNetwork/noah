use crate::errors::ZeiError;
use curve25519_dalek::scalar::Scalar;
use digest::Digest;
use rand_chacha::ChaChaRng;
use rand::SeedableRng;
use std::string::ToString;

pub struct MerkleNode<S>{
    pub(crate) value: S,
    pub(crate) left: Option<Box<MerkleNode<S>>>,
    pub(crate) right: Option<Box<MerkleNode<S>>>
}
pub struct MerkleTree<S>{
    pub root: MerkleNode<S>,
    pub size: usize,
}

pub trait MTHash<S>{
    fn new(level: usize) -> Self;
    fn digest(&self, left: &S, right: &S) -> S;
}

pub fn mt_build<S: Copy + PartialEq + Eq, H: MTHash<S>>(elements: &[S]) -> Result<MerkleTree<S>, ZeiError>{
    if ! is_power_two(elements.len()){
        return Err(ZeiError::ParameterError);
    }

    Ok(MerkleTree{
        root: create_merkle_node::<S,H>(elements, 0),
        size: elements.len()
    })


}


pub fn mt_prove<S: Copy + PartialEq + Eq>(tree: &MerkleTree<S>, index: usize) -> (S, Vec<(bool, S)>){
    prove_node::<S>(&tree.root, index, tree.size)
}

pub fn mt_verify<S: Copy  + PartialEq + Eq, H: MTHash<S>>(root: &MerkleNode<S>, element: &S, path: &[(bool, S)])
    -> bool
{
    let mut h_prev = *element;
    let mut level = path.len();
    for (b,s) in path.iter(){
        let hasher = H::new(level - 1);
        if *b {
            h_prev = hasher.digest(s, &h_prev);
            //h_prev = mimc_hash(level - 1, s, &h_prev);
        }
        else{
            h_prev = hasher.digest(&h_prev, s);
            //h_prev = mimc_hash(level - 1, &h_prev, s);
        }
        level = level -1;
    }
    h_prev == root.value
}

fn create_merkle_node<S: Copy, H: MTHash<S>>(elements: &[S], level: usize) -> MerkleNode<S>{
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
    let value = hash.digest(&left.value, &right.value);

    MerkleNode{
        left: Some(Box::new(left)),
        right: Some(Box::new(right)),
        value
    }
}

fn prove_node<S: Copy + PartialEq + Eq>(node: &MerkleNode<S>, index: usize, size: usize) -> (S, Vec<(bool, S)>){
    if node.left.is_none(){
        return (node.value, vec![]);
    }
    if index < size/2 {
        let (elem, mut v) = prove_node(node.left.as_ref().unwrap().as_ref() , index, size/2);
        v.push((false, node.right.as_ref().unwrap().value));
        return (elem, v);
    }
    let (elem, mut v) = prove_node(node.right.as_ref().unwrap().as_ref() , index/2, size/2);
    v.push((true, node.left.as_ref().unwrap().value));
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
    fn digest(&self, left: &Scalar, right: &Scalar) -> Scalar{
        let (sa,sc) = mimc_feistel(&left, &Scalar::from(0u8), &self.c[..]);
        let (out, _) = mimc_feistel(&(right + sa), &sc, &self.c[..]);
        out
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
        for i in 0..64u32{
            elements.push(Scalar::from(i));
        }
        let merkle_tree = mt_build::<Scalar, MiMCHash>(&elements[..]).unwrap();

        for i in 0..64usize{
            let (e, path) = mt_prove::<Scalar>(&merkle_tree, i);
            let b = mt_verify::<Scalar, MiMCHash>(&merkle_tree.root, &e, &path[..]);
            assert_eq!(true,b);

            let b = mt_verify::<Scalar, MiMCHash>(&merkle_tree.root, &(e+Scalar::from(1u8)), &path[..]);
            assert_eq!(false,b);
        }
    }
}
