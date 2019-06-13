use crate::errors::ZeiError;
use curve25519_dalek::scalar::Scalar;
use sha2::Digest;
use rand_chacha::ChaChaRng;
use rand::SeedableRng;
use std::string::ToString;

pub struct MerkleNode{
    pub(crate) value: Scalar,
    pub(crate) left: Option<Box<MerkleNode>>,
    pub(crate) right: Option<Box<MerkleNode>>
}
pub struct MerkleTree{
    pub root: MerkleNode,
    size: usize,
}

pub fn mt_build(elements:&[Scalar]) -> Result<MerkleTree, ZeiError>{
    if ! is_power_two(elements.len()){
        return Err(ZeiError::ParameterError);
    }
    Ok(MerkleTree{
        root: create_merkle_node(elements, 0),
        size: elements.len()
    })

}

pub fn mt_prove(tree: &MerkleTree, index: usize) -> (Scalar, Vec<(bool, Scalar)>){
    prove_node(&tree.root, index, tree.size)
}

pub fn mt_verify(root: &MerkleNode, element: &Scalar, path: &[(bool, Scalar)])
    -> bool
{
    let mut h_prev = element.clone();
    let mut level = path.len();
    for (b,s) in path.iter(){
        if *b {
            h_prev = mimc_hash(level - 1, s, &h_prev);
        }
        else{
            h_prev = mimc_hash(level - 1, &h_prev, s);
        }
        level = level -1;
    }
    h_prev == root.value
}

fn create_merkle_node(elements: &[Scalar], level: usize) -> MerkleNode{
    let len = elements.len();
    if elements.len() == 1 {
        return MerkleNode{
            left: None,
            right: None,
            value: elements[0],
        }
    }
    let left = create_merkle_node(&elements[0..len/2], level + 1);
    let right = create_merkle_node(&elements[len/2..], level + 1);

    let value = mimc_hash(level, &left.value, &right.value);

    MerkleNode{
        left: Some(Box::new(left)),
        right: Some(Box::new(right)),
        value
    }
}

fn prove_node(node: &MerkleNode, index: usize, size: usize) -> (Scalar, Vec<(bool, Scalar)>){
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

const MIMC_ROUNDS: usize = 159;
pub fn mimc_f(s: &Scalar, c: &Scalar) -> Scalar{
    let x = s + c;
    let x2 = x*x;
    return (x2 * x2) * x;
}

pub fn mimc_hash(level: usize, x: &Scalar, y:&Scalar) -> Scalar{
    let c = compute_mimc_constants(level);
    let (sa,sc) = mimc_feistel(&x, &Scalar::from(0u8), &c[..]);
    let (out, _) = mimc_feistel(&(y + sa), &sc, &c[..]);
    out
}

pub(crate) fn compute_mimc_constants(level: usize) -> Vec<Scalar>{
    let mut c = vec![Scalar::from(0u32); MIMC_ROUNDS];
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

pub fn mimc_feistel(left: &Scalar, right: &Scalar, c: &[Scalar]) -> (Scalar, Scalar){
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
        let merkle_tree = mt_build(&elements[..]).unwrap();

        for i in 0..64usize{
            let (e, path) = mt_prove(&merkle_tree, i);
            let b = mt_verify(&merkle_tree.root, &e, &path[..]);
            assert_eq!(true,b);

            let b = mt_verify(&merkle_tree.root, &(e+Scalar::from(1u8)), &path[..]);
            assert_eq!(false,b);
        }
    }
}
