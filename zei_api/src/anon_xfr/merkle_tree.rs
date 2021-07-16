
use algebra::bls12_381::{BLSScalar};
use crate::anon_xfr::structs::{MTNode, MTLeafInfo, AnonBlindAssetRecord};
use crypto::basics::hash::rescue::RescueInstance;
use algebra::groups::{Zero, ScalarArithmetic, One, Scalar};
use std::collections::HashMap;
use ruc::Result;

// const HASH_SIZE: i32 = 32;             // assuming we are storing SHA256 hash of abar
// const MAX_KEYS: u64 = u64::MAX;
const TREE_DEPTH: usize = 41;             // ceil(log(u64::MAX, 3))

#[derive(Debug, PartialEq)]
pub enum Path {
    Left,
    Middle,
    Right
}

pub struct MerkleTree {
    root_hash: BLSScalar,
    // consistency_hash: HashValue,

    version_count: u64,
    version: HashMap<u64, BLSScalar>,

    entry_count: u64,

    root: Option<Box<Node>>,
    uncommitted_data: Vec<BLSScalar>,
}

impl MerkleTree {

    pub fn new() -> MerkleTree {
        let mut mt = MerkleTree{
            root_hash: Default::default(),
            version_count: 0,
            version: HashMap::new(),
            entry_count: 0,
            root: Option::from(Box::from(Node{
                left_child: None,
                middle_child: None,
                right_child: None,
                hash: Default::default(),
                data: None,
                is_leaf: false
            })),
            uncommitted_data: vec![]
        };

        mt.root_hash = mt.root.as_mut().unwrap().update_hash();
        mt.version.insert(0, mt.root_hash);

        println!("is hash 3: {}", mt.root_hash == (BLSScalar::one().add(&BLSScalar::one()).add(&BLSScalar::one())));

        return mt;
    }

    pub fn add_abar(&mut self, abar: &AnonBlindAssetRecord) -> Result<u64> {
        let hash = RescueInstance::new();
        let uid = self.entry_count + self.uncommitted_data.len() as u64;

        let pk_hash = hash.rescue_hash(&[
            abar.public_key.0.point_ref().get_x(),
            abar.public_key.0.point_ref().get_x(),
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0];


        let data = hash.rescue_hash(&[
            BLSScalar::from_u64(uid),
            abar.amount_type_commitment,
            pk_hash,
            BLSScalar::zero()
        ])[0];

        self.add_new_leaf(data)
    }

    fn add_new_leaf(&mut self, data: BLSScalar) -> Result<u64> {

        // TODO: wrap in Mutex
        let new_id: u64 = self.entry_count + self.uncommitted_data.len() as u64;

        self.uncommitted_data.push(data);

        Ok(new_id)

    }

    pub fn get_mt_leaf_info(&self, id: u64) -> Result<MTLeafInfo> {

        let mut info = MTLeafInfo::default();

        info.uid = id;
        info.root = self.root_hash;
        info.root_version = self.version_count;

        let mut current = &self.root;
        let path = MerkleTree::get_path_from_uid(id);
        let mut depth = 0;
        while !current.as_ref().unwrap().is_leaf {
            let mut node = MTNode{
                siblings1: Default::default(),
                siblings2: Default::default(),
                is_left_child: 0,
                is_right_child: 0
            };

            let current_node = current.as_ref().unwrap();

            let next = {
                match path[depth] {
                    Path::Left => {
                        node.is_left_child = 1;
                        node.siblings1 = current_node._get_middle_child_hash();
                        node.siblings2 = current_node._get_right_child_hash();
                        &current_node.left_child
                    },
                    Path::Middle => {
                        node.siblings1 = current_node._get_left_child_hash();
                        node.siblings2 = current_node._get_right_child_hash();
                        &current_node.middle_child
                    },
                    Path::Right => {
                        node.is_right_child = 1;
                        node.siblings1 = current_node._get_left_child_hash();
                        node.siblings2 = current_node._get_middle_child_hash();
                        &current_node.right_child
                    }
                }
            };

            if let Some(_) = next {
                info.path.nodes.push(node);
                depth += 1;
                current = &next;
            } else {
                return Err(eg!("uid not found in tree"))
            }
        }

        info.path.nodes.reverse();

        Ok(info)
    }

    pub fn commit(&mut self) -> Result<u64> {
        if self.uncommitted_data.is_empty() {
            return Ok(self.version_count)
        }

        let mut root_hash = BLSScalar::default();
        let root = self.root.as_mut().unwrap();

        for data in self.uncommitted_data.iter() {
            let new_id = self.entry_count;
            let path = MerkleTree::get_path_from_uid(new_id);
            root_hash = root.add_child(new_id, *data, path, 0)?;
            self.entry_count += 1;

        };
        self.uncommitted_data.clear();
        self.root_hash = root_hash;

        self.version_count += 1;
        self.version.insert(self.version_count, self.root_hash);

        Ok(self.version_count)
    }

    pub fn discard(&mut self) {
        self.uncommitted_data.clear();
    }

    pub fn get_committed_count(&self) -> u64 {
        self.entry_count
    }

    pub fn get_uncommitted_count(&self) -> u64 {
        self.uncommitted_data.len() as u64
    }

    pub fn get_path_from_uid(mut uid: u64) -> Vec<Path> {

        let mut path: Vec<Path> = Vec::new();
        let mut count = 0;
        while count < TREE_DEPTH {
            let rem =  uid % 3;
            uid = uid / 3;

            match rem {
                0 => path.push(Path::Left),
                1 => path.push(Path::Middle),
                2 => path.push(Path::Right),
                _ => {}
            }
            count += 1;
        }
        path.reverse();
        path
    }
}

#[derive(Debug)]
pub struct Node {
    left_child: Option<Box<Node>>,
    middle_child: Option<Box<Node>>,
    right_child: Option<Box<Node>>,
    hash: BLSScalar,

    data: Option<BLSScalar>,
    is_leaf: bool,
}

impl Node {

    pub fn default() -> Node {
        return Node{
            left_child: None,
            middle_child: None,
            right_child: None,
            hash: BLSScalar::zero(),
            data: None,
            is_leaf: false
        }
    }

    pub fn add_child(&mut self, id: u64, data: BLSScalar, path: Vec<Path>, depth: usize) -> Result<BLSScalar>{

        let hasher = RescueInstance::new();

        if depth == TREE_DEPTH {
            if self.data.is_some() {
                return Err(eg!("wrong uid"));
            }
            self.is_leaf = true;
            self.data = Option::from(data);
            self.hash = data;
            return Ok(self.hash);
        }



        match path[depth] {
            Path::Left => {
                if self.left_child.is_none() {
                    self.left_child = Option::from(Box::from(Node {
                        left_child: None,
                        middle_child: None,
                        right_child: None,
                        hash: Default::default(),
                        data: None,
                        is_leaf: false
                    }));
                }
                let left_hash = self.left_child.as_mut().unwrap().add_child(id /3, data, path, depth+1)?;

                self.hash = hasher.rescue_hash(
                    &[left_hash,
                        self.middle_child.as_ref().unwrap_or(&Box::from(Node::default())).hash,
                        self.right_child.as_ref().unwrap_or(&Box::from(Node::default())).hash,
                        BLSScalar::zero()
                ])[0];
                return Ok(self.hash);
            },
            Path::Middle => {
                if self.middle_child.is_none() {
                    self.middle_child = Option::from(Box::from(Node {
                        left_child: None,
                        middle_child: None,
                        right_child: None,
                        hash: Default::default(),
                        data: None,
                        is_leaf: false
                    }));
                }
                let middle_hash = self.middle_child.as_mut().unwrap().add_child(id /3, data, path, depth+1)?;
                self.hash = hasher.rescue_hash(
                    &[self.left_child.as_ref().unwrap_or(&Box::from(Node::default())).hash,
                        middle_hash,
                        self.right_child.as_ref().unwrap_or(&Box::from(Node::default())).hash,
                        BLSScalar::zero()
                    ])[0];
                return Ok(self.hash);
            },
            Path::Right => {
                if self.right_child.is_none() {
                    self.right_child = Option::from(Box::from(Node {
                        left_child: None,
                        middle_child: None,
                        right_child: None,
                        hash: Default::default(),
                        data: None,
                        is_leaf: false
                    }));
                }
                let right_hash = self.right_child.as_mut().unwrap().add_child(id /3, data, path, depth+1)?;
                self.hash = hasher.rescue_hash(
                    &[self.left_child.as_ref().unwrap_or(&Box::from(Node::default())).hash,
                        self.middle_child.as_ref().unwrap_or(&Box::from(Node::default())).hash,
                        right_hash,
                        BLSScalar::zero()
                    ])[0];
                return Ok(self.hash);
            }
        }
    }

    #[inline(always)]
    pub fn update_hash(&mut self) -> BLSScalar{
        let hash = RescueInstance::new();

        println!( "is Left hash zero = {}", self._get_left_child_hash().is_zero());
        println!( "is middle hash zero = {}", self._get_middle_child_hash().is_zero());
        println!( "is right hash zero = {}", self._get_right_child_hash().is_zero());

        self.hash = hash.rescue_hash( &[
            self._get_left_child_hash(),
            self._get_middle_child_hash(),
            self._get_right_child_hash(),
            BLSScalar::zero(),
        ])[0];

        return self.hash
    }

    fn _get_left_child_hash(&self) -> BLSScalar {
        self.left_child.as_ref().unwrap_or(&Box::from(Node::default())).hash
    }
    fn _get_middle_child_hash(&self) -> BLSScalar {
        self.middle_child.as_ref().unwrap_or(&Box::from(Node::default())).hash
    }
    fn _get_right_child_hash(&self) -> BLSScalar {
        self.right_child.as_ref().unwrap_or(&Box::from(Node::default())).hash
    }
}


#[test]
pub fn test_tree() {
    let hash = RescueInstance::new();

    let mut mt = MerkleTree::new();
    assert_eq!(mt.root_hash, hash.rescue_hash(&[BLSScalar::zero(), BLSScalar::zero(), BLSScalar::zero(), BLSScalar::zero()])[0]);

    let uid = mt.add_new_leaf(BLSScalar::one()).unwrap();
    assert_eq!(uid, 0u64);
    assert_eq!(mt.get_committed_count(), 0);

    let first_hash = mt.root_hash.get_scalar();

    let uid2 = mt.add_new_leaf(BLSScalar::zero()).unwrap();
    assert_eq!(uid2, 1u64);
    assert_eq!(first_hash, mt.root_hash.get_scalar());
    assert_eq!(mt.get_committed_count(), 0);

    assert_eq!(mt.commit().unwrap(), 1);
    assert_ne!(mt.root_hash.get_scalar(), first_hash);
    assert_eq!(mt.get_committed_count(), 2);
    assert_eq!(mt.get_uncommitted_count(), 0);
    let first_commit_hash = mt.root_hash;

    let uid3 = mt.add_new_leaf(BLSScalar::one().add(&BLSScalar::one())).unwrap();
    assert_eq!(uid3, 2u64);
    assert_eq!(first_commit_hash, mt.root_hash);
    assert_eq!(mt.get_committed_count(), 2);

    let leaf_info = mt.get_mt_leaf_info(0).unwrap();
    assert_eq!(leaf_info.root, first_commit_hash);
    assert_eq!(leaf_info.root_version, 1);
    assert_eq!(leaf_info.uid, 0);
    assert_eq!(leaf_info.path.nodes.first().unwrap().is_left_child, 1u8);
    assert_eq!(leaf_info.path.nodes.first().unwrap().is_right_child, 0u8);
    assert_eq!(leaf_info.path.nodes.last().unwrap().is_left_child, 1u8);
    assert_eq!(leaf_info.path.nodes.last().unwrap().is_right_child, 0u8);

    let leaf_info = mt.get_mt_leaf_info(1).unwrap();
    assert_eq!(leaf_info.root, first_commit_hash);
    assert_eq!(leaf_info.root_version, 1);
    assert_eq!(leaf_info.uid, 1);
    assert_eq!(leaf_info.path.nodes.first().unwrap().is_left_child, 0u8);
    assert_eq!(leaf_info.path.nodes.first().unwrap().is_right_child, 0u8);
    assert_eq!(leaf_info.path.nodes.last().unwrap().is_left_child, 1u8);
    assert_eq!(leaf_info.path.nodes.last().unwrap().is_right_child, 0u8);

    assert!(mt.get_mt_leaf_info(2).is_err());

    assert_eq!(mt.commit().unwrap(), 2);
    let leaf_info = mt.get_mt_leaf_info(2).unwrap();
    assert_eq!(leaf_info.root, mt.root_hash);
    assert_eq!(leaf_info.root_version, 2);
    assert_eq!(leaf_info.uid, 2);
    assert_eq!(leaf_info.path.nodes.first().unwrap().is_left_child, 0u8);
    assert_eq!(leaf_info.path.nodes.first().unwrap().is_right_child, 1u8);
    assert_eq!(leaf_info.path.nodes.last().unwrap().is_left_child, 1u8);
    assert_eq!(leaf_info.path.nodes.last().unwrap().is_right_child, 0u8);
}

#[test]
fn test_get_path() {
    let zero_path = MerkleTree::get_path_from_uid(0);
    assert_eq!(zero_path[0], Path::Left);
    assert_eq!(zero_path[1], Path::Left);
    assert_eq!(zero_path[2], Path::Left);
    assert_eq!(zero_path[40], Path::Left);

    let one_path = MerkleTree::get_path_from_uid(1);
    assert_eq!(one_path, vec![Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Middle]);

    let two_path = MerkleTree::get_path_from_uid(2);
    assert_eq!(two_path, vec![Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Right]);

    let three_path = MerkleTree::get_path_from_uid(3);
    assert_eq!(three_path, vec![Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                              Path::Left, Path::Left, Path::Left, Path::Left, Path::Middle,
                              Path::Left]);

    let four_path = MerkleTree::get_path_from_uid(4);
    assert_eq!(four_path, vec![Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                                Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                                Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                                Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                                Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                                Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                                Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                                Path::Left, Path::Left, Path::Left, Path::Left, Path::Middle,
                                Path::Middle]);

    let five_path = MerkleTree::get_path_from_uid(5);
    assert_eq!(five_path, vec![Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                               Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                               Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                               Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                               Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                               Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                               Path::Left, Path::Left, Path::Left, Path::Left, Path::Left,
                               Path::Left, Path::Left, Path::Left, Path::Left, Path::Middle,
                               Path::Right]);
}