use crate::anon_xfr::keys::AXfrPubKey;
use crate::anon_xfr::structs::{AnonBlindAssetRecord, MTLeafInfo, MTNode, MTPath};
use algebra::bls12_381::BLSScalar;
use algebra::groups::{Scalar, Zero};
use crypto::basics::hash::rescue::RescueInstance;
use itertools::Itertools;
use ruc::{Result, RucResult};
use std::borrow::Borrow;
use std::collections::hash_map::Iter;
use std::collections::HashMap;
use storage::db::MerkleDB;
use storage::store::{ImmutablePrefixedStore, PrefixedStore, Stated, Store};
use utils::serialization::ZeiFromToBytes;

// const HASH_SIZE: i32 = 32;             // assuming we are storing SHA256 hash of abar
// const MAX_KEYS: u64 = u64::MAX;
const TREE_DEPTH: usize = 41; // ceil(log(u64::MAX, 3))
const BASE_KEY: &str = "abar:root:";
const ENTRY_COUNT_KEY: &str = "abar:entrycount:";

#[derive(Debug, PartialEq, Clone)]
pub enum Path {
    Left,
    Middle,
    Right,
}

///
/// PersistentMerkleTree is a 3-ary merkle tree
///
/// Usage:
///    ```
///
///     use std::collections::HashMap;
///     use std::thread;
///     use storage::db::TempRocksDB;
///     use std::sync::Arc;
///     use parking_lot::RwLock;
///     use storage::state::{ChainState, State};
///     use storage::store::PrefixedStore;
///     use zei::anon_xfr::merkle_tree::PersistentMerkleTree;
///     use algebra::bls12_381::BLSScalar;
///     use algebra::groups::Zero;
///     use zei::anon_xfr::structs::{AnonBlindAssetRecord, OpenAnonBlindAssetRecord};
///     use crypto::basics::hash::rescue::RescueInstance;
///
///
///     let hash = RescueInstance::new();
///
///         let path = thread::current().name().unwrap().to_owned();
///         let fdb = TempRocksDB::open(path).expect("failed to open db");
///         let cs = Arc::new(RwLock::new(ChainState::new(
///             fdb,
///             "test_db".to_string(),
///             0,
///         )));
///         let mut state = State::new(cs);
///         let mut store = PrefixedStore::new("my_store", &mut state);
///         let mut mt = PersistentMerkleTree::new(store).unwrap();
///
///         mt.get_current_root_hash();
///
///         mt.add_abar(&AnonBlindAssetRecord::from_oabar(&OpenAnonBlindAssetRecord::default()));
///            mt.commit();
///         mt.generate_proof(0);
///
///
/// ```
///
///
///
///
///
///

pub struct PersistentMerkleTree<'a, D: MerkleDB> {
    entry_count: u64,
    version: u64,
    store: PrefixedStore<'a, D>,
}

impl<'a, D: MerkleDB> PersistentMerkleTree<'a, D> {
    // Generates a new PersistentMerkleTree based on a sessioned KV store
    pub fn new(mut store: PrefixedStore<'a, D>) -> Result<PersistentMerkleTree<'a, D>> {
        let mut entry_count = 0;
        let mut version = 0;
        match store.get(BASE_KEY.as_bytes()).unwrap() {
            None => {
                let hash = RescueInstance::new();
                let zero_hash: BLSScalar = hash.rescue_hash(&[
                    BLSScalar::zero(),
                    BLSScalar::zero(),
                    BLSScalar::zero(),
                    BLSScalar::zero(),
                ])[0];
                store
                    .set(BASE_KEY.as_bytes(), zero_hash.zei_to_bytes())
                    .unwrap();
                store
                    .set(ENTRY_COUNT_KEY.as_bytes(), 0u64.to_be_bytes().to_vec())
                    .unwrap();
                store.state_mut().commit(0).c(d!())?;
            }
            Some(_) => {
                // TODO: In the case that a pre-existing tree is loaded, calculate the entry-count.
                let ecb = store.get(ENTRY_COUNT_KEY.as_bytes()).unwrap();
                match ecb {
                    Some(bytes) => {
                        let array: [u8; 8] = [
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                            bytes[6], bytes[7],
                        ];
                        entry_count = u64::from_be_bytes(array);
                        version = store.height().c(d!())?;
                    }
                    None => return Err(eg!("entry count key not found in Store")),
                };
            }
        };
        Ok(PersistentMerkleTree {
            entry_count,
            version,
            store,
        })
    }

    pub fn add_abar(&mut self, abar: &AnonBlindAssetRecord) -> Result<u64> {
        let mut cache = Cache::new();
        // 1. generate keys of ancestors for update in tree
        let path = get_path_from_uid(self.entry_count);
        let keys = generate_path_keys(path);

        let (leaf, ancestors) = keys.as_slice().split_last().unwrap();

        // 2. Hash ABAR and save leaf node
        let uid = self.entry_count;
        let hash = Self::hash_abar(uid, abar);

        cache.set(leaf, hash.zei_to_bytes());

        // 3. update hash of all ancestors of the new leaf
        for node_key in ancestors.iter().rev() {
            let parse_hash = |key: &str| -> Result<BLSScalar> {
                if let Some(b) = cache.get(key) {
                    return BLSScalar::zei_from_bytes(b.as_slice());
                }
                match self.get(key.as_bytes()).unwrap() {
                    Some(b) => BLSScalar::zei_from_bytes(b.as_slice()),
                    None => Ok(BLSScalar::zero()),
                }
            };
            let left_child_hash = parse_hash(format!("{}{}", node_key, "l").as_str())?;
            let middle_child_hash = parse_hash(format!("{}{}", node_key, "m").as_str())?;
            let right_child_hash = parse_hash(format!("{}{}", node_key, "r").as_str())?;

            let hasher = RescueInstance::new();
            let hash = hasher.rescue_hash(&[
                left_child_hash,
                middle_child_hash,
                right_child_hash,
                BLSScalar::zero(),
            ])[0];
            cache.set(node_key, BLSScalar::zei_to_bytes(&hash));
        }

        self.entry_count += 1;
        cache.set(ENTRY_COUNT_KEY, self.entry_count.to_be_bytes().to_vec());

        for (k, v) in cache.iter() {
            self.store.set(k.as_bytes(), v.to_vec())?;
        }
        Ok(uid)
    }

    pub fn generate_proof(&self, id: u64) -> Result<MTLeafInfo> {
        let path = get_path_from_uid(id);
        let keys = generate_path_keys(path);

        let mut previous = keys.first().unwrap();

        let nodes: Vec<MTNode> = keys
            .iter()
            .skip(1)
            .map(|key| {
                // if current node is not present in store then it is not a valid uid to generate
                if !self.store.exists(key.as_bytes()).unwrap() {
                    return Err(eg!("uid not found in tree, cannot generate proof"));
                }

                let direction = key.chars().last();
                let mut node = MTNode {
                    siblings1: Default::default(),
                    siblings2: Default::default(),
                    is_left_child: 0,
                    is_right_child: 0,
                };
                let sib1_key;
                let sib2_key;

                match direction {
                    Some('l') => {
                        sib1_key = format!("{}{}", previous, "m");
                        sib2_key = format!("{}{}", previous, "r");
                        node.is_left_child = 1;
                    }
                    Some('m') => {
                        sib1_key = format!("{}{}", previous, "l");
                        sib2_key = format!("{}{}", previous, "r");
                    }
                    Some('r') => {
                        sib1_key = format!("{}{}", previous, "l");
                        sib2_key = format!("{}{}", previous, "m");
                        node.is_right_child = 1;
                    }
                    _ => return Err(eg!("incorrect key")),
                };
                if let Some(b) = self.store.get(sib1_key.as_bytes()).unwrap() {
                    node.siblings1 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }
                if let Some(b) = self.store.get(sib2_key.as_bytes()).unwrap() {
                    node.siblings2 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }

                previous = key;
                Ok(node)
            })
            .collect::<Result<Vec<MTNode>>>()?;

        Ok(MTLeafInfo {
            path: MTPath { nodes },
            root: self.get_current_root_hash().unwrap(),
            root_version: 1,
            uid: id,
        })
    }

    pub fn get_current_root_hash(&self) -> Result<BLSScalar> {
        match self.store.get(BASE_KEY.as_bytes()).unwrap() {
            Some(hash) => BLSScalar::zei_from_bytes(hash.as_slice()),
            None => Err(eg!("root hash key not found")),
        }
    }

    fn hash_abar(uid: u64, abar: &AnonBlindAssetRecord) -> BLSScalar {
        let hash = RescueInstance::new();

        let pk_hash = hash.rescue_hash(&[
            abar.public_key.0.point_ref().get_x(),
            abar.public_key.0.point_ref().get_y(),
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0];

        hash.rescue_hash(&[
            BLSScalar::from_u64(uid),
            abar.amount_type_commitment,
            pk_hash,
            BLSScalar::zero(),
        ])[0]
    }

    #[allow(dead_code)]
    pub fn commit(&mut self) -> Result<u64> {
        let (_, ver) = self.store.state_mut().commit(self.version + 1).c(d!())?;
        self.version = ver;
        Ok(self.version)
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.store.get(key)
    }
}

#[allow(dead_code)]
pub struct ImmutablePersistentMerkleTree<'a, D: MerkleDB> {
    entry_count: u64,
    version: u64,
    store: ImmutablePrefixedStore<'a, D>,
}

impl<'a, D: MerkleDB> ImmutablePersistentMerkleTree<'a, D> {
    // Generates a new PersistentMerkleTree based on a sessioned KV store
    pub fn new(
        store: ImmutablePrefixedStore<'a, D>,
    ) -> Result<ImmutablePersistentMerkleTree<'a, D>> {
        let mut entry_count = 0;
        let mut version = 0;
        match store.get(BASE_KEY.as_bytes()).unwrap() {
            Some(_) => {
                // TODO: In the case that a pre-existing tree is loaded, calculate the entry-count.
                let ecb = store.get(ENTRY_COUNT_KEY.as_bytes()).unwrap();
                match ecb {
                    Some(bytes) => {
                        let array: [u8; 8] = [
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                            bytes[6], bytes[7],
                        ];
                        entry_count = u64::from_be_bytes(array);
                        version = store.height().c(d!())?;
                    }
                    None => return Err(eg!("entry count key not found in Store")),
                };
            }
            _ => {}
        };
        Ok(ImmutablePersistentMerkleTree {
            entry_count,
            version,
            store,
        })
    }

    pub fn generate_proof(&self, id: u64) -> Result<MTLeafInfo> {
        let path = get_path_from_uid(id);
        let keys = generate_path_keys(path);

        let mut previous = keys.first().unwrap();

        let nodes: Vec<MTNode> = keys
            .iter()
            .skip(1)
            .map(|key| {
                // if current node is not present in store then it is not a valid uid to generate
                if !self.store.exists(key.as_bytes()).unwrap() {
                    return Err(eg!("uid not found in tree, cannot generate proof"));
                }

                let direction = key.chars().last();
                let mut node = MTNode {
                    siblings1: Default::default(),
                    siblings2: Default::default(),
                    is_left_child: 0,
                    is_right_child: 0,
                };
                let sib1_key;
                let sib2_key;
                match direction {
                    Some('l') => {
                        sib1_key = format!("{}{}", previous, "m");
                        sib2_key = format!("{}{}", previous, "r");
                        node.is_left_child = 1;
                    }
                    Some('m') => {
                        sib1_key = format!("{}{}", previous, "l");
                        sib2_key = format!("{}{}", previous, "r");
                    }
                    Some('r') => {
                        sib1_key = format!("{}{}", previous, "l");
                        sib2_key = format!("{}{}", previous, "m");
                        node.is_right_child = 1;
                    }
                    _ => return Err(eg!("incorrect key")),
                };
                if let Some(b) = self.store.get(sib1_key.as_bytes()).unwrap() {
                    node.siblings1 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }
                if let Some(b) = self.store.get(sib2_key.as_bytes()).unwrap() {
                    node.siblings2 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }

                previous = key;
                Ok(node)
            })
            .collect::<Result<Vec<MTNode>>>()?;

        Ok(MTLeafInfo {
            path: MTPath { nodes },
            root: self.get_current_root_hash().unwrap(),
            root_version: 1,
            uid: id,
        })
    }

    pub fn get_current_root_hash(&self) -> Result<BLSScalar> {
        match self.store.get(BASE_KEY.as_bytes()).unwrap() {
            Some(hash) => BLSScalar::zei_from_bytes(hash.as_slice()),
            None => Err(eg!("root hash key not found")),
        }
    }

    #[allow(dead_code)]
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.store.get(key)
    }
}

struct Cache {
    store: HashMap<String, Vec<u8>>,
}

impl Cache {
    fn new() -> Cache {
        Cache {
            store: HashMap::new(),
        }
    }
    fn set(&mut self, key: &str, val: Vec<u8>) {
        self.store.insert(key.to_string(), val);
    }
    fn get(&self, key: &str) -> Option<&Vec<u8>> {
        self.store.get(key)
    }
    fn iter(&self) -> Iter<'_, String, Vec<u8>> {
        self.store.iter()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MerkleTree {
    root_hash: BLSScalar,
    // consistency_hash: HashValue,
    version_count: usize,
    version: HashMap<usize, BLSScalar>,

    entry_count: u64,

    root: Option<Box<Node>>,
    uncommitted_data: Vec<(BLSScalar, AnonBlindAssetRecord)>,

    leaf_lookup: HashMap<u64, AnonBlindAssetRecord>,
}

///
/// MerkleTree is a 3-ary dense tree implmentation for storing any BLSScalar as a log
/// of existence. It is designed to be used for abar hash storage and merkle path
/// proof.
///
/// Usage:
///     ```
///
///     use zei::anon_xfr::structs::{AnonBlindAssetRecord, OpenAnonBlindAssetRecord};
///     use zei::anon_xfr::merkle_tree::MerkleTree;
///     let mut mt = MerkleTree::new();
///
///     let uid0 = mt.add_abar(&AnonBlindAssetRecord::from_oabar(&OpenAnonBlindAssetRecord::default())).unwrap();
///
///     let version = mt.commit();
///
///     let leaf_info = mt.get_mt_leaf_info(uid0).unwrap();
/// ```
///
///
///
impl MerkleTree {
    pub fn new() -> MerkleTree {
        let mut mt = MerkleTree {
            root_hash: Default::default(),
            version_count: 0,
            version: HashMap::new(),
            entry_count: 0,
            root: Option::from(Box::from(Node {
                left_child: None,
                middle_child: None,
                right_child: None,
                hash: Default::default(),
                data: None,
                is_leaf: false,
            })),
            uncommitted_data: vec![],
            leaf_lookup: Default::default(),
        };

        mt.root_hash = mt.root.as_mut().unwrap().update_hash();
        mt.version.insert(0, mt.root_hash);

        mt
    }

    pub fn add_abar(&mut self, abar: &AnonBlindAssetRecord) -> Result<u64> {
        let hash = RescueInstance::new();
        let uid = self.entry_count + self.uncommitted_data.len() as u64;

        let pk_hash = hash.rescue_hash(&[
            abar.public_key.0.point_ref().get_x(),
            abar.public_key.0.point_ref().get_y(),
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0];

        let data = hash.rescue_hash(&[
            BLSScalar::from_u64(uid),
            abar.amount_type_commitment,
            pk_hash,
            BLSScalar::zero(),
        ])[0];

        self.add_new_leaf(data, abar.clone())
    }

    fn add_new_leaf(
        &mut self,
        data: BLSScalar,
        abar: AnonBlindAssetRecord,
    ) -> Result<u64> {
        // TODO: wrap in Mutex
        let new_id: u64 = self.entry_count + self.uncommitted_data.len() as u64;

        self.uncommitted_data.push((data, abar));

        Ok(new_id)
    }

    pub fn get_mt_leaf_info(&self, id: u64) -> Result<MTLeafInfo> {
        let mut info = MTLeafInfo {
            uid: id,
            root: self.root_hash,
            root_version: self.version_count,
            ..Default::default()
        };

        let mut current = &self.root;
        let path = MerkleTree::get_path_from_uid(id);
        let mut depth = 0;
        while !current.as_ref().unwrap().is_leaf {
            let mut node = MTNode {
                siblings1: Default::default(),
                siblings2: Default::default(),
                is_left_child: 0,
                is_right_child: 0,
            };

            let current_node = current.as_ref().unwrap();

            let next = {
                match path[depth] {
                    Path::Left => {
                        node.is_left_child = 1;
                        node.siblings1 = current_node._get_middle_child_hash();
                        node.siblings2 = current_node._get_right_child_hash();
                        &current_node.left_child
                    }
                    Path::Middle => {
                        node.siblings1 = current_node._get_left_child_hash();
                        node.siblings2 = current_node._get_right_child_hash();
                        &current_node.middle_child
                    }
                    Path::Right => {
                        node.is_right_child = 1;
                        node.siblings1 = current_node._get_left_child_hash();
                        node.siblings2 = current_node._get_middle_child_hash();
                        &current_node.right_child
                    }
                }
            };

            if next.is_some() {
                info.path.nodes.push(node);
                depth += 1;
                current = &next;
            } else {
                return Err(eg!("uid not found in tree"));
            }
        }

        Ok(info)
    }

    pub fn commit(&mut self) -> Result<usize> {
        if self.uncommitted_data.is_empty() {
            return Ok(self.version_count);
        }

        let mut root_hash = BLSScalar::default();
        let root = self.root.as_mut().unwrap();

        for data in self.uncommitted_data.iter() {
            let new_id = self.entry_count;
            let path = MerkleTree::get_path_from_uid(new_id);

            root_hash = root.add_child(data.0, path, 0)?;
            self.leaf_lookup.insert(new_id, data.1.clone());
            self.entry_count += 1;
        }
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
            let rem = uid % 3;
            uid /= 3;

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

    pub fn get_owned_abars_uids(&self, pub_key: AXfrPubKey) -> Vec<u64> {
        self.leaf_lookup
            .iter()
            .filter_map(|(id, abar)| {
                if abar.public_key == pub_key {
                    return Option::from(*id);
                }
                None
            })
            .collect_vec()
    }

    pub fn get_owned_abars(&self, pub_key: AXfrPubKey) -> Vec<AnonBlindAssetRecord> {
        self.leaf_lookup
            .iter()
            .filter_map(|(_id, abar)| {
                if abar.public_key == pub_key {
                    return Option::from(abar.clone());
                }
                None
            })
            .collect_vec()
    }

    pub fn get_latest_hash(&self) -> BLSScalar {
        self.root_hash
    }

    pub fn get_version_hash(&self, version: usize) -> Result<BLSScalar> {
        match self.version.get(&version) {
            None => Err(eg!("version not found in merkle tree")),
            Some(h) => Ok(*h),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
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
        Node {
            left_child: None,
            middle_child: None,
            right_child: None,
            hash: BLSScalar::zero(),
            data: None,
            is_leaf: false,
        }
    }

    pub fn add_child(
        &mut self,
        data: BLSScalar,
        path: Vec<Path>,
        depth: usize,
    ) -> Result<BLSScalar> {
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
                        is_leaf: false,
                    }));
                }
                let left_hash = self.left_child.as_mut().unwrap().add_child(
                    data,
                    path,
                    depth + 1,
                )?;

                self.hash = hasher.rescue_hash(&[
                    left_hash,
                    self.middle_child
                        .as_ref()
                        .unwrap_or(&Box::from(Node::default()))
                        .hash,
                    self.right_child
                        .as_ref()
                        .unwrap_or(&Box::from(Node::default()))
                        .hash,
                    BLSScalar::zero(),
                ])[0];

                Ok(self.hash)
            }
            Path::Middle => {
                if self.middle_child.is_none() {
                    self.middle_child = Option::from(Box::from(Node {
                        left_child: None,
                        middle_child: None,
                        right_child: None,
                        hash: Default::default(),
                        data: None,
                        is_leaf: false,
                    }));
                }
                let middle_hash = self.middle_child.as_mut().unwrap().add_child(
                    data,
                    path,
                    depth + 1,
                )?;
                self.hash = hasher.rescue_hash(&[
                    self.left_child
                        .as_ref()
                        .unwrap_or(&Box::from(Node::default()))
                        .hash,
                    middle_hash,
                    self.right_child
                        .as_ref()
                        .unwrap_or(&Box::from(Node::default()))
                        .hash,
                    BLSScalar::zero(),
                ])[0];

                Ok(self.hash)
            }
            Path::Right => {
                if self.right_child.is_none() {
                    self.right_child = Option::from(Box::from(Node {
                        left_child: None,
                        middle_child: None,
                        right_child: None,
                        hash: Default::default(),
                        data: None,
                        is_leaf: false,
                    }));
                }
                let right_hash = self.right_child.as_mut().unwrap().add_child(
                    data,
                    path,
                    depth + 1,
                )?;
                self.hash = hasher.rescue_hash(&[
                    self.left_child
                        .as_ref()
                        .unwrap_or(&Box::from(Node::default()))
                        .hash,
                    self.middle_child
                        .as_ref()
                        .unwrap_or(&Box::from(Node::default()))
                        .hash,
                    right_hash,
                    BLSScalar::zero(),
                ])[0];

                Ok(self.hash)
            }
        }
    }

    #[inline(always)]
    pub fn update_hash(&mut self) -> BLSScalar {
        let hash = RescueInstance::new();

        self.hash = hash.rescue_hash(&[
            self._get_left_child_hash(),
            self._get_middle_child_hash(),
            self._get_right_child_hash(),
            BLSScalar::zero(),
        ])[0];

        self.hash
    }

    fn _get_left_child_hash(&self) -> BLSScalar {
        self.left_child
            .as_ref()
            .unwrap_or(&Box::from(Node::default()))
            .hash
    }
    fn _get_middle_child_hash(&self) -> BLSScalar {
        self.middle_child
            .as_ref()
            .unwrap_or(&Box::from(Node::default()))
            .hash
    }
    fn _get_right_child_hash(&self) -> BLSScalar {
        self.right_child
            .as_ref()
            .unwrap_or(&Box::from(Node::default()))
            .hash
    }
}

fn generate_path_keys(path_stream: Vec<Path>) -> Vec<String> {
    let mut key = BASE_KEY.to_owned();
    let mut keys: Vec<String> = path_stream
        .into_iter()
        .map(|path| {
            key.push_str(get_path_str(path).borrow());
            key.clone()
        })
        .collect();

    keys.insert(0, BASE_KEY.to_owned());
    keys
}

fn get_path_str(p: Path) -> String {
    match p {
        Path::Left => "l".to_string(),
        Path::Middle => "m".to_string(),
        Path::Right => "r".to_string(),
    }
}

pub fn get_path_from_uid(mut uid: u64) -> Vec<Path> {
    let mut path: Vec<Path> = Vec::new();
    let mut count = 0;
    while count < TREE_DEPTH {
        let rem = uid % 3;
        uid /= 3;

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

#[cfg(test)]
mod tests {
    use crate::anon_xfr::circuits::{
        add_merkle_path_variables, compute_merkle_root, AccElemVars,
    };
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::anon_xfr::merkle_tree::{generate_path_keys, MerkleTree, Path, PersistentMerkleTree, BASE_KEY, ImmutablePersistentMerkleTree};
    use crate::anon_xfr::structs::{AnonBlindAssetRecord, OpenAnonBlindAssetRecord};
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{One, Scalar, ScalarArithmetic, Zero};
    use crypto::basics::hash::rescue::RescueInstance;
    use parking_lot::RwLock;
    use poly_iops::plonk::turbo_plonk_cs::ecc::Point;
    use poly_iops::plonk::turbo_plonk_cs::TurboPlonkConstraintSystem;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ruc::*;
    use std::sync::Arc;
    use std::thread;
    use storage::db::{RocksDB, TempRocksDB};
    use storage::state::{ChainState, State};
    use storage::store::{ImmutablePrefixedStore, PrefixedStore};

    #[test]
    pub fn test_generate_path_keys() {
        let keys = generate_path_keys(vec![Path::Right, Path::Left, Path::Middle]);
        assert_eq!(
            keys,
            vec!["abar:root:", "abar:root:r", "abar:root:rl", "abar:root:rlm"]
        );
    }

    #[test]
    pub fn test_tree() {
        let hash = RescueInstance::new();

        let mut mt = MerkleTree::new();
        assert_eq!(
            mt.root_hash,
            hash.rescue_hash(&[
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero()
            ])[0]
        );

        let uid = mt
            .add_new_leaf(
                BLSScalar::one(),
                AnonBlindAssetRecord {
                    amount_type_commitment: Default::default(),
                    public_key: Default::default(),
                },
            )
            .unwrap();
        assert_eq!(uid, 0u64);
        assert_eq!(mt.get_committed_count(), 0);

        let first_hash = mt.root_hash.get_scalar();

        let uid2 = mt
            .add_new_leaf(
                BLSScalar::zero(),
                AnonBlindAssetRecord {
                    amount_type_commitment: Default::default(),
                    public_key: Default::default(),
                },
            )
            .unwrap();
        assert_eq!(uid2, 1u64);
        assert_eq!(first_hash, mt.root_hash.get_scalar());
        assert_eq!(mt.get_committed_count(), 0);

        assert_eq!(mt.commit().unwrap(), 1);
        assert_ne!(mt.root_hash.get_scalar(), first_hash);
        assert_eq!(mt.get_committed_count(), 2);
        assert_eq!(mt.get_uncommitted_count(), 0);
        let first_commit_hash = mt.root_hash;

        let uid3 = mt
            .add_new_leaf(
                BLSScalar::one().add(&BLSScalar::one()),
                AnonBlindAssetRecord {
                    amount_type_commitment: Default::default(),
                    public_key: Default::default(),
                },
            )
            .unwrap();
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
        assert_eq!(
            one_path,
            vec![
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Middle
            ]
        );

        let two_path = MerkleTree::get_path_from_uid(2);
        assert_eq!(
            two_path,
            vec![
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Right
            ]
        );

        let three_path = MerkleTree::get_path_from_uid(3);
        assert_eq!(
            three_path,
            vec![
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Middle,
                Path::Left
            ]
        );

        let four_path = MerkleTree::get_path_from_uid(4);
        assert_eq!(
            four_path,
            vec![
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Middle,
                Path::Middle
            ]
        );

        let five_path = MerkleTree::get_path_from_uid(5);
        assert_eq!(
            five_path,
            vec![
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Middle,
                Path::Right
            ]
        );
    }

    #[test]
    fn test_abar_proof() {
        use crate::anon_xfr::circuits::add_merkle_path_variables;
        use crate::anon_xfr::circuits::compute_merkle_root;
        use crate::anon_xfr::circuits::AccElemVars;
        use crate::anon_xfr::keys::AXfrKeyPair;
        use poly_iops::plonk::turbo_plonk_cs::ecc::Point;
        use poly_iops::plonk::turbo_plonk_cs::TurboPlonkConstraintSystem;
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaChaRng;

        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let key_pair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);
        let abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };

        let mut mt = MerkleTree::new();
        let uid = mt.add_abar(&abar).unwrap();

        assert_ne!(mt.leaf_lookup.get(&uid), Option::from(&abar));
        assert_eq!(mt.get_owned_abars_uids(abar.public_key.clone()).len(), 0);
        assert_eq!(mt.get_owned_abars(abar.public_key.clone()).len(), 0);
        let _ver = mt.commit().unwrap();

        assert_eq!(mt.leaf_lookup.get(&uid), Option::from(&abar));
        assert_eq!(mt.get_owned_abars_uids(abar.public_key.clone()), vec![uid]);
        assert_eq!(
            mt.get_owned_abars(abar.public_key.clone()),
            vec![abar.clone()]
        );

        let mut cs = TurboPlonkConstraintSystem::new();
        let uid_var = cs.new_variable(BLSScalar::from_u64(uid));
        let comm_var = cs.new_variable(abar.amount_type_commitment);
        let pk_var = cs.new_point_variable(Point::new(
            abar.public_key.0.point_ref().get_x(),
            abar.public_key.0.point_ref().get_y(),
        ));
        let elem = AccElemVars {
            uid: uid_var,
            commitment: comm_var,
            pub_key_x: pk_var.get_x(),
            pub_key_y: pk_var.get_y(),
        };

        let leaf_info = mt.get_mt_leaf_info(uid).unwrap();
        let path_vars = add_merkle_path_variables(&mut cs, leaf_info.path.clone());
        let root_var = compute_merkle_root(&mut cs, elem, &path_vars);

        // Check Merkle root correctness
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());

        let hash = RescueInstance::new();
        let zero = BLSScalar::zero();
        let pk_hash = hash.rescue_hash(&[
            key_pair.pub_key().as_jubjub_point().get_x(),
            key_pair.pub_key().as_jubjub_point().get_y(),
            zero,
            zero,
        ])[0];
        let mut node = hash.rescue_hash(&[
            BLSScalar::from_u64(uid),
            abar.amount_type_commitment,
            pk_hash,
            zero,
        ])[0];
        let mut depth = 0;
        leaf_info
            .path
            .nodes
            .iter()
            .map(|n| {
                if n.is_left_child == 1u8 {
                    node = hash.rescue_hash(&[node, n.siblings1, n.siblings2, zero])[0];
                } else if n.is_right_child == 1u8 {
                    node = hash.rescue_hash(&[n.siblings1, n.siblings2, node, zero])[0];
                } else {
                    node = hash.rescue_hash(&[n.siblings1, node, n.siblings2, zero])[0];
                }
                depth += 1;
            })
            .last();

        assert_eq!(witness[root_var], node);
        assert_eq!(witness[root_var], mt.version[&leaf_info.root_version]);

        let uid2 = mt.add_abar(&abar).unwrap();
        let _ver = mt.commit().unwrap();
        let mut list = mt.get_owned_abars_uids(abar.public_key.clone());
        list.sort_unstable();
        assert_eq!(list, vec![uid, uid2]);
        assert_eq!(
            mt.get_owned_abars(abar.public_key.clone()),
            vec![abar.clone(), abar]
        );
    }

    #[test]
    fn test_persistent_merkle_tree() {
        let hash = RescueInstance::new();

        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("mystore", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        assert_eq!(
            mt.get_current_root_hash().unwrap(),
            hash.rescue_hash(&[
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero()
            ])[0]
        );

        let abar =
            AnonBlindAssetRecord::from_oabar(&OpenAnonBlindAssetRecord::default());
        assert!(mt.add_abar(&abar).is_ok());

        assert_ne!(
            mt.get_current_root_hash().unwrap(),
            hash.rescue_hash(&[
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero()
            ])[0]
        );

        let mut key = BASE_KEY.to_owned();
        for _t in 1..42 {
            key.push('l');
            let res = mt.get(key.as_bytes());
            assert!(res.is_ok());
            assert!(res.unwrap().is_some());
            // println!("{}       {} {:#?}", t, key, res.unwrap().unwrap());
        }

        assert!(mt.add_abar(&abar).is_ok());
        let key2 = "abar:root:llllllllllllllllllllllllllllllllllllllllm";
        let mut res = mt.get(key2.as_bytes());
        assert!(res.is_ok());
        assert!(res.unwrap().is_some());

        let key3 = "abar:root:llllllllllllllllllllllllllllllllllllllllr";
        res = mt.get(key3.as_bytes());
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());

        assert!(mt.add_abar(&abar).is_ok());
        res = mt.get(key3.as_bytes());
        assert!(res.is_ok());
        assert!(res.unwrap().is_some());

        assert!(mt.generate_proof(0).is_ok());
        assert!(mt.generate_proof(1).is_ok());
        assert!(mt.generate_proof(2).is_ok());

        assert!(mt.generate_proof(3).is_err());
        assert!(mt.generate_proof(4).is_err());
        assert!(mt.generate_proof(11234).is_err());
    }

    #[test]
    fn test_persistant_merkle_tree_proof_commitment() {
        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("mystore", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let key_pair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);
        let abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        assert!(mt.add_abar(&abar).is_ok());

        let proof = mt.generate_proof(0).unwrap();

        let mut cs = TurboPlonkConstraintSystem::new();
        let uid_var = cs.new_variable(BLSScalar::from_u64(0));
        let comm_var = cs.new_variable(abar.amount_type_commitment);
        let pk_var = cs.new_point_variable(Point::new(
            abar.public_key.0.point_ref().get_x(),
            abar.public_key.0.point_ref().get_y(),
        ));
        let elem = AccElemVars {
            uid: uid_var,
            commitment: comm_var,
            pub_key_x: pk_var.get_x(),
            pub_key_y: pk_var.get_y(),
        };

        let path_vars = add_merkle_path_variables(&mut cs, proof.path);
        let root_var = compute_merkle_root(&mut cs, elem, &path_vars);

        // Check Merkle root correctness
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        assert_eq!(witness[root_var], mt.get_current_root_hash().unwrap());

        let _ = mt.commit();
    }

    #[test]
    fn test_persistent_merkle_tree_recovery() {
        let path = thread::current().name().unwrap().to_owned();
        let _ = build_and_save_dummy_tree(path.clone()).unwrap();

        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("mystore", &mut state);
        let mt = PersistentMerkleTree::new(store).unwrap();

        assert_eq!(mt.version, 4);
        assert_eq!(mt.entry_count, 4);
    }

    #[test]
    fn test_init_tree() {
        let path = thread::current().name().unwrap().to_owned();

        let fdb = TempRocksDB::open(path).expect("failed to open db");

        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);

        build_tree(&mut state);
        build_tree(&mut state);
    }

    #[allow(dead_code)]
    fn build_tree(state: &mut State<TempRocksDB>) {
        let store = PrefixedStore::new("mystore", state);
        let _mt = PersistentMerkleTree::new(store).unwrap();
    }

    #[allow(dead_code)]
    fn build_and_save_dummy_tree(path: String) -> Result<()> {
        let fdb = RocksDB::open(path).expect("failed to open db");

        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("mystore", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let mut key_pair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);
        let mut abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        assert!(mt.add_abar(&abar).is_ok());
        mt.commit()?;

        key_pair = AXfrKeyPair::generate(&mut prng);
        abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        assert!(mt.add_abar(&abar).is_ok());
        mt.commit()?;

        key_pair = AXfrKeyPair::generate(&mut prng);
        abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        assert!(mt.add_abar(&abar).is_ok());
        mt.commit()?;

        key_pair = AXfrKeyPair::generate(&mut prng);
        abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        assert!(mt.add_abar(&abar).is_ok());
        mt.commit()?;

        Ok(())
    }

    #[test]
    pub fn test_merkle_proofs() {
        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);

        let store = PrefixedStore::new("mystore", &mut state);
        let mut pmt = PersistentMerkleTree::new(store).unwrap();


        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let key_pair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);
        let abar0 = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        let abar1 = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        let abar2 = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };

        pmt.add_abar(&abar0).unwrap();
        pmt.add_abar(&abar1).unwrap();
        pmt.add_abar(&abar2).unwrap();
        pmt.add_abar(&abar0).unwrap();
        pmt.add_abar(&abar1).unwrap();
        pmt.add_abar(&abar2).unwrap();
        pmt.add_abar(&abar0).unwrap();
        pmt.add_abar(&abar1).unwrap();
        pmt.add_abar(&abar2).unwrap();
        pmt.add_abar(&abar0).unwrap();
        pmt.add_abar(&abar1).unwrap();
        pmt.add_abar(&abar2).unwrap();
        pmt.add_abar(&abar0).unwrap();
        pmt.add_abar(&abar1).unwrap();
        pmt.add_abar(&abar2).unwrap();
        pmt.commit().unwrap();

        let mut mt = MerkleTree::new();
        let _ = mt.add_abar(&abar0).unwrap();
        let _ = mt.add_abar(&abar1).unwrap();
        let _ = mt.add_abar(&abar2).unwrap();
        let _ = mt.add_abar(&abar0).unwrap();
        let _ = mt.add_abar(&abar1).unwrap();
        let _ = mt.add_abar(&abar2).unwrap();
        let _ = mt.add_abar(&abar0).unwrap();
        let _ = mt.add_abar(&abar1).unwrap();
        let _ = mt.add_abar(&abar2).unwrap();
        let _ = mt.add_abar(&abar0).unwrap();
        let _ = mt.add_abar(&abar1).unwrap();
        let _ = mt.add_abar(&abar2).unwrap();
        let _ = mt.add_abar(&abar0).unwrap();
        let _ = mt.add_abar(&abar1).unwrap();
        let _ = mt.add_abar(&abar2).unwrap();
        mt.commit().unwrap();

        for i in 0..14 {
            assert_eq!(
                pmt.generate_proof(i).unwrap(),
                mt.get_mt_leaf_info(i).unwrap()
            );
        }


        let immutable_store = ImmutablePrefixedStore::new("my_store", &state);
        let ipmt = ImmutablePersistentMerkleTree::new(immutable_store).unwrap();

        for i in 0..14 {
            assert_eq!(
                ipmt.generate_proof(i).unwrap(),
                mt.get_mt_leaf_info(i).unwrap()
            );
        }
    }
}
