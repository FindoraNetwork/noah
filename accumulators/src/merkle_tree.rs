use algebra::bls12_381::BLSScalar;
use algebra::groups::Zero;
use crypto::basics::hash::rescue::RescueInstance;
use ruc::*;
use std::collections::hash_map::Iter;
use std::collections::HashMap;
use storage::db::MerkleDB;
use storage::store::{ImmutablePrefixedStore, PrefixedStore, Stated, Store};
use utils::serialization::ZeiFromToBytes;

// ceil(log(u64::MAX, 3)) = 41
// 3^0 + 3^1 + 3^2 + ... 3^40 < 2^64 (u64 can include all leaf & ancestor)
// store max is 3^40 = 12157665459056928801
// sid   max is 2^64 = 18446744073709551616
pub const TREE_DEPTH: usize = 40;
// 6078832729528464400 = 3^0 + 3^1 + 3^2 + ... 3^39, if change TREE_DEPTH, MUST update.
const LEAF_START: u64 = 6078832729528464400;

const KEY_PAD: [u8; 4] = [0, 0, 0, 0];
const ROOT_KEY: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // KEY_PAD + 0u64
const ENTRY_COUNT_KEY: [u8; 4] = [0, 0, 0, 1];

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
///    ```ignore
///     use std::collections::HashMap;
///     use std::thread;
///     use storage::db::TempRocksDB;
///     use std::sync::Arc;
///     use parking_lot::RwLock;
///     use storage::state::{ChainState, State};
///     use storage::store::PrefixedStore;
///     use accumulators::merkle_tree::PersistentMerkleTree;
///     use algebra::bls12_381::BLSScalar;
///     use algebra::groups::Zero;
///     use crypto::basics::hash::rescue::RescueInstance;
///
///     let hash = RescueInstance::new();
///
///     let path = thread::current().name().unwrap().to_owned();
///     let fdb = TempRocksDB::open(path).expect("failed to open db");
///     let cs = Arc::new(RwLock::new(ChainState::new(
///         fdb,
///         "test_db".to_string(),
///         0,
///     )));
///     let mut state = State::new(cs, false);
///     let mut store = PrefixedStore::new("my_store", &mut state);
///     let mut mt = PersistentMerkleTree::new(store).unwrap();
///
///     mt.get_current_root_hash();
///
///     mt.add_commitment_hash(BLSScalar::default());
///     mt.commit();
///     mt.generate_proof(0);
///
/// ```

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

        if let Some(bytes) = store.get(&ENTRY_COUNT_KEY)? {
            let array: [u8; 8] = [
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                bytes[7],
            ];
            entry_count = u64::from_be_bytes(array);
            version = store.height().c(d!())?;
        } else {
            store.set(&ROOT_KEY, BLSScalar::zero().zei_to_bytes())?;
            store.set(&ENTRY_COUNT_KEY, 0u64.to_be_bytes().to_vec())?;
            store.state_mut().commit(0).c(d!())?;
        }

        Ok(PersistentMerkleTree {
            entry_count,
            version,
            store,
        })
    }

    pub fn add_commitment_hash(&mut self, hash: BLSScalar) -> Result<u64> {
        let mut cache = Cache::new();
        // 1. generate keys of ancestors for update in tree
        let keys = get_path_keys(self.entry_count);
        let leaf = keys.first().unwrap();

        // 2. Hash ABAR and save leaf node
        let uid = self.entry_count;
        cache.set(leaf.0, hash.zei_to_bytes());

        // 3. update hash of all ancestors of the new leaf
        for (index, (node_key, path)) in keys[0..TREE_DEPTH].iter().enumerate() {
            let parse_hash = |key: u64| -> Result<BLSScalar> {
                if let Some(b) = cache.get(&key) {
                    return BLSScalar::zei_from_bytes(b.as_slice());
                }
                let mut store_key = KEY_PAD.to_vec();
                store_key.extend(key.to_be_bytes());
                match self.get(&store_key)? {
                    Some(b) => BLSScalar::zei_from_bytes(b.as_slice()),
                    None => Ok(BLSScalar::zero()),
                }
            };

            let (sib0, sib1, sib2) = match path {
                Path::Left => (
                    parse_hash(*node_key)?,
                    parse_hash(node_key + 1)?,
                    parse_hash(node_key + 2)?,
                ),
                Path::Middle => (
                    parse_hash(node_key - 1)?,
                    parse_hash(*node_key)?,
                    parse_hash(node_key + 1)?,
                ),
                Path::Right => (
                    parse_hash(node_key - 2)?,
                    parse_hash(node_key - 1)?,
                    parse_hash(*node_key)?,
                ),
            };

            let hasher = RescueInstance::new();
            let hash = hasher.rescue_hash(&[sib0, sib1, sib2, BLSScalar::zero()])[0];
            cache.set(keys[index + 1].0, BLSScalar::zei_to_bytes(&hash));
        }

        for (k, v) in cache.iter() {
            let mut store_key = KEY_PAD.to_vec();
            store_key.extend(k.to_be_bytes());
            self.store.set(&store_key, v.to_vec())?;
        }

        self.entry_count += 1;
        self.store
            .set(&ENTRY_COUNT_KEY, self.entry_count.to_be_bytes().to_vec())?;
        Ok(uid)
    }

    pub fn generate_proof(&self, id: u64) -> Result<Proof> {
        let keys = get_path_keys(id);

        let nodes: Vec<ProofNode> = keys[0..TREE_DEPTH]
            .iter()
            .rev()
            .map(|(key, path)| {
                // if current node is not present in store then it is not a valid uid to generate
                let mut store_key = KEY_PAD.to_vec();
                store_key.extend(key.to_be_bytes());
                if !self.store.exists(&store_key)? {
                    return Err(eg!("uid not found in tree, cannot generate proof"));
                }

                let mut node = ProofNode {
                    siblings1: Default::default(),
                    siblings2: Default::default(),
                    is_left_child: 0,
                    is_right_child: 0,
                };

                let (sib1, sib2) = match path {
                    Path::Left => {
                        node.is_left_child = 1;
                        (key + 1, key + 2)
                    }
                    Path::Middle => (key - 1, key + 1),
                    Path::Right => {
                        node.is_right_child = 1;
                        (key - 2, key - 1)
                    }
                };
                let mut store_key1 = KEY_PAD.to_vec();
                store_key1.extend(sib1.to_be_bytes());
                if let Some(b) = self.store.get(&store_key1)? {
                    node.siblings1 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }
                let mut store_key2 = KEY_PAD.to_vec();
                store_key2.extend(sib2.to_be_bytes());
                if let Some(b) = self.store.get(&store_key2)? {
                    node.siblings2 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }

                Ok(node)
            })
            .collect::<Result<Vec<ProofNode>>>()?;

        Ok(Proof {
            nodes: nodes,
            root: self.get_current_root_hash()?,
            root_version: 1,
            uid: id,
        })
    }

    pub fn get_current_root_hash(&self) -> Result<BLSScalar> {
        match self.store.get(&ROOT_KEY)? {
            Some(hash) => BLSScalar::zei_from_bytes(hash.as_slice()),
            None => Err(eg!("root hash key not found")),
        }
    }

    // fn hash_abar(uid: u64, abar: &AnonBlindAssetRecord) -> BLSScalar {
    //     let hash = RescueInstance::new();
    //
    //     let pk_hash = hash.rescue_hash(&[
    //         abar.public_key.0.point_ref().get_x(),
    //         abar.public_key.0.point_ref().get_y(),
    //         BLSScalar::zero(),
    //         BLSScalar::zero(),
    //     ])[0];
    //
    //     hash.rescue_hash(&[
    //         BLSScalar::from_u64(uid),
    //         abar.amount_type_commitment,
    //         pk_hash,
    //         BLSScalar::zero(),
    //     ])[0]
    // }

    pub fn commit(&mut self) -> Result<u64> {
        let (_, ver) = self.store.state_mut().commit(self.version + 1).c(d!())?;
        self.version = ver;
        Ok(self.version)
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.store.get(key)
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn entry_count(&self) -> u64 {
        self.entry_count
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

        if let Some(bytes) = store.get(&ENTRY_COUNT_KEY)? {
            let array: [u8; 8] = [
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                bytes[7],
            ];
            entry_count = u64::from_be_bytes(array);
            version = store.height().c(d!())?;
        }

        Ok(ImmutablePersistentMerkleTree {
            entry_count,
            version,
            store,
        })
    }

    pub fn generate_proof(&self, id: u64) -> Result<Proof> {
        let keys = get_path_keys(id);

        let nodes: Vec<ProofNode> = keys[0..TREE_DEPTH]
            .iter()
            .map(|(key, path)| {
                // if current node is not present in store then it is not a valid uid to generate
                let mut store_key = KEY_PAD.to_vec();
                store_key.extend(key.to_be_bytes());
                if !self.store.exists(&store_key)? {
                    return Err(eg!("uid not found in tree, cannot generate proof"));
                }

                let mut node = ProofNode {
                    siblings1: Default::default(),
                    siblings2: Default::default(),
                    is_left_child: 0,
                    is_right_child: 0,
                };

                let (sib1, sib2) = match path {
                    Path::Left => {
                        node.is_left_child = 1;
                        (key + 1, key + 2)
                    }
                    Path::Middle => (key - 1, key + 1),
                    Path::Right => {
                        node.is_right_child = 1;
                        (key - 2, key - 1)
                    }
                };
                let mut store_key1 = KEY_PAD.to_vec();
                store_key1.extend(sib1.to_be_bytes());
                if let Some(b) = self.store.get(&store_key1)? {
                    node.siblings1 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }
                let mut store_key2 = KEY_PAD.to_vec();
                store_key2.extend(sib2.to_be_bytes());
                if let Some(b) = self.store.get(&store_key2)? {
                    node.siblings2 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }

                Ok(node)
            })
            .collect::<Result<Vec<ProofNode>>>()?;

        Ok(Proof {
            nodes: nodes,
            root: self.get_current_root_hash()?,
            root_version: 1,
            uid: id,
        })
    }

    pub fn get_current_root_hash(&self) -> Result<BLSScalar> {
        match self.store.get(&ROOT_KEY)? {
            Some(hash) => BLSScalar::zei_from_bytes(hash.as_slice()),
            None => Err(eg!("root hash key not found")),
        }
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.store.get(key)
    }
}

#[derive(Clone)]
pub struct Proof {
    pub nodes: Vec<ProofNode>,
    pub root: BLSScalar,
    pub root_version: usize,
    pub uid: u64,
}
#[derive(Clone, Debug)]
pub struct ProofNode {
    pub siblings1: BLSScalar,
    pub siblings2: BLSScalar,
    pub is_left_child: u8,
    pub is_right_child: u8,
}

struct Cache {
    store: HashMap<u64, Vec<u8>>,
}

impl Cache {
    fn new() -> Cache {
        Cache {
            store: HashMap::new(),
        }
    }
    fn set(&mut self, key: u64, val: Vec<u8>) {
        self.store.insert(key, val);
    }
    fn get(&self, key: &u64) -> Option<&Vec<u8>> {
        self.store.get(key)
    }
    fn iter(&self) -> Iter<'_, u64, Vec<u8>> {
        self.store.iter()
    }
}

fn get_path_keys(uid: u64) -> Vec<(u64, Path)> {
    let mut keys = vec![];
    let mut key = LEAF_START + uid;

    for _ in 0..=TREE_DEPTH {
        let rem = key % 3;
        match rem {
            1 => {
                keys.push((key, Path::Left));
                key = key / 3;
            }
            2 => {
                keys.push((key, Path::Middle));
                key = key / 3;
            }
            0 => {
                keys.push((key, Path::Right));
                key = if key != 0 { key / 3 - 1 } else { 0 };
            }
            _ => {}
        }
    }
    keys
}
