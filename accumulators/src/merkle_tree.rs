use noah_algebra::{
    bls12_381::BLSScalar,
    collections::{hash_map::Iter, HashMap},
    prelude::*,
};
use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381, ANEMOI_JIVE_381_SALTS};
use storage::db::MerkleDB;
use storage::store::{ImmutablePrefixedStore, PrefixedStore, Stated, Store};

// ceil(log(u32::MAX, 3)) = 21
// 3^0 + 3^1 + 3^2 + ... 3^20 < 2^64 (u64 can include all leaf & ancestor)
// store max num is 3^20 = 3486784401 (max uid = 3^20 - 1)
// sid   max num is 2^64 = 18446744073709551616 (max uid = 2^64 - 1)

/// default merkle tree depth.
pub const TREE_DEPTH: usize = 20;

// 1743392200 = 3^0 + 3^1 + 3^2 + ... 3^19, if change TREE_DEPTH, MUST update.
const LEAF_START: u64 = 1743392200;

const KEY_PAD: [u8; 4] = [0, 0, 0, 0];
const ROOT_KEY: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // KEY_PAD + 0u64
const ENTRY_COUNT_KEY: [u8; 4] = [0, 0, 0, 1];

///
/// PersistentMerkleTree is a 3-ary merkle tree
///
/// # Example
/// ```
///
/// use mem_db::MemoryDB;
/// use parking_lot::RwLock;
/// use std::sync::Arc;
/// use storage::state::{ChainState, State};
/// use storage::store::PrefixedStore;
/// use noah_accumulators::merkle_tree::{PersistentMerkleTree, verify};
/// use noah_algebra::{bls12_381::BLSScalar, One};
///
/// let fdb = MemoryDB::new();
/// let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0, false)));
/// let mut state = State::new(cs, false);
/// let store = PrefixedStore::new("my_store", &mut state);
/// let mut mt = PersistentMerkleTree::new(store).unwrap();
/// assert_eq!(0, mt.version());
///
/// let uid = mt.add_commitment_hash(BLSScalar::one()).unwrap();
/// let proof = mt.generate_proof(uid).unwrap();
/// assert_eq!(proof.uid, uid);
/// assert!(verify(BLSScalar::one(), &proof));
/// let v = mt.commit().unwrap();
/// assert_eq!(1, mt.version());
/// assert_eq!(1, v);
///
/// ```
pub struct PersistentMerkleTree<'a, D: MerkleDB> {
    entry_count: u64,
    store: PrefixedStore<'a, D>,
}

impl<'a, D: MerkleDB> PersistentMerkleTree<'a, D> {
    /// Generates a new PersistentMerkleTree based on a sessioned KV store
    pub fn new(mut store: PrefixedStore<'a, D>) -> Result<PersistentMerkleTree<'a, D>> {
        let mut entry_count = 0;

        if let Some(bytes) = store.get(&ENTRY_COUNT_KEY)? {
            let array: [u8; 8] = [
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ];
            entry_count = u64::from_be_bytes(array);
        } else {
            store.set(&ROOT_KEY, BLSScalar::zero().noah_to_bytes())?;
            store.set(&ENTRY_COUNT_KEY, 0u64.to_be_bytes().to_vec())?;

            if !store.state_mut().cache_mut().good2_commit() {
                store.state_mut().discard_session();

                return Err(eg!("store commit no good"));
            }

            store.state_mut().commit(0).c(d!())?;
        }

        Ok(PersistentMerkleTree { entry_count, store })
    }

    /// add a new leaf and return the leaf uid.
    pub fn add_commitment_hash(&mut self, hash: BLSScalar) -> Result<u64> {
        let mut cache = Cache::new();
        // 1. generate keys of ancestors for update in tree
        let keys = get_path_keys(self.entry_count);
        let leaf = keys.first().unwrap();

        // 2. Hash ABAR and save leaf node
        let uid = self.entry_count;
        cache.set(leaf.0, hash.noah_to_bytes());

        // 3. update hash of all ancestors of the new leaf
        for (index, (node_key, path)) in keys[0..TREE_DEPTH].iter().enumerate() {
            let parse_hash = |key: u64| -> Result<BLSScalar> {
                if let Some(b) = cache.get(&key) {
                    return BLSScalar::noah_from_bytes(b.as_slice());
                }
                let mut store_key = KEY_PAD.to_vec();
                store_key.extend(key.to_be_bytes());
                match self.store.get(&store_key)? {
                    Some(b) => BLSScalar::noah_from_bytes(b.as_slice()),
                    None => Ok(BLSScalar::zero()),
                }
            };

            let (sib0, sib1, sib2) = match path {
                TreePath::Left => (
                    parse_hash(*node_key)?,
                    parse_hash(node_key + 1)?,
                    parse_hash(node_key + 2)?,
                ),
                TreePath::Middle => (
                    parse_hash(node_key - 1)?,
                    parse_hash(*node_key)?,
                    parse_hash(node_key + 1)?,
                ),
                TreePath::Right => (
                    parse_hash(node_key - 2)?,
                    parse_hash(node_key - 1)?,
                    parse_hash(*node_key)?,
                ),
            };

            let hash =
                AnemoiJive381::eval_jive(&[sib0, sib1], &[sib2, ANEMOI_JIVE_381_SALTS[index]]);
            cache.set(keys[index + 1].0, BLSScalar::noah_to_bytes(&hash));
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

    /// generate leaf's merkle proof by uid.
    pub fn generate_proof(&self, id: u64) -> Result<Proof> {
        self.generate_proof_with_depth(id, TREE_DEPTH)
    }

    /// generate leaf's merkle proof by uid and the depth.
    pub fn generate_proof_with_depth(&self, id: u64, depth: usize) -> Result<Proof> {
        if depth > TREE_DEPTH || id > 3u64.pow(depth as u32) {
            return Err(eg!("tree depth is invalid for generate proof"));
        }

        let keys = get_path_keys(id);

        let nodes: Vec<ProofNode> = keys[0..depth]
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
                    path: *path,
                };

                let (sib1, sib2) = match path {
                    TreePath::Left => (key + 1, key + 2),
                    TreePath::Middle => (key - 1, key + 1),
                    TreePath::Right => (key - 2, key - 1),
                };
                let mut store_key1 = KEY_PAD.to_vec();
                store_key1.extend(sib1.to_be_bytes());
                if let Some(b) = self.store.get(&store_key1)? {
                    node.siblings1 = BLSScalar::noah_from_bytes(b.as_slice())?;
                }
                let mut store_key2 = KEY_PAD.to_vec();
                store_key2.extend(sib2.to_be_bytes());
                if let Some(b) = self.store.get(&store_key2)? {
                    node.siblings2 = BLSScalar::noah_from_bytes(b.as_slice())?;
                }

                Ok(node)
            })
            .collect::<Result<Vec<ProofNode>>>()?;

        Ok(Proof {
            nodes: nodes,
            root: self.get_root_with_depth(depth)?,
            root_version: self.version(),
            uid: id,
        })
    }

    /// get tree current root
    pub fn get_root(&self) -> Result<BLSScalar> {
        self.get_root_with_depth(TREE_DEPTH)
    }

    /// get tree root by depth
    pub fn get_root_with_depth(&self, depth: usize) -> Result<BLSScalar> {
        let mut pos = 0u64;
        for i in 0..(TREE_DEPTH - depth) {
            pos += 3u64.pow(i as u32);
        }
        let mut store_key = KEY_PAD.to_vec();
        store_key.extend(pos.to_be_bytes());

        match self.store.get(&store_key)? {
            Some(hash) => BLSScalar::noah_from_bytes(hash.as_slice()),
            None => Err(eg!("root hash key not found at this depth")),
        }
    }

    /// get tree root by depth and version.
    pub fn get_root_with_depth_and_version(&self, depth: usize, version: u64) -> Result<BLSScalar> {
        if version == 0 {
            return Ok(BLSScalar::zero());
        }

        let mut pos = 0u64;
        for i in 0..(TREE_DEPTH - depth) {
            pos += 3u64.pow(i as u32);
        }
        let mut store_key = KEY_PAD.to_vec();
        store_key.extend(pos.to_be_bytes());
        match self.store.get_v(&store_key, version)? {
            Some(hash) => BLSScalar::noah_from_bytes(hash.as_slice()),
            None => Err(eg!("root hash key not found at this depth and version")),
        }
    }

    /// commit to store and add the tree version.
    pub fn commit(&mut self) -> Result<u64> {
        let height = self.store.height()?;

        if !self.store.state_mut().cache_mut().good2_commit() {
            self.store.state_mut().discard_session();

            return Err(eg!("store commit no good"));
        }

        let (_, ver) = self.store.state_mut().commit(height + 1).c(d!())?;
        Ok(ver)
    }

    /// get leaf hash by uid
    pub fn get_leaf(&self, uid: u64) -> Result<Option<BLSScalar>> {
        let mut store_key = KEY_PAD.to_vec();
        store_key.extend(uid.to_be_bytes());

        match self.store.get(&store_key)? {
            Some(hash) => Ok(Some(BLSScalar::noah_from_bytes(hash.as_slice())?)),
            None => Ok(None),
        }
    }

    /// get the tree version
    pub fn version(&self) -> u64 {
        self.store.height().unwrap_or(0)
    }

    /// get the number of entries
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }
}

/// The struct for an immutable, persistent Merkle tree,
/// used to store the records in anonymous payment
pub struct ImmutablePersistentMerkleTree<'a, D: MerkleDB> {
    entry_count: u64,
    store: ImmutablePrefixedStore<'a, D>,
}

impl<'a, D: MerkleDB> ImmutablePersistentMerkleTree<'a, D> {
    /// generate a new PersistentMerkleTree based on a sessioned KV store
    pub fn new(
        store: ImmutablePrefixedStore<'a, D>,
    ) -> Result<ImmutablePersistentMerkleTree<'a, D>> {
        let mut entry_count = 0;

        if let Some(bytes) = store.get(&ENTRY_COUNT_KEY)? {
            let array: [u8; 8] = [
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ];
            entry_count = u64::from_be_bytes(array);
        }

        Ok(ImmutablePersistentMerkleTree { entry_count, store })
    }

    /// generate leaf's merkle proof by uid
    pub fn generate_proof(&self, id: u64) -> Result<Proof> {
        self.generate_proof_with_depth(id, TREE_DEPTH)
    }

    /// generate leaf's merkle proof by uid and the depth
    pub fn generate_proof_with_depth(&self, id: u64, depth: usize) -> Result<Proof> {
        if depth > TREE_DEPTH || id > 3u64.pow(depth as u32) {
            return Err(eg!("tree depth is invalid for generate proof"));
        }
        let v = self.version();

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
                    path: *path,
                };

                let (sib1, sib2) = match path {
                    TreePath::Left => (key + 1, key + 2),
                    TreePath::Middle => (key - 1, key + 1),
                    TreePath::Right => (key - 2, key - 1),
                };
                let mut store_key1 = KEY_PAD.to_vec();
                store_key1.extend(sib1.to_be_bytes());
                if let Some(b) = self.store.get_v(&store_key1, v)? {
                    node.siblings1 = BLSScalar::noah_from_bytes(b.as_slice())?;
                }
                let mut store_key2 = KEY_PAD.to_vec();
                store_key2.extend(sib2.to_be_bytes());
                if let Some(b) = self.store.get_v(&store_key2, v)? {
                    node.siblings2 = BLSScalar::noah_from_bytes(b.as_slice())?;
                }

                Ok(node)
            })
            .collect::<Result<Vec<ProofNode>>>()?;

        Ok(Proof {
            nodes: nodes,
            root: self.get_root_with_depth(depth)?,
            root_version: self.version(),
            uid: id,
        })
    }

    /// get tree current root
    pub fn get_root(&self) -> Result<BLSScalar> {
        self.get_root_with_depth(TREE_DEPTH)
    }

    /// get tree root by depth
    pub fn get_root_with_depth(&self, depth: usize) -> Result<BLSScalar> {
        let v = self.version();
        self.get_root_with_depth_and_version(depth, v)
    }

    /// get tree root by depth and version.
    pub fn get_root_with_depth_and_version(&self, depth: usize, version: u64) -> Result<BLSScalar> {
        if version == 0 {
            return Ok(BLSScalar::zero());
        }

        let mut pos = 0u64;
        for i in 0..(TREE_DEPTH - depth) {
            pos += 3u64.pow(i as u32);
        }
        let mut store_key = KEY_PAD.to_vec();
        store_key.extend(pos.to_be_bytes());
        match self.store.get_v(&store_key, version)? {
            Some(hash) => BLSScalar::noah_from_bytes(hash.as_slice()),
            None => Err(eg!("root hash key not found at this depth and version")),
        }
    }

    /// get leaf hash by uid
    pub fn get_leaf(&self, uid: u64) -> Result<Option<BLSScalar>> {
        let mut store_key = KEY_PAD.to_vec();
        store_key.extend(uid.to_be_bytes());
        let v = self.version();

        match self.store.get_v(&store_key, v)? {
            Some(hash) => Ok(Some(BLSScalar::noah_from_bytes(hash.as_slice())?)),
            None => Ok(None),
        }
    }

    /// get the tree version
    pub fn version(&self) -> u64 {
        self.store.height().unwrap_or(0)
    }

    /// get the number of entries
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }
}

/// verify merkle proof.
pub fn verify(leaf: BLSScalar, proof: &Proof) -> bool {
    let mut next = leaf;
    if proof.nodes.len() != TREE_DEPTH {
        return false;
    }
    for (i, node) in proof.nodes.iter().enumerate() {
        let (s1, s2, s3) = match node.path {
            TreePath::Left => (next, node.siblings1, node.siblings2),
            TreePath::Middle => (node.siblings1, next, node.siblings2),
            TreePath::Right => (node.siblings1, node.siblings2, next),
        };
        let hash = AnemoiJive381::eval_jive(&[s1, s2], &[s3, ANEMOI_JIVE_381_SALTS[i]]);
        next = hash
    }
    next == proof.root
}

/// PersistentMerkleTree Proof.
#[derive(Clone)]
pub struct Proof {
    /// proof nodes, from lower(leaf) to upper.
    pub nodes: Vec<ProofNode>,
    /// current root.
    pub root: BLSScalar,
    /// current root version.
    pub root_version: u64,
    /// leaf's uid.
    pub uid: u64,
}

/// PersistentMerkleTree Proof Node, 3-ary merkle tree,
/// so every leaf has two siblings and own position.
#[derive(Clone, Debug)]
pub struct ProofNode {
    /// siblings 1.
    pub siblings1: BLSScalar,
    /// siblings 2.
    pub siblings2: BLSScalar,
    /// representative the own position in the branch.
    pub path: TreePath,
}

/// leaf position in the branch of the tree.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TreePath {
    /// the left direction
    Left,
    /// the current position
    Middle,
    /// the right direction
    Right,
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

fn get_path_keys(uid: u64) -> Vec<(u64, TreePath)> {
    let mut keys = vec![];
    let mut key = LEAF_START + uid;

    for _ in 0..=TREE_DEPTH {
        let rem = key % 3;
        match rem {
            1 => {
                keys.push((key, TreePath::Left));
                key = key / 3;
            }
            2 => {
                keys.push((key, TreePath::Middle));
                key = key / 3;
            }
            0 => {
                keys.push((key, TreePath::Right));
                key = if key != 0 { key / 3 - 1 } else { 0 };
            }
            _ => {}
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::{get_path_keys, TreePath};

    #[test]
    fn test_merkle_tree_path() {
        let first_keys = get_path_keys(0);
        let mut first_sum = 0u64;
        for (i, (key, path)) in first_keys[0..first_keys.len() - 1].iter().rev().enumerate() {
            first_sum += 3u64.pow(i as u32);
            assert_eq!(*key, first_sum);
            assert_eq!(*path, TreePath::Left);
        }

        let mut t1 = get_path_keys(1);
        t1.pop(); // pop root.
        assert_eq!(t1[0].1, TreePath::Middle);
        for (_, path) in &t1[1..] {
            assert_eq!(*path, TreePath::Left);
        }

        let mut t2 = get_path_keys(2);
        t2.pop();
        assert_eq!(t2[0].1, TreePath::Right);
        for (_, path) in &t2[1..] {
            assert_eq!(*path, TreePath::Left);
        }

        let mut t3 = get_path_keys(3);
        t3.pop();
        assert_eq!(t3[0].1, TreePath::Left);
        assert_eq!(t3[1].1, TreePath::Middle);
        for (_, path) in &t3[2..] {
            assert_eq!(*path, TreePath::Left);
        }

        let tmp = get_path_keys(1_000_000);
        let tmp_path: Vec<TreePath> = tmp.iter().map(|(_, p)| *p).collect();
        let tmp_right = vec![
            TreePath::Middle,
            TreePath::Left,
            TreePath::Left,
            TreePath::Right,
            TreePath::Left,
            TreePath::Right,
            TreePath::Left,
            TreePath::Middle,
            TreePath::Right,
            TreePath::Right,
            TreePath::Middle,
            TreePath::Right,
            TreePath::Middle,
            TreePath::Left,
            TreePath::Left,
            TreePath::Left,
            TreePath::Left,
            TreePath::Left,
            TreePath::Left,
            TreePath::Left,
            TreePath::Right,
        ];
        assert_eq!(tmp_path, tmp_right);

        let last_keys = get_path_keys(3u64.pow(20) - 1);
        let mut last_sum = 0u64;
        for (i, (key, path)) in last_keys.iter().rev().enumerate() {
            last_sum += 3u64.pow(i as u32);
            assert_eq!(*key, last_sum - 1);
            assert_eq!(*path, TreePath::Right);
        }
    }
}
