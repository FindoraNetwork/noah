pub mod merkle_tree;

#[cfg(test)]
mod tests {
    use crate::merkle_tree::PersistentMerkleTree;
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::One;
    use crypto::basics::hash::rescue::RescueInstance;
    use parking_lot::RwLock;
    use std::sync::Arc;
    use std::thread;
    use storage::db::TempRocksDB;
    use storage::state::{ChainState, State};
    use storage::store::PrefixedStore;

    #[test]
    fn test() {
        let _hash = RescueInstance::new();

        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();
        //let root0 = mt.get_current_root_hash().unwrap();
        //assert_eq!(root0, BLSScalar::zero());

        let sid_0 = mt.add_commitment_hash(BLSScalar::one()).unwrap();
        assert_eq!(sid_0, 0);

        let v0 = mt.commit().unwrap();
        let proof0 = mt.generate_proof(0).unwrap();
        println!("nodes: {:?}", proof0.nodes.len()); // 1856 vs 492
        println!("root: {:?}", proof0.root);
        // root: BLSScalar(BigInt([4455513758586644197, 9240243640558842050, 15041668979369452445, 5894806090397613214]))
        // root: BLSScalar(BigInt([17393346530685615531, 10665263640234564765, 10406422131025996151, 3117343432492655840]))
        // root: BLSScalar(BigInt([11070693654976930170, 17319180623281640354, 839506441540242814, 4948558268637580532]))
        println!("root_verison: {:?}", proof0.root_version);
        println!("uid: {:?}", proof0.uid);
        assert_eq!(proof0.root_version as u64, v0);
    }
}
