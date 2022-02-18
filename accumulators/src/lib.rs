pub mod merkle_tree;

#[cfg(test)]
mod tests {
    use crate::merkle_tree::PersistentMerkleTree;
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::One;
    use parking_lot::RwLock;
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;
    use storage::db::TempRocksDB;
    use storage::state::{ChainState, State};
    use storage::store::PrefixedStore;

    #[test]
    fn test_merkle_tree() {
        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let start = Instant::now();
        for _ in 0..10 {
            let sid_0 = mt.add_commitment_hash(BLSScalar::one()).unwrap();
            let proof0 = mt.generate_proof(sid_0).unwrap();
            assert_eq!(proof0.uid, sid_0);
        }
        let end = start.elapsed();
        println!("Time: {:?} microseconds", end.as_micros());
    }
}
