#[cfg(test)]
mod tests {
    use crate::anon_xfr::{
        circuits::{add_merkle_path_variables, compute_merkle_root, AccElemVars},
        structs::{AnonBlindAssetRecord, MTNode, MTPath, OpenAnonBlindAssetRecord},
    };
    use parking_lot::RwLock;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ruc::*;
    use std::{sync::Arc, thread};
    use storage::{
        db::{RocksDB, TempRocksDB},
        state::{ChainState, State},
        store::PrefixedStore,
    };
    use zei_accumulators::merkle_tree::{PersistentMerkleTree, TreePath};
    use zei_algebra::{bls12_381::BLSScalar, traits::Scalar, Zero};
    use zei_crypto::basic::rescue::RescueInstance;
    use zei_plonk::plonk::constraint_system::TurboConstraintSystem;

    #[test]
    fn test_persistent_merkle_tree() {
        let hash = RescueInstance::new();

        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("mystore", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        assert_eq!(mt.get_root().unwrap(), BLSScalar::zero(),);

        let abar = AnonBlindAssetRecord::from_oabar(&OpenAnonBlindAssetRecord::default());
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());

        assert_ne!(
            mt.get_root().unwrap(),
            hash.rescue(&[
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero()
            ])[0]
        );

        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());

        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());

        assert!(mt.generate_proof(0).is_ok());
        assert!(mt.generate_proof(1).is_ok());
        assert!(mt.generate_proof(2).is_ok());

        assert!(mt.generate_proof(3).is_err());
        assert!(mt.generate_proof(4).is_err());
        assert!(mt.generate_proof(11234).is_err());
    }

    #[test]
    fn test_persistent_merkle_tree_proof_commitment() {
        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("mystore", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let abar = AnonBlindAssetRecord {
            commitment: BLSScalar::random(&mut prng),
        };
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());

        let proof = mt.generate_proof(0).unwrap();

        let mut cs = TurboConstraintSystem::new();
        let uid_var = cs.new_variable(BLSScalar::from(0u32));
        let comm_var = cs.new_variable(abar.commitment);
        let elem = AccElemVars {
            uid: uid_var,
            commitment: comm_var,
        };

        let path_vars = add_merkle_path_variables(
            &mut cs,
            MTPath {
                nodes: proof
                    .nodes
                    .iter()
                    .map(|e| MTNode {
                        siblings1: e.siblings1,
                        siblings2: e.siblings2,
                        is_left_child: (e.path == TreePath::Left) as u8,
                        is_right_child: (e.path == TreePath::Right) as u8,
                    })
                    .collect(),
            },
        );
        let root_var = compute_merkle_root(&mut cs, elem, &path_vars);

        // Check Merkle root correctness
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        assert_eq!(witness[root_var], mt.get_root().unwrap());

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

        assert_eq!(mt.version(), 4);
        assert_eq!(mt.entry_count(), 4);
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

        let mut abar = AnonBlindAssetRecord {
            commitment: BLSScalar::random(&mut prng),
        };
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());
        mt.commit()?;

        abar = AnonBlindAssetRecord {
            commitment: BLSScalar::random(&mut prng),
        };
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());
        mt.commit()?;

        abar = AnonBlindAssetRecord {
            commitment: BLSScalar::random(&mut prng),
        };
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());
        mt.commit()?;

        abar = AnonBlindAssetRecord {
            commitment: BLSScalar::random(&mut prng),
        };
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());
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
        let abar0 = AnonBlindAssetRecord {
            commitment: BLSScalar::random(&mut prng),
        };
        let abar1 = AnonBlindAssetRecord {
            commitment: BLSScalar::random(&mut prng),
        };
        let abar2 = AnonBlindAssetRecord {
            commitment: BLSScalar::random(&mut prng),
        };

        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
            .unwrap();
        pmt.commit().unwrap();
    }

    fn hash_abar(uid: u64, abar: &AnonBlindAssetRecord) -> BLSScalar {
        let hash = RescueInstance::new();

        hash.rescue(&[
            BLSScalar::from(uid),
            abar.commitment,
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0]
    }
}
