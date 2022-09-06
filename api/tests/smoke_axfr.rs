#[cfg(test)]
mod smoke_axfr {
    use digest::Digest;
    use mem_db::MemoryDB;
    use parking_lot::RwLock;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use sha2::Sha512;
    use std::sync::Arc;
    use storage::{
        state::{ChainState, State},
        store::PrefixedStore,
    };
    use zei::{
        anon_xfr::{
            abar_to_abar::*,
            abar_to_ar::*,
            abar_to_bar::*,
            ar_to_abar::*,
            bar_to_abar::*,
            keys::AXfrKeyPair,
            structs::{
                AnonAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonAssetRecord,
                OpenAnonAssetRecordBuilder,
            },
            FEE_TYPE, TREE_DEPTH,
        },
        setup::{ProverParams, VerifierParams},
        xfr::{
            asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType},
            sig::{XfrKeyPair, XfrPublicKey},
            structs::{
                AssetRecordTemplate, AssetType, BlindAssetRecord, OwnerMemo, ASSET_TYPE_LENGTH,
            },
        },
    };
    use zei_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
    use zei_algebra::{bls12_381::BLSScalar, prelude::*};
    use zei_crypto::basic::{pedersen_comm::PedersenCommitmentRistretto, rescue::RescueInstance};

    const AMOUNT: u64 = 10u64;
    const ASSET: AssetType = AssetType([1u8; ASSET_TYPE_LENGTH]);
    const ASSET3: AssetType = AssetType([2u8; ASSET_TYPE_LENGTH]);
    const ASSET4: AssetType = AssetType([2u8; ASSET_TYPE_LENGTH]);
    const ASSET5: AssetType = AssetType([2u8; ASSET_TYPE_LENGTH]);
    const ASSET6: AssetType = AssetType([2u8; ASSET_TYPE_LENGTH]);

    fn build_bar(
        pubkey: &XfrPublicKey,
        prng: &mut ChaChaRng,
        pc_gens: &PedersenCommitmentRistretto,
        amt: u64,
        asset_type: AssetType,
        ar_type: AssetRecordType,
    ) -> (BlindAssetRecord, Option<OwnerMemo>) {
        let ar = AssetRecordTemplate::with_no_asset_tracing(amt, asset_type, ar_type, *pubkey);
        let (bar, _, memo) = build_blind_asset_record(prng, &pc_gens, &ar, vec![]);
        (bar, memo)
    }

    fn build_oabar<R: CryptoRng + RngCore>(
        prng: &mut R,
        amount: u64,
        asset_type: AssetType,
        keypair: &AXfrKeyPair,
    ) -> OpenAnonAssetRecord {
        OpenAnonAssetRecordBuilder::new()
            .amount(amount)
            .asset_type(asset_type)
            .pub_key(&keypair.get_public_key())
            .finalize(prng)
            .unwrap()
            .build()
            .unwrap()
    }

    fn hash_abar(uid: u64, abar: &AnonAssetRecord) -> BLSScalar {
        let hash = RescueInstance::new();
        hash.rescue(&[
            BLSScalar::from(uid),
            abar.commitment,
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0]
    }

    fn build_mt_leaf_info_from_proof(proof: Proof, uid: u64) -> MTLeafInfo {
        return MTLeafInfo {
            path: MTPath {
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
            root: proof.root,
            root_version: proof.root_version,
            uid: uid,
        };
    }

    fn random_hasher<R: CryptoRng + RngCore>(prng: &mut R) -> Sha512 {
        let mut hasher = Sha512::new();
        let mut random_bytes = [0u8; 32];
        prng.fill_bytes(&mut random_bytes);
        hasher.update(&random_bytes);
        hasher
    }

    fn mock_fee(x: usize, y: usize) -> u32 {
        5 + (x as u32) + 2 * (y as u32)
    }

    #[test]
    fn ar_to_abar() {
        let mut prng = ChaChaRng::from_entropy();
        let pc_gens = PedersenCommitmentRistretto::default();
        let params = ProverParams::ar_to_abar_params().unwrap();
        let verify_params = VerifierParams::ar_to_abar_params().unwrap();

        let sender = XfrKeyPair::generate(&mut prng);
        let receiver = AXfrKeyPair::generate(&mut prng);

        let (bar, memo) = build_bar(
            &sender.pub_key,
            &mut prng,
            &pc_gens,
            AMOUNT,
            ASSET,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        );
        let obar = open_blind_asset_record(&bar, &memo, &sender).unwrap();

        let note = gen_ar_to_abar_note(
            &mut prng,
            &params,
            &obar,
            &sender,
            &receiver.get_public_key(),
        )
        .unwrap();
        assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok());

        // check open abar
        let oabar =
            OpenAnonAssetRecordBuilder::from_abar(&note.body.output, note.body.memo, &receiver)
                .unwrap()
                .build()
                .unwrap();
        assert_eq!(oabar.get_amount(), AMOUNT);
        assert_eq!(oabar.get_asset_type(), ASSET);
    }

    #[test]
    fn bar_to_abar() {
        let mut prng = ChaChaRng::from_entropy();
        let pc_gens = PedersenCommitmentRistretto::default();
        let params = ProverParams::bar_to_abar_params().unwrap();
        let verify_params = VerifierParams::bar_to_abar_params().unwrap();

        let sender = XfrKeyPair::generate(&mut prng);
        let receiver = AXfrKeyPair::generate(&mut prng);

        let (bar, memo) = build_bar(
            &sender.pub_key,
            &mut prng,
            &pc_gens,
            AMOUNT,
            ASSET,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        );
        let obar = open_blind_asset_record(&bar, &memo, &sender).unwrap();

        let note = gen_bar_to_abar_note(
            &mut prng,
            &params,
            &obar,
            &sender,
            &receiver.get_public_key(),
        )
        .unwrap();
        assert!(verify_bar_to_abar_note(&verify_params, &note, &sender.pub_key).is_ok());
        let mut note = note;
        let message = b"error_message";
        let bad_sig = sender.sign(message).unwrap();
        note.signature = bad_sig;
        assert!(verify_bar_to_abar_note(&verify_params, &note, &sender.pub_key).is_err());

        // check open ABAR
        let oabar =
            OpenAnonAssetRecordBuilder::from_abar(&note.body.output, note.body.memo, &receiver)
                .unwrap()
                .build()
                .unwrap();
        assert_eq!(oabar.get_amount(), AMOUNT);
        assert_eq!(oabar.get_asset_type(), ASSET);
    }

    #[test]
    fn abar_to_ar() {
        let mut prng = ChaChaRng::from_entropy();
        let params = ProverParams::abar_to_ar_params(TREE_DEPTH).unwrap();
        let verify_params = VerifierParams::abar_to_ar_params().unwrap();

        let sender = AXfrKeyPair::generate(&mut prng);
        let receiver = XfrKeyPair::generate(&mut prng);

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "abar_ar".to_owned(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut oabar = build_oabar(&mut prng, AMOUNT, ASSET, &sender);
        let abar = AnonAssetRecord::from_oabar(&oabar);
        mt.add_commitment_hash(hash_abar(0, &abar)).unwrap();
        mt.commit().unwrap();
        let proof = mt.generate_proof(0).unwrap();
        oabar.update_mt_leaf_info(build_mt_leaf_info_from_proof(proof.clone(), 0));

        let pre_note = init_abar_to_ar_note(&mut prng, &oabar, &sender, &receiver.pub_key).unwrap();
        let hash = random_hasher(&mut prng);
        let note = finish_abar_to_ar_note(&mut prng, &params, pre_note, hash.clone()).unwrap();
        verify_abar_to_ar_note(&verify_params, &note, &proof.root, hash.clone()).unwrap();

        let err_root = BLSScalar::random(&mut prng);
        assert!(verify_abar_to_ar_note(&verify_params, &note, &err_root, hash.clone()).is_err());

        let err_hash = random_hasher(&mut prng);
        assert!(verify_abar_to_ar_note(&verify_params, &note, &proof.root, err_hash).is_err());

        let mut err_nullifier = note.clone();
        err_nullifier.body.input = BLSScalar::random(&mut prng);
        assert!(verify_abar_to_ar_note(&verify_params, &err_nullifier, &proof.root, hash).is_err());

        // check open AR
        let obar = open_blind_asset_record(&note.body.output, &note.body.memo, &receiver).unwrap();
        assert_eq!(*obar.get_amount(), AMOUNT);
        assert_eq!(*obar.get_asset_type(), ASSET);
    }

    #[test]
    fn abar_to_bar() {
        let mut prng = ChaChaRng::from_seed([5u8; 32]);
        let params = ProverParams::abar_to_bar_params(TREE_DEPTH).unwrap();
        let verify_params = VerifierParams::abar_to_bar_params().unwrap();

        let sender = AXfrKeyPair::generate(&mut prng);
        let receiver = XfrKeyPair::generate(&mut prng);

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "abar_bar".to_owned(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut oabar = build_oabar(&mut prng, AMOUNT, ASSET, &sender);
        let abar = AnonAssetRecord::from_oabar(&oabar);
        mt.add_commitment_hash(hash_abar(0, &abar)).unwrap(); // mock
        mt.add_commitment_hash(hash_abar(1, &abar)).unwrap();
        mt.commit().unwrap();
        let proof = mt.generate_proof(1).unwrap();
        oabar.update_mt_leaf_info(build_mt_leaf_info_from_proof(proof.clone(), 1));

        let pre_note = init_abar_to_bar_note(
            &mut prng,
            &oabar,
            &sender,
            &receiver.pub_key,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        )
        .unwrap();
        let hash = random_hasher(&mut prng);
        let note = finish_abar_to_bar_note(&mut prng, &params, pre_note, hash.clone()).unwrap();
        verify_abar_to_bar_note(&verify_params, &note, &proof.root, hash.clone()).unwrap();

        let err_root = BLSScalar::random(&mut prng);
        assert!(verify_abar_to_bar_note(&verify_params, &note, &err_root, hash.clone()).is_err());

        let err_hash = random_hasher(&mut prng);
        assert!(verify_abar_to_bar_note(&verify_params, &note, &proof.root, err_hash).is_err());

        let mut err_nullifier = note.clone();
        err_nullifier.body.input = BLSScalar::random(&mut prng);
        assert!(
            verify_abar_to_bar_note(&verify_params, &err_nullifier, &proof.root, hash).is_err()
        );

        // check open BAR
        let obar = open_blind_asset_record(&note.body.output, &note.body.memo, &receiver).unwrap();
        assert_eq!(*obar.get_amount(), AMOUNT);
        assert_eq!(*obar.get_asset_type(), ASSET);
    }

    #[test]
    fn abar_1in_1out_1asset() {
        let fee_amount = mock_fee(1, 1);
        let outputs = vec![(1, FEE_TYPE)];
        let inputs = vec![(fee_amount as u64 + 1, FEE_TYPE)];
        test_abar(inputs, outputs, fee_amount, "abar-1-1-1");
    }

    #[test]
    fn abar_1in_2out_1asset() {
        let fee_amount = mock_fee(1, 2);
        let outputs = vec![(1, FEE_TYPE), (0, FEE_TYPE)];
        let inputs = vec![(fee_amount as u64 + 1, FEE_TYPE)];
        test_abar(inputs, outputs, fee_amount, "abar-1-2-1");
    }

    #[test]
    fn abar_2in_1out_1asset() {
        let fee_amount = mock_fee(2, 1);
        let outputs = vec![(1, FEE_TYPE)];
        let inputs = vec![(1, FEE_TYPE), (fee_amount as u64, FEE_TYPE)];
        test_abar(inputs, outputs, fee_amount, "abar-2-1-1");
    }

    #[test]
    fn abar_6in_6out_1asset() {
        // supported max inputs and outputs
        let fee_amount = mock_fee(6, 6);
        let outputs = vec![
            (1, FEE_TYPE),
            (22, FEE_TYPE),
            (333, FEE_TYPE),
            (4444, FEE_TYPE),
            (55555, FEE_TYPE),
            (666666, FEE_TYPE),
        ];
        let inputs = vec![
            (1, FEE_TYPE),
            (22, FEE_TYPE),
            (333, FEE_TYPE),
            (4444, FEE_TYPE),
            (55555, FEE_TYPE),
            (666666 + fee_amount as u64, FEE_TYPE),
        ];
        test_abar(inputs, outputs, fee_amount, "abar-6-6-1");
    }

    #[test]
    fn abar_2in_3out_2asset() {
        let fee_amount = mock_fee(2, 3);
        let outputs = vec![(5, FEE_TYPE), (15, FEE_TYPE), (30, ASSET)];
        let inputs = vec![(20 + fee_amount as u64, FEE_TYPE), (30, ASSET)];
        test_abar(inputs, outputs, fee_amount, "abar-2-3-2");
    }

    #[test]
    fn abar_6in_6out_6asset() {
        // supported max inputs and outputs and assets
        let fee_amount = mock_fee(6, 6);
        let outputs = vec![
            (1, FEE_TYPE),
            (22, ASSET),
            (333, ASSET3),
            (4444, ASSET4),
            (55555, ASSET5),
            (666666, ASSET6),
        ];
        let inputs = vec![
            (1 + fee_amount as u64, FEE_TYPE),
            (22, ASSET),
            (333, ASSET3),
            (4444, ASSET4),
            (55555, ASSET5),
            (666666, ASSET6),
        ];
        test_abar(inputs, outputs, fee_amount, "abar-6-6-6");
    }

    fn test_abar(
        inputs: Vec<(u64, AssetType)>,
        outputs: Vec<(u64, AssetType)>,
        fee: u32,
        name: &str,
    ) {
        let mut prng = ChaChaRng::from_entropy();
        let params = ProverParams::new(inputs.len(), outputs.len(), None).unwrap();
        let verifier_params = VerifierParams::load(inputs.len(), outputs.len()).unwrap();

        let sender = AXfrKeyPair::generate(&mut prng);
        let receivers: Vec<AXfrKeyPair> = (0..outputs.len())
            .map(|_| AXfrKeyPair::generate(&mut prng))
            .collect();

        let mut oabars: Vec<OpenAnonAssetRecord> = inputs
            .iter()
            .map(|input| build_oabar(&mut prng, input.0, input.1, &sender))
            .collect();
        let abars: Vec<_> = oabars.iter().map(AnonAssetRecord::from_oabar).collect();

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, name.to_owned(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();
        let mut uids = vec![];
        for i in 0..abars.len() {
            let abar_comm = hash_abar(mt.entry_count(), &abars[i]);
            uids.push(mt.add_commitment_hash(abar_comm).unwrap());
        }
        mt.commit().unwrap();
        let root = mt.get_root().unwrap();
        for (i, uid) in uids.iter().enumerate() {
            let proof = mt.generate_proof(*uid).unwrap();
            oabars[i].update_mt_leaf_info(build_mt_leaf_info_from_proof(proof, *uid));
        }

        let oabars_out: Vec<OpenAnonAssetRecord> = outputs
            .iter()
            .enumerate()
            .map(|(i, output)| build_oabar(&mut prng, output.0, output.1, &receivers[i]))
            .collect();

        let pre_note = init_anon_xfr_note(&oabars, &oabars_out, fee, &sender).unwrap();
        let hash = random_hasher(&mut prng);
        let note = finish_anon_xfr_note(&mut prng, &params, pre_note, hash.clone()).unwrap();

        verify_anon_xfr_note(&verifier_params, &note, &root, hash.clone()).unwrap();

        // check abar
        for i in 0..note.body.outputs.len() {
            let oabar = OpenAnonAssetRecordBuilder::from_abar(
                &note.body.outputs[i],
                note.body.owner_memos[i].clone(),
                &receivers[i],
            )
            .unwrap()
            .build()
            .unwrap();
            assert_eq!(oabars_out[i].get_amount(), oabar.get_amount());
            assert_eq!(oabars_out[i].get_asset_type(), oabar.get_asset_type());
        }
    }
}
