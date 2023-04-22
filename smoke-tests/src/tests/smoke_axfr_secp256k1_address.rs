#[cfg(test)]
mod smoke_axfr_secp256k1_address {
    use digest::Digest;
    use mem_db::MemoryDB;
    use noah::parameters::params::{ProverParams, VerifierParams};
    use noah::parameters::AddressFormat::SECP256K1;
    use noah::{
        anon_xfr::{
            abar_to_ar::*,
            abar_to_bar::*,
            ar_to_abar::*,
            bar_to_abar::*,
            structs::{
                AnonAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonAssetRecord,
                OpenAnonAssetRecordBuilder,
            },
        },
        keys::{KeyPair, PublicKey},
        xfr::{
            asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType},
            structs::{
                AssetRecordTemplate, AssetType, BlindAssetRecord, OwnerMemo, ASSET_TYPE_LENGTH,
            },
        },
    };
    use noah_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
    use noah_algebra::{bls12_381::BLSScalar, prelude::*, ristretto::PedersenCommitmentRistretto};
    use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381};
    use parking_lot::RwLock;
    use sha2::Sha512;
    use std::sync::Arc;
    use storage::{
        state::{ChainState, State},
        store::PrefixedStore,
    };

    const AMOUNT: u64 = 10u64;
    const ASSET: AssetType = AssetType([1u8; ASSET_TYPE_LENGTH]);

    fn build_bar<R: RngCore + CryptoRng>(
        pubkey: &PublicKey,
        prng: &mut R,
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
        keypair: &KeyPair,
    ) -> OpenAnonAssetRecord {
        OpenAnonAssetRecordBuilder::new()
            .amount(amount)
            .asset_type(asset_type)
            .pub_key(&keypair.get_pk())
            .finalize(prng)
            .unwrap()
            .build()
            .unwrap()
    }

    fn hash_abar(uid: u64, abar: &AnonAssetRecord) -> BLSScalar {
        AnemoiJive381::eval_variable_length_hash(&[BLSScalar::from(uid), abar.commitment])
    }

    fn build_mt_leaf_info_from_proof(proof: Proof, uid: u64) -> MTLeafInfo {
        return MTLeafInfo {
            path: MTPath {
                nodes: proof
                    .nodes
                    .iter()
                    .map(|e| MTNode {
                        left: e.left,
                        mid: e.mid,
                        right: e.right,
                        is_left_child: (e.path == TreePath::Left) as u8,
                        is_mid_child: (e.path == TreePath::Middle) as u8,
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

    #[test]
    fn secp256k1_to_abar() {
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();
        let params = ProverParams::gen_bar_to_abar().unwrap();
        let verify_params = VerifierParams::get_bar_to_abar().unwrap();

        let sender = KeyPair::sample(&mut prng, SECP256K1);
        let receiver = KeyPair::sample(&mut prng, SECP256K1);

        let (bar, memo) = build_bar(
            &sender.get_pk(),
            &mut prng,
            &pc_gens,
            AMOUNT,
            ASSET,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        );
        let obar = open_blind_asset_record(&bar, &memo, &sender).unwrap();

        let note =
            gen_bar_to_abar_note(&mut prng, &params, &obar, &sender, &receiver.get_pk()).unwrap();
        assert!(verify_bar_to_abar_note(&verify_params, &note, &sender.get_pk()).is_ok());
        let mut note = note;
        let message = b"error_message";
        let bad_sig = sender.sign(message).unwrap();
        note.signature = bad_sig;
        assert!(verify_bar_to_abar_note(&verify_params, &note, &sender.get_pk()).is_err());

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
    fn address_to_abar() {
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();
        let params = ProverParams::gen_ar_to_abar().unwrap();
        let verify_params = VerifierParams::get_ar_to_abar().unwrap();

        let sender = KeyPair::sample_address(&mut prng);
        let receiver = KeyPair::sample(&mut prng, SECP256K1);

        let (bar, memo) = build_bar(
            &sender.get_pk(),
            &mut prng,
            &pc_gens,
            AMOUNT,
            ASSET,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        );
        let obar = open_blind_asset_record(&bar, &memo, &sender).unwrap();

        let note =
            gen_ar_to_abar_note(&mut prng, &params, &obar, &sender, &receiver.get_pk()).unwrap();
        verify_ar_to_abar_note(&verify_params, &note).unwrap();

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
    fn abar_to_address() {
        let mut prng = test_rng();
        let params = ProverParams::gen_abar_to_ar(SECP256K1).unwrap();
        let verify_params = VerifierParams::get_abar_to_ar(SECP256K1).unwrap();

        let sender = KeyPair::sample(&mut prng, SECP256K1);
        let receiver = KeyPair::sample_address(&mut prng);

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(
            fdb,
            "abar_address".to_owned(),
            0,
        )));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut oabar = build_oabar(&mut prng, AMOUNT, ASSET, &sender);
        let abar = AnonAssetRecord::from_oabar(&oabar);
        mt.add_commitment_hash(hash_abar(0, &abar)).unwrap();
        mt.commit().unwrap();
        let proof = mt.generate_proof(0).unwrap();
        oabar.update_mt_leaf_info(build_mt_leaf_info_from_proof(proof.clone(), 0));

        let pre_note =
            init_abar_to_ar_note(&mut prng, &oabar, &sender, &receiver.get_pk()).unwrap();
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
    fn abar_to_secp256k1() {
        let mut prng = test_rng();
        let params = ProverParams::gen_abar_to_bar(SECP256K1).unwrap();
        let verify_params = VerifierParams::get_abar_to_bar(SECP256K1).unwrap();

        let sender = KeyPair::sample(&mut prng, SECP256K1);
        let receiver = KeyPair::sample(&mut prng, SECP256K1);

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(
            fdb,
            "abar_secp256k1".to_owned(),
            0,
        )));
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
            &receiver.get_pk(),
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
}
