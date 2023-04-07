#[cfg(test)]
mod smoke_axfr_wasm {
    use digest::Digest;
    use noah::anon_xfr::init_anon_xfr;
    use noah::{
        anon_xfr::{
            abar_to_abar::*,
            abar_to_ar::*,
            abar_to_bar::*,
            ar_to_abar::*,
            bar_to_abar::*,
            structs::{
                AnonAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonAssetRecord,
                OpenAnonAssetRecordBuilder,
            },
            FEE_TYPE, TREE_DEPTH,
        },
        keys::{KeyPair, PublicKey},
        setup::{ProverParams, VerifierParams},
        xfr::{
            asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType},
            structs::{
                AssetRecordTemplate, AssetType, BlindAssetRecord, OwnerMemo, ASSET_TYPE_LENGTH,
            },
        },
    };
    use noah_accumulators::merkle_tree::{EphemeralMerkleTree, Proof, TreePath};
    use noah_algebra::{bls12_381::BLSScalar, prelude::*, ristretto::PedersenCommitmentRistretto};
    use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;
    use sha2::Sha512;
    use wasm_bindgen_test::*;

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
            uid,
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

    #[wasm_bindgen_test]
    async fn ar_to_abar_secp256k1() {
        init_anon_xfr().await.unwrap();

        let seed: [u8; 32] = [0u8; 32];
        let mut prng = ChaChaRng::from_seed(seed);
        let sender = KeyPair::generate_secp256k1(&mut prng);
        let receiver = KeyPair::generate_secp256k1(&mut prng);
        ar_to_abar(sender, receiver);
    }

    fn ar_to_abar(sender: KeyPair, receiver: KeyPair) {
        let seed: [u8; 32] = [0u8; 32];
        let mut prng = ChaChaRng::from_seed(seed);
        let pc_gens = PedersenCommitmentRistretto::default();
        let params = ProverParams::ar_to_abar_params().unwrap();
        let verify_params = VerifierParams::ar_to_abar_params().unwrap();

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
        assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok());
    }

    #[wasm_bindgen_test]
    async fn bar_to_abar_secp256k1() {
        init_anon_xfr().await.unwrap();

        let seed: [u8; 32] = [0u8; 32];
        let mut prng = ChaChaRng::from_seed(seed);
        let sender = KeyPair::generate_secp256k1(&mut prng);
        let receiver = KeyPair::generate_secp256k1(&mut prng);
        bar_to_abar(sender, receiver);
    }

    fn bar_to_abar(sender: KeyPair, receiver: KeyPair) {
        let seed: [u8; 32] = [0u8; 32];
        let mut prng = ChaChaRng::from_seed(seed);
        let pc_gens = PedersenCommitmentRistretto::default();
        let params = ProverParams::bar_to_abar_params().unwrap();
        let verify_params = VerifierParams::bar_to_abar_params().unwrap();

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

        let mut err_note = note.clone();
        let message = b"error_message";
        let bad_sig = sender.sign(message).unwrap();
        err_note.signature = bad_sig;
        assert!(verify_bar_to_abar_note(&verify_params, &err_note, &sender.get_pk()).is_err());
    }

    #[wasm_bindgen_test]
    async fn abar_to_ar_secp256k1() {
        init_anon_xfr().await.unwrap();

        let seed: [u8; 32] = [0u8; 32];
        let mut prng = ChaChaRng::from_seed(seed);
        let sender = KeyPair::generate_secp256k1(&mut prng);
        let receiver = KeyPair::generate_secp256k1(&mut prng);
        abar_to_ar(sender, receiver);
    }

    fn abar_to_ar(sender: KeyPair, receiver: KeyPair) {
        let seed: [u8; 32] = [0u8; 32];
        let mut prng = ChaChaRng::from_seed(seed);
        let params = ProverParams::abar_to_ar_params(TREE_DEPTH).unwrap();
        let verify_params = VerifierParams::abar_to_ar_params().unwrap();

        let mut mt = EphemeralMerkleTree::new().unwrap();

        let mut oabar = build_oabar(&mut prng, AMOUNT, ASSET, &sender);
        let abar = AnonAssetRecord::from_oabar(&oabar);
        mt.add_commitment_hash(hash_abar(0, &abar)).unwrap();
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
        assert!(
            verify_abar_to_ar_note(&verify_params, &note, &proof.root, err_hash.clone()).is_err()
        );

        let mut err_nullifier = note.clone();
        err_nullifier.body.input = BLSScalar::random(&mut prng);
        assert!(
            verify_abar_to_ar_note(&verify_params, &err_nullifier, &proof.root, hash.clone())
                .is_err()
        );
    }

    #[wasm_bindgen_test]
    async fn abar_to_bar_secp256k1() {
        init_anon_xfr().await.unwrap();

        let seed: [u8; 32] = [0u8; 32];
        let mut prng = ChaChaRng::from_seed(seed);
        let sender = KeyPair::generate_secp256k1(&mut prng);
        let receiver = KeyPair::generate_secp256k1(&mut prng);
        abar_to_bar(sender, receiver);
    }

    fn abar_to_bar(sender: KeyPair, receiver: KeyPair) {
        let seed: [u8; 32] = [0u8; 32];
        let mut prng = ChaChaRng::from_seed(seed);
        let params = ProverParams::abar_to_bar_params(TREE_DEPTH).unwrap();
        let verify_params = VerifierParams::abar_to_bar_params().unwrap();

        let mut mt = EphemeralMerkleTree::new().unwrap();

        let mut oabar = build_oabar(&mut prng, AMOUNT, ASSET, &sender);
        let abar = AnonAssetRecord::from_oabar(&oabar);
        mt.add_commitment_hash(hash_abar(0, &abar)).unwrap(); // mock
        mt.add_commitment_hash(hash_abar(1, &abar)).unwrap();
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
        assert!(
            verify_abar_to_bar_note(&verify_params, &note, &proof.root, err_hash.clone()).is_err()
        );

        let mut err_nullifier = note.clone();
        err_nullifier.body.input = BLSScalar::random(&mut prng);
        assert!(
            verify_abar_to_bar_note(&verify_params, &err_nullifier, &proof.root, hash.clone())
                .is_err()
        );
    }

    #[wasm_bindgen_test]
    async fn abar_2in_1out_1asset() {
        init_anon_xfr().await.unwrap();

        let fee_amount = mock_fee(2, 1);
        let outputs = vec![(1, FEE_TYPE)];
        let inputs = vec![(1, FEE_TYPE), (fee_amount as u64, FEE_TYPE)];
        test_abar(inputs, outputs, fee_amount);
    }

    fn test_abar(inputs: Vec<(u64, AssetType)>, outputs: Vec<(u64, AssetType)>, fee: u32) {
        let seed: [u8; 32] = [0u8; 32];
        let mut prng = ChaChaRng::from_seed(seed);
        let params = ProverParams::new(inputs.len(), outputs.len(), None).unwrap();
        let verifier_params = VerifierParams::load(inputs.len(), outputs.len()).unwrap();

        let sender = if prng.gen() {
            KeyPair::generate_secp256k1(&mut prng)
        } else {
            KeyPair::generate_ed25519(&mut prng)
        };
        let receivers: Vec<KeyPair> = (0..outputs.len())
            .map(|_| {
                if prng.gen() {
                    KeyPair::generate_secp256k1(&mut prng)
                } else {
                    KeyPair::generate_ed25519(&mut prng)
                }
            })
            .collect();

        let mut oabars: Vec<OpenAnonAssetRecord> = inputs
            .iter()
            .map(|input| build_oabar(&mut prng, input.0, input.1, &sender))
            .collect();
        let abars: Vec<_> = oabars.iter().map(AnonAssetRecord::from_oabar).collect();

        let mut mt = EphemeralMerkleTree::new().unwrap();
        let mut uids = vec![];
        for i in 0..abars.len() {
            let abar_comm = hash_abar(mt.entry_count(), &abars[i]);
            uids.push(mt.add_commitment_hash(abar_comm).unwrap());
        }
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
    }
}
