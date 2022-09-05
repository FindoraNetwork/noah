#[cfg(test)]
mod smoke_xfr_identity {
    use rand_chacha::ChaChaRng;
    use wasm_bindgen::__rt::std::collections::HashMap;
    use zei::{
        anon_creds::{self, ac_commit, ac_sign, ac_verify_commitment, Attr, Credential},
        setup::BulletproofParams,
        xfr::{
            asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType},
            gen_xfr_note,
            sig::{XfrKeyPair, XfrPublicKey},
            structs::{
                AssetRecord, AssetRecordTemplate, AssetTracerKeyPair, AssetType, BlindAssetRecord,
                IdentityRevealPolicy, OwnerMemo, TracingPolicies, TracingPolicy, ASSET_TYPE_LENGTH,
            },
            trace_assets, verify_xfr_note, RecordData, XfrNotePoliciesRef,
        },
    };
    use zei_algebra::prelude::*;
    use zei_crypto::basic::pedersen_comm::PedersenCommitmentRistretto;

    const ASSET1_TYPE: AssetType = AssetType([0u8; ASSET_TYPE_LENGTH]);

    fn conf_blind_asset_record_from_ledger(
        key: &XfrPublicKey,
        amount: u64,
        asset_type: AssetType,
    ) -> (BlindAssetRecord, OwnerMemo) {
        let mut prng = ChaChaRng::from_seed([1u8; 32]);
        let template = AssetRecordTemplate {
            amount,
            asset_type,
            public_key: key.clone(),
            asset_record_type: AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            asset_tracing_policies: Default::default(),
        };
        let (bar, _, owner) = build_blind_asset_record(
            &mut prng,
            &PedersenCommitmentRistretto::default(),
            &template,
            vec![],
        );

        (bar, owner.unwrap())
    }

    fn check_record_data(
        record_data: &RecordData,
        expected_amount: u64,
        expected_asset_type: AssetType,
        expected_ids: Vec<Attr>,
        expected_pk: &XfrPublicKey,
    ) {
        assert_eq!(record_data.0, expected_amount);
        assert_eq!(record_data.1, expected_asset_type);
        assert_eq!(record_data.2, expected_ids);
        assert_eq!(record_data.3, *expected_pk);
    }

    #[test]
    #[allow(non_snake_case)]
    fn bar_identity_on_inputs() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let mut params = BulletproofParams::default();
        let mut AIR: HashMap<Vec<u8>, _> = HashMap::new();

        let amount_in1 = 50u64;
        let amount_in2 = 75u64;
        let amount_out1 = 125u64;

        let sender1 = XfrKeyPair::generate(&mut prng);
        let sender2 = XfrKeyPair::generate(&mut prng);
        let receiver1 = XfrKeyPair::generate(&mut prng);

        // create credential keys
        let (cred_issuer_sk, cred_issuer_pk) = anon_creds::ac_keygen_issuer(&mut prng, 4);
        let (user1_ac_sk, user1_ac_pk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
        let (user2_ac_sk, user2_ac_pk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);

        // setup policy
        let tracer_keys = AssetTracerKeyPair::generate(&mut prng);
        let id_policy_policy = IdentityRevealPolicy {
            cred_issuer_pub_key: cred_issuer_pk.clone(),
            reveal_map: vec![true, true, false, false], // reveal first two attributes
        };
        let policy = TracingPolicy {
            enc_keys: tracer_keys.enc_key.clone(),
            asset_tracing: true,                      // do asset tracing
            identity_tracing: Some(id_policy_policy), // do not trace identity
        };
        let policies = TracingPolicies::from_policy(policy);
        let no_policies = TracingPolicies::new();

        // credential for input senders
        let user1_attr = vec![1u32, 2u32, 3u32, 4u32];
        let user2_attr = vec![11u32, 22u32, 33u32, 44u32];
        let cred_sig_user1 = ac_sign(&mut prng, &cred_issuer_sk, &user1_ac_pk, &user1_attr);
        let cred_sig_user2 = ac_sign(&mut prng, &cred_issuer_sk, &user2_ac_pk, &user2_attr);
        let credential_user1 = Credential {
            sig: cred_sig_user1.unwrap(),
            attrs: user1_attr,
            ipk: cred_issuer_pk.clone(),
        };
        let credential_user2 = Credential {
            sig: cred_sig_user2.unwrap(),
            attrs: user2_attr,
            ipk: cred_issuer_pk.clone(),
        };

        // credential commitments
        let (commitment_user1, proof_user1, commitment_key_user1) = ac_commit(
            &mut prng,
            &user1_ac_sk,
            &credential_user1,
            &sender1.pub_key.to_bytes(),
        )
        .unwrap();
        let (commitment_user2, proof_user2, commitment_key_user2) = ac_commit(
            &mut prng,
            &user2_ac_sk,
            &credential_user2,
            &sender2.pub_key.to_bytes(),
        )
        .unwrap();

        // verifying commitment and put them on AIR
        assert!(ac_verify_commitment(
            &cred_issuer_pk,
            &commitment_user1,
            &proof_user1,
            &sender1.pub_key.to_bytes()
        )
        .is_ok());
        AIR.insert(sender1.pub_key.to_bytes().to_vec(), commitment_user1);
        assert!(ac_verify_commitment(
            &cred_issuer_pk,
            &commitment_user2,
            &proof_user2,
            &sender2.pub_key.to_bytes()
        )
        .is_ok());
        AIR.insert(sender2.pub_key.to_bytes().to_vec(), commitment_user2);

        // prepare input AssetRecord
        let (bar1, memo1) =
            conf_blind_asset_record_from_ledger(&sender1.pub_key, amount_in1, ASSET1_TYPE);
        let oar1 = open_blind_asset_record(&bar1, &Some(memo1), &sender1).unwrap();
        let (bar2, memo2) =
            conf_blind_asset_record_from_ledger(&sender2.pub_key, amount_in2, ASSET1_TYPE);
        let oar2 = open_blind_asset_record(&bar2, &Some(memo2), &sender2).unwrap();

        let ar_in1 = AssetRecord::from_open_asset_record_with_tracing(
            &mut prng,
            oar1,
            policies.clone(),
            &user1_ac_sk,
            &credential_user1,
            &commitment_key_user1.unwrap(),
        )
        .unwrap();
        let ar_in2 = AssetRecord::from_open_asset_record_with_tracing(
            &mut prng,
            oar2,
            policies.clone(),
            &user2_ac_sk,
            &credential_user2,
            &commitment_key_user2.unwrap(),
        )
        .unwrap();

        // prepare output AssetRecord
        let template = AssetRecordTemplate::with_no_asset_tracing(
            amount_out1,
            ASSET1_TYPE,
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            receiver1.pub_key,
        );
        let ar_out = AssetRecord::from_template_no_identity_tracing(&mut prng, &template).unwrap();

        // create xfr_note
        let xfr_note = gen_xfr_note(
            &mut prng,
            &[ar_in1, ar_in2],
            &[ar_out],
            &[&sender1, &sender2],
        )
        .unwrap();

        // verify
        let policies = XfrNotePoliciesRef::new(
            vec![&policies, &policies],
            vec![
                Some(&AIR[&xfr_note.body.inputs[0].public_key.to_bytes().to_vec()]),
                Some(&AIR[&xfr_note.body.inputs[1].public_key.to_bytes().to_vec()]),
            ],
            vec![&no_policies],
            vec![None],
        );
        assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies).is_ok());

        // check
        let recv_bar1 = &xfr_note.body.outputs[0];
        let recv_memo1 = &xfr_note.body.owners_memos[0];
        let recv_oar1 = open_blind_asset_record(recv_bar1, recv_memo1, &receiver1).unwrap();
        assert!(recv_memo1.is_some());
        assert!(recv_bar1.amount.is_confidential());
        assert!(!recv_bar1.asset_type.is_confidential());
        assert_eq!(recv_oar1.asset_type, ASSET1_TYPE);
        assert_eq!(recv_oar1.amount, amount_out1);
        assert_eq!(recv_oar1.blind_asset_record.public_key, receiver1.pub_key);

        // check asset tracing on inputs
        assert_eq!(xfr_note.body.asset_tracing_memos.len(), 3);
        assert_eq!(xfr_note.body.asset_tracing_memos[0].len(), 1);
        assert_eq!(xfr_note.body.asset_tracing_memos[1].len(), 1);
        assert_eq!(xfr_note.body.asset_tracing_memos[2].len(), 0);

        let records_data = trace_assets(&xfr_note.body, &tracer_keys).unwrap();
        assert_eq!(records_data.len(), 2);
        check_record_data(
            &records_data[0],
            amount_in1,
            ASSET1_TYPE,
            vec![1u32, 2],
            &sender1.pub_key,
        );
        check_record_data(
            &records_data[1],
            amount_in2,
            ASSET1_TYPE,
            vec![11u32, 22],
            &sender2.pub_key,
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn bar_identity_on_outputs() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let mut params = BulletproofParams::default();
        let mut AIR: HashMap<Vec<u8>, _> = HashMap::new();

        let amount_in1 = 100u64;
        let amount_out1 = 75u64;
        let amount_out2 = 25u64;

        let sender1 = XfrKeyPair::generate(&mut prng);
        let receiver1 = XfrKeyPair::generate(&mut prng);
        let receiver2 = XfrKeyPair::generate(&mut prng);

        // credential keys
        let (cred_issuer_sk, cred_issuer_pk) = anon_creds::ac_keygen_issuer(&mut prng, 4);
        let (recv_user1_ac_sk, recv_user1_ac_pk) =
            anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
        let (recv_user2_ac_sk, recv_user2_ac_pk) =
            anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);

        // setup policy
        let tracer_keys = AssetTracerKeyPair::generate(&mut prng);
        let id_policy_policy = IdentityRevealPolicy {
            cred_issuer_pub_key: cred_issuer_pk.clone(),
            reveal_map: vec![false, true, true, true], // reveal last three attributes
        };
        let policy = TracingPolicy {
            enc_keys: tracer_keys.enc_key.clone(),
            asset_tracing: true,                      // do asset tracing
            identity_tracing: Some(id_policy_policy), // do not trace identity
        };
        let policies = TracingPolicies::from_policy(policy);
        let no_policy = TracingPolicies::new();

        // credential for receivers
        let recv1_attr = vec![1u32, 2u32, 3u32, 4u32];
        let recv2_attr = vec![11u32, 22u32, 33u32, 44u32];
        let cred_sig_user1 =
            ac_sign(&mut prng, &cred_issuer_sk, &recv_user1_ac_pk, &recv1_attr).unwrap();
        let cred_sig_user2 =
            ac_sign(&mut prng, &cred_issuer_sk, &recv_user2_ac_pk, &recv2_attr).unwrap();
        let credential_user1 = Credential {
            sig: cred_sig_user1,
            attrs: recv1_attr,
            ipk: cred_issuer_pk.clone(),
        };
        let credential_user2 = Credential {
            sig: cred_sig_user2,
            attrs: recv2_attr,
            ipk: cred_issuer_pk.clone(),
        };

        // credential commitments
        let (commitment_user1, proof_user1, commitment_key_user1) = ac_commit(
            &mut prng,
            &recv_user1_ac_sk,
            &credential_user1,
            &receiver1.pub_key.to_bytes(),
        )
        .unwrap();
        let (commitment_user2, proof_user2, commitment_key_user2) = ac_commit(
            &mut prng,
            &recv_user2_ac_sk,
            &credential_user2,
            &receiver2.pub_key.to_bytes(),
        )
        .unwrap();

        // verifying commitment and put them on AIR
        assert!(ac_verify_commitment(
            &cred_issuer_pk,
            &commitment_user1,
            &proof_user1,
            &receiver1.pub_key.to_bytes()
        )
        .is_ok());
        AIR.insert(receiver1.pub_key.to_bytes().to_vec(), commitment_user1);
        assert!(ac_verify_commitment(
            &cred_issuer_pk,
            &commitment_user2,
            &proof_user2,
            &receiver2.pub_key.to_bytes()
        )
        .is_ok());
        AIR.insert(receiver2.pub_key.to_bytes().to_vec(), commitment_user2);

        // prepare input AssetRecord
        let (bar1, memo1) =
            conf_blind_asset_record_from_ledger(&sender1.pub_key, amount_in1, ASSET1_TYPE);
        let oar1 = open_blind_asset_record(&bar1, &Some(memo1), &sender1).unwrap();
        let ar_in = AssetRecord::from_open_asset_record_no_asset_tracing(oar1);

        // prepare output AssetRecord
        let template1 = AssetRecordTemplate::with_asset_tracing(
            amount_out1,
            ASSET1_TYPE,
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            receiver1.pub_key,
            policies.clone(),
        );
        let template2 = AssetRecordTemplate::with_asset_tracing(
            amount_out2,
            ASSET1_TYPE,
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            receiver2.pub_key,
            policies.clone(),
        );
        let ar_out1 = AssetRecord::from_template_with_identity_tracing(
            &mut prng,
            &template1,
            &recv_user1_ac_sk,
            &credential_user1,
            &commitment_key_user1.unwrap(),
        )
        .unwrap();
        let ar_out2 = AssetRecord::from_template_with_identity_tracing(
            &mut prng,
            &template2,
            &recv_user2_ac_sk,
            &credential_user2,
            &commitment_key_user2.unwrap(),
        )
        .unwrap();

        // create xfr_note
        let xfr_note = gen_xfr_note(&mut prng, &[ar_in], &[ar_out1, ar_out2], &[&sender1]).unwrap();

        // verify
        let policies = XfrNotePoliciesRef::new(
            vec![&no_policy],
            vec![None],
            vec![&policies, &policies],
            vec![
                Some(&AIR[&xfr_note.body.outputs[0].public_key.to_bytes().to_vec()]),
                Some(&AIR[&xfr_note.body.outputs[1].public_key.to_bytes().to_vec()]),
            ],
        );
        assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies).is_ok());

        // check
        let recv_bar1 = &xfr_note.body.outputs[0];
        let recv_memo1 = &xfr_note.body.owners_memos[0];
        let recv_oar1 = open_blind_asset_record(recv_bar1, recv_memo1, &receiver1).unwrap();
        assert!(recv_memo1.is_some());
        assert!(recv_bar1.amount.is_confidential());
        assert!(!recv_bar1.asset_type.is_confidential());
        assert_eq!(recv_oar1.asset_type, ASSET1_TYPE);
        assert_eq!(recv_oar1.amount, amount_out1);
        assert_eq!(recv_oar1.blind_asset_record.public_key, receiver1.pub_key);

        let recv_bar2 = &xfr_note.body.outputs[1];
        let recv_memo2 = &xfr_note.body.owners_memos[1];
        let recv_oar2 = open_blind_asset_record(recv_bar2, recv_memo2, &receiver2).unwrap();
        assert!(recv_memo2.is_some());
        assert!(recv_bar2.amount.is_confidential());
        assert!(!recv_bar2.asset_type.is_confidential());
        assert_eq!(recv_oar2.asset_type, ASSET1_TYPE);
        assert_eq!(recv_oar2.amount, amount_out2);
        assert_eq!(recv_oar2.blind_asset_record.public_key, receiver2.pub_key);

        // check asset tracing
        assert_eq!(xfr_note.body.asset_tracing_memos.len(), 3);
        assert_eq!(xfr_note.body.asset_tracing_memos[0].len(), 0);
        assert_eq!(xfr_note.body.asset_tracing_memos[1].len(), 1);
        assert_eq!(xfr_note.body.asset_tracing_memos[2].len(), 1);

        let records_data = trace_assets(&xfr_note.body, &tracer_keys).unwrap();

        assert_eq!(records_data.len(), 2);
        check_record_data(
            &records_data[0],
            amount_out1,
            ASSET1_TYPE,
            vec![2u32, 3, 4],
            &receiver1.pub_key,
        );
        check_record_data(
            &records_data[1],
            amount_out2,
            ASSET1_TYPE,
            vec![22u32, 33, 44],
            &receiver2.pub_key,
        );
    }
}
