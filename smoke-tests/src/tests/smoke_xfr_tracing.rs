#[cfg(test)]
mod smoke_xfr_tracing {
    use noah::parameters::bulletproofs::BulletproofParams;
    use noah::parameters::AddressFormat::SECP256K1;
    use noah::{
        keys::{KeyPair, PublicKey},
        xfr::{
            asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType},
            gen_xfr_note,
            structs::{
                AssetRecord, AssetRecordTemplate, AssetTracerKeyPair, AssetType, BlindAssetRecord,
                OwnerMemo, TracingPolicies, TracingPolicy, ASSET_TYPE_LENGTH,
            },
            trace_assets, verify_xfr_note, RecordData, XfrNotePoliciesRef,
        },
    };
    use noah_algebra::{prelude::*, ristretto::PedersenCommitmentRistretto};

    const ASSET1_TYPE: AssetType = AssetType([0u8; ASSET_TYPE_LENGTH]);

    /// Simulate getting a BlindAssetRecord from Ledger
    fn conf_blind_asset_record_from_ledger(
        key: &PublicKey,
        amount: u64,
        asset_type: AssetType,
    ) -> (BlindAssetRecord, OwnerMemo) {
        let mut prng = test_rng();
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
        expected_pk: &PublicKey,
    ) {
        assert_eq!(record_data.0, expected_amount);
        assert_eq!(record_data.1, expected_asset_type);
        assert_eq!(record_data.3, *expected_pk);
    }

    #[test]
    fn bar_tracing_on_inputs() {
        let mut prng = test_rng();
        let mut params = BulletproofParams::default();

        let amount_in1 = 50u64;
        let amount_in2 = 75u64;
        let amount_out1 = 100u64;
        let amount_out2 = 25u64;

        let sender1 = KeyPair::sample(&mut prng, SECP256K1);
        let sender2 = KeyPair::sample(&mut prng, SECP256K1);
        let receiver1 = KeyPair::sample(&mut prng, SECP256K1);
        let receiver2 = KeyPair::sample(&mut prng, SECP256K1);

        // setup policy
        let tracer_keys = AssetTracerKeyPair::generate(&mut prng);
        let policy = TracingPolicy {
            enc_keys: tracer_keys.enc_key.clone(),
            asset_tracing: true,    // do asset tracing
            identity_tracing: None, // do not trace identity
        };
        let policies = TracingPolicies::from_policy(policy);
        let no_policy = TracingPolicies::new();

        // fake and build input blind_asset_record with associated policy
        let (bar_in1, memo1) =
            conf_blind_asset_record_from_ledger(&sender1.get_pk(), amount_in1, ASSET1_TYPE);
        let (bar_in2, memo2) =
            conf_blind_asset_record_from_ledger(&sender2.get_pk(), amount_in2, ASSET1_TYPE);

        let oar_in1 = open_blind_asset_record(&bar_in1, &Some(memo1), &sender1).unwrap();
        let oar_in2 = open_blind_asset_record(&bar_in2, &Some(memo2), &sender2).unwrap();

        let ar_in1 = AssetRecord::from_open_asset_record_with_asset_tracing_but_no_identity(
            &mut prng,
            oar_in1,
            policies.clone(),
        )
        .unwrap();
        let ar_in2 = AssetRecord::from_open_asset_record_with_asset_tracing_but_no_identity(
            &mut prng,
            oar_in2,
            policies.clone(),
        )
        .unwrap();

        // prepare output AssetRecord
        let template_out1 = AssetRecordTemplate::with_no_asset_tracing(
            amount_out1,
            ASSET1_TYPE,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            receiver1.get_pk(),
        );
        let template_out2 = AssetRecordTemplate::with_no_asset_tracing(
            amount_out2,
            ASSET1_TYPE,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            receiver2.get_pk(),
        );

        let ar_out1 =
            AssetRecord::from_template_no_identity_tracing(&mut prng, &template_out1).unwrap();
        let ar_out2 =
            AssetRecord::from_template_no_identity_tracing(&mut prng, &template_out2).unwrap();

        // create xfr_note
        let xfr_note = gen_xfr_note(
            &mut prng,
            &[ar_in1, ar_in2],
            &[ar_out1, ar_out2],
            &[&sender1, &sender2],
        )
        .unwrap();

        // verify
        let policies = XfrNotePoliciesRef::new(
            vec![&policies; 2],
            vec![None; 2],
            vec![&no_policy; 2],
            vec![None; 2],
        );
        assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies).is_ok());

        // check
        let recv_bar1 = &xfr_note.body.outputs[0];
        let recv_memo1 = &xfr_note.body.owners_memos[0];
        let recv_oar1 = open_blind_asset_record(recv_bar1, recv_memo1, &receiver1).unwrap();
        assert!(recv_memo1.is_some());
        assert!(recv_bar1.amount.is_confidential());
        assert!(recv_bar1.asset_type.is_confidential());
        assert_eq!(recv_oar1.asset_type, ASSET1_TYPE);
        assert_eq!(recv_oar1.amount, amount_out1);
        assert_eq!(recv_oar1.blind_asset_record.public_key, receiver1.get_pk());

        let recv_bar2 = &xfr_note.body.outputs[1];
        let recv_memo2 = &xfr_note.body.owners_memos[1];
        let recv_oar2 = open_blind_asset_record(recv_bar2, recv_memo2, &receiver2).unwrap();
        assert!(recv_memo2.is_some());
        assert!(recv_bar2.amount.is_confidential());
        assert!(recv_bar2.asset_type.is_confidential());
        assert_eq!(recv_oar2.asset_type, ASSET1_TYPE);
        assert_eq!(recv_oar2.amount, amount_out2);
        assert_eq!(recv_oar2.blind_asset_record.public_key, receiver2.get_pk());

        // check asset tracing
        assert_eq!(xfr_note.body.asset_tracing_memos.len(), 4);
        assert_eq!(xfr_note.body.asset_tracing_memos[0].len(), 1);
        assert_eq!(xfr_note.body.asset_tracing_memos[1].len(), 1);
        assert_eq!(xfr_note.body.asset_tracing_memos[2].len(), 0);
        assert_eq!(xfr_note.body.asset_tracing_memos[3].len(), 0);

        let records_data = trace_assets(&xfr_note.body, &tracer_keys).unwrap();
        check_record_data(&records_data[0], amount_in1, ASSET1_TYPE, &sender1.get_pk());
        check_record_data(&records_data[1], amount_in2, ASSET1_TYPE, &sender2.get_pk());
    }

    #[test]
    fn bar_tracing_on_outputs() {
        let mut prng = test_rng();
        let mut params = BulletproofParams::default();

        let amount_in1 = 50u64;
        let amount_out1 = 30u64;
        let amount_out2 = 20u64;

        let sender1 = KeyPair::sample(&mut prng, SECP256K1);
        let receiver1 = KeyPair::sample(&mut prng, SECP256K1);
        let receiver2 = KeyPair::sample(&mut prng, SECP256K1);

        // instantiate issuer with public keys
        let asset_tracing_key_pair = AssetTracerKeyPair::generate(&mut prng);
        let asset_tracing_policy = TracingPolicy {
            enc_keys: asset_tracing_key_pair.enc_key.clone(), // publicly available
            asset_tracing: true,                              // encrypt record info to asset issuer
            identity_tracing: None,                           // no identity tracking
        };
        let policies = TracingPolicies::from_policy(asset_tracing_policy);
        let no_policy = TracingPolicies::new();

        // prepare input AssetRecord
        let (bar, memo) =
            conf_blind_asset_record_from_ledger(&sender1.get_pk(), amount_in1, ASSET1_TYPE);
        let oar = open_blind_asset_record(&bar, &Some(memo), &sender1).unwrap();
        let ar = AssetRecord::from_open_asset_record_no_asset_tracing(oar);

        // prepare output AssetRecord
        let template1 = AssetRecordTemplate::with_asset_tracing(
            amount_out1,
            ASSET1_TYPE,
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            receiver1.get_pk(),
            policies.clone(),
        );
        let template2 = AssetRecordTemplate::with_asset_tracing(
            amount_out2,
            ASSET1_TYPE,
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            receiver2.get_pk(),
            policies.clone(),
        );

        let ar_out1 =
            AssetRecord::from_template_no_identity_tracing(&mut prng, &template1).unwrap();
        let ar_out2 =
            AssetRecord::from_template_no_identity_tracing(&mut prng, &template2).unwrap();

        // create xfr_note
        let xfr_note = gen_xfr_note(&mut prng, &[ar], &[ar_out1, ar_out2], &[&sender1]).unwrap();

        // verify
        let policies = XfrNotePoliciesRef::new(
            vec![&no_policy],
            vec![None],
            vec![&policies; 2],
            vec![None; 2],
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
        assert_eq!(recv_oar1.blind_asset_record.public_key, receiver1.get_pk());

        let recv_bar2 = &xfr_note.body.outputs[1];
        let recv_memo2 = &xfr_note.body.owners_memos[1];
        let recv_oar2 = open_blind_asset_record(recv_bar2, recv_memo2, &receiver2).unwrap();
        assert!(recv_memo2.is_some());
        assert!(recv_bar2.amount.is_confidential());
        assert!(!recv_bar2.asset_type.is_confidential());
        assert_eq!(recv_oar2.asset_type, ASSET1_TYPE);
        assert_eq!(recv_oar2.amount, amount_out2);
        assert_eq!(recv_oar2.blind_asset_record.public_key, receiver2.get_pk());

        // check asset tracing
        assert_eq!(xfr_note.body.asset_tracing_memos.len(), 3);
        assert_eq!(xfr_note.body.asset_tracing_memos[0].len(), 0);
        assert_eq!(xfr_note.body.asset_tracing_memos[1].len(), 1);
        assert_eq!(xfr_note.body.asset_tracing_memos[2].len(), 1);

        let records_data = trace_assets(&xfr_note.body, &asset_tracing_key_pair).unwrap();
        check_record_data(
            &records_data[0],
            amount_out1,
            ASSET1_TYPE,
            &receiver1.get_pk(),
        );
        check_record_data(
            &records_data[1],
            amount_out2,
            ASSET1_TYPE,
            &receiver2.get_pk(),
        );
    }
}
