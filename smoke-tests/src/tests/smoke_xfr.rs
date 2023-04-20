#[cfg(test)]
mod smoke_xfr {
    use noah::parameters::bulletproofs::BulletproofParams;
    use noah::{
        keys::{KeyPair, PublicKey},
        xfr::{
            asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType},
            gen_xfr_note,
            structs::{
                AssetRecord, AssetRecordTemplate, AssetType, BlindAssetRecord, OwnerMemo,
                XfrAmount, XfrAssetType, ASSET_TYPE_LENGTH,
            },
            verify_xfr_note, XfrNotePolicies,
        },
    };
    use noah_algebra::{prelude::*, ristretto::PedersenCommitmentRistretto};

    const AMOUNT: u64 = 10u64;
    const ASSET1_TYPE: AssetType = AssetType([0u8; ASSET_TYPE_LENGTH]);
    const ASSET2_TYPE: AssetType = AssetType([1u8; ASSET_TYPE_LENGTH]);
    const ASSET3_TYPE: AssetType = AssetType([2u8; ASSET_TYPE_LENGTH]);

    // Simulate getting a BlindAssetRecord from Ledger
    fn non_conf_blind_asset_record_from_ledger(
        key: &PublicKey,
        amount: u64,
        asset_type: AssetType,
    ) -> BlindAssetRecord {
        BlindAssetRecord {
            amount: XfrAmount::NonConfidential(amount),
            asset_type: XfrAssetType::NonConfidential(asset_type),
            public_key: key.clone(),
        }
    }

    // Simulate getting a BlindAssetRecord from Ledger
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

    #[test]
    fn ar_1in_1out_1asset() {
        let mut prng = test_rng();
        let mut params = BulletproofParams::default();

        let sender = KeyPair::generate_secp256k1(&mut prng);
        let receiver = KeyPair::generate_secp256k1(&mut prng);

        // fake and build blind_asset_record from ledger
        let bar = non_conf_blind_asset_record_from_ledger(&sender.get_pk(), AMOUNT, ASSET1_TYPE);
        let oar = open_blind_asset_record(&bar, &None, &sender).unwrap();
        let ar = AssetRecord::from_open_asset_record_no_asset_tracing(oar);

        // prepare output AssetRecord
        let template = AssetRecordTemplate::with_no_asset_tracing(
            AMOUNT,
            ASSET1_TYPE,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            receiver.get_pk(),
        );
        let recv_ar = AssetRecord::from_template_no_identity_tracing(&mut prng, &template).unwrap();

        // create xfr_note
        let xfr_note = gen_xfr_note(&mut prng, &[ar], &[recv_ar], &[&sender]).unwrap();

        // verify
        let policies = XfrNotePolicies::empty_policies(1, 1);
        let policies_ref = policies.to_ref();
        assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies_ref).is_ok());

        // check
        let recv_bar = &xfr_note.body.outputs[0];
        let recv_memo = &xfr_note.body.owners_memos[0];
        let recv_oar = open_blind_asset_record(recv_bar, recv_memo, &receiver).unwrap();
        assert_eq!(recv_oar.asset_type, ASSET1_TYPE);
        assert_eq!(recv_oar.amount, AMOUNT);
        assert_eq!(recv_oar.blind_asset_record.public_key, receiver.get_pk());
    }

    #[test]
    fn bar_1in_1out_1asset() {
        let mut prng = test_rng();
        let mut params = BulletproofParams::default();

        let sender = KeyPair::generate_secp256k1(&mut prng);
        let receiver = KeyPair::generate_secp256k1(&mut prng);

        // fake and build blind_asset_record from ledger
        let bar = non_conf_blind_asset_record_from_ledger(&sender.get_pk(), AMOUNT, ASSET1_TYPE);
        let oar = open_blind_asset_record(&bar, &None, &sender).unwrap();
        let ar = AssetRecord::from_open_asset_record_no_asset_tracing(oar);

        // prepare output AssetRecord
        let template = AssetRecordTemplate::with_no_asset_tracing(
            AMOUNT,
            ASSET1_TYPE,
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            receiver.get_pk(),
        );
        let recv_ar = AssetRecord::from_template_no_identity_tracing(&mut prng, &template).unwrap();

        // create xfr_note
        let xfr_note = gen_xfr_note(&mut prng, &[ar], &[recv_ar], &[&sender]).unwrap();

        // verify
        let policies = XfrNotePolicies::empty_policies(1, 1);
        let policies_ref = policies.to_ref();
        assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies_ref).is_ok());

        // check
        let recv_bar = &xfr_note.body.outputs[0];
        let recv_memo = &xfr_note.body.owners_memos[0];
        let recv_oar = open_blind_asset_record(recv_bar, recv_memo, &receiver).unwrap();
        assert!(recv_memo.is_some());
        assert!(recv_bar.amount.is_confidential());
        assert_eq!(recv_oar.asset_type, ASSET1_TYPE);
        assert_eq!(recv_oar.amount, AMOUNT);
        assert_eq!(recv_oar.blind_asset_record.public_key, receiver.get_pk());
    }

    #[test]
    fn bar_3in_4out_3asset() {
        let mut prng = test_rng();
        let mut params = BulletproofParams::default();

        let amount_in1 = 100u64;
        let amount_in2 = 50u64;
        let amount_in3 = 20u64;
        let amount_out1 = 30u64;
        let amount_out2 = 70u64;
        let amount_out3 = 50u64;
        let amount_out4 = 20u64;

        let sender1 = KeyPair::generate_secp256k1(&mut prng);
        let sender2 = KeyPair::generate_secp256k1(&mut prng);
        let sender3 = KeyPair::generate_secp256k1(&mut prng);
        let receiver1 = KeyPair::generate_secp256k1(&mut prng);
        let receiver2 = KeyPair::generate_secp256k1(&mut prng);
        let receiver3 = KeyPair::generate_secp256k1(&mut prng);
        let receiver4 = KeyPair::generate_secp256k1(&mut prng);

        // fake and build blind_asset_record
        let (bar_in1, memo1) =
            conf_blind_asset_record_from_ledger(&sender1.get_pk(), amount_in1, ASSET1_TYPE);
        let (bar_in2, memo2) =
            conf_blind_asset_record_from_ledger(&sender2.get_pk(), amount_in2, ASSET2_TYPE);
        let (bar_in3, memo3) =
            conf_blind_asset_record_from_ledger(&sender3.get_pk(), amount_in3, ASSET3_TYPE);

        let oar_in1 = open_blind_asset_record(&bar_in1, &Some(memo1), &sender1).unwrap();
        let oar_in2 = open_blind_asset_record(&bar_in2, &Some(memo2), &sender2).unwrap();
        let oar_in3 = open_blind_asset_record(&bar_in3, &Some(memo3), &sender3).unwrap();

        let ar_in1 = AssetRecord::from_open_asset_record_no_asset_tracing(oar_in1);
        let ar_in2 = AssetRecord::from_open_asset_record_no_asset_tracing(oar_in2);
        let ar_in3 = AssetRecord::from_open_asset_record_no_asset_tracing(oar_in3);

        // prepare output AssetRecord
        let temp1 = AssetRecordTemplate::with_no_asset_tracing(
            amount_out1,
            ASSET1_TYPE,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            receiver1.get_pk(),
        );
        let temp2 = AssetRecordTemplate::with_no_asset_tracing(
            amount_out2,
            ASSET1_TYPE,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            receiver2.get_pk(),
        );
        let temp3 = AssetRecordTemplate::with_no_asset_tracing(
            amount_out3,
            ASSET2_TYPE,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            receiver3.get_pk(),
        );
        let temp4 = AssetRecordTemplate::with_no_asset_tracing(
            amount_out4,
            ASSET3_TYPE,
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            receiver4.get_pk(),
        );

        let ar_out1 = AssetRecord::from_template_no_identity_tracing(&mut prng, &temp1).unwrap();
        let ar_out2 = AssetRecord::from_template_no_identity_tracing(&mut prng, &temp2).unwrap();
        let ar_out3 = AssetRecord::from_template_no_identity_tracing(&mut prng, &temp3).unwrap();
        let ar_out4 = AssetRecord::from_template_no_identity_tracing(&mut prng, &temp4).unwrap();

        // create xfr_note
        let xfr_note = gen_xfr_note(
            &mut prng,
            &[ar_in1, ar_in2, ar_in3],
            &[ar_out1, ar_out2, ar_out3, ar_out4],
            &[&sender1, &sender2, &sender3],
        )
        .unwrap();

        // verify
        let policies = XfrNotePolicies::empty_policies(3, 4);
        let policies_ref = policies.to_ref();
        assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies_ref).is_ok());

        // check
        let recv_bar1 = &xfr_note.body.outputs[0];
        let recv_memo1 = &xfr_note.body.owners_memos[0];
        let recv_oar1 = open_blind_asset_record(recv_bar1, recv_memo1, &receiver1).unwrap();
        assert!(recv_memo1.is_some());
        assert!(recv_bar1.amount.is_confidential());
        assert!(recv_bar1.asset_type.is_confidential());
        assert_eq!(recv_oar1.asset_type, ASSET1_TYPE);
        assert_eq!(recv_oar1.amount, amount_out1);
        assert_eq!(
            &recv_oar1.blind_asset_record.public_key,
            &receiver1.get_pk()
        );

        let recv_bar2 = &xfr_note.body.outputs[1];
        let recv_memo2 = &xfr_note.body.owners_memos[1];
        let recv_oar2 = open_blind_asset_record(recv_bar2, recv_memo2, &receiver2).unwrap();
        assert!(recv_memo2.is_none());
        assert!(!recv_bar2.amount.is_confidential());
        assert!(!recv_bar2.asset_type.is_confidential());
        assert_eq!(recv_oar2.asset_type, ASSET1_TYPE);
        assert_eq!(recv_oar2.amount, amount_out2);
        assert_eq!(recv_oar2.blind_asset_record.public_key, receiver2.get_pk());

        let recv_bar3 = &xfr_note.body.outputs[2];
        let recv_memo3 = &xfr_note.body.owners_memos[2];
        let recv_oar3 = open_blind_asset_record(recv_bar3, recv_memo3, &receiver3).unwrap();
        assert!(recv_memo3.is_some());
        assert!(recv_bar3.amount.is_confidential());
        assert!(recv_bar3.asset_type.is_confidential());
        assert_eq!(recv_oar3.asset_type, ASSET2_TYPE);
        assert_eq!(recv_oar3.amount, amount_out3);
        assert_eq!(recv_oar3.blind_asset_record.public_key, receiver3.get_pk());

        let recv_bar4 = &xfr_note.body.outputs[3];
        let recv_memo4 = &xfr_note.body.owners_memos[3];
        let recv_oar4 = open_blind_asset_record(recv_bar4, recv_memo4, &receiver4).unwrap();
        assert!(recv_memo4.is_some());
        assert!(recv_bar4.amount.is_confidential());
        assert!(!recv_bar4.asset_type.is_confidential());
        assert_eq!(recv_oar4.asset_type, ASSET3_TYPE);
        assert_eq!(recv_oar4.amount, amount_out4);
        assert_eq!(recv_oar4.blind_asset_record.public_key, receiver4.get_pk());
    }
}
