#[cfg(test)]
mod smoke_xfr_secp256k1_address {
    use rand_chacha::ChaChaRng;
    use zei::{
        setup::BulletproofParams,
        xfr::{
            asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType},
            gen_xfr_note,
            sig::{XfrKeyPair, XfrPublicKey, XfrPublicKeyInner, XfrSecretKey},
            structs::{
                AssetRecord, AssetRecordTemplate, AssetType, BlindAssetRecord, OwnerMemo,
                XfrAmount, XfrAssetType, ASSET_TYPE_LENGTH,
            },
            verify_xfr_note, XfrNotePolicies,
        },
    };
    use zei_algebra::prelude::*;
    use zei_crypto::basic::pedersen_comm::PedersenCommitmentRistretto;

    const AMOUNT: u64 = 10u64;
    const ASSET1_TYPE: AssetType = AssetType([0u8; ASSET_TYPE_LENGTH]);
    const ASSET2_TYPE: AssetType = AssetType([1u8; ASSET_TYPE_LENGTH]);

    // Simulate getting a BlindAssetRecord from Ledger
    fn non_conf_blind_asset_record_from_ledger(
        key: &XfrPublicKey,
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
        key: &XfrPublicKey,
        amount: u64,
        asset_type: AssetType,
    ) -> (BlindAssetRecord, OwnerMemo) {
        let mut prng = ChaChaRng::from_entropy();
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
    fn bar_secp256k1_address() {
        let mut prng = ChaChaRng::from_entropy();
        let mut params = BulletproofParams::default();

        let sk = "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e";
        let address = "8626f6940e2eb28930efb4cef49b2d1f2c9c1199";
        let xs = XfrSecretKey::from_secp256k1_with_address(&hex::decode(sk).unwrap()).unwrap();
        let sender = xs.into_keypair();
        match sender.pub_key.inner() {
            XfrPublicKeyInner::Address(hash) => {
                assert_eq!(hash.to_vec(), hex::decode(address).unwrap())
            }
            _ => panic!("not secp256k1 address"),
        }
        let receiver = XfrKeyPair::generate_secp256k1(&mut prng);

        // fake and build blind_asset_record from ledger
        let bar1 = non_conf_blind_asset_record_from_ledger(&sender.pub_key, AMOUNT, ASSET1_TYPE);
        let oar1 = open_blind_asset_record(&bar1, &None, &sender).unwrap();
        let ar1 = AssetRecord::from_open_asset_record_no_asset_tracing(oar1);

        let bar2 = non_conf_blind_asset_record_from_ledger(&receiver.pub_key, AMOUNT, ASSET2_TYPE);
        let oar2 = open_blind_asset_record(&bar2, &None, &receiver).unwrap();
        let ar2 = AssetRecord::from_open_asset_record_no_asset_tracing(oar2);

        let (bar3, memo3) =
            conf_blind_asset_record_from_ledger(&receiver.pub_key, AMOUNT, ASSET2_TYPE);
        let oar3 = open_blind_asset_record(&bar3, &Some(memo3), &receiver).unwrap();
        let ar3 = AssetRecord::from_open_asset_record_no_asset_tracing(oar3);

        // prepare output AssetRecord
        let temp1 = AssetRecordTemplate::with_no_asset_tracing(
            AMOUNT,
            ASSET1_TYPE,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            receiver.pub_key,
        );
        let recv_ar1 = AssetRecord::from_template_no_identity_tracing(&mut prng, &temp1).unwrap();

        let temp2 = AssetRecordTemplate::with_no_asset_tracing(
            AMOUNT,
            ASSET2_TYPE,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType, // address only support ar
            sender.pub_key,
        );
        let recv_ar2 = AssetRecord::from_template_no_identity_tracing(&mut prng, &temp2).unwrap();

        let temp3 = AssetRecordTemplate::with_no_asset_tracing(
            AMOUNT,
            ASSET2_TYPE,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            receiver.pub_key,
        );
        let recv_ar3 = AssetRecord::from_template_no_identity_tracing(&mut prng, &temp3).unwrap();

        // create xfr_note
        let xfr_note = gen_xfr_note(
            &mut prng,
            &[ar1, ar2, ar3],
            &[recv_ar1, recv_ar2, recv_ar3],
            &[&sender, &receiver, &receiver],
        )
        .unwrap();

        // verify
        let policies = XfrNotePolicies::empty_policies(3, 3);
        let policies_ref = policies.to_ref();
        assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies_ref).is_ok());

        // check
        let recv_bar1 = &xfr_note.body.outputs[0];
        let recv_memo1 = &xfr_note.body.owners_memos[0];
        let recv_oar1 = open_blind_asset_record(recv_bar1, recv_memo1, &receiver).unwrap();
        assert!(!recv_memo1.is_some());
        assert!(!recv_bar1.amount.is_confidential());
        assert!(!recv_bar1.asset_type.is_confidential());
        assert_eq!(recv_oar1.asset_type, ASSET1_TYPE);
        assert_eq!(recv_oar1.amount, AMOUNT);
        assert_eq!(recv_oar1.blind_asset_record.public_key, receiver.pub_key);

        let recv_bar2 = &xfr_note.body.outputs[1];
        let recv_memo2 = &xfr_note.body.owners_memos[1];
        let recv_oar2 = open_blind_asset_record(recv_bar2, recv_memo2, &sender).unwrap();
        assert!(!recv_memo2.is_some());
        assert!(!recv_bar2.amount.is_confidential());
        assert!(!recv_bar2.asset_type.is_confidential());
        assert_eq!(recv_oar2.asset_type, ASSET2_TYPE);
        assert_eq!(recv_oar2.amount, AMOUNT);
        assert_eq!(recv_oar2.blind_asset_record.public_key, sender.pub_key);

        let recv_bar3 = &xfr_note.body.outputs[2];
        let recv_memo3 = &xfr_note.body.owners_memos[2];
        let recv_oar3 = open_blind_asset_record(recv_bar3, recv_memo3, &receiver).unwrap();
        assert!(recv_memo3.is_some());
        assert!(recv_bar3.amount.is_confidential());
        assert!(recv_bar3.asset_type.is_confidential());
        assert_eq!(recv_oar3.asset_type, ASSET2_TYPE);
        assert_eq!(recv_oar3.amount, AMOUNT);
        assert_eq!(recv_oar3.blind_asset_record.public_key, receiver.pub_key);
    }
}
