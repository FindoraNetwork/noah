use noah::{
    anon_creds::{self, ac_commit, ac_sign, ac_verify_commitment, Attr, Credential},
    keys::{KeyPair, PublicKey},
    setup::BulletproofParams,
    xfr::{
        asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType},
        gen_xfr_note,
        structs::{
            AssetRecord, AssetRecordTemplate, AssetTracerKeyPair, AssetType, BlindAssetRecord,
            IdentityRevealPolicy, OwnerMemo, TracingPolicies, TracingPolicy, ASSET_TYPE_LENGTH,
        },
        trace_assets, verify_xfr_note, RecordData, XfrNotePoliciesRef,
    },
};
use noah_algebra::{prelude::*, ristretto::PedersenCommitmentRistretto};
use wasm_bindgen::__rt::std::collections::HashMap;

const ASSET1_TYPE: AssetType = AssetType([0u8; ASSET_TYPE_LENGTH]);
const ASSET2_TYPE: AssetType = AssetType([1u8; ASSET_TYPE_LENGTH]);
const ASSET3_TYPE: AssetType = AssetType([2u8; ASSET_TYPE_LENGTH]);

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
    expected_ids: Vec<Attr>,
    expected_pk: &PublicKey,
) {
    assert_eq!(record_data.0, expected_amount);
    assert_eq!(record_data.1, expected_asset_type);
    assert_eq!(record_data.2, expected_ids);
    assert_eq!(record_data.3, *expected_pk);
}

/// Complex transaction with
/// * M = 3 inputs
/// * N = 4 outputs
/// * Some inputs are confidentials others are not
/// * Some outputs are confidentials others are not
/// * Some inputs are tracked, others are not
/// * Some outputs are tracked, others are not
/// * Three asset types and two asset issuers
#[test]
#[allow(non_snake_case)]
fn complex_transaction() {
    // 4 total users, 1 sender three receivers
    // 3 asset types, 2 different tracing policies and one with no policy

    let mut prng = test_rng();
    let mut params = BulletproofParams::default();
    let mut AIR: HashMap<Vec<u8>, _> = HashMap::new();

    let amount_asset1_in1 = 25;
    let amount_asset2_in2 = 50;
    let amount_asset3_in3 = 75;

    let amount_asset1_out1 = 20;
    let amount_asset1_out2 = 5;
    let amount_asset2_out3 = 50;
    let amount_asset3_out4 = 75;

    // credential keys
    let (cred_issuer_sk, cred_issuer_pk) = anon_creds::ac_keygen_issuer(&mut prng, 4);

    // asset tracing keys
    let asset1_tracing_key = AssetTracerKeyPair::generate(&mut prng);
    let asset2_tracing_key = AssetTracerKeyPair::generate(&mut prng);

    // setup users keys
    let user1_key_pair1 = KeyPair::generate(&mut prng);
    let user1_key_pair2 = KeyPair::generate(&mut prng);
    let user1_key_pair3 = KeyPair::generate(&mut prng);
    let (user1_ac_sk, user1_ac_pk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let user2_key_pair1 = KeyPair::generate(&mut prng);
    let (user2_ac_sk, user2_ac_pk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let user3_key_pair1 = KeyPair::generate(&mut prng);
    let (user3_ac_sk, user3_ac_pk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let user4_key_pair1 = KeyPair::generate(&mut prng);
    let (user4_ac_sk, user4_ac_pk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);

    // generate credential for each of the 4 users
    let user1_attrs = vec![0u32, 1, 2, 3];
    let user2_attrs = vec![4u32, 5, 6, 7];
    let user3_attrs = vec![8u32, 9, 10, 11];
    let user4_attrs = vec![12u32, 13, 14, 15];
    let credential_user1 = Credential {
        sig: ac_sign(
            &mut prng,
            &cred_issuer_sk,
            &user1_ac_pk,
            user1_attrs.as_slice(),
        )
        .unwrap(),
        attrs: user1_attrs,
        ipk: cred_issuer_pk.clone(),
    };
    let credential_user2 = Credential {
        sig: ac_sign(
            &mut prng,
            &cred_issuer_sk,
            &user2_ac_pk,
            user2_attrs.as_slice(),
        )
        .unwrap(),
        attrs: user2_attrs,
        ipk: cred_issuer_pk.clone(),
    };
    let credential_user3 = Credential {
        sig: ac_sign(
            &mut prng,
            &cred_issuer_sk,
            &user3_ac_pk,
            user3_attrs.as_slice(),
        )
        .unwrap(),
        attrs: user3_attrs,
        ipk: cred_issuer_pk.clone(),
    };
    let credential_user4 = Credential {
        sig: ac_sign(
            &mut prng,
            &cred_issuer_sk,
            &user4_ac_pk,
            user4_attrs.as_slice(),
        )
        .unwrap(),
        attrs: user4_attrs,
        ipk: cred_issuer_pk.clone(),
    };

    // register address/identity in AIR
    let (commitment_user1_addr1, proof, commitment_user1_addr1_key) = ac_commit(
        &mut prng,
        &user1_ac_sk,
        &credential_user1,
        &user1_key_pair1.get_pk().noah_to_bytes(),
    )
    .unwrap();
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user1_addr1,
        &proof,
        &user1_key_pair1.get_pk().noah_to_bytes()
    )
    .is_ok());
    AIR.insert(
        user1_key_pair1.get_pk().noah_to_bytes(),
        commitment_user1_addr1,
    );

    let (commitment_user2_addr1, proof, _commitment_user2_addr1_key) = ac_commit(
        &mut prng,
        &user2_ac_sk,
        &credential_user2,
        &user2_key_pair1.get_pk().noah_to_bytes(),
    )
    .unwrap();
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user2_addr1,
        &proof,
        &user2_key_pair1.get_pk().noah_to_bytes()
    )
    .is_ok());
    AIR.insert(
        user2_key_pair1.get_pk().noah_to_bytes(),
        commitment_user2_addr1,
    );

    let (commitment_user3_addr1, proof, commitment_user3_addr1_key) = ac_commit(
        &mut prng,
        &user3_ac_sk,
        &credential_user3,
        &user3_key_pair1.get_pk().noah_to_bytes(),
    )
    .unwrap();
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user3_addr1,
        &proof,
        &user3_key_pair1.get_pk().noah_to_bytes()
    )
    .is_ok());
    AIR.insert(
        user3_key_pair1.get_pk().noah_to_bytes(),
        commitment_user3_addr1,
    );

    let (commitment_user4_addr1, proof, _commitment_user4_addr1_key) = ac_commit(
        &mut prng,
        &user4_ac_sk,
        &credential_user4,
        &user4_key_pair1.get_pk().noah_to_bytes(),
    )
    .unwrap();
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user4_addr1,
        &proof,
        &user4_key_pair1.get_pk().noah_to_bytes()
    )
    .is_ok());
    AIR.insert(
        user4_key_pair1.get_pk().noah_to_bytes(),
        commitment_user4_addr1,
    );

    // define asset issuer tracing policies
    let id_tracing_policy1 = IdentityRevealPolicy {
        cred_issuer_pub_key: cred_issuer_pk.clone(),
        reveal_map: vec![false, true, false, true],
    }; // revealing attr2 and attr4

    let id_tracing_policy2 = IdentityRevealPolicy {
        cred_issuer_pub_key: cred_issuer_pk,
        reveal_map: vec![true, true, false, true],
    }; // revealing attr1 , attr2 and attr4

    let asset_tracing_policy_asset1_input = TracingPolicies::from_policy(TracingPolicy {
        // use in asset 1 when it is an input of a Xfr
        enc_keys: asset1_tracing_key.enc_key.clone(), // publicly available
        asset_tracing: true,                          // encrypt record info to asset issuer
        identity_tracing: Some(id_tracing_policy1),   // no identity tracking
    });
    let asset_tracing_policy_asset2_output = TracingPolicies::from_policy(TracingPolicy {
        // use in asset 2 when it is an output of a Xfr
        enc_keys: asset2_tracing_key.enc_key.clone(), // publicly available
        asset_tracing: true,                          // encrypt record info to asset issuer
        identity_tracing: Some(id_tracing_policy2),   // no identity tracking
    });

    // prepare inputs
    let (bar_user1_addr1, memo1) = conf_blind_asset_record_from_ledger(
        &user1_key_pair1.get_pk(),
        amount_asset1_in1,
        ASSET1_TYPE,
    );
    let (bar_user1_addr2, memo2) = conf_blind_asset_record_from_ledger(
        &user1_key_pair2.get_pk(),
        amount_asset2_in2,
        ASSET2_TYPE,
    );
    let (bar_user1_addr3, memo3) = conf_blind_asset_record_from_ledger(
        &user1_key_pair3.get_pk(),
        amount_asset3_in3,
        ASSET3_TYPE,
    );

    let oar_user1_addr1 =
        open_blind_asset_record(&bar_user1_addr1, &Some(memo1), &user1_key_pair1).unwrap();
    let oar_user1_addr2 =
        open_blind_asset_record(&bar_user1_addr2, &Some(memo2), &user1_key_pair2).unwrap();
    let oar_user1_addr3 =
        open_blind_asset_record(&bar_user1_addr3, &Some(memo3), &user1_key_pair3).unwrap();

    let ar_in1 = AssetRecord::from_open_asset_record_with_tracing(
        &mut prng,
        oar_user1_addr1,
        asset_tracing_policy_asset1_input.clone(),
        &user1_ac_sk,
        &credential_user1,
        &commitment_user1_addr1_key.unwrap(),
    )
    .unwrap();
    let ar_in2 = AssetRecord::from_open_asset_record_no_asset_tracing(oar_user1_addr2);
    let ar_in3 = AssetRecord::from_open_asset_record_no_asset_tracing(oar_user1_addr3);

    // prepare outputs
    let template1 = AssetRecordTemplate::with_no_asset_tracing(
        amount_asset1_out1,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        user1_key_pair1.get_pk(),
    );
    let template2 = AssetRecordTemplate::with_no_asset_tracing(
        amount_asset1_out2,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        user2_key_pair1.get_pk(),
    );
    let template3 = AssetRecordTemplate::with_asset_tracing(
        amount_asset2_out3,
        ASSET2_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        user3_key_pair1.get_pk(),
        asset_tracing_policy_asset2_output.clone(),
    );
    let template4 = AssetRecordTemplate::with_no_asset_tracing(
        amount_asset3_out4,
        ASSET3_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        user4_key_pair1.get_pk(),
    );

    let output_asset_record1 =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template1).unwrap();
    let output_asset_record2 =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template2).unwrap();
    let output_asset_record3 = AssetRecord::from_template_with_identity_tracing(
        &mut prng,
        &template3,
        &user3_ac_sk,
        &credential_user3,
        &commitment_user3_addr1_key.unwrap(),
    )
    .unwrap();
    let output_asset_record4 =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template4).unwrap();

    // create xfr_note
    let xfr_note = gen_xfr_note(
        &mut prng,
        &[ar_in1, ar_in2, ar_in3],
        &[
            output_asset_record1,
            output_asset_record2,
            output_asset_record3,
            output_asset_record4,
        ],
        &[&user1_key_pair1, &user1_key_pair2, &user1_key_pair3],
    )
    .unwrap();

    // verify
    let no_policy = TracingPolicies::new();
    let input1_credential_commitment = &AIR[&xfr_note.body.inputs[0].public_key.noah_to_bytes()];
    let input_policies = vec![&asset_tracing_policy_asset1_input, &no_policy, &no_policy];
    let inputs_sig_commitments = vec![Some(input1_credential_commitment), None, None];

    let output3_credential_commitment = &AIR[&xfr_note.body.outputs[2].public_key.noah_to_bytes()];
    let output_policies = vec![
        &no_policy,
        &no_policy,
        &asset_tracing_policy_asset2_output,
        &no_policy,
    ];
    let output_sig_commitments = vec![None, None, Some(output3_credential_commitment), None];

    let policies = XfrNotePoliciesRef::new(
        input_policies,
        inputs_sig_commitments,
        output_policies,
        output_sig_commitments,
    );
    assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies).is_ok());

    // check tracing
    let records_data = trace_assets(&xfr_note.body, &asset1_tracing_key).unwrap();
    assert_eq!(records_data.len(), 1);
    check_record_data(
        &records_data[0],
        amount_asset1_in1,
        ASSET1_TYPE,
        vec![1, 3], // expect second and last attribute
        &user1_key_pair1.get_pk(),
    );

    let records_data = trace_assets(&xfr_note.body, &asset2_tracing_key).unwrap();
    assert_eq!(records_data.len(), 1);
    check_record_data(
        &records_data[0],
        amount_asset2_out3,
        ASSET2_TYPE,
        vec![8u32, 9, 11], // expect first, second and last attribute of user 3
        &user3_key_pair1.get_pk(),
    );
}
