#![deny(warnings)]
#[cfg(test)]
pub(crate) mod examples {

  use rand::SeedableRng;
  use rand_chacha::ChaChaRng;
  use wasm_bindgen::__rt::std::collections::HashMap;
  use zei::api::anon_creds;
  use zei::api::anon_creds::{ac_commit, ac_sign, ac_verify_commitment, Credential};
  use zei::xfr::asset_record::{open_blind_asset_record, AssetRecordType};
  use zei::xfr::asset_tracer::gen_asset_tracer_keypair;
  use zei::xfr::lib::gen_xfr_note;
  use zei::xfr::lib::{trace_assets, verify_xfr_note, verify_xfr_note_no_policies};
  use zei::xfr::sig::XfrKeyPair;
  use zei::xfr::structs::{
    AssetRecord, AssetRecordTemplate, AssetTracingPolicy, AssetType, IdentityRevealPolicy,
  };
  use zei_utilities::examples::{
    check_record_data, conf_blind_asset_record_from_ledger, non_conf_blind_asset_record_from_ledger,
  };

  pub const ASSET1_TYPE: AssetType = [0u8; 16];
  pub const ASSET2_TYPE: AssetType = [1u8; 16];
  pub const ASSET3_TYPE: AssetType = [2u8; 16];

  #[test]
  fn xfr_note_non_confidential_one_input_one_output() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let amount = 100u64;
    // 1. setup
    // 1.1 user keys
    let sender_keypair = XfrKeyPair::generate(&mut prng);
    let recv_keypair = XfrKeyPair::generate(&mut prng);
    let recv_pub_key = recv_keypair.get_pk_ref();
    let recv_sec_key = recv_keypair.get_sk_ref();

    // 1.2. fake blind_asset_record from ledger
    let bar =
      non_conf_blind_asset_record_from_ledger(sender_keypair.get_pk_ref(), amount, ASSET1_TYPE);

    // 2. Prepare input AssetRecord
    // 2.1 user opens blind asset record, it is not confidential so no memo was received
    let oar = open_blind_asset_record(&bar, &None, sender_keypair.get_sk_ref()).unwrap();

    // 2.2. build AssetRecord from oar
    let sender_asset_record = AssetRecord::from_open_asset_record_no_asset_tracking(oar);

    // 3. Prepare output AssetRecord
    // 3.1. build output asset_record template
    let template = AssetRecordTemplate::with_no_asset_tracking(
      amount, ASSET1_TYPE, AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType, recv_pub_key.clone());
    // 3.3 build output asset record
    let recv_asset_record =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template).unwrap(); // do not attach identity tracking fields

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(&mut prng,
                                &[sender_asset_record], // one input
                                &[recv_asset_record],   // one output
                                &[&sender_keypair]).unwrap(); // sender secret key

    // 5. Validator verifies xfr_note
    assert!(verify_xfr_note_no_policies(&mut prng, &xfr_note).is_ok()); // there are no policies associated with this xfr note

    //6. receiver retrieves his BlindAssetRecord and opens it
    let recv_bar = &xfr_note.body.outputs[0];
    let recv_open_asset_record =
      open_blind_asset_record(recv_bar, &xfr_note.body.owners_memos[0], recv_sec_key).unwrap();

    assert_eq!(recv_open_asset_record.asset_type, ASSET1_TYPE);
    assert_eq!(recv_open_asset_record.amount, amount);
    assert_eq!(&recv_open_asset_record.blind_asset_record.public_key,
               recv_pub_key);
  }

  #[test]
  fn xfr_note_confidential_amount_one_input_one_output() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let amount = 100u64;
    // 1. setup
    // 1.1 user keys
    let sender_keypair = XfrKeyPair::generate(&mut prng);
    let recv_keypair = XfrKeyPair::generate(&mut prng);
    let recv_pub_key = recv_keypair.get_pk_ref();
    let recv_sec_key = recv_keypair.get_sk_ref();

    // 1.2. fake blind_asset_record from ledger
    let bar =
      non_conf_blind_asset_record_from_ledger(sender_keypair.get_pk_ref(), amount, ASSET1_TYPE);

    // 2. Prepare input AssetRecord
    // 2.1 user opens blind asset record, it is not confidential so no memo was received
    let oar = open_blind_asset_record(&bar, &None, sender_keypair.get_sk_ref()).unwrap();

    // 2.2. build AssetRecord from oar
    let sender_asset_record = AssetRecord::from_open_asset_record_no_asset_tracking(oar);

    // 3. Prepare output AssetRecord
    // 3.1. build output asset_record template
    let template = AssetRecordTemplate::with_no_asset_tracking(
      amount, ASSET1_TYPE, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, recv_pub_key.clone());
    // 3.3 build output asset record
    let recv_asset_record =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template).unwrap(); // do not attach identity tracking fields

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(&mut prng,
                                &[sender_asset_record], // one input
                                &[recv_asset_record],   // one output
                                &[&sender_keypair]).unwrap(); // sender secret key

    // 5. Validator verifies xfr_note
    assert!(verify_xfr_note_no_policies(&mut prng, &xfr_note).is_ok()); // there are no policies associated with this xfr note

    //6. receiver retrieves his BlindAssetRecord and opens it
    let recv_bar = &xfr_note.body.outputs[0];
    let recv_open_asset_record =
      open_blind_asset_record(recv_bar, &xfr_note.body.owners_memos[0], recv_sec_key).unwrap();

    assert!(&xfr_note.body.owners_memos[0].is_some());
    assert!(&xfr_note.body.outputs[0].amount.is_confidential());
    assert_eq!(recv_open_asset_record.asset_type, ASSET1_TYPE);
    assert_eq!(recv_open_asset_record.amount, amount);
    assert_eq!(&recv_open_asset_record.blind_asset_record.public_key,
               recv_pub_key);
  }

  #[test]
  fn xfr_note_confidential_two_inputs_two_outputs_asset_tracking_on_inputs() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let amount_in1 = 50u64;
    let amount_in2 = 75u64;
    let amount_out1 = 100u64;
    let amount_out2 = 25u64;
    // 1. setup
    // 1.1 user keys
    let sender1_keypair = XfrKeyPair::generate(&mut prng);
    let sender2_keypair = XfrKeyPair::generate(&mut prng);
    let recv1_keypair = XfrKeyPair::generate(&mut prng);
    let recv1_pub_key = recv1_keypair.get_pk_ref();
    let recv1_sec_key = recv1_keypair.get_sk_ref();
    let recv2_keypair = XfrKeyPair::generate(&mut prng);
    let recv2_pub_key = recv2_keypair.get_pk_ref();
    let recv2_sec_key = recv2_keypair.get_sk_ref();

    // setup policy
    let tracer_keys = gen_asset_tracer_keypair(&mut prng);
    let policy = AssetTracingPolicy{
      enc_keys: tracer_keys.enc_key.clone(),
      asset_tracking: true, // do asset tracing
      identity_tracking: None // do not trace identity
    };

    // 1.2. fake input blind_asset_record with associated policy
    let (bar_in1, memo1) =
      conf_blind_asset_record_from_ledger(sender1_keypair.get_pk_ref(), amount_in1, ASSET1_TYPE);
    let (bar_in2, memo2) =
      conf_blind_asset_record_from_ledger(sender2_keypair.get_pk_ref(), amount_in2, ASSET1_TYPE);

    // 2. Build inputs
    // open blind asset record
    let oar_in1 =
      open_blind_asset_record(&bar_in1, &Some(memo1), sender1_keypair.get_sk_ref()).unwrap();
    let oar_in2 =
      open_blind_asset_record(&bar_in2, &Some(memo2), sender2_keypair.get_sk_ref()).unwrap();
    // create inputs from open asset record and policies
    let ar_in1 = AssetRecord::from_open_asset_record_with_asset_tracking_but_no_identity(oar_in1, policy.clone()).unwrap();
    let ar_in2 = AssetRecord::from_open_asset_record_with_asset_tracking_but_no_identity(oar_in2, policy.clone()).unwrap();

    // 3. Prepare output AssetRecord
    // 3.1. build output asset_record template
    let template_out1 = AssetRecordTemplate::with_no_asset_tracking(
      amount_out1, ASSET1_TYPE, AssetRecordType::ConfidentialAmount_ConfidentialAssetType, recv1_pub_key.clone());
    let template_out2 = AssetRecordTemplate::with_no_asset_tracking(
      amount_out2, ASSET1_TYPE, AssetRecordType::ConfidentialAmount_ConfidentialAssetType, recv2_pub_key.clone());
    // 3.3 build output asset record
    let ar_out1 =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template_out1).unwrap(); // do not attach identity tracking fields
    let ar_out2 =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template_out2).unwrap(); // do not attach identity tracking fields

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(&mut prng,
                                &[ar_in1, ar_in2],   // one input
                                &[ar_out1, ar_out2], // one output
                                &[&sender1_keypair, &sender2_keypair]).unwrap(); // sender secret key

    // 5. Validator verifies xfr_note
    assert!(verify_xfr_note(&mut prng,
                            &xfr_note,
                            &[Some(&policy), Some(&policy)],
                            &[None, None],
                            &[None, None],
                            &[None, None]).is_ok()); // there are no policies associated with this xfr note

    //6. receives retrieves his BlindAssetRecord and opens it
    let recv_bar1 = &xfr_note.body.outputs[0];
    let recv_open_asset_record1 =
      open_blind_asset_record(recv_bar1, &xfr_note.body.owners_memos[0], recv1_sec_key).unwrap();

    assert!(&xfr_note.body.owners_memos[0].is_some());
    assert!(&xfr_note.body.outputs[0].amount.is_confidential());
    assert!(&xfr_note.body.outputs[0].asset_type.is_confidential());
    assert_eq!(recv_open_asset_record1.asset_type, ASSET1_TYPE);
    assert_eq!(recv_open_asset_record1.amount, amount_out1);
    assert_eq!(&recv_open_asset_record1.blind_asset_record.public_key,
               recv1_pub_key);

    let recv_bar2 = &xfr_note.body.outputs[1];
    let recv_open_asset_record2 =
      open_blind_asset_record(recv_bar2, &xfr_note.body.owners_memos[1], recv2_sec_key).unwrap();

    assert!(&xfr_note.body.owners_memos[1].is_some());
    assert!(&xfr_note.body.outputs[1].amount.is_confidential());
    assert!(&xfr_note.body.outputs[1].asset_type.is_confidential());
    assert_eq!(recv_open_asset_record2.asset_type, ASSET1_TYPE);
    assert_eq!(recv_open_asset_record2.amount, amount_out2);
    assert_eq!(&recv_open_asset_record2.blind_asset_record.public_key,
               recv2_pub_key);

    //7. Check asset tracing
    assert_eq!(xfr_note.body.asset_tracing_memos.len(), 4);
    assert!(xfr_note.body.asset_tracing_memos[0].is_some());
    assert!(xfr_note.body.asset_tracing_memos[1].is_some());
    assert!(xfr_note.body.asset_tracing_memos[2].is_none());
    assert!(xfr_note.body.asset_tracing_memos[3].is_none());
    let records_data = trace_assets(&xfr_note,
                                    &tracer_keys,
                                    &[ASSET1_TYPE, ASSET2_TYPE, ASSET3_TYPE]).unwrap();

    check_record_data(&records_data[0],
                      amount_in1,
                      ASSET1_TYPE,
                      vec![],
                      sender1_keypair.get_pk_ref());
    check_record_data(&records_data[1],
                      amount_in2,
                      ASSET1_TYPE,
                      vec![],
                      sender2_keypair.get_pk_ref());
  }

  #[test]
  fn xfr_note_confidential_one_input_two_outputs_asset_tracking_on_outputs() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let amount_in1 = 50u64;
    let amount_out1 = 30u64;
    let amount_out2 = 20u64;

    // 1. setup
    // 1.1 users keys
    let sender1_keypair = XfrKeyPair::generate(&mut prng);
    let recv1_keypair = XfrKeyPair::generate(&mut prng);
    let recv1_pub_key = recv1_keypair.get_pk_ref();
    let recv1_sec_key = recv1_keypair.get_sk_ref();
    let recv2_keypair = XfrKeyPair::generate(&mut prng);
    let recv2_pub_key = recv2_keypair.get_pk_ref();
    let recv2_sec_key = recv2_keypair.get_sk_ref();

    // 1.3 Instantiate issuer with his public keys
    let asset_tracing_key_pair = gen_asset_tracer_keypair(&mut prng);

    // 1.4 Define issuer tracking policy
    let asset_tracing_policy = AssetTracingPolicy{
      enc_keys: asset_tracing_key_pair.enc_key.clone(), // publicly available
      asset_tracking: true, // encrypt record info to asset issuer
      identity_tracking: None, // no identity tracking
    };

    // 2. Prepare input AssetRecord
    // 2.1 user opens blind asset record, it is not confidential so no memo was received
    let bar = non_conf_blind_asset_record_from_ledger(sender1_keypair.get_pk_ref(),
                                                      amount_in1,
                                                      ASSET1_TYPE);
    let oar = open_blind_asset_record(&bar, &None, sender1_keypair.get_sk_ref()).unwrap();
    // 2.2. build AssetRecord from oar
    let input_asset_record = AssetRecord::from_open_asset_record_no_asset_tracking(oar);

    // 3. Prepare output AssetRecord
    // 3.2. build output asset_record template
    let template1 = AssetRecordTemplate::with_asset_tracking(
      amount_out1, ASSET1_TYPE, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, recv1_pub_key.clone(), asset_tracing_policy.clone());
    let template2 = AssetRecordTemplate::with_asset_tracking(
      amount_out2, ASSET1_TYPE, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, recv2_pub_key.clone(), asset_tracing_policy.clone());

    // 3.3
    let output_asset_record1 =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template1).unwrap();
    let output_asset_record2 =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template2).unwrap();

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(&mut prng,
                                &[input_asset_record],
                                &[output_asset_record1, output_asset_record2],
                                &[&sender1_keypair]).unwrap();

    // 5. validator verify xfr_note
    assert!(verify_xfr_note(&mut prng,
                            &xfr_note,
                            &[None],
                            &[None],
                            &[Some(&asset_tracing_policy), Some(&asset_tracing_policy)],
                            &[None, None]).is_ok());

    //6. receiver retrieved his BlindAssetRecord
    //6. receives retrieves his BlindAssetRecord and opens it
    let recv_bar1 = &xfr_note.body.outputs[0];
    let recv_open_asset_record1 =
      open_blind_asset_record(recv_bar1, &xfr_note.body.owners_memos[0], recv1_sec_key).unwrap();

    assert!(&xfr_note.body.owners_memos[0].is_some());
    assert!(&xfr_note.body.outputs[0].amount.is_confidential());
    assert!(!&xfr_note.body.outputs[0].asset_type.is_confidential());
    assert_eq!(recv_open_asset_record1.asset_type, ASSET1_TYPE);
    assert_eq!(recv_open_asset_record1.amount, amount_out1);
    assert_eq!(&recv_open_asset_record1.blind_asset_record.public_key,
               recv1_pub_key);

    let recv_bar2 = &xfr_note.body.outputs[1];
    let recv_open_asset_record2 =
      open_blind_asset_record(recv_bar2, &xfr_note.body.owners_memos[1], recv2_sec_key).unwrap();

    assert!(&xfr_note.body.owners_memos[1].is_some());
    assert!(&xfr_note.body.outputs[1].amount.is_confidential());
    assert!(!&xfr_note.body.outputs[1].asset_type.is_confidential());
    assert_eq!(recv_open_asset_record2.asset_type, ASSET1_TYPE);
    assert_eq!(recv_open_asset_record2.amount, amount_out2);
    assert_eq!(&recv_open_asset_record2.blind_asset_record.public_key,
               recv2_pub_key);

    //7. Check asset tracing
    assert_eq!(xfr_note.body.asset_tracing_memos.len(), 3);
    assert!(xfr_note.body.asset_tracing_memos[0].is_none());
    assert!(xfr_note.body.asset_tracing_memos[1].is_some());
    assert!(xfr_note.body.asset_tracing_memos[2].is_some());
    let records_data = trace_assets(&xfr_note,
                                    &asset_tracing_key_pair,
                                    &[ASSET1_TYPE, ASSET2_TYPE]).unwrap();
    check_record_data(&records_data[0],
                      amount_out1,
                      ASSET1_TYPE,
                      vec![],
                      recv1_pub_key);
    check_record_data(&records_data[1],
                      amount_out2,
                      ASSET1_TYPE,
                      vec![],
                      recv2_pub_key);
  }

  #[test]
  #[allow(non_snake_case)]
  fn xfr_note_confidential_two_inputs_one_output_asset_tracking_and_identity_tracking_on_inputs() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let mut AIR: HashMap<&[u8], _> = HashMap::new();
    let amount_in1 = 50u64;
    let amount_in2 = 75u64;
    let amount_out1 = 100u64;
    // 1. setup
    // 1.1 user keys
    let user1_keypair = XfrKeyPair::generate(&mut prng);
    let user1_pubkey = user1_keypair.get_pk_ref();
    let user2_keypair = XfrKeyPair::generate(&mut prng);
    let user2_pubkey = user2_keypair.get_pk_ref();
    let recv1_keypair = XfrKeyPair::generate(&mut prng);
    let recv1_pub_key = recv1_keypair.get_pk_ref();
    let recv1_sec_key = recv1_keypair.get_sk_ref();

    // 1.2 Credential keys
    let (cred_issuer_pk, cred_issuer_sk) = anon_creds::ac_keygen_issuer(&mut prng, 4);
    let (user1_ac_pk, user1_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let (user2_ac_pk, user2_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);

    // 1.3 setup policy
    let tracer_keys = gen_asset_tracer_keypair(&mut prng);
    let id_policy_policy = IdentityRevealPolicy{
      cred_issuer_pub_key: cred_issuer_pk.clone(),
      reveal_map: vec![true, true, false, false], // reveal first two attributes
    };
    let policy = AssetTracingPolicy{
      enc_keys: tracer_keys.enc_key.clone(),
      asset_tracking: true, // do asset tracing
      identity_tracking: Some(id_policy_policy) // do not trace identity
    };

    // 2. Credential for input users
    // 2.1 credential issuance:
    let user1_attr = vec![1u32, 2u32, 3u32, 4u32];
    let user2_attr = vec![11u32, 22u32, 33u32, 44u32];
    let cred_sig_user1 = ac_sign(&mut prng, &cred_issuer_sk, &user1_ac_pk, &user1_attr);
    let cred_sig_user2 = ac_sign(&mut prng, &cred_issuer_sk, &user2_ac_pk, &user2_attr);
    let credential_user1 = Credential { signature: cred_sig_user1.unwrap(),
                                        attributes: user1_attr,
                                        issuer_pub_key: cred_issuer_pk.clone() };
    let credential_user2 = Credential { signature: cred_sig_user2.unwrap(),
                                        attributes: user2_attr,
                                        issuer_pub_key: cred_issuer_pk.clone() };

    // 2.2 credential commitments
    let (commitment_user1, proof_user1, commitment_key_user1) =
      ac_commit(&mut prng,
                &user1_ac_sk,
                &credential_user1,
                user1_keypair.get_pk_ref().as_bytes()).unwrap();
    let (commitment_user2, proof_user2, commitment_key_user2) =
      ac_commit(&mut prng,
                &user2_ac_sk,
                &credential_user2,
                user2_keypair.get_pk_ref().as_bytes()).unwrap();

    // 2.3 verifying commitment and put them on AIR
    assert!(ac_verify_commitment(&cred_issuer_pk,
                                 &commitment_user1,
                                 &proof_user1,
                                 user1_pubkey.as_bytes()).is_ok());
    AIR.insert(user1_pubkey.as_bytes(), commitment_user1.clone());
    assert!(ac_verify_commitment(&cred_issuer_pk,
                                 &commitment_user2,
                                 &proof_user2,
                                 user2_pubkey.as_bytes()).is_ok());
    AIR.insert(user2_pubkey.as_bytes(), commitment_user2.clone());

    // 3. Prepare input AssetRecord
    // 3.1 get blind asset records "from ledger" and open them
    let (bar1, memo1) =
      conf_blind_asset_record_from_ledger(user1_keypair.get_pk_ref(), amount_in1, ASSET1_TYPE);
    let oar1 = open_blind_asset_record(&bar1, &Some(memo1), user1_keypair.get_sk_ref()).unwrap();
    let (bar2, memo2) =
      conf_blind_asset_record_from_ledger(user2_keypair.get_pk_ref(), amount_in2, ASSET1_TYPE);
    let oar2 = open_blind_asset_record(&bar2, &Some(memo2), user2_keypair.get_sk_ref()).unwrap();

    // 3.2. build AssetRecord from oar
    let input_asset_record1 =
      AssetRecord::from_open_asset_record_with_identity_tracking(&mut prng,
                                                                 oar1,
                                                                 policy.clone(),
                                                                 &user1_ac_sk,
                                                                 &credential_user1,
                                                                 &commitment_key_user1).unwrap();

    let input_asset_record2 =
      AssetRecord::from_open_asset_record_with_identity_tracking(&mut prng,
                                                                 oar2,
                                                                 policy.clone(),
                                                                 &user2_ac_sk,
                                                                 &credential_user2,
                                                                 &commitment_key_user2).unwrap();

    // 3. Prepare output AssetRecord
    // 3.1. build output asset_record template
    let template = AssetRecordTemplate::with_no_asset_tracking(
      amount_out1, ASSET1_TYPE, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, recv1_pub_key.clone());
    // 3.3
    let output_asset_record =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template).unwrap();

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(&mut prng,
                                &[input_asset_record1, input_asset_record2],
                                &[output_asset_record],
                                &[&user1_keypair, &user2_keypair]).unwrap();

    // 5. validator verify xfr_note
    assert!(verify_xfr_note(&mut prng,
                            &xfr_note,
                            &[Some(&policy), Some(&policy)],
                            &[Some(&AIR[xfr_note.body.inputs[0].public_key.as_bytes()]),
                              Some(&AIR[xfr_note.body.inputs[1].public_key.as_bytes()])],
                            &[None],
                            &[None]).is_ok());

    //6. receiver retrieved his BlindAssetRecord
    let recv_bar1 = &xfr_note.body.outputs[0];
    let recv_open_asset_record1 =
      open_blind_asset_record(recv_bar1, &xfr_note.body.owners_memos[0], recv1_sec_key).unwrap();

    assert!(&xfr_note.body.owners_memos[0].is_some());
    assert!(&xfr_note.body.outputs[0].amount.is_confidential());
    assert!(!&xfr_note.body.outputs[0].asset_type.is_confidential());
    assert_eq!(recv_open_asset_record1.asset_type, ASSET1_TYPE);
    assert_eq!(recv_open_asset_record1.amount, amount_out1);
    assert_eq!(&recv_open_asset_record1.blind_asset_record.public_key,
               recv1_pub_key);

    //7. asset tracing on inputs
    assert_eq!(xfr_note.body.asset_tracing_memos.len(), 3);
    assert!(xfr_note.body.asset_tracing_memos[0].is_some());
    assert!(xfr_note.body.asset_tracing_memos[1].is_some());
    assert!(xfr_note.body.asset_tracing_memos[2].is_none());
    let records_data = trace_assets(&xfr_note,
                                    &tracer_keys,
                                    &[ASSET1_TYPE, ASSET2_TYPE, ASSET3_TYPE]).unwrap();
    assert_eq!(records_data.len(), 2);
    check_record_data(&records_data[0],
                      amount_in1,
                      ASSET1_TYPE,
                      vec![1u32, 2],
                      user1_pubkey);
    check_record_data(&records_data[1],
                      amount_in2,
                      ASSET1_TYPE,
                      vec![11u32, 22],
                      user2_pubkey);
  }

  #[test]
  #[allow(non_snake_case)]
  fn xfr_note_confidential_one_input_two_outputs_asset_tracking_and_identity_tracking_on_outputs(
    ) {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let mut AIR: HashMap<&[u8], _> = HashMap::new();
    let amount_in1 = 100u64;
    let amount_out1 = 75u64;
    let amount_out2 = 25u64;
    // 1. setup
    // 1.1 user keys
    let sender_user_keypair = XfrKeyPair::generate(&mut prng);
    let sender_user_pubkey = sender_user_keypair.get_pk_ref();
    let recv_user1_keypair = XfrKeyPair::generate(&mut prng);
    let recv_user1_pub_key = recv_user1_keypair.get_pk_ref();
    let recv_user1_sec_key = recv_user1_keypair.get_sk_ref();
    let recv_user2_keypair = XfrKeyPair::generate(&mut prng);
    let recv_user2_pub_key = recv_user2_keypair.get_pk_ref();
    let recv_user2_sec_key = recv_user2_keypair.get_sk_ref();

    // 1.2 Credential keys
    let (cred_issuer_pk, cred_issuer_sk) = anon_creds::ac_keygen_issuer(&mut prng, 4);
    let (recv_user1_ac_pk, recv_user1_ac_sk) =
      anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let (recv_user2_ac_pk, recv_user2_ac_sk) =
      anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);

    // 1.3 setup policy
    let tracer_keys = gen_asset_tracer_keypair(&mut prng);
    let id_policy_policy = IdentityRevealPolicy{
      cred_issuer_pub_key: cred_issuer_pk.clone(),
      reveal_map: vec![false, true, true, true], // reveal last three attributes
    };
    let policy = AssetTracingPolicy{
      enc_keys: tracer_keys.enc_key.clone(),
      asset_tracking: true, // do asset tracing
      identity_tracking: Some(id_policy_policy) // do not trace identity
    };

    // 2. Credential for input users
    // 2.1 credential issuance:
    let recv1_attr = vec![1u32, 2u32, 3u32, 4u32];
    let recv2_attr = vec![11u32, 22u32, 33u32, 44u32];
    let cred_sig_user1 =
      ac_sign(&mut prng, &cred_issuer_sk, &recv_user1_ac_pk, &recv1_attr).unwrap();
    let cred_sig_user2 =
      ac_sign(&mut prng, &cred_issuer_sk, &recv_user2_ac_pk, &recv2_attr).unwrap();
    let credential_user1 = Credential { signature: cred_sig_user1,
                                        attributes: recv1_attr,
                                        issuer_pub_key: cred_issuer_pk.clone() };
    let credential_user2 = Credential { signature: cred_sig_user2,
                                        attributes: recv2_attr,
                                        issuer_pub_key: cred_issuer_pk.clone() };

    // 2.2 credential commitments
    let (commitment_user1, proof_user1, commitment_key_user1) =
      ac_commit(&mut prng,
                &recv_user1_ac_sk,
                &credential_user1,
                recv_user1_keypair.get_pk_ref().as_bytes()).unwrap();
    let (commitment_user2, proof_user2, commitment_key_user2) =
      ac_commit(&mut prng,
                &recv_user2_ac_sk,
                &credential_user2,
                recv_user2_keypair.get_pk_ref().as_bytes()).unwrap();

    // 2.3 verifying commitment and put them on AIR
    assert!(ac_verify_commitment(&cred_issuer_pk,
                                 &commitment_user1,
                                 &proof_user1,
                                 recv_user1_pub_key.as_bytes()).is_ok());
    AIR.insert(recv_user1_pub_key.as_bytes(), commitment_user1.clone());
    assert!(ac_verify_commitment(&cred_issuer_pk,
                                 &commitment_user2,
                                 &proof_user2,
                                 recv_user2_pub_key.as_bytes()).is_ok());
    AIR.insert(recv_user2_pub_key.as_bytes(), commitment_user2.clone());

    // 3. Prepare input AssetRecord
    // 3.1 get blind asset records "from ledger" and open them
    let (bar1, memo1) =
      conf_blind_asset_record_from_ledger(sender_user_pubkey, amount_in1, ASSET1_TYPE);
    let oar1 =
      open_blind_asset_record(&bar1, &Some(memo1), sender_user_keypair.get_sk_ref()).unwrap();

    // 3.2. build AssetRecord from oar
    let input_asset_record1 = AssetRecord::from_open_asset_record_no_asset_tracking(oar1);

    // 4. Prepare output AssetRecord
    // 3.1. build output asset_record template
    let template = AssetRecordTemplate::with_asset_tracking(
      amount_out1, ASSET1_TYPE, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, recv_user1_pub_key.clone(), policy.clone());
    let output_asset_record_1 =
      AssetRecord::from_template_with_identity_tracking(&mut prng,
                                                        &template,
                                                        &recv_user1_ac_sk,
                                                        &credential_user1,
                                                        &commitment_key_user1).unwrap();

    let template = AssetRecordTemplate::with_asset_tracking(
      amount_out2, ASSET1_TYPE, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, recv_user2_pub_key.clone(), policy.clone());
    let output_asset_record_2 =
      AssetRecord::from_template_with_identity_tracking(&mut prng,
                                                        &template,
                                                        &recv_user2_ac_sk,
                                                        &credential_user2,
                                                        &commitment_key_user2).unwrap();

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(&mut prng,
                                &[input_asset_record1],
                                &[output_asset_record_1, output_asset_record_2],
                                &[&sender_user_keypair]).unwrap();

    // 5. validator verify xfr_note
    assert!(verify_xfr_note(&mut prng,
                            &xfr_note,
                            &[None],
                            &[None],
                            &[Some(&policy), Some(&policy)],
                            &[Some(&AIR[xfr_note.body.outputs[0].public_key.as_bytes()]),
                              Some(&AIR[xfr_note.body.outputs[1].public_key.as_bytes()])]).is_ok());

    //6. receiver retrieved his BlindAssetRecord
    let recv_bar1 = &xfr_note.body.outputs[0];
    let recv_open_asset_record1 = open_blind_asset_record(recv_bar1,
                                                          &xfr_note.body.owners_memos[0],
                                                          recv_user1_sec_key).unwrap();

    assert!(&xfr_note.body.owners_memos[0].is_some());
    assert!(&xfr_note.body.outputs[0].amount.is_confidential());
    assert!(!&xfr_note.body.outputs[0].asset_type.is_confidential());
    assert_eq!(recv_open_asset_record1.asset_type, ASSET1_TYPE);
    assert_eq!(recv_open_asset_record1.amount, amount_out1);
    assert_eq!(&recv_open_asset_record1.blind_asset_record.public_key,
               recv_user1_pub_key);

    let recv_bar2 = &xfr_note.body.outputs[1];
    let recv_open_asset_record2 = open_blind_asset_record(recv_bar2,
                                                          &xfr_note.body.owners_memos[1],
                                                          recv_user2_sec_key).unwrap();

    assert!(&xfr_note.body.owners_memos[1].is_some());
    assert!(&xfr_note.body.outputs[1].amount.is_confidential());
    assert!(!&xfr_note.body.outputs[1].asset_type.is_confidential());
    assert_eq!(recv_open_asset_record2.asset_type, ASSET1_TYPE);
    assert_eq!(recv_open_asset_record2.amount, amount_out2);
    assert_eq!(&recv_open_asset_record2.blind_asset_record.public_key,
               recv_user2_pub_key);

    //7. asset tracing on inputs
    assert_eq!(xfr_note.body.asset_tracing_memos.len(), 3);
    assert!(xfr_note.body.asset_tracing_memos[0].is_none());
    assert!(xfr_note.body.asset_tracing_memos[1].is_some());
    assert!(xfr_note.body.asset_tracing_memos[2].is_some());
    let records_data = trace_assets(&xfr_note,
                                    &tracer_keys,
                                    &[ASSET1_TYPE, ASSET2_TYPE, ASSET3_TYPE]).unwrap();
    assert_eq!(records_data.len(), 2);
    check_record_data(&records_data[0],
                      amount_out1,
                      ASSET1_TYPE,
                      vec![2u32, 3, 4],
                      recv_user1_pub_key);
    check_record_data(&records_data[1],
                      amount_out2,
                      ASSET1_TYPE,
                      vec![22u32, 33, 44],
                      recv_user2_pub_key);
  }

  #[test]
  #[allow(non_snake_case)]
  /// Complex transaction with
  /// * M = 3 inputs
  /// * N = 4 outputs
  /// * Some inputs are confidentials others are not
  /// * Some outputs are confidentials others are not
  /// * Some inputs are tracked, others are not
  /// * Some outputs are tracked, others are not
  /// * Three asset types and two asset issuers
  fn complex_transaction() {
    // 4 total users, 1 sender three receivers
    // 3 asset types, 2 different tracing policies and one with no policy

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let mut AIR: HashMap<&[u8], _> = HashMap::new();
    let amount_asset1_in1 = 25;
    let amount_asset2_in2 = 50;
    let amount_asset3_in3 = 75;

    let amount_asset1_out1 = 20;
    let amount_asset1_out2 = 5;
    let amount_asset2_out3 = 50;
    let amount_asset3_out4 = 75;
    // credential keys
    let (cred_issuer_pk, cred_issuer_sk) = anon_creds::ac_keygen_issuer(&mut prng, 4);

    // asset tracing keys
    let asset1_tracing_key = gen_asset_tracer_keypair(&mut prng);
    let asset2_tracing_key = gen_asset_tracer_keypair(&mut prng);
    // 1. setup
    // 1.1 users keys
    let user1_key_pair1 = XfrKeyPair::generate(&mut prng);
    let user1_key_pair2 = XfrKeyPair::generate(&mut prng);
    let user1_key_pair3 = XfrKeyPair::generate(&mut prng);
    let (user1_ac_pk, user1_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let user2_key_pair1 = XfrKeyPair::generate(&mut prng);
    let (user2_ac_pk, user2_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let user3_key_pair1 = XfrKeyPair::generate(&mut prng);
    let (user3_ac_pk, user3_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let user4_key_pair1 = XfrKeyPair::generate(&mut prng);
    let (user4_ac_pk, user4_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);

    //2.1 generate credential for each of the 4 users
    let user1_attrs = vec![0u32, 1, 2, 3];
    let user2_attrs = vec![4u32, 5, 6, 7];
    let user3_attrs = vec![8u32, 9, 10, 11];
    let user4_attrs = vec![12u32, 13, 14, 15];
    let credential_user1 = Credential { signature: ac_sign(&mut prng,
                                                           &cred_issuer_sk,
                                                           &user1_ac_pk,
                                                           user1_attrs.as_slice()).unwrap(),
                                        attributes: user1_attrs,
                                        issuer_pub_key: cred_issuer_pk.clone() };
    let credential_user2 = Credential { signature: ac_sign(&mut prng,
                                                           &cred_issuer_sk,
                                                           &user2_ac_pk,
                                                           user2_attrs.as_slice()).unwrap(),
                                        attributes: user2_attrs,
                                        issuer_pub_key: cred_issuer_pk.clone() };
    let credential_user3 = Credential { signature: ac_sign(&mut prng,
                                                           &cred_issuer_sk,
                                                           &user3_ac_pk,
                                                           user3_attrs.as_slice()).unwrap(),
                                        attributes: user3_attrs,
                                        issuer_pub_key: cred_issuer_pk.clone() };
    let credential_user4 = Credential { signature: ac_sign(&mut prng,
                                                           &cred_issuer_sk,
                                                           &user4_ac_pk,
                                                           user4_attrs.as_slice()).unwrap(),
                                        attributes: user4_attrs,
                                        issuer_pub_key: cred_issuer_pk.clone() };

    // 1.4 Register address/identity in AIR
    let (commitment_user1_addr1, proof, commitment_user1_addr1_key) =
      ac_commit(&mut prng,
                &user1_ac_sk,
                &credential_user1,
                user1_key_pair1.get_pk_ref().as_bytes()).unwrap();
    assert!(ac_verify_commitment(&cred_issuer_pk,
                                 &commitment_user1_addr1,
                                 &proof,
                                 user1_key_pair1.get_pk_ref().as_bytes()).is_ok());
    AIR.insert(user1_key_pair1.get_pk_ref().as_bytes(),
               commitment_user1_addr1);

    let (commitment_user2_addr1, proof, _commitment_user2_addr1_key) =
      ac_commit(&mut prng,
                &user2_ac_sk,
                &credential_user2,
                user2_key_pair1.get_pk_ref().as_bytes()).unwrap();
    assert!(ac_verify_commitment(&cred_issuer_pk,
                                 &commitment_user2_addr1,
                                 &proof,
                                 user2_key_pair1.get_pk_ref().as_bytes()).is_ok());
    AIR.insert(user2_key_pair1.get_pk_ref().as_bytes(),
               commitment_user2_addr1);

    let (commitment_user3_addr1, proof, commitment_user3_addr1_key) =
      ac_commit(&mut prng,
                &user3_ac_sk,
                &credential_user3,
                user3_key_pair1.get_pk_ref().as_bytes()).unwrap();
    assert!(ac_verify_commitment(&cred_issuer_pk,
                                 &commitment_user3_addr1,
                                 &proof,
                                 user3_key_pair1.get_pk_ref().as_bytes()).is_ok());
    AIR.insert(user3_key_pair1.get_pk_ref().as_bytes(),
               commitment_user3_addr1);

    let (commitment_user4_addr1, proof, _commitment_user4_addr1_key) =
      ac_commit(&mut prng,
                &user4_ac_sk,
                &credential_user4,
                user4_key_pair1.get_pk_ref().as_bytes()).unwrap();
    assert!(ac_verify_commitment(&cred_issuer_pk,
                                 &commitment_user4_addr1,
                                 &proof,
                                 user4_key_pair1.get_pk_ref().as_bytes()).is_ok());
    AIR.insert(user4_key_pair1.get_pk_ref().as_bytes(),
               commitment_user4_addr1);

    // 1.5 Define asset issuer tracking policies
    let id_tracking_policy1 = IdentityRevealPolicy { cred_issuer_pub_key: cred_issuer_pk.clone(),
                                                     reveal_map: vec![false, true, false, true] }; // revealing attr2 and attr4

    let id_tracking_policy2 = IdentityRevealPolicy { cred_issuer_pub_key: cred_issuer_pk.clone(),
                                                     reveal_map: vec![true, true, false, true] }; // revealing attr1 , attr2 and attr4

    let asset_tracing_policy_asset1_input = AssetTracingPolicy{ // use in asset 1 when it is an input of a Xfr
      enc_keys: asset1_tracing_key.enc_key.clone(), // publicly available
      asset_tracking: true, // encrypt record info to asset issuer
      identity_tracking: Some(id_tracking_policy1), // no identity tracking
    };
    let asset_tracing_policy_asset2_output = AssetTracingPolicy{ // use in asset 2 when it is an output of a Xfr
      enc_keys: asset2_tracing_key.enc_key.clone(), // publicly available
      asset_tracking: true, // encrypt record info to asset issuer
      identity_tracking: Some(id_tracking_policy2), // no identity tracking
    };

    // 2. Prepare inputs
    // 2.1 get "from ledger" blind asset records
    let (bar_user1_addr1, memo1) =
      conf_blind_asset_record_from_ledger(user1_key_pair1.get_pk_ref(),
                                          amount_asset1_in1,
                                          ASSET1_TYPE);
    let (bar_user1_addr2, memo2) =
      conf_blind_asset_record_from_ledger(user1_key_pair2.get_pk_ref(),
                                          amount_asset2_in2,
                                          ASSET2_TYPE);
    let (bar_user1_addr3, memo3) =
      conf_blind_asset_record_from_ledger(user1_key_pair3.get_pk_ref(),
                                          amount_asset3_in3,
                                          ASSET3_TYPE);
    // 2.2 open asset records
    let oar_user1_addr1 = open_blind_asset_record(&bar_user1_addr1,
                                                  &Some(memo1),
                                                  user1_key_pair1.get_sk_ref()).unwrap();
    let oar_user1_addr2 = open_blind_asset_record(&bar_user1_addr2,
                                                  &Some(memo2),
                                                  user1_key_pair2.get_sk_ref()).unwrap();
    let oar_user1_addr3 = open_blind_asset_record(&bar_user1_addr3,
                                                  &Some(memo3),
                                                  user1_key_pair3.get_sk_ref()).unwrap();
    // 2.3 prepare inputs
    let ar_in1 = AssetRecord::from_open_asset_record_with_identity_tracking(&mut prng,
                                                                            oar_user1_addr1,
                                                                            asset_tracing_policy_asset1_input.clone(),
                                                                            &user1_ac_sk,
                                                                            &credential_user1, &commitment_user1_addr1_key).unwrap();
    let ar_in2 = AssetRecord::from_open_asset_record_no_asset_tracking(oar_user1_addr2);
    let ar_in3 = AssetRecord::from_open_asset_record_no_asset_tracking(oar_user1_addr3);

    // 3. Prepare outputs

    let template1 = AssetRecordTemplate::with_no_asset_tracking(
      amount_asset1_out1, ASSET1_TYPE, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, user1_key_pair1.get_pk());

    let template2 = AssetRecordTemplate::with_no_asset_tracking(
      amount_asset1_out2, ASSET1_TYPE, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, user2_key_pair1.get_pk());

    let template3 = AssetRecordTemplate::with_asset_tracking(
      amount_asset2_out3, ASSET2_TYPE, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, user3_key_pair1.get_pk(), asset_tracing_policy_asset2_output.clone());

    let template4 = AssetRecordTemplate::with_no_asset_tracking(
      amount_asset3_out4, ASSET3_TYPE, AssetRecordType::ConfidentialAmount_NonConfidentialAssetType, user4_key_pair1.get_pk());

    let output_asset_record1 =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template1).unwrap();

    let output_asset_record2 =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template2).unwrap();

    let output_asset_record3 =
      AssetRecord::from_template_with_identity_tracking(&mut prng,
                                                        &template3,
                                                        &user3_ac_sk,
                                                        &credential_user3,
                                                        &commitment_user3_addr1_key).unwrap();

    let output_asset_record4 =
      AssetRecord::from_template_no_identity_tracking(&mut prng, &template4).unwrap();

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(&mut prng,
                                &[ar_in1, ar_in2, ar_in3],
                                &[output_asset_record1,
                                  output_asset_record2,
                                  output_asset_record3,
                                  output_asset_record4],
                                &[&user1_key_pair1, &user1_key_pair2, &user1_key_pair3]).unwrap();
    // 5. Verify xfr_note
    let input1_credential_commitment = &AIR[xfr_note.body.inputs[0].public_key.as_bytes()];
    let input_policies = [Some(&asset_tracing_policy_asset1_input), None, None];
    let inputs_sig_commitments = [Some(input1_credential_commitment), None, None];

    let output3_credential_commitment = &AIR[xfr_note.body.outputs[2].public_key.as_bytes()];
    let output_policies = [None, None, Some(&asset_tracing_policy_asset2_output), None];
    let output_sig_commitments = [None, None, Some(output3_credential_commitment), None];
    assert!(verify_xfr_note(&mut prng,
                            &xfr_note,
                            &input_policies,
                            &inputs_sig_commitments,
                            &output_policies,
                            &output_sig_commitments).is_ok());

    // 5. check tracing
    // 5.1 tracer 1
    let records_data = trace_assets(&xfr_note,
                                    &asset1_tracing_key,
                                    &[ASSET1_TYPE, ASSET2_TYPE, ASSET3_TYPE]).unwrap();
    assert_eq!(records_data.len(), 1);
    check_record_data(&records_data[0],
                      amount_asset1_in1,
                      ASSET1_TYPE,
                      vec![1, 3], // expect second and last attribute
                      user1_key_pair1.get_pk_ref());

    let records_data = trace_assets(&xfr_note,
                                    &asset2_tracing_key,
                                    &[ASSET1_TYPE, ASSET2_TYPE, ASSET3_TYPE]).unwrap();
    assert_eq!(records_data.len(), 1);
    check_record_data(&records_data[0],
                      amount_asset2_out3,
                      ASSET2_TYPE,
                      vec![8u32, 9, 11], // expect first, second and last attribute of user 3
                      user3_key_pair1.get_pk_ref());
  }
}
