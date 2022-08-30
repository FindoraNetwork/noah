use rand_chacha::ChaChaRng;
use zei::anon_creds::{
    ac_commit, ac_sign, ACCommitment, ACCommitmentKey, ACUserSecretKey, Credential,
};
use zei::xfr::asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType};
use zei::xfr::sig::{XfrKeyPair, XfrPublicKey};
use zei::xfr::structs::{
    AssetRecord, AssetRecordTemplate, AssetTracerKeyPair, AssetType, BlindAssetRecord,
    IdentityRevealPolicy, OwnerMemo, TracingPolicy, ASSET_TYPE_LENGTH,
};
use zei::{
    anon_creds,
    setup::BulletproofParams,
    xfr::{gen_xfr_body, structs::TracingPolicies, verify_xfr_body, XfrNotePoliciesRef},
};
use zei_algebra::prelude::*;
use zei_crypto::basic::pedersen_comm::PedersenCommitmentRistretto;

/// Test asset one, which is also FRA.
const ASSET_TYPE_1: AssetType = AssetType([0u8; ASSET_TYPE_LENGTH]);

fn check_xfr_body(n: usize) {
    let (
        sender_key_pairs,
        user_ac_sks,
        credentials,
        ac_commitment_keys,
        asset_tracing_policy_asset_input,
        ac_commitments,
    ) = setup_with_policies(n);
    let sender_key_pairs_ref = sender_key_pairs.iter().collect_vec();

    let (ar_ins, output_asset_records) = prepare_inputs_and_outputs_with_policies_single_asset(
        sender_key_pairs_ref.as_slice(),
        user_ac_sks,
        credentials,
        ac_commitment_keys,
        Some(asset_tracing_policy_asset_input.clone()),
        n,
    );

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let xfr_body = gen_xfr_body(
        &mut prng,
        ar_ins.as_slice(),
        output_asset_records.as_slice(),
    )
    .unwrap();

    let no_policies = TracingPolicies::new();
    let policies = TracingPolicies::from_policy(asset_tracing_policy_asset_input);

    let policies = XfrNotePoliciesRef::new(
        vec![&policies; n],
        ac_commitments.iter().map(Some).collect_vec(),
        vec![&no_policies; n],
        vec![None; n],
    );

    let mut params = BulletproofParams::default();

    assert!(verify_xfr_body(&mut prng, &mut params, &xfr_body, &policies).is_ok());
}

#[test]
fn test() {
    let sizes = vec![1, 2, 8, 16];
    for size in sizes.iter() {
        check_xfr_body(*size);
    }
}

fn prepare_inputs_and_outputs_with_policies_single_asset(
    sender_key_pairs: &[&XfrKeyPair],
    user_ac_sks: Vec<ACUserSecretKey>,
    credentials: Vec<Credential>,
    ac_commitment_keys: Vec<ACCommitmentKey>,
    asset_tracing_policy_input: Option<TracingPolicy>,
    n: usize,
) -> (Vec<AssetRecord>, Vec<AssetRecord>) {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);

    let amount = 10;

    // Prepare inputs
    let mut ar_ins = vec![];

    for i in 0..n {
        let user_key_pair = &sender_key_pairs[i];

        let (bar_user_addr, memo) =
            conf_blind_asset_record_from_ledger(&user_key_pair.pub_key, amount, ASSET_TYPE_1);

        let oar_user_addr =
            open_blind_asset_record(&bar_user_addr, &Some(memo), &user_key_pair).unwrap();

        let credential_user = credentials[i].clone();

        let user_ac_sk = user_ac_sks[i].clone();
        let ac_commitment_key = ac_commitment_keys[i].clone();

        let policies = match asset_tracing_policy_input.clone() {
            Some(p) => TracingPolicies::from_policy(p),
            None => TracingPolicies::new(),
        };

        let ar_in = AssetRecord::from_open_asset_record_with_tracing(
            &mut prng,
            oar_user_addr,
            policies,
            &user_ac_sk,
            &credential_user,
            &ac_commitment_key,
        )
        .unwrap();

        ar_ins.push(ar_in);
    }

    // Prepare outputs
    let mut output_asset_records = vec![];
    for i in 0..n {
        let user_key_pair = &sender_key_pairs[i];

        let template = AssetRecordTemplate::with_no_asset_tracing(
            amount,
            ASSET_TYPE_1,
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            user_key_pair.pub_key,
        );

        let output_asset_record =
            AssetRecord::from_template_no_identity_tracing(&mut prng, &template).unwrap();

        output_asset_records.push(output_asset_record);
    }

    (ar_ins, output_asset_records)
}

fn setup_with_policies(
    n: usize,
) -> (
    Vec<XfrKeyPair>,
    Vec<ACUserSecretKey>,
    Vec<Credential>,
    Vec<ACCommitmentKey>,
    TracingPolicy,
    Vec<ACCommitment>,
) {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);

    const ATTR_SIZE: usize = 4;

    let (sender_key_pairs, _) = multiple_key_gen(n);

    // credential keys
    let (cred_issuer_sk, cred_issuer_pk) = anon_creds::ac_keygen_issuer(&mut prng, ATTR_SIZE);
    // asset tracing keys
    let asset_tracing_key = AssetTracerKeyPair::generate(&mut prng);

    // All AC keys are the same
    let mut user_ac_pks = vec![];
    let mut user_ac_sks = vec![];
    let mut credentials = vec![];
    let mut ac_commitments = vec![];
    let mut ac_commitment_keys = vec![];
    let mut ac_proofs = vec![];

    let user_attrs = vec![0u32, 1, 2, 3];

    #[allow(clippy::needless_range_loop)]
    for i in 0..n {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let (user_ac_sk, user_ac_pk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
        user_ac_pks.push(user_ac_pk.clone());
        user_ac_sks.push(user_ac_sk.clone());
        let credential_user = Credential {
            sig: ac_sign(
                &mut prng,
                &cred_issuer_sk,
                &user_ac_pk,
                user_attrs.as_slice(),
            )
            .unwrap(),
            attrs: user_attrs.clone(),
            ipk: cred_issuer_pk.clone(),
        };
        credentials.push(credential_user.clone());

        let user_key_pair = &sender_key_pairs[i];

        let (sig_commitment, pok, key) = ac_commit(
            &mut prng,
            &user_ac_sk,
            &credential_user.clone(),
            &user_key_pair.pub_key.to_bytes(),
        )
        .unwrap();
        ac_commitment_keys.push(key.unwrap());
        ac_commitments.push(sig_commitment);
        ac_proofs.push(pok);
    }

    let id_tracing_policy = IdentityRevealPolicy {
        cred_issuer_pub_key: cred_issuer_pk,
        reveal_map: vec![false, true, false, true],
    };

    let asset_tracing_policy_asset_input = TracingPolicy {
        enc_keys: asset_tracing_key.enc_key,
        asset_tracing: true,
        identity_tracing: Some(id_tracing_policy),
    };

    (
        sender_key_pairs,
        user_ac_sks,
        credentials,
        ac_commitment_keys,
        asset_tracing_policy_asset_input,
        ac_commitments,
    )
}

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

// All the key pairs generated are the same.
fn multiple_key_gen(n: usize) -> (Vec<XfrKeyPair>, XfrPublicKey) {
    let mut sender_key_pairs = vec![];

    for _i in 0..n {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let sender_keypair = XfrKeyPair::generate(&mut prng);
        sender_key_pairs.push(sender_keypair);
    }

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let recv_keypair = XfrKeyPair::generate(&mut prng);
    let recv_pub_key = recv_keypair.pub_key;
    (sender_key_pairs, recv_pub_key)
}
