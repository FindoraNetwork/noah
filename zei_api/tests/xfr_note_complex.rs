#![deny(warnings)]
#[cfg(test)]
pub(crate) mod xfr_note_complex_variable_size {

    use itertools::Itertools;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use zei::setup::PublicParams;
    use zei::xfr::lib::{gen_xfr_body, verify_xfr_body, XfrNotePoliciesRef};
    use zei::xfr::structs::TracingPolicies;
    use zei::xfr::test_utils::{
        prepare_inputs_and_outputs_with_policies_single_asset, setup_with_policies,
    };

    fn check_xfr_body(n: usize) {
        let (
            sender_key_pairs,
            user_ac_sks,
            credentials,
            ac_commitment_keys,
            asset_tracing_policy_asset_input,
            ac_commitments,
        ) = setup_with_policies(n);
        let sender_key_pairs_ref = sender_key_pairs.iter().map(|x| x).collect_vec();

        let (ar_ins, output_asset_records) =
            prepare_inputs_and_outputs_with_policies_single_asset(
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

        let mut params = PublicParams::default();

        assert!(verify_xfr_body(&mut prng, &mut params, &xfr_body, &policies).is_ok());
    }
    #[test]
    fn test() {
        let sizes = vec![1, 2, 8, 16];
        for size in sizes.iter() {
            check_xfr_body(*size);
        }
    }
}
