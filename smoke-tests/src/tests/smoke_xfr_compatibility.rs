#[cfg(test)]
mod smoke_xfr_compatibility {
    use noah::parameters::bulletproofs::BulletproofParams;
    use noah::xfr::{structs::*, *};
    use noah_algebra::prelude::*;

    #[test]
    fn compatibility_v1_bar_to_bar_no_trancing() {
        let body = r##"
{
    "inputs":[
        {
        "amount":{"Confidential":["5g8IfrT4NYp_61JJiax5CUAirCYpozEpAMhJCAOE0S4=","QDtwusr-UHTBrw0zG5KpSDCie9Y3dtCUkN2EsiATLhc="]},
        "asset_type":{"Confidential":"TotuwivH9kNvnCZg8fCmPFMMNgOx1bXYl8tDhJWDzEk="},"public_key":"zpTV5hl3UDlSAU0wzByBMDTHu7jd52yLGclcHwE4HB0="}
    ],
    "outputs":[{"amount":{"NonConfidential":"10000"},
                "asset_type":{"NonConfidential":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]},
                "public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
               {"amount":{"Confidential":["vh2zjBDXpN20c2i4WOpqr3VcsOJwjXRw_cwYACdq-Tk=","DLEPKxj5BgXVT-cNsHWhgds81yZ-G27sUWdSXdfUmWY="]},
                "asset_type":{"Confidential":"LHOJXMsD4kP-Ni3ZyTuTBoTO-p06iXa4HBvWjEJAdBc="},
                "public_key":"zpTV5hl3UDlSAU0wzByBMDTHu7jd52yLGclcHwE4HB0="}],
    "proofs":{
        "asset_type_and_amount_proof":{
            "ConfAll":[
                {"range_proof":"Tr_LQl18i8AIuZqDNsrDGbp8pX_KT5gU3Le7gHEfSkTqwRWRCFYZzOzq6Wo7w3WKl_J8-C5Kz0zQQFIH0wNve3aZEHRu3KuxqSczwEQQIrdWq9jLEAzPSfQ4DC4-2qwABKCd0IaXYHROY482qEZMblCiVcYbEToA6J_uvkl3oUISC-GG9fEBURGsHNFEC4u88lPJ_-szQMY-pUiQ3bm7CF7B-sknvGjnWGjKVHWqXG2zDIIKpukxFNtNmnaE4YMD0TdlMG8F3YqFZwtuSvZiIQ1VV3aMIn39nl331CNlLQagJs-v7ZmrGdi_AfpVZ8nC5X7xFMfneUOYIoA06JySNswC7xo1k2E2WVJq9fPvlc2AOC0lNPogLSm20ebnWUEv_GFI_yav7gmgUi7sK6TKeG5bMYvIECT8KxvjOmdz4nYC3yfhPGXHYSEdRRGEZASZgtYipOaBax98Zivl4RN5NIwIvvJQtAj9j7aN3TTIhLMkvwn4roDpQMHdm8KKhWIFhA5i0PHuPibeeY-tP8RxPg4xKa4GwZG_B7I88uOqyVKUCzxkKI6Y15KYMoICD0AIcw8Dt4sHORX1EmcFyxahMuAkg9uECANXEkt6yRMK4u-fCvEz_l5kx2rZcGGYwAwLunrmmY8MISCd_gOqrYmyhmUHDjAoMY-hSMkVEetYXFgK3pVY7t0G1nYnS9LVkuNe9QnHBQEUEdLhdaLOoY2QAiyy0Tqk4HOfcPCKOYjUhdPQWi0-yx54K7HCoJxEp6wS0EWCdspldSrEFEBN4oMxccGky5ybIb_xyNqn8htJpgzokEStY5L71cGeTcFbhpP8dhcjb1LkNF2dNRJy7qheBup0jJT8QUQDwIL7HHv9nFy4TaFsQUSr0VAadsmWGl0Vnk4wUADGqFEaTeiywf8keexPZJW4mkvGtZpoOcJ8eQKSGsVhdsbFgKwh9DK-nRl9t-iJwH_wEpp89dlsOFhzcyTH2q4Ovhc3QT83JNiK8HAXbWgOBUxpZ6bffgzNuQANcO-B7xGUA5UenOXW8s6FPXjK8GdEq9M5TTgs-JiJ2Qg=",
                 "xfr_diff_commitment_low":"3N1tvEXirnPAPSC4kBB0dhXnTZHgkDFWHa2GrK4qxDA=",
                 "xfr_diff_commitment_high":"tg5SuaMqJFopA3T2sTTYuKtyi-cg_BaU2yZgt1y-I3M="},
                {"c1_eq_c2":{"c3":"kEK1yXh2wl6qPooAxV3FILoii3OBi10G6MkIrkf6smk=","c4":"0CC-9-urVfiJqDIXapMsKtHccjE-Tps6jUOJNw0-a2c=","z1":"RSIl-0xYwA0NqquJE3YTm35ll1FGouOHSdAKHTeO9Qw=","z2":"dYxCFFo8nXrH_9K_t6y2xiVB_JXdvPSR--CTXptHggc=","z3":"PpXwARoiktXjcnsp4ulfzNWqjTsmEyxpEAoTq_BhgwM="},
                 "zero":{"c3":"Zk6NkzsDthU1A4miO4gtq0XFcTK3_x8pnoknYaF7AH4=","c4":"6HBX41mNk6drZ8wxpYkIfxPNDjGid0NKN2lhVR4VanQ=","z1":"JiWqImDX8-_xmjFsbQQBs6qqHIDzOVW6L0Tx2XpbewE=","z2":"XntbL9IUQqfgjwwyvCIK_w4fAGXAPtjp5IVdL7yPxAc=","z3":"Dn4dhElNF4iXN55Vm2kXGyoZ-o-eBbVR5qDWhF88XQU="}}
            ]},
        "asset_tracing_proof":{
            "asset_type_and_amount_proofs":[],"inputs_identity_proofs":[[]],"outputs_identity_proofs":[[],[]]
        }
    },
    "asset_tracing_memos":[[],[],[]],
    "owners_memos":[null,{"blind_share":"DCwxC8OMKdoUrkH5upcMzEFrRtgx_QmNapPfYsoQzis=","lock":{"ciphertext":"B2krDhuxQYASoGUHQAtB0iUH2x8GwtwPxrhTEr1M7QWSq9E2xdURHg==","ephemeral_public_key":"YTQHBbPb8J8CS-2wDMl1adLrF_PWQYZ6nN9hsGwzUFk="}}]
}
"##;

        let body: XfrBody = serde_json::from_str(&body).unwrap();

        let mut params = BulletproofParams::default();
        let mut prng = test_rng();
        let policies = XfrNotePolicies::empty_policies(body.inputs.len(), body.outputs.len());
        let policies_ref = policies.to_ref();

        assert!(
            batch_verify_xfr_bodies(&mut prng, &mut params, &[&body], &[&policies_ref]).is_ok()
        );
    }
}
