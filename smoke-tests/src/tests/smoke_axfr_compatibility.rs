#[cfg(test)]
mod smoke_axfr_compatibility {
    use digest::Digest;
    use ed25519_dalek::Sha512;
    use mem_db::MemoryDB;
    use noah::anon_xfr::AXfrAddressFoldingInstance;
    use noah::keys::SecretKey;
    use noah::parameters::params::{ProverParams, VerifierParams};
    use noah::parameters::AddressFormat::{ED25519, SECP256K1};
    use noah::{
        anon_xfr::{
            abar_to_abar::{
                finish_anon_xfr_note, init_anon_xfr_note, verify_anon_xfr_note, AXfrNote,
            },
            abar_to_ar::{
                finish_abar_to_ar_note, init_abar_to_ar_note, verify_abar_to_ar_note, AbarToArNote,
            },
            abar_to_bar::{
                finish_abar_to_bar_note, init_abar_to_bar_note, verify_abar_to_bar_note,
                AbarToBarNote,
            },
            ar_to_abar::{gen_ar_to_abar_note, verify_ar_to_abar_note, ArToAbarNote},
            bar_to_abar::{gen_bar_to_abar_note, verify_bar_to_abar_note, BarToAbarNote},
            structs::{
                AnonAssetRecord, AxfrOwnerMemo, MTLeafInfo, MTNode, MTPath, OpenAnonAssetRecord,
                OpenAnonAssetRecordBuilder,
            },
            FEE_TYPE,
        },
        keys::KeyPair,
        xfr::{
            asset_record::{open_blind_asset_record, AssetRecordType},
            structs::{AssetType, BlindAssetRecord, OwnerMemo},
        },
    };
    use noah_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
    use noah_algebra::{bn254::BN254Scalar, rand_helper::test_rng, serialization::NoahFromToBytes};
    use noah_crypto::anemoi_jive::{AnemoiJive, AnemoiJive254};
    use parking_lot::RwLock;
    use rand::Rng;
    use rand_core::{CryptoRng, RngCore};
    use std::sync::Arc;
    use storage::{
        state::{ChainState, State},
        store::PrefixedStore,
    };

    #[test]
    fn ar_to_abar_secp256k1_test1() {
        let bar = r##"
        {
            "amount": {
                "NonConfidential": "10"
            },
            "asset_type": {
                "NonConfidential": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
            },
            "public_key": "AQN0vyugBr9CwmEXTRBn0_XB-HSSNk7nGlwW6i8TkgeNyg=="
        }
        "##;

        let sender = &[
            1, 192, 77, 218, 176, 60, 214, 159, 61, 111, 15, 81, 78, 18, 153, 13, 154, 141, 2, 175,
            51, 78, 253, 250, 59, 177, 125, 220, 25, 151, 154, 255, 2, 1, 3, 116, 191, 43, 160, 6,
            191, 66, 194, 97, 23, 77, 16, 103, 211, 245, 193, 248, 116, 146, 54, 78, 231, 26, 92,
            22, 234, 47, 19, 146, 7, 141, 202,
        ];

        let bar: BlindAssetRecord = serde_json::from_str(&bar).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        assert_eq!(sender.get_pk(), bar.public_key);
        ar_to_abar(&bar, &sender);
    }

    #[test]
    fn ar_to_abar_ed25519_test1() {
        let abar = r##"
        {
            "amount": {
                "NonConfidential": "10"
            },
            "asset_type": {
                "NonConfidential": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
            },
            "public_key": "_fzHq2QINt43eqSfEwUXWZ_PhIGtl92r4tojScyzjVA="
        }
        "##;

        let send_key_pair = &[
            0, 174, 86, 209, 121, 168, 132, 10, 101, 143, 58, 129, 64, 113, 4, 131, 127, 24, 12,
            41, 97, 29, 125, 17, 102, 81, 223, 138, 126, 141, 88, 27, 156, 253, 252, 199, 171, 100,
            8, 54, 222, 55, 122, 164, 159, 19, 5, 23, 89, 159, 207, 132, 129, 173, 151, 221, 171,
            226, 218, 35, 73, 204, 179, 141, 80,
        ];

        let bar: BlindAssetRecord = serde_json::from_str(&abar).unwrap();
        let sender = KeyPair::noah_from_bytes(send_key_pair).unwrap();
        ar_to_abar(&bar, &sender);
    }

    fn ar_to_abar(bar: &BlindAssetRecord, sender: &KeyPair) {
        let mut prng = test_rng();
        let params = ProverParams::gen_ar_to_abar().unwrap();
        let verify_params = VerifierParams::get_ar_to_abar().unwrap();
        let receiver = if prng.gen() {
            KeyPair::sample(&mut prng, SECP256K1)
        } else {
            KeyPair::sample(&mut prng, ED25519)
        };

        let obar = open_blind_asset_record(&bar, &None, sender).unwrap();

        let note =
            gen_ar_to_abar_note(&mut prng, &params, &obar, &sender, &receiver.get_pk()).unwrap();
        assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok());
    }

    #[test]
    fn ar_to_abar_secp256k1_test2() {
        let note = r##"
        {"body":{"input":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQJHv7fC7BWyCu-p77HTUXF4P2TRcCx0epOKfrWdZ9Shcw=="},"output":{"commitment":"zJ47X6qiBzoXm0jXgZ438rElhEQlMzAA9c7KJe113Sw="},"proof":{"cm_w_vec":["rcVZrf_N8Napi0PaoK38f7i_M1w5m3GQdry25jULA58=","Fg7QhuMYvEHfzHWHoQ2rYuP-_07pWxeM9p9SusPSfA0=","wCi5lTuxKJHWAF3IeHHm2heTOSZMbfzJ5Fz_kVruqIk=","JPthF_9s06pKSEEd8gIW2Z9qcsctU9OkrtveCDSVmo8=","UNZudkwV5Bt2FpL9hRo7e9OpYjNaRFiiflYbCQCQaR8="],"cm_t_vec":["N8KPz9iQHFdGAxvAI7T1kbcw_i7XLqNGTSCLgE4YdJo=","iiu8TmAP_vlMlp5TEdKqh2cbICjo6Hn6begOYZRklSE=","Mrx-O-RIu25rbqEDYH-5DFHc_qwNmkRR8_X8H99xrIw=","s2pRSY0aO1XQJiXVIbl9u0AmUyCPg5dmILkiDmgrKKk=","yITfJfAYYe72kNIFTswJG1x93a94rwShyyhqvwcBPAA="],"cm_z":"aag5DuX152Lq7dNaGgHQLw2l1st6kGi8yiNWG89yfiU=","prk_3_poly_eval_zeta":"0nP8LuALKPe6kqrGZdEh9FI59iIahwBFgWSa_MQpCi8=","prk_4_poly_eval_zeta":"t3vgW-Ac9FxzWH2LWPiIMwfMs-Eyeid7q0MdvALTmyk=","w_polys_eval_zeta":["wU6bmqvonwmXwKpZjhrYuw6b2gLabG638UO9YPgKhQw=","EcAKRYRHNhrZXn6mUZY8dMFauzz_hXuCx37RU9Gf5wE=","oXd64yEBFhBBRk8Rw5ZB0TnCKM18nOQz_EZ3v1oxjSw=","d2xOkK7gNM4FulkaDruCeim6Pop7ZNUVTKB1FW4bSgM=","KPvx7MWUMDgujydqRbljZ3crUtg_1bF1816zzRaaZiE="],"w_polys_eval_zeta_omega":["p2DYtxthqGu8UmV4NipjKlQ21-qvMhatgNQ3wH-u6yk=","uihBjPMDuJh2Hl8OyvVPr3e_xwmc9M3CVrwM9E7lEBk=","dBGlBzift4R71iOxy7OI1uEHI1xlutQOs-2S1_ar0xg="],"z_eval_zeta_omega":"vAKSWbPECmzZnleutOQHIOowu69K2Y-Fv46ypT1Lug4=","s_polys_eval_zeta":["2Tt6HZ1b77A_1mXlqUKdXvjCqdxl6TPbeDB5n7e1DhM=","oR3uwaXsvyJnjLYt16cbPTVNxI_uF4RpvVg4ZAmHJig=","LBfU0NA-SDcoCbNYryCY6BUIOQ3lg5mZjFMYpC7NhQU=","p8aV7Zt7YdBlTkT3kYkbzILf1ZBdViuxyJrlGaqspQ8="],"opening_witness_zeta":"hnIgNWCF0q6r4fw0H3kRRcLnB1Falil56ZWh_VDk5QM=","opening_witness_zeta_omega":"WajP1NkrW35eQ0-AJhvEkp4CzaJFLjftX1bwdSO4jSs="},"memo":"1PLPu4Ey30ct5EGQoaeuB-hnubwmzYLRQIKND5uZu7mAJcS9PxYbTEeGc0G0kESVVc521YKUbu_5bUfWbPGDiXbAtT0VkVLPzUVRxvtIG8N_zkNk1hZ4axPHMo5n9XINinhcyzrUwfLJuIz7vAbGA56YKv4S5cIbMw=="},"signature":"AbrEXB640TDP28sSX302-afQybg1E3t7GK7MX_n9GFKLSzFeIs5bGBFhdU97gat7PBYfwr-MiBuV5rmCFvvxT1AB"}
        "##;

        let note: ArToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_ar_to_abar().unwrap();
        assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok());
    }

    #[test]
    fn ar_to_abar_ed25519_test2() {
        let note = r##"
        {"body":{"input":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"FmTb2hwhY0EyJ1o5PyOllljsBN3ttpcWX5duutV1iuc="},"output":{"commitment":"kyZRjASl4Yi9sW59XxXNeBfgWBMWEP14X8TZBsd8uhc="},"proof":{"cm_w_vec":["76oTtDf8pKiStZFcmk39L1bcwXW7fFg0IFke2F808Yg=","1t-ZD50A75B6OLzPljf2aN2ol9cx2VNfKSeg7POTmY8=","XPlyT7JkWBC8cQ-8hItYzxtXhMmNyiUxd6YH-71lyiY=","Bxc4tZIN2zMOqmzVJdB7HQPSKEf_C0D8_1XCDWLC0hQ=","5zr4WHt3bbw5IoEnLrxZuBsHQgyRJuUaNbEXglfSO4A="],"cm_t_vec":["GCdTkhzPpSlNyr-5_l4l1qt_YWN5FfVAZZiKnbeOsBk=","Ub_g6szX0AZ6oteUx2dqSPwdhSJlsTdLybFPObN_B7A=","GilJ8F3sLS1hj_8LGBm7gM7gKUSiaL7DjuuFdnBydqA=","OJyXgyI88lRNdczUFCnH9PPTYvu4Ex5GNgvZHPqm6AY=","29frXFtFWnL-x5lH1hRA5hpTKwWnmmgHlfip80DqOaA="],"cm_z":"abTp-mONu6vnCOcfBCFunkBspsZBdiIJm5DGtSszcio=","prk_3_poly_eval_zeta":"M4wvak0JaPiZQRapTgCSRGo-uWCfskknc0Yk27cMhCA=","prk_4_poly_eval_zeta":"NP5tpWILkSDRXuMafeSdPdHefPy8oBn0R2gVVXe7ViQ=","w_polys_eval_zeta":["XxHq2lmUzjUkP9jeuPCvc4MvFgH8RCw2sgGH7_YVVCk=","gQAa-JuyG_gIQNNqbiOwAdN8L_smVHbVLSdMSSHnLRs=","ohCREiboe2-9CHugK_ATuGRZOU0Fd8p9PohRWkg3ty4=","OsbUt3VrDVzODZKQhOKtuWaqlvXYR5rj59iDNedTPQ8=","fEjeMiT0ZBZMmes415VZ3dFTtgfQPmI7QAIdrNS8VRE="],"w_polys_eval_zeta_omega":["C_MEND05epmtm6iTOr-A9oHp1TgMSy-cvkb2tYwJDQU=","ZbOp1nqepINPrMxExfbKzDPObaRbsP8GWPOK-w_b9iY=","Q10dz3N8FQocwtzYusSkJ1MB_z2f0O9aJDVjs804QhY="],"z_eval_zeta_omega":"CfdoYLBwAoDssW1dHZR7xPgImcExDxSkXO0YRAx4gBA=","s_polys_eval_zeta":["aqtUx-jk9_zzzXCWX5ANfCuaciRK08rjiRiTEqx_lgI=","F3CIw1GmrcwQLuLQdQG4jEnc604sY-qQ8MInMpcCBwg=","3hkPKx8hTYmWpa0NBfvjiH3jG2IdFSBUereNZLLWtg0=","cFD1P2aqKH0QjYZfIN-3rTcbcfCr3F-rZ9gk6IgUNB4="],"opening_witness_zeta":"Sll503kLQfwGaiFCsGR572BbW_obwst-m9XDhWXb9Cg=","opening_witness_zeta_omega":"K0WNgpKPl17xuyVjlu6yjofZJ1Zk01s9Kvg4yJiqugw="},"memo":"8hfv5bS1WpOJwfaw6dSqoYcRuqtymo5fjc_JEzEQdfVB1VYeTu5OP3DYt17-zfvLcQI3MXd8rE6iwMJGMwRvplfeZ8mo-TBnPLAKcx_nQ4hclJfFWI_WA66sFbTC1-U09BK8yUdu8mZKyTKBZyIoHZL9R9fnZQ-j"},"signature":"AHZ9aRVoTQmRTjVkpkhHpCAp87PD6vdcQbjSPTqwyc_SFiMXDwyIc3SayYyGUoIXCskOrrQnO_xwSILfWJInXQ0A"}
        "##;

        let note: ArToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_ar_to_abar().unwrap();
        assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok());
    }

    #[test]
    fn bar_to_abar_secp256k1_test1() {
        let bar = r##"
        {"amount":{"Confidential":["2Hr9fv6W3MZbY0FD24cHLQO0LgkHJHe4a0IUTas07Hk=","jvG5gkmysJ6vTlC7EeafuPy_Ktw5VVzb6uXDR1d47G8="]},"asset_type":{"Confidential":"XKScJSw9qLcg2cBA-CKduHAfP5x5BKh28iAnfCp1lwA="},"public_key":"AQLR1KmOhJ05Zqz19xUcDbAqAXdY0nwu9Pyhcsc_E69JPQ=="}
        "##;

        let sender = &[
            1, 31, 101, 108, 81, 176, 128, 115, 78, 107, 216, 212, 201, 59, 84, 212, 130, 22, 13,
            65, 32, 221, 38, 179, 78, 219, 15, 135, 66, 147, 172, 32, 172, 1, 2, 209, 212, 169,
            142, 132, 157, 57, 102, 172, 245, 247, 21, 28, 13, 176, 42, 1, 119, 88, 210, 124, 46,
            244, 252, 161, 114, 199, 63, 19, 175, 73, 61,
        ];

        let memo = r##"
        {"key_type":"Secp256k1","blind_share_bytes":"9jfkP7i3xonKmQoahtWnQ_L3rzBD5nmEdW0W_uE2IB8A","lock_bytes":"ucQ9f3wvhz06zUWfrdKTYQcLUsH_URTgbQWnDACVMdaApp8f27CIPye7vJkH2xb-7saXR5Ji98_hbnyFIQ7-NmYrsH0yvm6c_GOd4GhsPl9MJqi8Z4XTRmA="}
        "##;

        let bar: BlindAssetRecord = serde_json::from_str(&bar).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: OwnerMemo = serde_json::from_str(&memo).unwrap();
        assert_eq!(sender.get_pk(), bar.public_key);
        bar_to_abar(&bar, &sender, memo);
    }

    #[test]
    fn bar_to_abar_ed25519_test1() {
        let bar = r##"
        {"amount":{"Confidential":["nmV_HruoWM-7gfrprYvQ-jtGpLJR2hfWvv3Nk1smhQQ=","bMNPPxforiFKfx8MyTVu6RUc-hGu6bTplF6221vUzgE="]},"asset_type":{"Confidential":"HvVIKQONVUlaEdCQRnWf8PjrEDj1yMF9CSJRJBc43Wg="},"public_key":"0qxG5r-YXF5meGrP_a1UvUbtIoFoOO4oXp62giUoX5c="}
        "##;

        let sender = &[
            0, 250, 114, 118, 129, 234, 7, 178, 241, 144, 243, 7, 218, 255, 104, 175, 12, 97, 238,
            177, 226, 247, 252, 39, 102, 176, 106, 130, 14, 255, 245, 188, 94, 210, 172, 70, 230,
            191, 152, 92, 94, 102, 120, 106, 207, 253, 173, 84, 189, 70, 237, 34, 129, 104, 56,
            238, 40, 94, 158, 182, 130, 37, 40, 95, 151,
        ];

        let memo = r##"
        {"key_type":"Ed25519","blind_share_bytes":"nb69edqqCI2KyJBYo-asr_9Mp2v7B22sGxYxi7BkpKw=","lock_bytes":"9rPMcgrZv4IBNvkeij54NsX3SbUemfgdG6yk3MC9ZU4hTGfyLg9T9vZxZHDPeVcB1qp2fyehQxhEK1ukBjm1oZXsXppMhMvF"}
        "##;

        let bar: BlindAssetRecord = serde_json::from_str(&bar).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: OwnerMemo = serde_json::from_str(&memo).unwrap();
        assert_eq!(sender.get_pk(), bar.public_key);
        bar_to_abar(&bar, &sender, memo);
    }

    fn bar_to_abar(bar: &BlindAssetRecord, sender: &KeyPair, memo: OwnerMemo) {
        let mut prng = test_rng();
        let params = ProverParams::gen_bar_to_abar().unwrap();
        let verify_params = VerifierParams::get_bar_to_abar().unwrap();
        let receiver = if prng.gen() {
            KeyPair::sample(&mut prng, SECP256K1)
        } else {
            KeyPair::sample(&mut prng, ED25519)
        };

        let obar = open_blind_asset_record(&bar, &Some(memo), &sender).unwrap();

        let note =
            gen_bar_to_abar_note(&mut prng, &params, &obar, sender, &receiver.get_pk()).unwrap();
        assert!(verify_bar_to_abar_note(&verify_params, &note, &sender.get_pk()).is_ok());
    }

    #[test]
    fn bar_to_abar_secp256k1_test2() {
        let note = r##"
        {"body":{"input":{"amount":{"Confidential":["iskgKSdroRx7vrQ8chZ51pN0nKH--pos24lhIfZl4mg=","pgb7CTQaQtZwZ6fZzT93fkauSc7qfdfOqmbhMH9-ZBo="]},"asset_type":{"Confidential":"iOHI3_r4l0GUy270JfNJIy5Jj_MmVqSCwx3LiksxGXA="},"public_key":"dbDduxsIyICFZHmRYk3dbEjTu_lagQVpPMB3KSHQnxk="},"output":{"commitment":"cr0p-OwCKIQeD1wl81Y855FfJ-pUnpeQ7j-62uh1niI="},"proof":[{"inspection_comm":"avMqMeaaV5saC9WYMXbHMz0xqrNjMPdYC0L6_VP6rhc=","randomizers":["0Kylnyuw5V-n1wuLpUuSYc5i0P1zWiA6Oj5La_LcySA=","xqJP1iO1o3dJEhIOv7zl2U9w0RIlubfzDjLSh_n7ZBI="],"response_scalars":[["5aAwrK2EXvHYHyFSgezq5q9jtBBuOl2SwrVEuW7ktgg=","z_ETzUcxWL3YTJ14fmBWJDZcgW9ifL8YM_18lb-RdgA="],["nIe-rVD66eZoskdt6AdFMXWgyT9eJHyEhxPhdpBH-wE=","3QlE0ReODnDdUHqzNgVcdnj__l5u5tC7gWMQVRqF8AU="]]},{"cm_w_vec":["W9m7bXKwb8r52D6ssv_YliJTOpS4WEejxuhkpmnlMwk=","hc316_OG7HMS1T83hjidn-cjXC6Oqq7VuN9iniv-cYE=","n5R6891PA4WA4R8Z6w870K3NAJlNf0UgrzBeRT14XAw=","-oq-Id0yiCg640umxtJ3j7zACRgQC8LI_PCMI0Jq7Jc=","tYAdSFRGqJwilgvPiaZa9jr7qXyNzPZHNTNqush4Jhk="],"cm_t_vec":["rr7SYDtnrYM7K3x2kk2bX8kiAayWrmP35DWvVm07jp8=","qcjtNOU6N0ho8ocKY9u2tvbd6CdhkPCikM5S3rlnrS4=","l60F2O3x6slZ1tyPgPnATmbHF_DGHz_b03c0GAVzK6c=","7af41vX2o-ODEE6fK89dj4c95O0MqyG8Jp5Zj9s13oU=","ONa6Eb0IM_FKfK5JXO6fK2YtPXbMcmH4yb6FqUXAAiY="],"cm_z":"6HfUlLc0zFDmz9MC60D9A56nwsALuhiti3tfk6SjdRE=","prk_3_poly_eval_zeta":"SkdPiE9qXoH8pVzzddKQnsD_bCh4tvvkxQ3hSIFdyyQ=","prk_4_poly_eval_zeta":"MzZOUSf6JI_TAB0zQD38K4nCu8hLKipvOb5npnNEQwE=","w_polys_eval_zeta":["UhiBexYYBz4ChBwnlcT393gDoVEVuamdNr9sXnIYKik=","alb691D7Gduix7Vb2MKvaUuL4feATDsc4pc6qtEFIwg=","wAqIZmoKxP9cbpZhZIA59gTDTP8kzs_wZLBtiKc3jig=","aIud87kSkLaCOCGuF45TPfBSeWnQh6WtvD1Cb1M0nhQ=","3vZEF1_Uxlzki7N08lkcrnDt5dhUrLgQpLfthttCGww="],"w_polys_eval_zeta_omega":["OhauJ1T06TXtSXQjqIyrI2bqJwBzFlcsoqD4xSEU3Bk=","ANXuHjrpu-PTI4BC02jggReXTCEpJMaQV0sXl-O8wwU=","0OJUu5AJnMYld4pg0G-gtJwcDwbQd262Zp67h-RXzxo="],"z_eval_zeta_omega":"Z0MpawwX3ptdYJREU1GAznFnCHoqJxwHwpYBlEujSgQ=","s_polys_eval_zeta":["ByV5ElONkmuB1CKcwqgH6LG25pqE6Sg6cEMm23TdYzA=","Y1f77qUT7jEeSk801MAr8VSDwYe34lEVcyinleaNABY=","HHbtvjckvINStQko51lMM_pc61Gbet7k0utx8O32DCs=","k_N4NcU6fUxexhIESniPc9uj1WQY4iR8Tc4VDyHYACs="],"opening_witness_zeta":"DU1haukIgEa5skp5YUlEW6hTjN3cN1WM0VB63vOgCBQ=","opening_witness_zeta_omega":"hcsyLE_8ps3JU-2Ti5X3nuq4NuU6SazER6HAUKAMLgg="}],"memo":"82_Cfya5qMi9lFtSPUW0beBdJwhsxO-ERgCSzb8M2TgF-zKcsapiTww901a8MUd1dNmmFRhRZBPNQIYbA21Hoh_l1GSjpGpzVIa9t3x3HFVafJ4XcDRLkFwQqrxAkXQ0fVNHoxVEhUVl9M2CH4K2uCUfQ4x7Vfyq"},"signature":"ALI5JCeCVSnyK6NMk7p3VFo5IjTMG3RyDc7B14KZN5vMQnLV9Is2Bg8T3L_j61KUBGrHx4V70N--v9kUlCfghg4A"}
        "##;

        let note: BarToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_bar_to_abar().unwrap();
        assert!(
            verify_bar_to_abar_note(&verify_params, &note, &note.body.input.public_key).is_ok()
        );
    }

    #[test]
    fn bar_to_abar_ed25519_test2() {
        let note = r##"
        {"body":{"input":{"amount":{"Confidential":["WMQ0QECfEBXWIcO9dlPpt8kIrk7SG-YfnVqQ4qKd9UA=","HJBrauyDS__DYaWyU8176ZzA_QZumpJQ2CjkdQDmsC4="]},"asset_type":{"Confidential":"-IaRDS6EfO35_k9kyXOtj6d7jSdLC30P2TlMthBoG0M="},"public_key":"aHU3Z1cNcmrnKLsuWf4c6VAvzX8sEmNuiBo0Bg52byY="},"output":{"commitment":"MtW8LkFfz0UN5LOuycnfV4t4bIf2y6r0G9ynhEloTAI="},"proof":[{"inspection_comm":"25N1LodKoLqXr_6Of17U9xCmgEqF96XKLb9rLY2CVR8=","randomizers":["huN0d62gHbZcsDYEALe0dalysWTK1I9cfkc5LE4b01I=","vB3nKZOc0fKk9JqEXxYHeb7BTdzUFAM5Jb9JCZ1SVyg="],"response_scalars":[["CcwBt272Z2uX0P-Af7Ps7Z3stJcGz9sPNFD9uw27YgU=","pTpryN0Oy2PS0Jkzeo95khD-v9WsHWSTQgw3bkY5gwM="],["aeJoOyuSrhA7fWyrrk1q9S-Seawgu4WMiP8tu_byTgQ=","sBJJqwkTobOdtVqzNLFUOh0_6iAd_ff6gSSCRyZ0Wwo="]]},{"cm_w_vec":["pgh5KnquhIcTrzPB-9P_nJ_Y0Fd49YrGFvKOZ8vfNQU=","9hlt4Ad5g8k7o_MD5J7yQR1Sb-u2AqyIiUFcqF5K2hA=","uUC4JNx4WTpAabZk3vg6e57i0wCdps0i2brXezKkii0=","jBIecvZxlJq8jPxQ9mOYoPYhf-TJHANd8mL1TUCdqRE=","bxycXgnALKKzXdl0yivf5dumyjvunI9g20zo4gv534Q="],"cm_t_vec":["kJkW08KD-DPpVPWqYbTgjBvWiXVrQFUTR2tjzSMfK5w=","Pcc-N3SMjNnpyZbdbqKZA5XvlLVsA5inKNULaQC0Cio=","xDLj1xZMQqS6aT9gyuxfORdFbi_TRnRZk07npqo_c5Y=","bnIQ9WhaWpBCJHpDGSH1oBb0c62KR0p7udOswQmDjRM=","oaaZ3AXP6dfcZts7bpluFdtWQbG3pnnq8LcWM41OJBQ="],"cm_z":"DN1W3fBvZwTsxNKYIX9R86CfMvscqdyDZ4U1bv8qwgo=","prk_3_poly_eval_zeta":"Jm5sO9YOBuo80aKxDrL9790aODHmccoBsmtlWJ0DYgY=","prk_4_poly_eval_zeta":"PpSXwFbazkTscSm5M_x43HXvZnokpbBAk5WEQkFqswc=","w_polys_eval_zeta":["AEFgjvrt5RXe0662KagFN1Hr2L5glV9VLmFggStwWBM=","FK-YAfLDyN9mQgUcUIDdGsb84HUvQRsPUJZb3JxmMyI=","kNId6DLhYdGJyJYhIkae3sKWCn3HU0WOqfKa2iMGVgU=","y2kxCZ3J0vttPkwXuxQfzTTK36NHu8AAc83mt599Lhc=","TFRckTlb58DMjFY967ttz0yBR8O2S-61DaZR_LELXhA="],"w_polys_eval_zeta_omega":["9wsEPC-iAk1h1snRjd1zJ1QX1xFiZlNQnz5fuGaPfi8=","CHRTzWz4oSZrJAJPJ0T1qiJhS1UAD3BG9wH6b2NBbBM=","JMCHRWAyT-p5_2V-CgDtJ2rVmCPsXcpvCwG9G3Bt_BA="],"z_eval_zeta_omega":"x2QDGa0fRs0iD1mnK6yIUpRPwY449vySjJtEzrbo4xc=","s_polys_eval_zeta":["Sb-JHhRJglhhuFXxZObBYizfQRzkyZTOyHg4KygnQBE=","bTixMgi8BAUyjC-3qmPi1OamYqqf_MEwf3ENzm6MdyQ=","afUs-vRyspk2otTevY5Km-gaDCUu_88ohfPt5rq3wBo=","nqeSR4cbQNmudOfqRo5FoH40vmmoQbRXqU7qHQAiaQU="],"opening_witness_zeta":"_PcD1FoBUu94wOGMpezJUYVuyi-cKo1xra5k3DjIsQQ=","opening_witness_zeta_omega":"CWLnPdP4qo3HIypSATIbtJ8NOtXFaiRoowHgtmEOhBE="}],"memo":"qPs54elW65kpe5uqSA3TB0oORvM38hBJQdAx_DaNn0GPzOJpieVzq859yrmHjKnbZxUWq9_XKQ8LrmKvV7EGQe7aF9sS23c5YvzFFgIv51ukzjjTVg6oOpCLUThLmJzKLQF1-uySl9_tblRzZVMrrmRtgtIUaDki"},"signature":"AObhV7pc2ssS4sjghbiaNIvT_e5OjAdcodb4WYYv4DobRW56dXKF-LtzkqPCT9MBE2gSp81tVRuG-9AqRgBQ2Q4A"}
        "##;

        let note: BarToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_bar_to_abar().unwrap();
        assert!(
            verify_bar_to_abar_note(&verify_params, &note, &note.body.input.public_key).is_ok()
        );
    }

    #[test]
    fn abar_to_ar_secp256k1_test1() {
        let abar = r##"
        {
            "commitment": "GODLIOjHXNsSzxDYzeG4ychfdrTjyq7N7XDOaTP0ARw="
        }
        "##;

        let sender = &[
            1, 33, 204, 170, 22, 4, 29, 49, 149, 4, 212, 86, 187, 116, 177, 255, 51, 106, 48, 118,
            171, 233, 53, 242, 194, 114, 3, 244, 198, 55, 104, 167, 39, 1, 3, 132, 122, 45, 191,
            77, 69, 178, 12, 242, 75, 238, 60, 150, 102, 166, 170, 141, 221, 79, 110, 147, 9, 83,
            139, 123, 114, 239, 216, 255, 214, 91, 113,
        ];

        let memo = r##"
       "DZhGP6bb4PKSYfxSkkJcd-quEjzEStv4yNOwf0LhEAOA66YVYsANU8vVM1tXMFap0Kp4EpKY1ZPdSEiSeseGUoeLKzAOpg3m4z3r1bgWKjOVifONRQao6gKbCJKTrr_G0ssbZz0g8oITIg_J2q2pzBCXRqIozRXCFA=="
        "##;

        let abar: AnonAssetRecord = serde_json::from_str(&abar).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: AxfrOwnerMemo = serde_json::from_str(&memo).unwrap();
        abar_to_ar(&abar, &sender, memo);
    }

    #[test]
    fn abar_to_ar_ed25519_test1() {
        let abar = r##"
        {"commitment": "fh3Ugzhg7cUZgHOkKZHAg1n7vHH7uR6EiY0-wmmL-iM="}
        "##;

        let sender = &[
            0, 103, 107, 87, 181, 37, 168, 181, 194, 232, 35, 51, 254, 93, 183, 203, 47, 124, 187,
            143, 72, 64, 80, 37, 241, 11, 59, 81, 99, 192, 86, 118, 180, 2, 168, 239, 243, 61, 88,
            66, 0, 32, 136, 136, 180, 139, 78, 126, 217, 0, 76, 137, 214, 167, 21, 18, 8, 63, 29,
            18, 20, 205, 13, 126, 253,
        ];

        let memo = r##"
        "ta7OuYoMkIhQ5D0Dh-HblwWQ5IbYZLAUI7GwsZwLuouO68imVk8-4huLwoguKqVOqx5s-q4WueCTMUVJtlTVsK8fvN-2HApLo2uMdN55WRKaaeeN67rCC0Gjx0ow3wBYnB9hPoGBsYe0kgSTa1pR-SaXuoyWqDRI"
        "##;

        let abar: AnonAssetRecord = serde_json::from_str(&abar).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: AxfrOwnerMemo = serde_json::from_str(&memo).unwrap();
        abar_to_ar(&abar, &sender, memo);
    }

    fn abar_to_ar(abar: &AnonAssetRecord, sender: &KeyPair, memo: AxfrOwnerMemo) {
        let address_format = match sender.get_sk_ref() {
            SecretKey::Ed25519(_) => ED25519,
            SecretKey::Secp256k1(_) => SECP256K1,
        };

        let mut prng = test_rng();
        let params = ProverParams::gen_abar_to_ar(address_format).unwrap();
        let verify_params = VerifierParams::get_abar_to_ar(address_format).unwrap();
        let receiver = if prng.gen() {
            KeyPair::sample(&mut prng, SECP256K1)
        } else {
            KeyPair::sample(&mut prng, ED25519)
        };

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "abar_ar".to_owned(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut oabar = OpenAnonAssetRecordBuilder::from_abar(abar, memo, sender)
            .unwrap()
            .build()
            .unwrap();
        mt.add_commitment_hash(hash_abar(0, &abar)).unwrap();
        mt.commit().unwrap();
        let proof = mt.generate_proof(0).unwrap();
        oabar.update_mt_leaf_info(build_mt_leaf_info_from_proof(proof.clone(), 0));

        let pre_note =
            init_abar_to_ar_note(&mut prng, &oabar, &sender, &receiver.get_pk()).unwrap();

        let hash = random_hasher([
            35, 136, 236, 102, 61, 6, 246, 48, 59, 215, 171, 188, 225, 184, 117, 220, 128, 167, 23,
            155, 152, 14, 187, 16, 241, 230, 79, 132, 133, 39, 148, 246,
        ]);
        let note = finish_abar_to_ar_note(&mut prng, &params, pre_note, hash.clone()).unwrap();

        assert!(verify_abar_to_ar_note(&verify_params, &note, &proof.root, hash.clone()).is_ok());
    }

    #[test]
    fn abar_to_ar_secp256k1_test2() {
        let note = r##"
        {"body":{"input":"tokVrQJNUZU90L_yV1yKHK_qVwsgvdFeVa3_9CfEUC0=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQP3yhCYPCcuvxUJ0Ek79cJpj37BErGWPhLGVTuAf5uogA=="},"merkle_root":"bzSbv8WcT-w1y-3pOsLdwxoIBULSU9ZxW90QSzVW-wU=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["cQSwtJsFkSmpnbESH3U7yse_OTvIa2jqQoq5e-Gp_y4=","G0qAA_pjWqviqZG45zrzzmT1D9AHw751Br_5YhTItAs=","rdkBkVST5Uq0PWCJgthravJRcMDGh9DYRHyInqa8sIo=","FMY-tufH1L-_iZmKVZ67tTiwvMDOk2seXGOnxG_oDRQ=","XtKtHtefwq41l5aQXQm3GQzfsP_T3wP-zClwX6clMx0="],"cm_t_vec":["hAqDIvWgJZ4P8d70xUKicd2W1ouX4lM3qGz9lHtQ0BQ=","Egm4hMcGxYGYBp4X8XoxaoCLm1BJWJ0BudodrwirXAk=","cDWraLJHTrAc4BJi1JwEsOFV7FKuzFf2bkLDvn3asiI=","fCj0rmZe8BxmGib5G5ZDg8guUmyy19_mBTPZptNnngc=","LDU1hdOka-PayU757xDhL0wPjqA9fyUvmNoyKngsBqQ="],"cm_z":"N36CH0YjRFgkuap-p-AxlUP34Sn8nJInUXleCKpj4gY=","prk_3_poly_eval_zeta":"DzcvPVG39o3oCuZdXuM2u5SqhP0-lHE0w33zcXR6OBY=","prk_4_poly_eval_zeta":"1MDiTGZMUv_VmNLx43khwfVacjiyqzWqVJECwKXEPxI=","w_polys_eval_zeta":["mlO8n7wNL3h6u1VNkKeAQHt-BCDyOCYfZPJt0luIEBE=","NZIw0FQxTrsD5pPi0GsIgLe5-KWKdb-y100tXyjWNhk=","Q3eZ2HYuonvDSKfohb9Tdbc9bEWC2ZX8aXPgw0kpUCA=","zDDJy25r8rixeln7dqKPqES8VMEp1Rs-QjxEN2B12Ak=","rD8qGDp9281mbUVY-B_gJkDzwArb_dNEl70pGL3RsQs="],"w_polys_eval_zeta_omega":["gOQxrPzxP7QdEK9BM_jPx-CgWT45RLQztnYSqFOYNyE=","qBv2XdyhPcWUrMM8iw5ukefLBSyF2xLMwSjxOnwNYSM=","hLyyyY4wgxz-dJ4x8NvFarcAr3A9c0E4mQ95w2IhHhQ="],"z_eval_zeta_omega":"CKUE98pRJ2PFcVU0mPNX2uOyBUp1ssWt2CobIes12i4=","s_polys_eval_zeta":["_Q6x1pWwt6feOxuho4bH34OgGJpxZtws94bm4EpU-Ro=","4Ee40ibrceUWhbQF-HmQHsBwP4oPceOSRa_f8YbS-w0=","vCHv_IVEHdKCLcjNrYvOXXoPoUvHLX-FWTG8DdtDjB8=","QpV82K4rMzNirBLE_r8xyFygk4u_TxtlCx2GdMlseiI="],"opening_witness_zeta":"bDC1bVBPwIlTH9Noikr-QdwSJRvDDujEeLnnl024vIo=","opening_witness_zeta_omega":"aMTRW8kHJmfxV3-9DppEKx3YueHQ7uqD8Ls-EJ_qrAw="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"nAA4Rw54KygiTJOIenWdcMnQUjWE6xmENOjhOJZ7sQg=","randomizers":["d_dScoF13Yz9mFg8ca9fujAbvdRrJZQ-Z_XfYNAP6UqA","BHimi3NzKPLN7eTs1fpSTICkbIGZ4p8JwVTVZGIxr_eA","o7nqtEJBBoZUmHLixe3bFbuSlCLOyg0qdE33ZSaTVzkA"],"response_scalars":[["tZxHt02W7bxgVyYOGpgbthukuWEvlxrFWHa6fYylF-o=","IECYphEdoNiBMMZymiFn9hv8ysWOnN4wDdIWvVZTUKw="],["1clkiJ-1-66W3ApYsYty4o9-KkmHxaN-6Fp75Vnx3zY=","R1-s4LNL0jvlpoIMfzyw2eEWRcuYfVaW_n6aZo27flU="],["T0_L44iInEA3w-tQu5GQ0pcQaCegomnbBLMubySE7i4=","wcf90z2QvTuKHKGML_oXDBjbVmpw2Oy7CCJsN7h0DkU="]]},"scalar_mul_commitments":["h843jmKmxCTUOKJev06150oZPYpMGPZzAht2Y0uHplIA","vVem4iJmXSzIiIgXIhzH5no4vU_IbmjiCwqWQLE9BIuA","fD6j1miwWmdKUYVkySfL5AeekeVH-S84fw81ePVT2l-A"],"scalar_mul_proof":"0jAL2v3li2Cpk5ihxWykeC-F6c_B3U_5NuiLahN700cAu39ZJh6kjeYQED1dH-ppTuo8TE9N0aUt8bMklvEqj-kAh74kFRMqGVtyaMl9w3P-wFA8HurUfdZPiMv9GlxENdMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAkmjdAJ8POxk1g5KJ6fU2JnY8SVSWKNBdoCYFQU3Ir70AfRkmVKNJA7CsJpaAgKGYa6jqjgSv13-c8C2bQe1bYSwA52ZFq9gJL8lvd3fukgm4Yop-1gqxguDPra8kN6Hkg1aAXgZS-kGQrtt8KcoHbpdEKRVwhwOGmD5LtRcRqMH3NwmAmrnqGckelqajDY5U_AOzPQPabnUeWuzfDgiB9zm5tdqA7HyESwfueoZqjKIdMR9b_YreT86Zgum83fosGS8aKO7Dc8FRKHKwJ0WrBQ9I8D2LmtGZBTyVC7fz4wKUkt4uewTb3TBmADr5N15Vk8YNm9I17nU3nftyPguyonbNQw8ZCwAAAAAAAABfXpdc0uFg3jnGzaUAHV8_3iPiKySfDf36YaW4zttQXIAUf1SPORgQo1aZZt_F14yBh4hPrYrQ8atH0D54AD8HIADLZu8nsjXgkoKh7hkQdkrPspYNJIlX7s0Q8SSo5mDCr4CPb_RdR_6-uc0tcHjHMA59lgLDrNdna2Nb4Njb1Nz2_wD1scSz6SuDJ9WLjw1mE45KxjXW-ht-y1ZLQu6UMITYewAvrEq9KweMK8RwRFrdoMN7goXM7JzLLS0tftSAimrk2IDuvdF9Z_xaewkj-DV_rK0xrFZJrg3ZrA7YAv7m9Dke_oB8eRYaYHkdH6pyJ-ffBaZE9Z2EBco_4ifma0kPp0CqggD6lJ1x545q5xt0qA-1FioGqC0zlERxneT0apM9zXytXYB0qWAyAYyHa9JhViqJqOuP86kc62hS3dSyqQoCryiHxICSA1HwLXhfX_W4Pw8Y9gK5S23OLao1SmPlITNoEAppoIALAAAAAAAAAGvvSHdreLWq9fsuD5c2r3iVOu6Tw00N8cNR1_vZ8bwkAPEIDUVBUX1rIbxHMCw4qReza96wMaP8uT8QM77s6VcOgKREph3duQFrfJq1flFZTZhsr0q9TmFbNq6gg0dEQuaXgEoCAhhJBoWFFvbGQhgQN7ATx38KtAHGLonifrF6SXJEAEp_DuwJcmp5FFXOqopHIJZ0aB6J52uhgVzfDpyM0U_GgD_8ESJpLK6A_PLBI4-rIs9i_2V6ZMUa570oaVR5OyDWgIWMYcyOD-o7F08gK55_MEPLDJv6SmVbWJzEWubhgYnsALgEcG9xd-8UA9ZUzC-1l1xJCTpyrnEEBICnwP1o-SdAgFEqywJUKFg6JEMfUV1YDqxO_vjs2GinGBdP9ZMcDRkzgPeF8Lql4p3nPEh3MrPedGhlHyglQRIz-zAiGS05bWiggEn9CfIwgfks9zggrig-JzEJxEF-M-ErMK28wVoPzAnTABzquMqrjb4M46fXU2XROUW2aEKV5DRWRBCmmSX1ylsoHmA8aZaLYpSAHLrnhfVkFzDdiA-TLERkgzSoqiqYBaA="}}}
        "##;

        let note: AbarToArNote = serde_json::from_str(&note).unwrap();

        let address_format = match note.folding_instance {
            AXfrAddressFoldingInstance::Secp256k1(_) => SECP256K1,
            AXfrAddressFoldingInstance::Ed25519(_) => ED25519,
        };

        let verify_params = VerifierParams::get_abar_to_ar(address_format).unwrap();
        let hash = random_hasher([
            103, 66, 251, 144, 1, 224, 85, 209, 216, 239, 63, 22, 200, 38, 229, 85, 27, 165, 91,
            73, 206, 34, 207, 49, 44, 44, 59, 203, 59, 237, 102, 90,
        ]);
        assert!(verify_abar_to_ar_note(
            &verify_params,
            &note,
            &note.body.merkle_root,
            hash.clone()
        )
        .is_ok());
    }

    #[test]
    fn abar_to_ar_ed25519_test2() {
        let note = r##"
        {"body":{"input":"K7z3-Hr2filCKGRl953e3xnAIBJCsGyIP2F-YVppoRg=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"Ij5vw6xKlY1coNhD6yAX_n4dgxzGWRfPI1IHmDybBM8="},"merkle_root":"i_Kmg0KVFNVlAUUAQNMW0KYuf7rcx_zGgCyNcFCSmBE=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["LpxApf4MBDhrTqllkZnChQI3u8LEObS73nJKcvK3RIQ=","UVx-a626b58cYk-6AocpX9FEQeYCJ852XBsWa81Uap8=","nNmDlIJHnMalMs05RVHMN4DC7nOa4A0aAmKaWDbOggQ=","I21Rh5hVkFdMmpjG0bZ1kJtQXMh3KejwYKhfUgOXfCc=","NKsL_aBn52an97yeIG4-GBhz9mLOkEpYhX5T8nBb6Rc="],"cm_t_vec":["2IgGP0jCfyF4zR14HFpYsIJgQjm4m4iF_Ac70s3YY58=","-93sSakBalFR1un0fnQeXJEJm1aYAugaDbzvhN9lcQw=","Ko6OrXAu_0SqMEAUg5WzPbnJlTkVBmgyYcOmcHP9FJY=","oJCKCGbwODnMMM2b37nyes81pz3p1Y0XcL_7Kg9o_i8=","hNzD--sqTSQ64q5UrYwtmQ4N4v8Xwt9KMJ1-qo82RAI="],"cm_z":"deMSawbpEpSvzilWYKQdlfZSkkUkmogCurKKDG8llas=","prk_3_poly_eval_zeta":"d8OtXJgUAChh8DG4wp8wMK6kBkdmwLJxkhjJNA18lAk=","prk_4_poly_eval_zeta":"AmC4tc8bGVW_cfZDuk3sBpZg-qZBfkH9fednimsUpyQ=","w_polys_eval_zeta":["Vvb2P9zc1tptkooq2hnoqWGvpXObzmYSlSwLNY6KWAg=","Z2sdTKcmPl6O5TK7fe2rkENsUr413TCN-Ibpv3Ndeiw=","QVBM8qNII75n2-jHa9JZzVkFoM2WJfxC4u3eQ0_J7AA=","2Lsw1FjsmA31_vZAGK7LYEQ_2X06MfZmqD9tgLNrKwM=","nzCDHUiYkYX3oUVswPX0B_kqC2qx972RiFpn__BwKQs="],"w_polys_eval_zeta_omega":["ge7U05medBKpe7bAC4GWOyJ6zGsiCggONHh0dcATOig=","GJ5ixwsLfvTgt27r9z5_l0xoiB5_1ZbxGXAC6455TwY=","WVP0wDeoNONwPiwtVXwiIjyDl1rLxXPQbiMTngjKmCg="],"z_eval_zeta_omega":"5NQduc4w9mzRgdFJ3Ux7iPDrLb4pyK2czygo4ctXsgQ=","s_polys_eval_zeta":["LILLABNqORlijr6e0OKh3Cxo13gUHhsoIhbKopk1NA0=","HrrHjLKx-AGi2TI3xpESTDQ_gFiOjx-oRhkiHiErGyM=","ykdaAcNb5AqCVQfK-TLoMXvZJiF2xEkrgzzbhbrKBBs=","UXFpmnbCEje4MwjmVybPWdMBjmnu85ooAiSx6DptBS0="],"opening_witness_zeta":"6kJPOxXMFH9YHBlcL-iGLRFFiX-DNwPvfAREEfT0QCU=","opening_witness_zeta_omega":"lYpMoZH8wdWgvX1MI5-k-IWwyz1iX64_LanqhWKB9iQ="},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"V95BkNcGjsx6uIqpP54JeNa7uOBwKgJWN-pjnJIlGQ8=","randomizers":["tQtKr_tY_fSoN88pGAK-Y8AgN2msCnD8tmpx6rD_zzQA","dqzQRrbosu7DLmxACo5yfmIz0eCeNOH7nPEJVxMvaVEA","lwI71akAyhBfOMlcZLR05QowuvDsP8Cm5EKSIzKsvVOA"],"response_scalars":[["2SXCgLrWmkH_em-r5PCcZddgzsUxXZ1BdeUJBX3s6C8=","o5naNk9V1cf-R5X9M0wZGxt4MPmqvCvEhiCSVVF6x10="],["3FHM6qwlKCmPvACg0iM0eMQiox-PcvLhCwswdU9sN2I=","WQPY-eGS-iOGrGtPxwn5Ko9PKhd1UrvwyXsnBHvsbwQ="],["NCo67N9K7krV6qJoxZo3tkmjJkiXSzTgJNJ7H800PVg=","MHbSkw7VQj_oMtay7OjRcpzi9vyc9DsLpozvnnNJyxU="]]},"scalar_mul_commitments":["jz1P-JfJ1Lah_wNzRDFwRE_ky53d8Aj4xpHf9RylJEGA","BmVMVxCFzTW3tetAodPeuTj0UaChLBMjOFkEC472VVaA","AY6G0BAcNmqIjrRp1H5vvz6OOaJvYuPZ58l9mP-YQyYA"],"scalar_mul_proof":"MBxJm6BB0KmbX4LH4AJrIGY1v7eFEfWml5LBLvSiJhuAiFL5ReJTNCFPW2Mguw6OSPY2PYPepL8PeyBi_Zr8ghAAJUc4MfSXHZHlcPsG1Q7cOkszhgS7_fhipTSYloH_tWgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAfW7BRi7qFz4G_amnUCk83tBQhkcA4Y27fVpuKJRqbAEAkMQNxKsNWnjDjBiZ75UKnbs9EfPKSOeNuBjhK3YskAIAf6hqetCo3JOkIDKTfnaRsDFh1xEmllCe5XtWbCLjAy-AELykmdz_z8w1pv2agWowdKgOO-MQpg-1GoO7A6TlVnQAMQA5sPWcXBr1UGKZT4oYjQ8-tiXqT_-FZF9ZuIh8lECAy7T_CxXqk9qWTUwAotYJ6dWuMV-38viLaf0_wU_upnjsY44bqFJy4FtSyPW7dwyQAio268h3SZTne1HPlpCdPju2obSz-sTTjvYgKUtiuC4TEh3Out__J9Y9bCTN2aUKCwAAAAAAAACMpIcGnwdfCYs-6mNA4pEI2RUKqGWW6Hc2ngH1CfcOZ4BtRNrriRtIdCC6pilW5lgbBa_449XfuSFfuIAaHLWXXADcWqSXOsNKyJ7ihl0wztksAJ_MeDV8G9wGF3xeSV5PLoAr_S0GSytNEnBhgTw5Ypnw_rJitmWUTowXNmDqS7EINoBn2EkU88GWGV372XYnII3b0IA7gfTTC87Oh0wyQGlQSIDDL0e6eHthLl1ouXZBYuneJpOGqH0sJjjEwqDKUo30bADPviW46VuZZ0lnPUDBRjrnotz-BPLCMsHQeH3AfJZdKwDZkHVI0pHHMj_md9RL-MfXqHrpXZ2HDhZZbqfid4iFHgAOjRmZmYZZfQys2eb0jRuiwH09jxhSCpbN4KSRPeAOdAC__0yszCF0swJGLhYkSzEY0BfOknK_mZSdfUXRYdd-UoCZcKJn4_levcutAnchVfqSU4Km9CK9At590CuzWJYjWgALAAAAAAAAAIkPDMBOyUg6Xu8s8dot-X8MOH-0aHGE0d_MzMQ1hbF8AOUQzIBgX30qm5XTe7CIwTj7p07szgqhylwl2vQygtYoAAMQfWtg1NzFaJ0wFwwCaiVrPL3tKQT2KP9v7q2ObK4gAHR4RwJsMGUv0Cmlqxlu0hnTFchVLkLU5cqb4QZdAbwMAN4ibBypxKaPA_WlADZ7I-ZjCmTRo7V2je08583TWvkogMJZ9wbWhWDXMKCEz8kLJBDVS4WlTMuDF_kyejy3YWg3AAWnAdeE3qxeQvWsCuqxKO6KteRXU154lgo3K8A4mVJrAMY-64d2zyhiJnMs-EAcIkmx9170Qyr_9Kn5YSN9DUMNAPxxTljcKNxcGP50UaUKvpqTVRw3h6z9B8ML1p-H3PlpANWQyeRsDcdmusjdsbVLKrCCYvVF-cj6H14vXG0q1KUcgKDEm0g2pf3hn516fAlwRKZh9WSNXnMHW4vnbkXYQ3FkgEnI2kYTibhOswVPiveY5KnvPg31bijBtHnqXsmvKIhVEvWI1Y9ezVWyiXdhsaPTUVaeKdF7SXq6HbZZ92ZUajg="}}}
        "##;

        let note: AbarToArNote = serde_json::from_str(&note).unwrap();

        let address_format = match note.folding_instance {
            AXfrAddressFoldingInstance::Secp256k1(_) => SECP256K1,
            AXfrAddressFoldingInstance::Ed25519(_) => ED25519,
        };

        let verify_params = VerifierParams::get_abar_to_ar(address_format).unwrap();
        let hash = random_hasher([
            129, 9, 199, 199, 195, 61, 168, 138, 50, 167, 237, 14, 26, 191, 15, 75, 230, 173, 197,
            235, 124, 64, 230, 4, 208, 115, 171, 33, 82, 89, 99, 176,
        ]);
        assert!(verify_abar_to_ar_note(
            &verify_params,
            &note,
            &note.body.merkle_root,
            hash.clone()
        )
        .is_ok());
    }

    #[test]
    fn abar_to_bar_secp256k1_test1() {
        let abar = r##"
        {
            "commitment": "4KRVxVnMvwq_oszCB0cMzUN9jrqRMwB6Nbqi2eLzEBw="
        }
        "##;

        let sender = &[
            1, 58, 245, 246, 113, 11, 65, 215, 151, 37, 194, 200, 124, 51, 48, 101, 35, 255, 192,
            203, 137, 172, 116, 13, 184, 156, 136, 142, 182, 200, 179, 83, 81, 1, 3, 219, 101, 112,
            86, 214, 110, 117, 55, 46, 29, 33, 176, 104, 234, 228, 177, 104, 123, 50, 190, 88, 150,
            60, 129, 179, 97, 147, 90, 221, 195, 33, 155,
        ];

        let memo = r##"
        "oReRhzHtioFRTWNgqnVH7gEH43uCcoAdr5-TvnZJWkuAI1be5gtAPmGK-RQcpzsTSdnzCwT97NqKB9Ja3FZxdEqDWhVm3Nr64jFB1EetXQoGTSDmJeZIrw7Hwn1m9RCEyTJGqKBTWteawGzUeTb5SWYl9KKkFMmtJA=="
        "##;

        let abar: AnonAssetRecord = serde_json::from_str(&abar).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: AxfrOwnerMemo = serde_json::from_str(&memo).unwrap();
        abar_to_bar(&abar, &sender, memo);
    }

    #[test]
    fn abar_to_bar_ed25519_test1() {
        let abar = r##"
        {"commitment":"d_x1cDNpn7cwEOfWPVDAJtIWb7eD8iyc1Xa5lPvcnyU="}
        "##;

        let sender = &[
            0, 146, 188, 159, 246, 0, 191, 10, 11, 32, 111, 210, 236, 44, 105, 2, 116, 116, 156,
            118, 57, 238, 70, 203, 0, 144, 68, 2, 199, 184, 150, 186, 38, 210, 81, 69, 45, 95, 215,
            206, 229, 232, 108, 177, 116, 114, 248, 6, 106, 195, 39, 101, 227, 151, 161, 23, 161,
            21, 46, 253, 85, 248, 118, 149, 34,
        ];

        let memo = r##"
"qVPo4ATi9aCQGCOzEYKTyogEDJyK9kuXAvtdIh25Tny7xHsj4PF7pA9ec_oRwbvtj8zwGGF8uXu0pnJTNQAeceNW-yEdfbRIrZpK2hSPvB74d6-hrKFqMa0dstd0H9UhobtdOZn65ltrVRFGQH7jnt6IUY1-oN1K"
        "##;

        let abar: AnonAssetRecord = serde_json::from_str(&abar).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: AxfrOwnerMemo = serde_json::from_str(&memo).unwrap();
        abar_to_bar(&abar, &sender, memo);
    }

    fn abar_to_bar(abar: &AnonAssetRecord, sender: &KeyPair, memo: AxfrOwnerMemo) {
        let mut prng = test_rng();

        let address_format = match sender.get_sk_ref() {
            SecretKey::Ed25519(_) => ED25519,
            SecretKey::Secp256k1(_) => SECP256K1,
        };

        let params = ProverParams::gen_abar_to_bar(address_format).unwrap();
        let verify_params = VerifierParams::get_abar_to_bar(address_format).unwrap();
        let receiver = if prng.gen() {
            KeyPair::sample(&mut prng, SECP256K1)
        } else {
            KeyPair::sample(&mut prng, ED25519)
        };

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "abar_bar".to_owned(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut oabar = OpenAnonAssetRecordBuilder::from_abar(abar, memo, sender)
            .unwrap()
            .build()
            .unwrap();
        mt.add_commitment_hash(hash_abar(0, &abar)).unwrap(); //mock
        mt.add_commitment_hash(hash_abar(1, &abar)).unwrap();
        mt.commit().unwrap();
        let proof = mt.generate_proof(0).unwrap();
        oabar.update_mt_leaf_info(build_mt_leaf_info_from_proof(proof.clone(), 0));

        let pre_note = init_abar_to_bar_note(
            &mut prng,
            &oabar,
            &sender,
            &receiver.get_pk(),
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        )
        .unwrap();
        let hash = random_hasher([
            98, 242, 237, 108, 132, 100, 118, 9, 224, 184, 208, 102, 48, 116, 119, 38, 120, 140,
            235, 177, 83, 151, 18, 66, 247, 60, 251, 244, 89, 20, 226, 3,
        ]);
        let note = finish_abar_to_bar_note(&mut prng, &params, pre_note, hash.clone()).unwrap();
        verify_abar_to_bar_note(&verify_params, &note, &proof.root, hash.clone()).unwrap();
    }

    #[test]
    fn abar_to_bar_secp256k1_test2() {
        let note = r##"
        {"body":{"input":"_JBFBWTOF9oOumHTj6BjNDR2OafLjFD9oYDuWELU1S8=","output":{"amount":{"Confidential":["PpGNRj8GsyWapPkdpHbOYSWKZL1SuYwKoUqOsKaMt08=","dKywcGspj19-VdTeagtcTjw7e9cI9uTrJ5YR--zOpBI="]},"asset_type":{"Confidential":"rK3LnKQNBVknVH658Auv2OVfU_cwPFR7hzHIB_2MODo="},"public_key":"AQJYjxdMeZ8Zw2DRb7ao7ZDOlYSMWTmKQ_4vESdDJ72Plg=="},"delegated_schnorr_proof":{"inspection_comm":"givi33okCsUDqRYu_As313mANzooRp14u6AS4asoagE=","randomizers":["_gntJvhRHyIT-naYrJerDpyYDL6kI3tOWeFKpDUui3E=","hubLAclTBcLqB8vu7MR65JkxwoSQrfKc7Z5bMzGPdQw="],"response_scalars":[["dl5Nvs1-UbV6RVje_xwKAWnW1xlVToFA8Gd6ZC4JmQo=","ydQq0Ox1JVStnJfQNju5bCupgQWqEISVIj_Oof6bTgI="],["cZzP8lQ2UgJXELTWd5Sw9zWX5ax0Z0eSUbKSjLJzVA8=","icASPBkMpKehg6ofjsDG8VGOzTp6p8SaTxcMIwLqTwk="]]},"merkle_root":"bmeq2ttKN_MOWraVSJr9lOM0AKoLXYzysmo9zLtNwSo=","merkle_root_version":1,"memo":{"key_type":"Secp256k1","blind_share_bytes":"wRDLCiReMLLyC-LnMb563inPYLP_yoTNuSCk5K-hi-SA","lock_bytes":"APRtrMZ1JOR3CDIjJcpQIlIb7MHRN9QnqssPaLgbpBaATzrrQ4PJa8JVyuOa0XLjpwZdNg3iUU2fT8Y4lX9cr5Fd3LIZJ0FVcyvy1TDGz2ldjMBoNZYAL2M="}},"proof":{"cm_w_vec":["1IYjmZOor3qNmCKGKoCp9fOG77xPx72d0jbJ9lV5Ugc=","XtJIqXI87LWXO10_JIeU5FX2-WVuK3X1JDy-dKbL-aY=","EJGHshmQN7jg5JLqa_dd7pZ7BhiYZWtU36MsRJC0UyQ=","RmARADN9FqwsUMZsl2VQfv0ttpxZhT3L3PKiMmBspRQ=","KAUcM1BjsXkJnh9DHZnnQo0gzzryEe0F55--vcbgxB4="],"cm_t_vec":["94DoB84mATGwKltIdTZXNnU7qZ0-F_7QooC9o7GFdIs=","eza7B55jPH58RXRBnexvAF4L3WOBdOikCxTV-DGBFKE=","lNeeB8_qObjsiAWl063PMDx6xZjPm_TGwWinyxk-VBY=","FI7jyfAWLU81Kb-EEVpEBDZtR5U44BxueVzCkLy2VRY=","GFsZWqFafxKDje57KVZX8a-Gr0IyoKLqZ7-OJggVPhI="],"cm_z":"GMBDIGBYzUddBRBi9OT4RKTZOb0afDzMkMlw6UhBdx8=","prk_3_poly_eval_zeta":"jL6nDT2meEAadNnDFMqdZv3wsNt97ii_7M5AKUNZoyQ=","prk_4_poly_eval_zeta":"FPEfBA7puRwFq2KEvW72XrIpIugHeF-RCmmZ3n4eVh4=","w_polys_eval_zeta":["QGZhzRd9PAhJNvxUL1flZwAUnEQmdCko5akDq7LfRCc=","QE-R543rcqLWKmn67n4tzjn5s8efZh-wkGy8UsNQvC8=","_u5xIHL4l_Bx55HpM4_D73_nJ5Y5ogn8yUwdeMxLZx0=","fDxCk7EmyidlZal3oxtMl11CaaIaHtGyBUMsjbtiYxM=","yOk2IQ_TAyxLuNQNpGTe8czFJATmx7QqINxaJcA_8yA="],"w_polys_eval_zeta_omega":["FbdUhTi3539MdUlZB0jEqW0r5oQ5w4tjYQdCfSWu-is=","yHPPh34k4-_kPe27qpEvoFOK_BoYrw6X3JkzIitqzyo=","H0c_EiTRLCTrbDAC0q0AeztgFgYYV5OJKaCzw9p-UAQ="],"z_eval_zeta_omega":"4KF0Y9X3FKyYYXYCYNs-H-TyMTdhUcTBvGi2BiNMngE=","s_polys_eval_zeta":["6oYXjhkYIRZjUyyBnFFVA832B3khG-jTASsGbh_h4wA=","b7hK5NmSxSQpDLZF4WMWsV-inzfSEu7BlaNn5UdhwSc=","-lxhHLaqhZHNSiO8ts84Py6q-ziZUbG33BUfx3n4Bxo=","xftUVEuTg90ctuqEgh9m3su1xzwHuDc1Hw4L_vVJfig="],"opening_witness_zeta":"kv-hadKzH0sUY5rMzkohWP_QSTLCFjqAF8baDSVvMBo=","opening_witness_zeta_omega":"ygIBnk6IUS0be-65OLu3GhyAWUvBoSzRrHOzHR5RXww="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"_t_5fuD403RIAPE78xMikGus2KP539LFjIQR0ACN9yE=","randomizers":["fFR08q3viRnniiWWrEpiwLqijTlhcgfz8y_6Ts2i1jqA","WN8lRLkBb5ShhW1L9aAP6LPKVWwdi12_KIf8Cwb7zqiA","XL2Sj84HuaC531IGhCkVeHggQthtn8pB_FhbN0vaP98A"],"response_scalars":[["_G1BUFK57Eq5A8BVIF12C2UW1vqVGgzo8KzJ7atyswA=","TfKs0zT5Z63KJJFZxqzwXEloT6rZvRGXT9E7JfuxtDQ="],["U2nnTdGqDbBQODt8C110goWmthLyLPIibLdl5yuw0tI=","C3gQ0eNaMEXLLX-C6-0r2x9rASEEGfOVKvqCyvHhUcA="],["3aixjJtARYJU_nncmA38kW9o0WihOvhcJxchuh8BxIU=","ICfZElN15OqrPqhxCSmZnAAyh4y8ypKHBE1wwl3gbQQ="]]},"scalar_mul_commitments":["ckh11d3RQTsXjuP_wTKGpKiDYvGNG_VebQAijAFhqZIA","vr1TKUJWexxRO4RAxvJAbDQRC0NOpREnpu5c-1U3WtaA","L0K0aMqjuOxZby0r5dbckIPu2PkMp4nOHICG2YGoPTeA"],"scalar_mul_proof":"pUsdQPUa1ETBZKBniUv39e569GyjcwHDD0w9Xk3UFPUAxdhmfTRX5DsJ_cZdea9DkbLsIUWvwe1BBnBUkWW4eQ-AQnzC74cOWahfC4brPL_vijQU4w1X-LqxftNaVLiRNjqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAUcUI4euZsJu6Dww3k0e7a8wDRCDfeC2N1NYH6O7uJsQAAlWn3EZ4cVORqnd4woAxXjMMhs_a4ksz8exN5Tx0l8kA0kOYmpVKe3zlDnVzgMhW40OK2sg5c5fwbFjEVB_OE6YAjj2sptXEdTPqSdxhn1kdqqqz0QaxIDZgO4pkG433GEkAb1DcKdf2_WxS0wdb9sJRyXz3NOhaHLCyHgzhfFi0d6EAo_hjC4izYSJ4r8MEYM9rF7VQhC_fq3HjLl0q2hj1Q8lzN_FQHAmSZPfGkXGHoJXRMRba_PKLtkDwU_5VLgYkkJGHQmhskPWfFFNcZCg1hYN5rjw2CskmvxD9gWAg3o3kCwAAAAAAAACg0KTbkKZiOMwINxlAbHbyjuE_KFQ-DT3McNn1MovyQoCSK9faRvNYc4Ceygobm1dXOpHhuDFPMWuobplssur4wQDk-L9Yw_qZV6p5oWN4GDhHJrGug-pW5xlLhwxIwOpTaYDFZFUWXRKXkDccdRAl6FRwlhOZvNrdPh-EIVmCNIuYYYCRv5gv078vlFs3QNz7v8EdVk4kS6TxwoCp1qFo6FCeCAArSv9BqMvrzQ5aIVHNniDXon-EA8ub5mbPzYh7TM9qNoC82xoWN9Oz7c6ERJ74hYg90lxIkV610KT5g3p2-UfPxwBhqjZVyCSHFidjsfJVE6CAaQBpqMGeqgwMxwdHYSuM3IBE6hxsCpth7ZR0dyBbv3W-IpkPk6bbHmGFJL2kqot5IwC3-wwDC7JO2DcgdqY9TRouvxd3-4gBHmMc1hEW_S4OEgAJeu_jM-hrn94JVb9KiT7zDU-qwV2LZjoqr5__Trd4bAALAAAAAAAAADacB_mnXL_gADZugoWr7eneRKB1O1ZRcPxq6saxLpxHgLTOBDITDTIFynkLpAfDZ4xLlnV3HSe9Dq_2yuxhHse_AIzcuPSh9OJN9GGdYLPSvoQJTlkdrXTA5vV8hOvkw3WnANtMgwSHNoD41wEip2T-vFZsQhB6BVG_CNMK8UJEDnLwgF-lmoUeygBhXUtuOsOs_0kWiUe7KLTUyLfL9f3WINtOgBfcqK7M32wFM9DUpjpU2dF25t_9UIrqXO5K4gavgUy9gIbYWze7Lhxzha1riNupAaWZKLXbFjjBu81y1xucUMPRAESIfZi6wXhGgr-zYKaOV-wi6SfW0kEhbDTDao2bbmENgKFgUzjzmbv6hsTvCFBkKP-2VnKtuy3VUZFGY5mrUOI5AIvB0ckkfzWgrEG7VQTdIOE_tAeEFgoeC-9Z65qbFsc5AH4rv25dQdlgbNce2VsrFPrc4qslfG_oAvc6NbHq1RcLgDqbj2IMLwxlKsNvt7IHQmI9g0OCgtGUrsT5c2RJrnI52KBIyT4_KjrsbzlHuT700lT6x2f2ER27myEuOwx7j1A="}}}
        "##;

        let note: AbarToBarNote = serde_json::from_str(&note).unwrap();

        let address_format = match note.folding_instance {
            AXfrAddressFoldingInstance::Secp256k1(_) => SECP256K1,
            AXfrAddressFoldingInstance::Ed25519(_) => ED25519,
        };

        let verify_params = VerifierParams::get_abar_to_bar(address_format).unwrap();
        let hash = random_hasher([
            111, 246, 98, 223, 100, 27, 196, 56, 237, 171, 136, 77, 24, 58, 10, 116, 244, 164, 70,
            2, 9, 55, 120, 182, 42, 131, 188, 176, 48, 227, 177, 96,
        ]);
        assert!(verify_abar_to_bar_note(
            &verify_params,
            &note,
            &note.body.merkle_root,
            hash.clone()
        )
        .is_ok());
    }

    #[test]
    fn abar_to_bar_ed25519_test2() {
        let note = r##"
        {"body":{"input":"9VymjLjunm8XZcMx_zXGA6zRFXlY8sZq4VNcAX_fZiw=","output":{"amount":{"Confidential":["QOgY6h4R_6iY9zi_462D69ZnbaEwsP0Ja7RbeDr8MWk=","CmWpS5keAD5rfxIfgKRjaWAv4CemCP8YXj6TP5p-YjQ="]},"asset_type":{"Confidential":"Bge6ifu3NjtBVHkN_iaUt7nnjYCiSeYMjs3MsTFzriI="},"public_key":"3RBKNedaTW9QbLJg2VjSWP9y_EX8m5TK0JbDM_9RKuc="},"delegated_schnorr_proof":{"inspection_comm":"d8dkOzIHox08cJLrz9KftUAxLvry2Rdu3wA-EdF8pCw=","randomizers":["0txBeV97y-CX5kL4zWMcm9FU3Jz0v9l6OEtiA3T16ic=","9ngpl0uNJHSQs3Cs_JDCBkvTwEGm-JS6LgY0NwCf7xk="],"response_scalars":[["YwFqBjRKDEMuTIbBOgqY8quVqc1JEznBnmJ6ivmUVw4=","Fah0AXQuGerWuGq_hZXdKH75HO6GhAr5dQOMU9zA7gg="],["eN4BN90zOhDVlJNXnikt6XHaNYi0J4fBxvIjMHgHDwo=","Kvk9jLAoJ2XNPZHfJ18SKnTS5YixEHqESwtrzj1_wg4="]]},"merkle_root":"r4E-LeHqZMTh0krlVneUaZ_8X2FLa5sQgN4C_cebJRQ=","merkle_root_version":1,"memo":{"key_type":"Ed25519","blind_share_bytes":"8WVVkz8b9QjSWt2rPlvoUXXQhiK-Z4u2Ai5eqShqTdE=","lock_bytes":"Ox_joJ4GtcSU3Z-jPznXVsIKRhm-izhQIHoa3WwU7TdEEziOmEndT9S9yfeUwiBVvObpobgj4ckafKRVVGKx-eQJNIn8n2kG"}},"proof":{"cm_w_vec":["fT0UbCX-eHz0aGBqw5h9ymPDQ51nbNo6m6_w5lfrnqk=","FZk9vDRIUddoyZXvY20TflF73XB8HrMP0Gb9NzbxzwM=","RylhM-jWJaMw2WEu-GaYaFoP9PvL1e8MDFSaWFucaI8=","OlNfwCODXN9HPVYfmYznh4FDyJNZbgJzekthkxMqbAs=","lVjMDnz-xtCgwJZqcxrD9ia7xi-K5OiyzJaPe4k466c="],"cm_t_vec":["NUQvv8FUrdTRKus1UrGOgURRclvDtA2bZmbKKQRFM4k=","vOG6n2Qn1iAAppTw5e4sDW7fNk_dQq5rPwVxXfuoAyA=","2pxJ11YANhcT_oLFGzl6JFvU6w_0u13IJnvVCG4XUS8=","rPruWT8QFkSjvcpPRxvKxZdjAhGze1E8ANO0Q_p0MC0=","9xs6ounKGYpCqndpHzYBto2xMj-iDX7iTfY0TNVClB0="],"cm_z":"ezE8iK-dkFYdqaTNTITUq6JizShotMpE9CysWuPl2aM=","prk_3_poly_eval_zeta":"cgKs18xAkavNwsECuslMbiHgF737L1USYvs0mM5I3Ro=","prk_4_poly_eval_zeta":"t2pQmFTZtBzNe2vVRpfFcdup9IHVlz79zcaVt1sNQhU=","w_polys_eval_zeta":["ZSJB2hR2y5I2AJGSJTkcAoRjv1_LE1X-UODqHyUq0ys=","Z5hU_8i_wlY3zMD7d_ZBjbBvCHRrfAu0fZdxckYciQ8=","Lbx9TZDq7tv298gjZYRRIXhtZsfH6RCNxSgqSnKntwI=","a1G5nSsuFCDhRldS_ZDDKG9DA0d25TtxS58MqQ6IEBQ=","uzsgSGiYaJiPK2lsWNfvNqMpLQXzl6Rpre6z1IZ0ShA="],"w_polys_eval_zeta_omega":["bgmDqQhuJIXIy-rOaAbv_5Q1TSoKs77uAI3nAl3ooi0=","Bv5McMc3PevV2Z2vEeHOAMdFA1Hjgtf_-cPbCweh5wg=","bAobmKrdsGI5FXR9H8uVkjG3zgowNr9kVh6F6wW7Igw="],"z_eval_zeta_omega":"LC9x6Q1cR7S1toO3SRXjr4kQT6cKFxLfdUz3Rm7yug8=","s_polys_eval_zeta":["Tji0lp_K7AZ7G7W2aRW3sHS-ouETr3lTwsg3TIwruBw=","BJaVbDIpzWuSISLjgVb2y01Rgt0NPz5k5BlJ__KZ0C4=","1elnoeNrwoggSAyvWLhK63GlgXKD1bCC18aOYoWqkSw=","-Bca7zpJfH7q7qmb_WpOv-8lPp2LbbT_gz7WTwLIiSs="],"opening_witness_zeta":"fCokWTP3IM-aE3WPvFYGnuQDa1t5uHKFaNF7AL1Iuho=","opening_witness_zeta_omega":"nmxRJ2hxVVAgVikqxEzJq21pEPNMW8IjDISj2f_kCB8="},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"uiXtYwUgS098WHrFEgAROXo1pJhVMbCbFduuujXEGgw=","randomizers":["A90c7AckFtI7JPt8oFAw7EJxDC8s7lukmMUp0CJokTiA","MYvrJsmr0FSPg58OhxbswOJamqZPGqduYw9NOsU_G2UA","cWEn3kvVHBQgRU93L5EYbeWn6E-e9uvrqGdhgzRDBQ-A"],"response_scalars":[["AWEB7--HneLRZwCVyMeNil0wh-3GZS0voYQaCmwPxgE=","9MqonMPEJlRSuW4rqmybPoRM582sz0SbrcHCnrb3wSU="],["qh2Qvjk40BjNGKlb8Br-WWmVBFmgFLf59Il5B5jN92s=","5MK9sQiGW1oajj2C-mhi3UxmB81yuSIPhWJg8GlWnSo="],["R80uWqq0x688kdbhk1bhYiERtLwbjuR_Rccez1BvKg8=","OjJF4yVIi8LPa0nEZ7uLbRk0BGE9N6qol12iBXhfCXc="]]},"scalar_mul_commitments":["kBZCX53gGWZzOT-xBC-SmgAxxyXqOnAdcagY6DRN0xOA","W80Ig7VFtUnFsbnqAqVigsTm75w9gvpAJcjomTCeURUA","_9elfcf05ozZo2FQV-gJyLpwQMzPPeQfDEZU-zn8pgSA"],"scalar_mul_proof":"myAT1dmvSdiYCZbVn6N3_0xuICqQnGM0bckFVTjxwGYAnbEqNGdrpqm9uxHLcbVMW1vtWFFXmBMNZuGyXCG5E0qA_jFI64pwo87YC9IAofM-bCPr-q8MLwSaiv43E0GIZXeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAmu7VryiqPRp5XBicw1tiA_Fx4edpsHXAWCp_um37HGeAorLn2DBppq553VYAA-n6RKu6GhJvsP5Avv6wPfMbH1iA4539SvDdMo0zfCXdZSCBVfJnXPEIkmZQwdeBiSJgVw8AYj4EWGL10pQMFx605LGM7w35-TrMMiIgMzd2d-UTGGkA5nR7wfWihhLjSLqP5tUmE5YlZu7QKFGN5krJXsgOwXMAmQX0snP5TN68biC1HVFUbsIZ_ZhNMLCqrz1NmVbPflpjkbPUWHKwFL0rF3XWxNeSIYmdNtjb-B1qMAHt4w-lTPccDrBfClIT7avwWvz1ENP2bqm7f2xuKahNx6ZDJMAgCwAAAAAAAABjnv2Gr6UYJsK6tvzN96bpaYDKWyUUM2DRo-Fw6flAcQDsGVj2GLxU4nsfgmY15wIzb09WEVMeoXjR_O2ze8hfJoA809D0q_SJkupVLQhusya_z26b4b2s7uxmYLu5SfaVY4B_HqfYpBIfF8K-BGVaIhelQfuuydrjmgWe8eHu0kf3OIBllwAWh4d-64GbRVbAlkBmhURi-K0R2dHW-VCm0HGeDoBfdgJHO-_kkZh5uISxEHY4bkSMvkqA9C0XiWkRL9HKXQD90wgdyFTF0Z-_Fq57YzIgcfTgkoqOEG896TGHpRC_QQA9IrxQsSZ7PKWtOW0ouA9DKpSI_vxh-vgT1yJBXhudSYBQxy8c30QbhF1sXZ6cg4OsIo8Ewe2QtAKkfnYWr8_LMACPIiJOijCqO_yzjEGr1dmlgO6WOciSQjgwlK5ZRUSkYwA4NR9bZ5y90-jtWvC9hbIix5j0TLcswtMQunbUnWRCHwALAAAAAAAAAO-I8PX-u90mMRS2R7tlgshi5mBewT2swXfaLraW0nRDAH-LVDRTqsL-3YwCACs3PKzZXot5zc-b7uEG3iql2IFCAFEcMEJb0pDRmk-t2nT7EqSm8Cp5CsVIQj9Vle70_KdNAEBBZythqBN0CauxqcIyp76nHBam2VMlsPn6yP4CR1ZbAPEDMMokhWhvPrZRFh8BUFMJhDZwjhKzNcoOsyMsSicBAD9AScGjzK4VHQuY56ObGqKnZMbv_CTfJ-BerUvxrClrAGt0qFX6xyVLyo29kOBc56cT2LykwxpAcorFy_pys45cgLraxooG8ZPOY4xQaLH5whb91XsFcksgfr3e63FElbwIAPdvubkFjh0lz3OHTN_67s2f69TDsTUf3Nm2phy0KlNhgB5UEconoY4yjOS-LeA9cdJdaGJBz52ACbOpp4tBLDgJgN2HqUUU6ZXRuIKQ3IAoyuraEC6v5EYcIdD8_aetrt4sgMC5DbgCi3jNRbVVu48FjkPElz17YR_Ujdex5p0coFREig2aA2Or5qXsifEFiozTofZZ_C_N2r2XPffrcQeP1nc="}}}
        "##;

        let note: AbarToBarNote = serde_json::from_str(&note).unwrap();

        let address_format = match note.folding_instance {
            AXfrAddressFoldingInstance::Secp256k1(_) => SECP256K1,
            AXfrAddressFoldingInstance::Ed25519(_) => ED25519,
        };

        let verify_params = VerifierParams::get_abar_to_bar(address_format).unwrap();
        let hash = random_hasher([
            59, 76, 67, 37, 137, 103, 71, 36, 80, 140, 49, 68, 39, 189, 76, 116, 136, 125, 240, 85,
            83, 24, 239, 132, 173, 111, 164, 93, 207, 199, 115, 61,
        ]);
        assert!(verify_abar_to_bar_note(
            &verify_params,
            &note,
            &note.body.merkle_root,
            hash.clone()
        )
        .is_ok());
    }

    #[test]
    fn abar_1in_1out_1asset() {
        let abars = r##"
        [{
            "commitment": "_qjSkM5vHJzQ2cVK-FDDeQU_8yTj8duYrcc4t8zB6gg="
        }]
        "##;

        let sender = &[
            0, 36, 222, 119, 96, 132, 235, 220, 44, 107, 168, 128, 161, 134, 76, 139, 206, 93, 193,
            107, 39, 181, 246, 60, 169, 115, 40, 185, 175, 71, 181, 29, 187, 185, 42, 124, 243,
            189, 27, 3, 51, 123, 85, 210, 73, 211, 178, 13, 60, 229, 222, 142, 119, 251, 6, 191,
            170, 74, 5, 239, 153, 66, 113, 106, 2,
        ];

        let memos = r##"
        [
            "sGuXTmtbMgwgJFraoNOUlGDZFitN7oALsbIJ04YynCb77jJPm3Cycf3eh6n3fGONypP_2HXzp12lXhitqUanYROoWPCsCoss8lXJ1bScQMPTgFuJZo_Lsk9RBCd0WI_LpITRej3K6y0f1T9dlYQZpLf2X-0UXAou"
        ]
        "##;

        let abar: Vec<AnonAssetRecord> = serde_json::from_str(&abars).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: Vec<AxfrOwnerMemo> = serde_json::from_str(&memos).unwrap();
        let outputs = vec![(1, FEE_TYPE)];
        abar_to_abar(&abar, &sender, &memo, outputs);
    }

    #[test]
    fn abar_6in_6out_1asset() {
        let abars = r##"
        [{"commitment":"qyPwCkKMlimC1L50tRMSzPFpXfTgBwWBQaI_VWjipQU="},{"commitment":"6Wzxotw9DyVfV19-3fStLxBdwNlmsWAHgpbYs2LhTSo="},{"commitment":"ycYE1AaI-yX0R1_oZT-ftALQCg7wr6CX4CsfUByD9yI="},{"commitment":"paIry691vfl3DljlGv6wFU9Pz4OD7-YRkX8XT2fFwww="},{"commitment":"mK0l86FmhM_OUI-CAgjltqOr3SPkPAwwAlohdDiPJxc="},{"commitment":"xWzGJNkmignwVChHwTrE50KpgHrc5uwpdOWT_jCj0CY="}]
        "##;

        let sender = &[
            0, 193, 194, 247, 213, 225, 157, 206, 0, 254, 81, 131, 0, 20, 251, 75, 119, 145, 193,
            199, 159, 12, 135, 194, 184, 158, 227, 57, 114, 238, 161, 151, 228, 194, 187, 184, 86,
            168, 13, 77, 212, 111, 137, 63, 54, 96, 126, 174, 186, 208, 76, 129, 154, 154, 205, 27,
            248, 191, 68, 22, 84, 175, 14, 191, 56,
        ];

        let memos = r##"
          [
            "yicu46o_R26n7-WdCQoXgBFQDYbqAahslZvi-hIQ1LcVOMe3i8YsRc6a5o8NOAy30IZhShhFqY33Wv7529vY85L1USIKAPRd0tizP2fhkxUtVqc1OQdVMQreq-kHAbNpb42hgGa1dZtrLgiY7g5cCUio6wO06jIb",
"OU2inpCn9VWiB5IvOVap3hS0gy-NDTolp0UUKVs7Sw1VKcf4Hc0hoU8CxiqUnTahQZqTzFEb9gJ9CQUSsT1OHTdC45MxdC32OHVMZTVY0PfDF3ijTkBmFO8eSR7L0TxNHh7JkgmY46BnbULU_v5z1f3oPY_3EXVG",
"JnWfXm8iScRD9_UmHJmpW3NFvgrUFfWyQHucUb15zRR_3j2pW9dMbZLPb_9AhSLE_Nbnru7yoIcAaIwwF3KhwI_DBN4VQVoCIdx4P3Yo6oE9PhA-N35N7NCDN7E26dhbif-GNsuWUsA0puUNKg0K4_LGyM-Bcnk2",
"Rmzqkv-DLqX4hUmplI519ZJyx51AwjEoaubT32MbrA0BuOwSWKkRxthKUc3RTml5I-TWGb65x_WYEK8K687h0H5vwRta3lXatSRvIZbUXzNoneNBk4FhjAAFUf8lPnlW5wGM-Q5cR1_fOg4URXzQeY8oywQoiQ7v",
"SY9viXWyhaJn5Q03Dm5OSWUFg-EYdf175fe0SI_3rEow56W-TLLY1R2x_G1WXyEEZLcao7se_60jZ8DNobgN1kvRirAo0YHTWnX7XrVf_3SvSeXzHpI3J2PORl04hD063zu4X_QZpGVeN8hexCkR8OSq142aeajQ",
"0E3ZBrDWIITOj3bv3b7r430kIn42qS9oRrMQZVbYIuMvXfxivnh8sdpRJUf79jq_R577wiGdCVvgiIbGIC4whwSyDt8UoAnAfdLpPngk6EGrQ4sZ9IltQmGHfhCWPN4YZ5YvopOX402xez7CX_Yab3VUZrad3fo7"
          ]
        "##;

        let abar: Vec<AnonAssetRecord> = serde_json::from_str(&abars).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: Vec<AxfrOwnerMemo> = serde_json::from_str(&memos).unwrap();
        let outputs = vec![
            (1, FEE_TYPE),
            (22, FEE_TYPE),
            (333, FEE_TYPE),
            (4444, FEE_TYPE),
            (55555, FEE_TYPE),
            (666666, FEE_TYPE),
        ];
        abar_to_abar(&abar, &sender, &memo, outputs);
    }

    #[test]
    fn abar_6in_6out_1asset_test2() {
        let note = r##"
        {"body":{"inputs":["buA-VJMln7OzE2ICY7lUmGlDfNSgNe0jxHBzyRRU5SA=","Q28tuG4ZuK1TUIFDSQJKBaEilH04t3VhVazsXMnUcyA=","YfqZWPVhuqt5XJ8NSXgSfKCQMN-OMfYrtXcwEAYi8Qs=","EOvTw7Ii-soYlV3RaRKj2PDnkRfN4xLiAo3YjvcOxBE=","mdGh2sWDrXIh2wpSBSKvXNd9cZogGuj_PaSdb33ORBo=","sJzPaBrAW4vnEwooa1m7mGk3lOv7yumHYmwFmcE0EiQ="],"outputs":[{"commitment":"aR5VrR9y3w69WeACESFkwwLmrgQvbRUp29Tru-10aiU="},{"commitment":"uY148ANswILCSTMZpXhZnjjrSHTHqPRA8TSFkTNcuhk="},{"commitment":"yBHUqjDAkQVgAklJmTHEO5j_VI_yUsafDdE8wMun1xk="},{"commitment":"nYBk0iDYg8DFMGRmPIk7W6fY1Cs4OHzXPk0_1l09_gc="},{"commitment":"h7-2QBRxo4d1QM3wbJLY5uGPuvgiSOHm_xeHjlNZNgA="},{"commitment":"5GeE4_a34zUH3JLp-bLftOIUVDvoRteyl0H7IvsQ8CA="}],"merkle_root":"ndTiO4zD89H5T6qG8OghLZr8PenVp_bOwRMMX3dwLCU=","merkle_root_version":1,"fee":23,"owner_memos":["rsWGVpfZcTLNkjvmZRGtVXah7tIljM-mhea9S-w0_FOAmPA83ZSwSQc18sgn71sOREX_VMwIT4TEvf6JkWyjqn6gr0N4DZegQkfpu3F_WxNLDFb52VorwkNK3nZHBitAP9tN4hBR0fN3xb8jUymYcCiP1_KRq93DbA==","sYa5AL9Kr8UzL8REykFBINKzIOkkkGJ5BiMYtn_7WTooKmVIL97gstIy48Jcm7IMJKbjtUIJkrxIMmKp832P3SI25C2VIbltEL7rkAqUv64ap4ndwwJLQ5blON36jZG7J_uhhRGNM9aYtyNQF7glkPpA0Gka9gwx","OK7y_CT9dRTDNCg-qqIk15MweE7U4Un49_I890H6oMuAyJKh937REL7JcMmgrEPVgCgeGVBFzdVEp1mVSy75Zh9iM14s_YLli21wq1Tfqj7UkOiKZ-mvGt0K6bncwuCEbOfHLdBs0DaIWRGk-VnzBm8U33NJuw8VGw==","Zr_PFBPcFm7eSjmNLGxo_FgeD1IwSrQlg25wG9qUUTGACIBcrIXRNoY2n74-CSzCBh5bUguMnETK0LUWaiHbwBh8Gacxb4-ABKPR9g3fxRz8YZp_Kl05Q889ERjybuOFNL61RAOQNmH8iKsMxl-9HQbB-NEWOG7RPA==","q_xZRiUTUtakmTTkPJZawWlbqX_fHJSOBoUndoTrSBp7tx_Ypi4o9Q2TsN7qrH9ZtyfkJTSGPxSWr0KLosQP5nwQdh0byUR8t1BSmB8U-mZNSy9Oe5nOfQRw7GS_rsThvJ3s3-Z9_hb_6XQ7Vb5pulRnmKIpMWVO","klViL2bhm6ft7XrSi9oBfdrRD9tG4dh8hBlcXWSoo6kA0wiPje4I-uWE8yxwCPGxPwIOIKKXue_SbPr66ukCEboTy6lCqO_glQ4HwgeTXtUDNOjtwSxm24YfW5kalcWslbL3k9cdiUTWukb8oTs-3FAYC-SySatrtQ=="]},"proof":{"cm_w_vec":["i5KkYIOcamqc2qIK61TfljMnHYcKkV7vxVaCRbrmtCo=","_CEcuegjatJnhH_or6JgXd2vzfYOaag3kDVUsRfwgwk=","J5y4Bk_txs-_jBWiuXrjmE5SX-pVekXUcsFOhsGLaQU=","ODOJABKF-cP6tQocoZ6SX_rUW4umjp75ZePqT7vo8ps=","m8uHCncqluE2ebDL-Y-UopN9Uqg2zY0UE6og7R4jzI0="],"cm_t_vec":["mxV2WjEhBwZ9BZ_TbNN7NhM-7AfRsL6ecEqWZJfpeq0=","_H7HP46Vm9XaRJBRfK8BzCyeef0NAgoIBAAuFK0mMhY=","6Em1Sg6FFU5xws14TJXvR-eF6dDInFs6fT4JZAs4h4k=","RUk967iHs1q3M9FKS1WX9mghdHkzMk--5R1nEv6loQ8=","WSbgsKsXwWcZV7NXE3qIpC3p-l2HFMg9NSFGT75RFIU="],"cm_z":"u8S76TUccSLHFZMPbc1uiwyFKpznGeUa5eCqQLeMvis=","prk_3_poly_eval_zeta":"cf-6JFy6yqd8qcXE88s-dCVezPIRbdI67NWNI69pThg=","prk_4_poly_eval_zeta":"e4jMcdgj5uVsoerNRkSYrg9b-bhKiNwZAH54RIIPxhM=","w_polys_eval_zeta":["mDxiComIpXAgqyIwKGlafuiCsQpLVAvU_bYiHE7kCAQ=","PgnAzOoTTg4XWyfM3b7OdchXZfg3D88fl8XrXrI11gM=","2PVpgV6gsH_GMQXH_EnFe58sWPMx8FJYm4lMTHCBLy8=","db1w79E4YJByNIfMtv_jmOEsuGDQNP2BG1u8nr-qQR4=","tm8g4F7xaJ-sR8NRM-bpoSkAE6MnPMkZUfkDGGgulCU="],"w_polys_eval_zeta_omega":["0CEofUgmJ_p3GIfbZ0GD_spG8HHE4pLTrieof735jiw=","CPkLY74DdTZ5TrR-jL09ERJUozt0_h2ACCbDecEdggI=","Lu6hKT1e88YNtYjhcQ3CfbUhpSG5Sdw0_xnjDWEUcgs="],"z_eval_zeta_omega":"30Ogq9OYOcr0QXV5rkYHOyQey7o0L3v5_KdATC4NTSI=","s_polys_eval_zeta":["LZU8qCw2ee5mmyH3Ub3tt1I-zbBgjF7-GZmX1E4X9xo=","00DAylpAsKOH-L1fkEfWBymWajE2GHcW0ZP26QhTuyc=","jAuedJqmBNzf-ROe2rk9QOhfFly2R55vGwzVElflTxM=","a06u5rqLGJEjyQl44SzeN9Fj5BFVYCk7CMMsG9s86ww="],"opening_witness_zeta":"1nKOPC4cqWgfach2eHD7Edt4cX6UruswjlwQK79ZvSk=","opening_witness_zeta_omega":"IL8S6Xn_6nkkyn58hr9trMuHS30dnXqumwV3p_aK85U="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"0r7Aq4AhO4yghPWVtiuFQ4r33PnTvGYxNS081GD9TQ4=","randomizers":["NTWTJxmghCd6VXF7-1iJ2dnUKpR6pkhF-8trsvOIyLGA","wrYZ5z_gaR5eIfQh0gSpaetrnP9yloUlkMFPdft675EA","7r1-xBrtTicOolK6FZH_SJVh7LJt9lHUq5TysX9WCg6A"],"response_scalars":[["RHwfN3MlYPF8VVEJ3dTwMcOoJq0H-yCN2hrsjt6S_No=","_hRQL41tGGrm1bwdfNvd1xEoAMFrXdgYi37g5UfPhT0="],["RF-xmE2M8yc4BbHYT2DwzOqUuvws3y16Y_tX5zCbb70=","OfeENCZ6IFxg7laxIP1D_Zs6y8u4N-SGlz5gpCPOBNo="],["JPmFHouAvM35cxCoGtgHn0XCpH-fyRMGOdysEH1bKoc=","Q0QZdLCJqZlReVQE8J0ruw37HkOR5J0hW-3P78Y0uBs="]]},"scalar_mul_commitments":["mhqLZgi0TRcoxS0fM6ajrh85eXIXeDVNkhI2CcXbLpGA","btACZj0CBAlvooTNIGyo6lm2iKu02URm_gTGWwfyVGUA","LsjkdFlQcBS0yX0Ezu1IWGjpio6Kr0pSNZO8OfpyLl0A"],"scalar_mul_proof":"3rMpAmPi9IMzxzZYypm4q_vhtxMvty_ohlXLhhPnrzuApUhCtKH9Jw9B8jo8hhXObY263pZG35DK4__pI-Hvtl8AQ1AUIRWMEaChMrdZQSA4irnTxHoyq5YkAifJkYHMaZoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAN7PC4YhEoH5CduDpXMl7XXlQGmU5DlfTtNveyQR8ZAoAgjK1XarnUpvcHij_L_f7wyWjZ_7LQmy0VO8SlUbW0a-AgyeUXWUQRfBoAVssHanbHXdOpe7gKaKudstUkMssLGeAW7XU4fdUqKpzEF3WUis7_6aYu-c9yTEHlil1hOCK_yWAwc6cCv9LT8oyW5nVV2ktddITge0TqEwTp8ao_2_CEOyA9LeKWCRc4tjWaOQr3atSa0CxoYb-vtp48q94pX3yGXkcgp8155ZHP0f4y0yAK3xIsClrU1DD56Wrd5OUEWxcMxVO50c1JjXaAucqN-jkXXx4H-FYq4P4nHe3OyXz2QaDCwAAAAAAAAAW6r1R2XABGV-uFYxcPiqhvY4KTLJyCMwUrDiDlsGVgQA2_IV6rSk6rnD9HXZ6aSy1i5AtQiGmJMAmuqdXBtCqPYAigZklU55zSqyrA_J7Rx6GQYz_MqEvxqtMD4I1-Ar5x4A7V5Ir4NMskllP51jjAwZkyxU2DpNBxtNRdXdHHEPNloBoPzyuAtxLwDF4tASd0s9SvrKTUikni_ei6MNz0AilYgCyU_0fKQ6-z5-2IEriltYAw11nbq3lFQKHTWHvXBTcTICUiEl2liCRDYVbVa5pZEkH-CIGF4Sn_raG3ky0bVx3YYBMggNdE114r04mIJIoE2OquQQg4bgd9Xrw4fs-4KNf8QCaKuaeDHMb7Q9q6iGGRkgKwcfQqn_RgTgK0iET1jAJxACQJdBIE74Xg-4GM11WUttnkTpkia-euqOjsrpIegxAfYCF_UmGTrDtrAGt6vjxYoYfkacVo8gJ1aghUrkynkUBGQALAAAAAAAAAI43uaUBH972PCeZNTiSRbAJbUBtYC406x-6xpilaTqngGjsIlRWzYAJiN399y4dcR4DewJ4f0EaKhpRcDS5qoFJgEIB7YcrK9l8F1pcjCMLvJj1OT09g-xlnxyg_OqtrkUbAKDBD0jE75ZwXLrqEqZkbqAZ4TMtQKBmRmT36DRWnK8GACSTOP-AUPl4pnB5BZUutejC5nz1nQMHv2dpsSVdfFNSgEX6uoPiFsgfU4o_L9iUImABebd40ICiAMmM1RM0851GAK1_Gt48AKSyM57NeooXkkVgYRBEoMZ4dbydqZqdBCHSAKPoKogxZvxOUXcs0L7ZCPF9AoKE1URQL5qvq10mSDgVgJgSwWpl4NgT7ruwGiHu0nCdYH5pKOdGTHrUYDHjxIdJAEuJDQT8Yn4-DJhWb9hezUQBIdRxXALuJQMujek5e2BugIokFl_cuPIO46AkH6HyQJ_NmZ_7b2Pi6VtWU9TtKL5kgB2JKEAmOmtTvK5ylowWYdA0i_h_GtHXIkzywcUCGYviWuRaBEqBpPJ-D0E8gJ5YcWdHIiMqzVDcXPImzle7zQw="}}}
        "##;

        let note: AXfrNote = serde_json::from_str(&note).unwrap();

        let address_format = match note.folding_instance {
            AXfrAddressFoldingInstance::Secp256k1(_) => SECP256K1,
            AXfrAddressFoldingInstance::Ed25519(_) => ED25519,
        };

        let verifier_params = VerifierParams::load_abar_to_abar(6, 6, address_format).unwrap();
        let hash = random_hasher([
            168, 11, 13, 35, 45, 205, 68, 1, 186, 87, 46, 229, 65, 102, 177, 166, 75, 215, 66, 161,
            214, 138, 236, 52, 182, 250, 75, 115, 8, 193, 3, 229,
        ]);
        assert!(verify_anon_xfr_note(
            &verifier_params,
            &note,
            &note.body.merkle_root,
            hash.clone()
        )
        .is_ok());
    }

    fn abar_to_abar(
        abars: &[AnonAssetRecord],
        sender: &KeyPair,
        memos: &[AxfrOwnerMemo],
        outputs: Vec<(u64, AssetType)>,
    ) {
        let mut prng = test_rng();

        let address_format = match sender.get_sk_ref() {
            SecretKey::Ed25519(_) => ED25519,
            SecretKey::Secp256k1(_) => SECP256K1,
        };

        let params =
            ProverParams::gen_abar_to_abar(abars.len(), outputs.len(), address_format).unwrap();
        let verifier_params =
            VerifierParams::load_abar_to_abar(abars.len(), outputs.len(), address_format).unwrap();

        let receivers: Vec<KeyPair> = (0..outputs.len())
            .map(|_| {
                if prng.gen() {
                    KeyPair::sample(&mut prng, SECP256K1)
                } else {
                    KeyPair::sample(&mut prng, ED25519)
                }
            })
            .collect();

        let fee = mock_fee(abars.len(), outputs.len());
        let mut oabars = abars
            .iter()
            .zip(memos.iter())
            .map(|(abar, memo)| {
                OpenAnonAssetRecordBuilder::from_abar(abar, memo.clone(), sender)
                    .unwrap()
                    .build()
                    .unwrap()
            })
            .collect::<Vec<OpenAnonAssetRecord>>();

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "abar".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();
        let mut uids = vec![];
        for i in 0..abars.len() {
            let abar_comm = hash_abar(mt.entry_count(), &abars[i]);
            uids.push(mt.add_commitment_hash(abar_comm).unwrap());
        }
        mt.commit().unwrap();
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
        let mut random_bytes = [0u8; 32];
        prng.fill_bytes(&mut random_bytes);
        let hash = random_hasher(random_bytes);
        let note = finish_anon_xfr_note(&mut prng, &params, pre_note, hash.clone()).unwrap();
        verify_anon_xfr_note(&verifier_params, &note, &root, hash.clone()).unwrap();
    }

    fn hash_abar(uid: u64, abar: &AnonAssetRecord) -> BN254Scalar {
        AnemoiJive254::eval_variable_length_hash(&[BN254Scalar::from(uid), abar.commitment])
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

    fn random_hasher(random_bytes: [u8; 32]) -> Sha512 {
        let mut hasher = Sha512::new();
        hasher.update(&random_bytes);
        hasher
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

    fn mock_fee(x: usize, y: usize) -> u32 {
        5 + (x as u32) + 2 * (y as u32)
    }
}
