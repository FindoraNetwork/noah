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
        {"body":{"input":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQLVDzv8dUoilzfO-5tqY2bBgrFRaEgVxH_f3jl9rzckew=="},"output":{"commitment":"HYoyzJrlE9HWACyL80pgf_D3ULNNnzxqY4ef2muPGCY="},"proof":{"cm_w_vec":["PJy_5cOsF1RYdgrZWuxboZHs7J-L2qd3aggeyNGiwo4=","MaHEHPS7kIZP-ko0zETgaBVNk1lR17fFll5HedJGChQ=","irA3I4-DKn4dinSk-I16BKGyfoU-zkBx1Za2Afp0EpQ=","zj3JCAgedG4FLf3cARqz8YoQV5fD71z-uHfI6M38Bqg=","8UnnuxjBS-MY1UL_fUMUMdKnXzVoreAVsn6D5rmNUoc="],"cm_t_vec":["TaPRbOQ2CW740YKr6DMX2i1kTzxZaLLK0CjClD266B4=","O9pThN-hg_EakmIW4b69qP7Nfvv2fQVFVrkATJuX3Y0=","0uktkHqPT1hjETGIrR8vOd0mSObxEAnpLBR2h0vWMic=","dqUq8XOCbJO7C1P3afdyksZWWsg9pGMbLTlC98TQey0=","HwRTaHZSesrtX0H85aCOac9eaM_HTCiQICAGTDUOzwI="],"cm_z":"sNGoRB3B7vhqUhSbdu_ntexvShK3bunMDKZiCGU-DRA=","prk_3_poly_eval_zeta":"QzvCoEyjPGv4Rn1KsK6l7c-Xj_2_uKvGnJ-AvEvaxgQ=","prk_4_poly_eval_zeta":"saMgwWxA-PjtGGdu7N8IFDjs08PdxkLn8Y2Dmx_8ugo=","w_polys_eval_zeta":["CgX5H6zjfypAO6Sfwlaq4MNYbq8_7Ulcy3jrDHSx-Sw=","_ousnLMQO00N4w-TCdQzjXOhwcARA1VXovyKNzGe2Cc=","OqW5cgOleWAwolrGJtbUG2SJrCFzGljQ2pohdvnguyA=","xQ1gGMj4dP6TbixSuYY2uDdRNtSFvj-vHOcCl3UIOyo=","A6ea-zCTUmIAHtA9KLCjt--55MQEEHjaNQ30jheu0Qk="],"w_polys_eval_zeta_omega":["PdaB7SpymZ79CkJgWzJMwFQwc0l3u5pPB1NQ4PaZSwE=","trU8OKtoRQhf88QeFUyc5FKul4qBZVC4qKGphGC2OAA=","TuRO_UWLo0oIrIYZfZWhmunghiPRKRbrxdwyac5JGB4="],"z_eval_zeta_omega":"H0xmqGypmtqXikzAbwrESckq5v9cX62kjTbjp3HDHQw=","s_polys_eval_zeta":["-pHpbLYBmiKvg47J_oZsRUfjpv8VadvFKfSTUfohowc=","uQQ9R8OUfifwVST6Z2DLZy8JTpV_xxtNDiT3e-7MfBw=","bgJVMB37XWKsGV6LtDQKuOJII5m5rkLeWDN2wWXN5R4=","4itfOgD3NT9rRDa3NkvgS0dSHCXJ4NLwZUlkSy5wBCk="],"opening_witness_zeta":"HtLM2GzeGTTF6vHc_P6A__S4coUfYro73z2FC2_w7Y8=","opening_witness_zeta_omega":"IbOiCbiGb5hGQNTRa9tNBJhmXClOXYh5eEVCRm2jRyI="},"memo":"kb62v-IReawqAdba0zkl5UAbRkl1rfxNqB2ClEih_ssAhFaMsbJttITeR762qpBSf1ucMi4UpJkCef4DiR6hocXXNDBVPU5Qt4O3Unkd4-tM7kOUW-TnuJMv6yncqLm0NgRM0tKAUkMDnHa5nLa1Sfbk67Uwkjhyvg=="},"signature":"AaSRGOMsE7Kl1HdNIc3fBpEqvZ_IsYPHjgt7NHuCKQvPbL9tJC607TWQBtaiBGsYRI50BTp4EXEOWQSQtmoAfWsA"}
        "##;

        let note: ArToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_ar_to_abar().unwrap();
        assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok());
    }

    #[test]
    fn ar_to_abar_ed25519_test2() {
        let note = r##"
     {"body":{"input":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"fpl_Sh-YAUXAWqCJmOAzxeT2DeZuQNPUvoYnzHAHIRM="},"output":{"commitment":"L7CqM4S9Ig9Aa4z9EBtV_0FsT9HquQ8kF001wrJA2h0="},"proof":{"cm_w_vec":["qIeE9GqFzQ55F9x3OXgWKzqOdEl0J3gw7kGo92UCKCM=","F4CSsuOGeQ8YgdNNsJ8nn19iUxA_iluqYsJfq-T_BQw=","Eac9P3Ls1itD7UavktoV3AkgE-udDEpvKEyHAOHkvYM=","kaU_dG_yqhkG5ZgbIqYpkn8LQK_dbRBg4X116frdkiQ=","o1snPaqtS5NAIMskzgO-ObZxrcDxjjxcI4BqIrBbv5c="],"cm_t_vec":["1j7vPpahxDN9vsZV8AF0WTVnfy_2Yd8L23myKVQsgS8=","GS-ZCg6MmjiaKX8yUgno1kpbOqz_GIHzBQDP4pEeLSI=","45SLv1-0gedoKLzCCrC12nciPUIoWBswBmlKV8Yytw4=","VBQTc0vLwxUUOglPhngiIjJzXnmoNrxcdFOsRaLEZwk=","Bfn4YZjvR5lkvA0Z5oF3QcqkTygcLFE9hwTcmyEaI5s="],"cm_z":"1C_fnAr2Axb9HdRFMLPemjpYIbdvtEfOfaEtFJVLVwY=","prk_3_poly_eval_zeta":"FPKXaujvX7n-e2weAa1Z0ao3uWG2bdrIc2ytTcrN1hs=","prk_4_poly_eval_zeta":"RyEwX7i1LhzCjfBgMOrD7KMywo0_Y7qghI2NvrzQNyY=","w_polys_eval_zeta":["CocoJJSTQBNDhF5NuuIvmKdaKZrV9Az8YcKgIkgIDSQ=","GvPSljc9535UaVUOLmkFr1Qo6kiSIr-hQNSTOuDPciw=","3YTN1yf5kb4D3zywLrR_hFJri2SA_fPk2Y1RoqnDgyc=","3ad1E3ookJIIPZrjwBD4nP9kiyIVFDDVb5xKzNlBeg8=","7T_5cAYdXKdOWxNi3AsGgB2W-MYowg5g2dMpMhq5Sy4="],"w_polys_eval_zeta_omega":["zNTtSXG_-s-NgPxgSuyacjfx3TXcZeaI4NB7_-XMrAo=","Qf9h1XjhwPah_U58RwGLi7YiE_bu3MTtpGMUQvTi3AQ=","pOhh1LL5BZ4HVM-hpACUKFPeeaItx57OSQ8v9o-u7gw="],"z_eval_zeta_omega":"ikSvZ3Qgren6o0r6C100_YGL8TO7k-fZae26Yx1bdhI=","s_polys_eval_zeta":["sji16B-dtpsOiRc0aPLJ3VmafhTOlojrHx7qn6lm3B8=","jnT-JjH8V8KEsesNof8DPGaF2X8ERPDb0_n10uOGjSY=","zeNRkoqZf0-uOk2RG2Ij2huT-S6siJzeVtgLTNNrfyk=","5FN1Vu7fa42kmU9jFDGZubx2xhz_od4CdZD-05jutQ0="],"opening_witness_zeta":"KIynM11rL1XUhBHTq4xvLsMYqTLPY_jYlMRprZ0jppc=","opening_witness_zeta_omega":"v6lTF470o_CQffgp5_Zd-HrSq4myamTojvT37Gu7pxE="},"memo":"JkwSEMp-R5kZPGDRCUXy4m7p28nQ-DevnEcPQrRdkrmPxN1FFx_-uuKEApSydnQ2-66r7uYCtp5R18leDQHttaVmRSpRfW-OBSB93CXC60NgUPbYYRanG0-g8G-D2l6PA-L49Ic_zMQgabiXYoL_Hh-uRwbhSzHi"},"signature":"AEpVg8TBcbLQ8ohKmhLG4X-EByN9XMTm7c9hL7N0NaBW1IqpL_MesNeDVDRiNlcrV8h4KG-WiSgINizKisY7TgcA"}
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
        {"body":{"input":{"amount":{"Confidential":["LiaVGtwZPksBfvnkIwuJyqjdMLyBSlIQ6CM5o-F5QmM=","1ix8eyvUkW722ernc4Vmi0E_sv0nidZol5mBUMUrX38="]},"asset_type":{"Confidential":"QNfMCZOZ4WcwlQt3E1tCJgldJtKOiysvE3gFwwBi1Us="},"public_key":"AQIVGm2S3KP4xoYqi0ND12fZeK9YBNsWv0rVc4WEXh6W8Q=="},"output":{"commitment":"T0PRAxXdp0vbny6u3jsf-JZwXii_j1Ohp1h4mXrRPAM="},"proof":[{"inspection_comm":"VHS_s_maLDf_LwtL89J8o5UWgn6RIwjRiRxMr6MuZSY=","randomizers":["qCOFRX5hq7DcNkTcc7tkhUGWsHPeIuSjuPXuJO11RVA=","ireVseGYfMS-u3mFJUwH8Cfg0C7SgTTr628Y6QiUX1w="],"response_scalars":[["8zSFD4Dey_dH8_phQDfpr88OXL7_JsTjrrTIRD6OWAM=","HX-_ebz5L_teAponLlAgqdDPtgoY19ba6qwoRPxG1gE="],["Re27hlEn6OEscbHeLFW-IGmaBKf9Vj6BE1jT--_41AA=","55ozjM1NTN6UTit_uU5rfemUWCbuEf3HIBt1vmQsCww="]]},{"cm_w_vec":["omrITtAAaeiOE4ZB0MidDN3BTaURQLNswwuUOqeyYqs=","pwzCWaRc8XETk9XKboEMQJVrA6UfayuTFPUzUvkJe4U=","_aDxO0PF8tUYoIsuUiuTqTTT0YU-O0-QA3yG7C4IZgA=","ePVzHE-FD52nlojULfgy9iNtX6LTnBO3vgZBO7y1dKQ=","opj_xw6HEbFCYbJJ3y4xiqa4KwlEe5z5IUD_G2vsKJI="],"cm_t_vec":["VieZKAh6INDB-sNmWeWUjoNIIoyH6eOTH1tzDjvhtZQ=","anasCLfaABoUAl32KTEcvq3uknnubaivq9mYy1MPmg0=","zjgb55DPyt0Pj3ZbVPUVl8YKCBTauATCeUYJtgSbcg0=","YSp1fJ3_n2sRkvK_XlVPbM7yFhS6pHKqgEUAdvpJ6qg=","uHwcwFoT_DbOQ6stIOYwZ06dVb7xTxSmAo7_74x35oA="],"cm_z":"9SVrmewY4GfrAPjyfUZLldNLdRiUphFhtbkGzbxAIqY=","prk_3_poly_eval_zeta":"da2fwNLbF12lM0tF2dKjFrKWuEtpcMuhABfdMTvZoxw=","prk_4_poly_eval_zeta":"4LYi_Y8j-VRGYZib1rmLWfWQhEkxC6LxWj3qT2YmkwM=","w_polys_eval_zeta":["uvRk_gfx9EEoVTJPKwCN5zTRetYX3wA301-RF2YgOxE=","mDu0_g_Ard1QbfsSlNfcoLcVmFS1imaQW6RuoX5tvwA=","j2UuUbdZ0uqScocfmA9PGY7w5sMrnoQdlX6ZHVS0PC0=","VaytQO8_Ajz9NypUFgenTuXdwV4GmzLmiZtRxNOm2Sg=","03zkL1HCEBWHzDlnxmNfAa6QeZ76g64KKa-5fYL93xQ="],"w_polys_eval_zeta_omega":["SKbdIC-IbQ3aDQ1uopZo3UsDcwzm8uE4tN-dkdDG9Ck=","BY5nKVvRSH_MshLwp2LRWnl_Ly44UV5CmvhtCLc2lRU=","9Wp9aS8gH9xyyTR-AlCNaxB5-cQkgNGeuoj0o9JiogE="],"z_eval_zeta_omega":"PSHoSS86PYu7GojfS9Rv_PgVW56VQqUiStqvn5qybCs=","s_polys_eval_zeta":["xZOgxnRIRO_i8cR4mdG3cWljkUseiOh675tUaxC34SY=","jXvOUfyZF5cBqhDlWk59POJE0SOvgH9R-O2Mr4LPSAI=","7w2H_AtkF2g5KjL6ySaFLdh5p7XyXcaynSWKNjV4DhY=","Kf2Ff_Duccmolv3-5EO7as6Qc9tvPzgj4esc6JWZBS0="],"opening_witness_zeta":"z8WAXu-Hw9vlGvMKh6wslp2JR78wTi3diQxi6EtIoKI=","opening_witness_zeta_omega":"FAV4bR0SOuJyDAebTWCyHWKIi-7zior4m2rfnQptyRM="}],"memo":"6rbhVqvh1lhgTIxRMCxlA4YRgklqVo0gQMGAdguvnoYA9fCFLDKjdG4EjneF83oFTrQBs-9LRP63jU8-hHlFhscMPQaJ1DJGZB1kXCmmGVbC4SSI6lXZwlonsQlwn1Uzr83b6C166qa388AlbkvvWrbuySkU9xxyfg=="},"signature":"ATk48dd13r2sRAL3DrVhP2WNQYl9Vbd9y5Ft8PVcD6_RNqDYVX8yPallb50cTwJ3GjhHEqy4KcXOvCgKtqfC6lAB"}
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
        {"body":{"input":{"amount":{"Confidential":["RjgGhYFWMrLAu93mTUQpce2Rm8QDW3vMRqLFDfse2nI=","nFjqgAHVcb6y6fjnid4N5gbBVX_9UhHLS1QSlHQ1Iko="]},"asset_type":{"Confidential":"ws860Gtn1Xn-yT7UOdsKvNPODIe6L0Da1xT48QHjvl0="},"public_key":"-4NtuqwUMJBU5LtUUjBj-MfG6YmrnRCxHPhssM0s4rs="},"output":{"commitment":"slNDEOWoVEmN47B3JN_TtOgnihNJhHdVJtMvVazySyQ="},"proof":[{"inspection_comm":"iPenRoPvmrHnAkBdeoOT4lZMt3tcKqbcAxcT68ShTC8=","randomizers":["2Mr0qXiERTZNUPxt-6sydUxiX-pLjirfBUc0LEtzawM=","oF92ubv4jCMK_DMV-w5bgOyQFH7w3c6EWyeTttXOvAw="],"response_scalars":[["SbGSkdbMbi_AyVuFN2P4eS8qqGvvGUyZkxWvG97sog0=","pIWqARrPlnkCQPkUL6516fp0FP2zZAGitH-la4HAAwM="],["PYaCE36xptXEWU34HSA4WCKOgsek-D7qXCoCD6yYWgM=","SF3KSs9uEbQa8CZg1ptNEeVVq5ZZ4PQE_3fNvaW-pgY="]]},{"cm_w_vec":["5yeNTDB2VImTN-jo01MReEgb5w-eCGl2qzm0YlEahoQ=","pIN8zI-IRs09Xu-n0oJjCcNhEIbJSYFbW9smpA8JUxQ=","lZBpZWkfFMJ4niLIwubz9Erfinm10hZNzO2qePV-1yU=","5-sug4yikis-7e31dRqrvTJRA-oaUrmsjq4lNC11Vws=","FwRysroWl7uAsnqlx1JFBHcmZpC_Q36RccbsJqKZO4Y="],"cm_t_vec":["bfNiJMbYULdXNBl-5wE4l2Fnl8qeCpY01agwCiEKUg0=","Wmckw6sELqpuwCjjxUczMZrM6uYMtIMc35fn9sV9iao=","Qp9c_UB_Ijl7JrivHYIDS5B2JV9dovdjzxLm_cd-LCs=","zh8rS7cbBE4tnh2PPVk8yGalXJmwG5k8KAsUyHL2s4s=","ha1EEfHMgxSjGGiNsJJuogzwgNe7BuszUYZg4wWg5Ko="],"cm_z":"IFAYRwjXdpLEJY9606UYEn-Mpc5aCCF-GDtRH2MUXoM=","prk_3_poly_eval_zeta":"BVJeLZ-NLHUi6elGsXKDXCWhIjx3Fw3i6O7IXE4NQAs=","prk_4_poly_eval_zeta":"oezcFabG-K8UxJY0JPmAs955reNMb9WSjw0kRsWUuCU=","w_polys_eval_zeta":["CwJjKLvaP20QEDAwZrEcQgRRJOpt-LEK__6gvJeZIxw=","1tZ0Z7i9omwq9LOUKQjgYdV8guwkKPNxohBTQNZ6gRQ=","Kv9_u94JfNd_XaERciCYN5pGips2ejvyEAO7lh2NOSY=","ulgxhcGFvCregDeREpgCwXc_5FfHQLgOtqPrgWXGqSI=","QRHsK_9qKhvnUgUQUuN_6V2svGO_Qjh00jtQljs-zig="],"w_polys_eval_zeta_omega":["gQtYoRjx6OQUK7gw5ezE22cJ80uE_f0SwvR3vaLS0iU=","OAhZekuO_eMJha9toESvpXB1I4M0CxDH1clsMAAFPiM=","bNZVKouAbHA2zI6SLi_MJ7PC-R2fWIA6f8tjgOCwxRM="],"z_eval_zeta_omega":"ccEqsI3tNTzXd3GlLtcWxj5BaVpRIvBWEf-lyewciBg=","s_polys_eval_zeta":["PeXGEEHAhZwdEfuwPIIQC5pKFSqrUOkKgAmT2QVYhBQ=","plOxTyTy5_w08y0SPNdXitktFGIvbAgpuwoE6c5tLiQ=","T6GaS5lL8F3sM25iOuAC38Z8MFYQ5bCYJ8-t6-x7YBw=","HO3H_UCJoevKNfdKrpXcU3XZNBILeq1UZLElZvc4Xxg="],"opening_witness_zeta":"DmENyyD9Ro0yAJmwwQ0gbUIX0wBAokvdhcxDi-XgAoc=","opening_witness_zeta_omega":"3hEk5OI4HYRSPLtLgzUiNC2-u7mNFsj-8Yz6TR_1CKg="}],"memo":"Iyp3oSvwAtygPtk53rCfMpIpBDOZ5Pcu9zAlXyEXG6Li3hSkXoQJzweDMWFxUEBadYOShwCXVLOAJcH9M7dIwAazvnVaeB-Rz31T1XngmCIMonzIkjaMzzgyN205q0QS_LUsB753bf1xyxLTtCGHxhDQ5_cuUKh3"},"signature":"AD6kVYKb51rtolnzPepYU12oYlTYZKkHcCEInn3zSL_uzEf3WPWJ7x7ohIWQZXOmzgZpg2yktgUV-xlRSpvnBQ8A"}
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
        {"commitment":"1cloqh2qrjCWCrcDkXzmri6WDor7L_CohfGNLgMWzRs="}
        "##;

        let sender = &[
            1, 73, 48, 126, 223, 68, 10, 92, 68, 164, 248, 138, 112, 111, 177, 26, 224, 224, 3, 83,
            142, 82, 55, 6, 200, 51, 133, 159, 59, 94, 126, 136, 253, 1, 3, 128, 63, 72, 247, 117,
            167, 162, 183, 69, 234, 123, 242, 1, 229, 30, 1, 207, 8, 199, 145, 243, 137, 226, 254,
            223, 71, 98, 129, 174, 167, 161, 36,
        ];

        let memo = r##"
        "GyoHzNLXU7NKFzb8GHZo1WsOlk2O46ZeSe-a0HP7-kWAWtw7naH6BOpY7rjqdELvbR2qaae23do7Uj3dNsKIM_960JIvRWfl_YPjoS8uaiDos8FKLVlm0U11PqP1py8e1pFxlsIYVO7k5zj0I7DioRWb7BFoz13rZw=="
        "##;

        let abar: AnonAssetRecord = serde_json::from_str(&abar).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: AxfrOwnerMemo = serde_json::from_str(&memo).unwrap();
        abar_to_ar(&abar, &sender, memo);
    }

    #[test]
    fn abar_to_ar_ed25519_test1() {
        let abar = r##"
        {"commitment":"5z3VaQqHBI6PT22cRDdh2dGb6VGC-es9uwCPNsV2LBg="}
        "##;

        let sender = &[
            0, 34, 42, 23, 125, 225, 165, 139, 107, 100, 253, 231, 34, 59, 114, 6, 194, 28, 246,
            236, 177, 128, 134, 134, 106, 50, 233, 50, 57, 59, 21, 98, 201, 242, 5, 138, 23, 215,
            221, 234, 164, 137, 206, 131, 197, 31, 178, 244, 200, 117, 45, 3, 141, 55, 27, 180, 78,
            93, 16, 114, 182, 63, 95, 48, 85,
        ];

        let memo = r##"
        "i2Oa6CY5RscRrKnedReWcln8zfimrS1g-BLEzZhPAfalcvQBbnziH0BBrvn6T9PP1OhmO1iwi5Fk0an0WM-roj98UYegfbhy7QjdWfqME9sHNrU2L8gZfGz7XOn_VYRMR-ln5niiJnYzbPj05OLnTmF3hHMh2vdK"
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
        let note: &str = r##"
        {"body":{"input":"YebtkpTpxaGj3DG9IqGxQ1aV4frFNQgExEcom6j4kCE=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQM4R6zHNgjtA4wu4YKEILeF8hHluS0Q5GkRdrc8sK1pgw=="},"merkle_root":"JJJymlWGxNkF3OfLGpaVtNGsdUVX4YAI20l9Jnz19wA=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["KO44NNyIb8V2So2YPrcfVe8Ee8-wDqmdk-KE-fHINaU=","2Y2qfOMRtOQnoLFcNQXgb_11uwZLK7vigN6NXCUg0A0=","4xS6cMPdl-MOH_9SZIYd2qYszExfqX3fx5x7aBRgYRU=","O12p7XBMXqL6k9nzy4FSsnr2_P3DvvjnjNlKQfnk4JM=","U5McJEHWJdaOK2XhiEimF0ewspDORtZKZbZoY-_eoKY="],"cm_t_vec":["t2LIY29tJW1FW7xRNQL7MIM5P8zIfvT2KoWU2gGacig=","AEdylxP7XyEvvqHHw1cSTGBFUy5ZfG_AVi_OJoA5g4I=","YGiF4HMZ3k5yaAOP4OwGjDS5bTxzZxMbyMg08bnhpi0=","KPNG9CnttKIuFvuucy-c_q5XnZ9TLd5eNkJCKGMDxA4=","y3lxtB4pfSia-KpyZ0c0q0JQeK49LAPiKuWvgNVUfKs="],"cm_z":"d_YJNZz-6cM-Wtqjdt_ZoWDjtJzM1slyj3mLIusyKoI=","prk_3_poly_eval_zeta":"HFACara-TRJT-3h6ZJI-YUbCOf63Pl7sAsywdPkpGCg=","prk_4_poly_eval_zeta":"lC3BXQ2VGFZDOFj-39eXoyIz6S8CV7Gw2irRjIuyxgM=","w_polys_eval_zeta":["45rCPjgmVcjv9NNQUERJLXY5PU8NDTrbpt8Yj0Vszhs=","-3QUS8DAyUBVfi1ck5mD0tHYbIYen-tM5DfwUy6USQ8=","HtSkFGSGMtm2D1xP766w-W4GcZDvN0tqQTWSr7ZaKCA=","1v79iATIrER6LXDrZfsOhopMny_PeQoJKfwBAaa73hA=","VVYojAL2atI0NQDz2hFQY1BS3vQKJvHQrvOTOYdrQQ4="],"w_polys_eval_zeta_omega":["3t2GBkiR-51Ndmh4pHt8PuXHKpw_ZfVqqt6kv--U4Rg=","UOZBO_0_dWiVgCwNy9LQTKqO2ytTmveR1tSaTGOmUxs=","ojaZn58et6coX5SOOARFxbPHGEKiU3GabFqlFziV5SU="],"z_eval_zeta_omega":"o5l6Jv62KEQLQnJxOs-22jeGccgYYAy7-WTn3prUdwA=","s_polys_eval_zeta":["NEtnbJ4kp9xcGw5uROKFsXlaAJbXmatC5QVjS9RVawA=","mAUgqnG71P93JsZeuhYmkZVU3twYgfaLVLzw6fVqEAk=","5MUjtbHHnIKOQ5aF29F6O9nYfC7LMl_97tMIvWz7Cw8=","lCty3SyzzDHi0xCZrKMDsAyCGDLe6ZZhEWzQfOa9BQU="],"opening_witness_zeta":"rIQsyiRGas3Ykm4f4PHsOa4K5Nc5olQUtTTYG5CZhRA=","opening_witness_zeta_omega":"11y99taUxVjssYFYaACc3U2klywkOasFLmk2JjAP2ig="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"MioUX_xLhLUh02zr8eZu3xF6nqp4i33n4MiARI0-sgU=","randomizers":["iElMqenMYGz4MTbqQX_2B3-epCuSxJqawWgxDqz3eQuA","A0fus8jE-WlCWzB8md1C2bPapPZiC_pe2NKjDviOetSA","HCN0dEFWbAbUxO4eC1Mdnsk3zlp5Z_8CJD0XIvJmixoA"],"response_scalars":[["kaLmo9lP7LXPnMYqoVb662VOqKu5MO3hSH218m_1zdo=","j0oHtgmtSNGsWFtHMrqh6ltpnAAdSwtab9484dTMVwA="],["edo0-n2l95nJ9eRV32OuWFWtWFW05JvhyiL9p4-GiOU=","oX8D2dJfbXRsxi1IBPuJ-fNPM21lBb6ZLBHDbmtHeA0="],["OmSPnNN7nSg6hypne_MRgoDdDx8AUEZCUElz201VdZ0=","KolBpuHyrTOAQfIyAEBpj7NeyjV0z7jiEdvi5W2puGY="]]},"scalar_mul_commitments":["Ykl_3HtEIqTIr6z_VOUqOKZEG53lP744KY7uq1ax37QA","plHxZDb0jq3jTx6GxBGwJDO9OXdJJn7y1MlFCsLDceMA","l5lX6755hy90cxLTVf_qcimDqTR1xpe2K2-hfKJu3dMA"],"scalar_mul_proof":"tq1XY0r0aCJxih1qTG1p8W-L6jJdjzl2AKRACBMjnfUAyGqdjCO20cLG-yrO6ClOmY3B7_TUjd8Sy6n8W9f7hSYAGy3g3Q0aJVMzkLUIv_Nwg2yOOM-NEoctdFGhjjv-8lsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAaA-npaByWzGqYNvLkJA0jFNoh_PTveE60rkSTbxaFgA96ZkC3YMsoWAdLyD_6d0IhONxVa2JQZwJkmSEnfL3IAAhna0QcnMophb0z9qloDbtK05HZkZxbZlty7CVwIYLE4AO90ZVmZzk0HHzBPQDVY7HHU-JQKgM4PA2BakyCq_qOkArllgfHlHqKiHge_0-IlpmwmDnN7kUAUmwQU3zWxEzcIAWBoZ7may2Ab60XT0zqZcZpgJmqXxxc1iwUkrFXqIovFPZES_Yto2kR2GmUEUKwgIv3xAfC1R8MqTGzpttYGQuj5Te0_tWa77BJIagCM6KSXqt01PsnHEHw_453HaXTZfCwAAAAAAAAC7AC34g5zCDyrH2F2yWjO1eDZnwIwUFtzKFPYI7NWFi4DI5BnLi41dZbgxuDWQbZX08A6jGj-bTv3Tzk_rGIm1mQCFQycEX6gjqB4aegEqvweW4hXm57x_NFY54U5QBLJdxwDTM171OWX732UgKKjF6W0tCKBSfJ0Ml6gGRqfrZKSu94DlXYexa2uCjrW-ItQVPnyEfPCwnh8q5pn8UtqoVzJCP4D6cy7sIAv9e_deQ1GTg0zR3BPOdCQkD_ak2QFsb-SMrQBEQzygjMPZRdCG1c2ocKTIMSnifsMGsoW_OzG4VLVSmwB8eQM0OyQrZm-Hgp620m2LefY3dC2KfxWwbRpn6GmA6oCKKJdRmaqhzbTqgskjizLQhndmBHR58fqtYrslDRlDWYAIRuya7TOfo6hxPBEubfPP9owqw0z-UAvbeBaOgDbV14CrifdK0E5mFVkLkR0t7C2zwoqgVITkDfLeHnzCI3CQR4ALAAAAAAAAANTtikB8iTN9iBZIQ0hzMatrEEqXU-IgvWsOXKOpYEYrAOMEP22xwWP7QrckRTgjX4NBZFjxjnY1xhP5f-oFA0nSAPTsgIiuZWifn0VSnVtUtkWM46s8EdDvIa6II5k5idsKAHJ7bDayT2-U6qmuJifpqSNVwvSx-Jc0S2qP8OKwDwX3gL2tg7cgZQ506zrYWjXsTNJMGSeDfcELrCXmsu636Xu1gINCmyOrh5xFXYf6GD8N55Dcfo3s6xy6J-mwcL-CbvCTAILi1CMarqPKSdTmCkPXcxXWfgGDcyhZkw776_MMfogIgIiTwnMkYtW8Zl5zuba-H9W8mVoazgl5PX_LTTqD8l_CgB4fBOeC8eQ7PirjblBGZkhm3Ac7KpGlxmyYoUeAoarHAOF2NBitaXUEd7RTw47GzFVAZL0ptmVmn5pN9vxe69ihABie4piCknlXFdxiarDePSrbce3yRqtA6zjX_LIxi5ZKgEVe5mcRIVwQFbBA-Dkx5-HatuHW2j8MDTmP5T-XToFbn4Ox5EutkxJSoyKLKfsANqe5EL3ztmpoTWXe2h2Bfk0="}}}
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
    fn abar_to_ar_ed25519_test2() {
        let note = r##"
        {"body":{"input":"kN3OKkddUHglnGWEHg2cL_YwszSLJ44HCKVDQjn3Rwc=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"idUUSICb1sXAs13fsjXSTvl2gepk2RH3EV7lMG4ku70="},"merkle_root":"qZaTi_yF13PRYafK3lQF4jUE54K00dKwwTGMQ0W3eCY=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["oYxz0RZw5I0EjjtW1EWdG9h5bNlMf1n16P4Pg0ZfVqw=","UCLaHbOZ_VMCybp4QC-vpGMW8dqNgHfKm00NTGdoIwI=","NeyhFs9SkwwngTnKoWJ4urH8sCyBqMmMGf_vjcFfRos=","5Au0VjMVwQge1HJPOLic1RcvN8GhEzqgaMymdM8M9S4=","GKQuZNSgw18-bLcbuJtqmFkX5xlbuXl_BxFsZUMeXwk="],"cm_t_vec":["ZsGoChUU9QAC2vIAK9kvmm79QkykVwyi0Ds2JjJQcwU=","INp1ZurHHwG1sWE_LSiIwqw1k71Q9b4PVrWRVzU8Q50=","OCiUXaVmUwoft0G_4JKGN6iEXLK4zA4fMb5jFxjhjS0=","wFHlIrPLuHWWTGBX1szKx6Zz_S8X6XwroMiNApEwj6M=","BMOm0knHnoEz_wRvnms5xcYb5gMGKa-Ft9Cutrsk3IU="],"cm_z":"cG2dU24GKgKb1kLqJVpCIsVQzTDNCX-QaOlvg_nRahQ=","prk_3_poly_eval_zeta":"S31dAuqg1YEHcQgQkQidiK3Ki8-8fSbffWUq-Ttktxg=","prk_4_poly_eval_zeta":"23LXUF9nX2JRwWDWyPeQXfOdzOnx2Q_AKOGIJ30nrAY=","w_polys_eval_zeta":["0_8KQiOm9C_IZ3iTdEwxpx1LzHATIFco8T1zTu-meQY=","y_yoKBzaMuHvQ92g1Mj2H4vCcD9aHVhQcwfyNXG-6RM=","4uf0ih9NfmYOddGUFfeCYj4ss4x07rPDQGTnh8rjeiA=","68418PVR7B0jaIX2n15i7fybin7JDst9FfXNXSVLFRI=","yCQ4OwSd5L_t0ljfk944AYXSmmzwlzMZM0Dt2pREpQ0="],"w_polys_eval_zeta_omega":["Beim9eUFdxsOkUZwJqsmlqnuYjBUSeW4d2Vx8UrdwgQ=","IPF3hm0NPOB_a-d_G0YSEFrJNB53c0LmI363ag3zlhI=","bs0UGojiCtIO-CSSdP_2s7tq-glA_W4mOSO1CZlgjCc="],"z_eval_zeta_omega":"oMa1qNokFg7O4gyRwtrI5fNj916uXOKLrZ470OtC6ws=","s_polys_eval_zeta":["i2TNW_wmV68qlnwgPliA2HQfDWPZPhm8l_zs41RxmBA=","SxQ9noXbmn8j-Cr18rSanKJcA_rngNY84-uLTsGNvCY=","lPpCMH1I-2IE1JWJItFKZizbu39r3AMw8UIFsM4hDBc=","HU4iX9ls4BtlreiJ3j0cFl4htvzDIqEXFO8XC_A8OAI="],"opening_witness_zeta":"t5wi75r5rlmNyiXb5z_keuQUqMLEG77OVibZ4CgZayw=","opening_witness_zeta_omega":"4PYBjq4tlACTXPY_6nabcvs7tV4yHxlupO0wCQJh65E="},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"-MCqEnFS6_e5csiE852yvrT0dXMTLKSSJ3RC2qMlHAk=","randomizers":["B0yZtCLrkc_tYVXuJz5bmSwas_HRYwNVTDeNWSIkbROA","_qiO3w520iM_rtXtMlbsHvNIdF57YcHQPi-oE8ycu0yA","S0B6J9r9_m0illRQ1sne85jAOeC2Q0UKbaqWWEMCoD2A"],"response_scalars":[["DT-41hHInsLMtaVA2GzutjSgcOP4bD5UI3dN05hOgic=","0KUR_K5qf7Hu9SHSrpyMgp8XyFPswWvfjgQb71bTXyA="],["QJEF71wxLt56xpIstEUlr-7OkQtL0tB1ZP10nS5_SkI=","ZmedP5VvKLc_udkK2rR_Kbt3JwKT_WNGPTuHAnvfUwI="],["XDmZqI3LxcQFUX8lKPR4kMU3URCoM2BfCnsr-ju3Ow0=","j_38xmtmBfwNvpvGXr9d33HYLCjBNN_HPIQt1MjvBCM="]]},"scalar_mul_commitments":["fVlT9v1hw4vTR3REpOECI9S-KxHr-Te45u4zSyIRbRUA","FGzeNj2pQbSf9po4usb1sYt9hnmNx7JNRIRQv3SVPQgA","H1vXGgko2UySKumGJtObdWc9E8W-zb8MtQZfzQ1RUhAA"],"scalar_mul_proof":"D0U9gkZ3SDH7j3o5eE5JlwU2BaUUVtsasKT-nA1kjW2AKEX7ULFk2ZvMGfz_gn0v4IERQiEPQq9KthjBJHWFOnQADJQHtMqDpcmEJBJXgCMGsZzuVMxrJ62T6twpbxj0qV-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABACUe5EeuvqJ8GDB53nO7-7MAV55TWZxUHE6Bd9bDXcmoAQHBXhQ_y831Uim2WD6LIfqdupQL_6As5cI9fT47LEWGAg_JUSUkBbbX70js559ouXu6K-jgTeYlEM7U-hkBt-WcAeReZ3ADGf_XQOwnvSqDgfFDQpcC4sBKHD_DewD6BYT8AWgmbTnR-GzUDTAEwPcSvXCDx7rv8lvLEwVzRoek7rjAADQ524_I-gGPjVTZaCvqSCMAgV4-cPEfmZrJ3FoDfsQqSwPfH-w-jguP7yKREVGGJJYJeEwDznmwEry8jzLwxWIHvttVvtusqYa4QMkx0f_RSjEq7WJr3KDBI7Xu-K84ICwAAAAAAAACC2CBVP44nmcqya5uR1Z0SnDj11T-bNk256Mili0wDGwCu_Sns2ELGC4jVTTdyoKC7OEYvY28pBCtcB3mj2pKIHoBouUed-D47J5HYixNyIX0RqTGhGPCGuGC1SK0Lvu2sLYBVV03jcSWqdnBO9R5PXBF9pLKps1DtWvZ8Sbj9Li6mCACBKfawbLEnYyFglErIhx36Z_g1hQogNAEJDQ-BzjDmYICMZkFgxRTuZwF5Ay3m0PaFUU6KUCrdDGwNT9ySmoBmWQAX2xOArsZqUI4KSSdS6qJLQ-Xo_RROkbGj7MqjzhKMTAC9XxrusvzNlqex3RgIV3RXgCoxyfKjWwKbY6RMWfe_dAD75xKKQlwiAaq7UEL4gsgxDahrKzRaYRnXzLWspG4XQICOM1jd6o1meTeCgzcZC6WflDjBpd5brBmisG-xVS2bToAKirVrUC8QfxiRdlWrRquehQhhbgl5_S6XyV9EmdU3EIALAAAAAAAAAL5IQmJLiECy1Gyq50Q6TK3VBjUVvD6ZWUK7GZ0PU_MwAB8Z8ye1PZ-AWGcUZxcybHLThsNamyq4y5MtZZ4IX6s6gPhnj84JToaUtsPpEA0Gy5Qh4AdgrD2KFNhW3kHIwgVZAF889hOXf5Tgaa11nCqrz3IYd9qPjdn6noordClNy2lPgPdV1Cab3ipI106IDYhXeW7XA8Rsj5fmERGoYWOyj6BZALBraj9xkPIIfyIiBsSYwoAxRDwSQV_kxYso1eSo6r8lgHduv-ePAAh1ShtItRZ06F-7F4Gl0Vn87D5yYWE0xL13AAf_Ri0MZvPk4Nt-ey261QzmML-3nzWcX5vhUb5Vl_RDgFNfCu4Z-XK5F94lKZ2lT8NuUDlgrVAyzrCph6aL7yJ6ABQoLHiu8fIXRuOz47LJ6BuGHWh07hFks9V8BZWU-EBHgPUXUogLFEdd7tcust3syBAvPIH0w_1Vjki5Zhb5Aro1AM8is2UIixQ4uHezlXzWEQYwOFG8NJUVnlxi_kBDGfxQCfjqzmE8tRVQ3YgacNmBDrs3qCzF_3TNTaWGO_27xiY="}}}
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
        {"commitment":"-5mvcWITozP3gLFs4a5DjTX7NawZ6bMeChltCRyoTRo="}
        "##;

        let sender = &[
            1, 30, 190, 34, 254, 141, 16, 179, 123, 55, 68, 109, 232, 108, 154, 97, 101, 182, 109,
            179, 0, 131, 35, 40, 179, 195, 65, 66, 65, 223, 190, 36, 182, 1, 3, 41, 173, 126, 10,
            61, 121, 55, 23, 93, 70, 198, 131, 91, 249, 37, 7, 84, 71, 219, 120, 3, 240, 31, 200,
            68, 238, 128, 157, 156, 24, 214, 50,
        ];

        let memo = r##"
"wml1URQr4AYRVXNJudTs_GTqQDgU-Icw7O_IzeuRlVkAbeKu9yD0g2R6GpgLE8zF6-o3u_AkJWlvNZWJQhjwOvtwXCBsz2r0mOzqpeUdh9NhD5Eq-JWS2qKJWG7WYfwrW0Ok-9PFtzLzX-sjH7a5Yt8cAnz5ZaRyhw=="
        "##;

        let abar: AnonAssetRecord = serde_json::from_str(&abar).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: AxfrOwnerMemo = serde_json::from_str(&memo).unwrap();
        abar_to_bar(&abar, &sender, memo);
    }

    #[test]
    fn abar_to_bar_ed25519_test1() {
        let abar = r##"
        {"commitment":"qDN6gYSzye-7Rb3sZrnTGsWet7crIkrME_PfAjXIgS4="}
        "##;

        let sender = &[
            0, 236, 142, 200, 127, 43, 56, 35, 249, 239, 83, 40, 77, 219, 65, 85, 118, 44, 131,
            115, 255, 175, 98, 106, 126, 227, 68, 97, 89, 246, 226, 165, 124, 61, 64, 55, 90, 30,
            209, 100, 189, 175, 140, 189, 172, 40, 133, 206, 28, 42, 238, 249, 62, 188, 122, 73,
            224, 219, 197, 193, 129, 191, 181, 10, 174,
        ];

        let memo = r##"
        "8M4V4-27NUOE_cwqu-FVM1GrasNTRXC2PcAxICwcJaquis7-IrO06FIXKSQ9w1a_1JJmkZKphpXaULEiLGx91nryKVAVaxBQQDFWmsdIHdy88hiUy7n4V_aTx6s-2j37yPA-fJbE_wJlo2rJ1uWgVP-bYDNmtabd"
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
        {"body":{"input":"S9qpIeOPOthfECa9Mj8pSKwCYg53kZ5YdH4BNJUTvwA=","output":{"amount":{"Confidential":["hgGmh7oBJWMcBGH-63aTPdXGi8QUcb1Z2ovGzi8K4hc=","RiSpgZQeASaHsfBM5TVbPKavWyya2yvAmsDwhE6IZiQ="]},"asset_type":{"Confidential":"WrR6BN6qw_D1lqupYYRGf7ofCnsYydsqu1bcUPATHkY="},"public_key":"AQNbmdYikgH3PGKz4rjW0MkQhcviNhMBZblFdJYrlhDuVw=="},"delegated_schnorr_proof":{"inspection_comm":"PH1yJMq_KTvJeVykhupaxqSKKywKJIL2lIsUMFL6rQw=","randomizers":["Ar0RyYxoegkFpKBnmNsZ1OihbFXwDtfZ_xjTOmv92m8=","gCSWs_rtlOcJDbvzmZg3Fh0Ciitqd_1xg4P9zj3VTzg="],"response_scalars":[["_sR0iu2pACw6vtsCexxUfInE5Or7McDxu4a3B3FraAo=","fzp1ndnrAaK8bBzPMMwUTrlx7FHVeKABdIWyXQeFPw0="],["-4GtVo6nOyEXFq1SRb3ouXnNl7jWCqOmCNkM7QP7Bws=","E2xv4tEDepq6yGGfoQbtna3arhn8Srmyg8LSUWK90w0="]]},"merkle_root":"ZDVsOhLRX1XyKn6ZGedvO3YIJMjw9vWtfEg_hSbAgQM=","merkle_root_version":1,"memo":{"key_type":"Secp256k1","blind_share_bytes":"tcZqloOLMGpDKJ3PKlL59Yo4yzLmGSioP8jLj3mEiaAA","lock_bytes":"AWXlqnRFNAQ-CMndWaHgDpya-Kxhip1T6wVPdwOXNlyA8QdsVOEQpYyPb_hCxMAzoFZrwhQ5a1eUz7Uc5BVI4zlloe0Xx8rm7ysBIzbfh4hWZsowwFPQcX8="}},"proof":{"cm_w_vec":["C9PQBC6fMRboIoCf9wDcjE2yq99s9RFwkz7vaSdrMyw=","PvgilXCSw-Vgw8xfAMxTpG5XR1r-k9CRzJi8Osxn2i0=","5E25VrjsBjjpeK0R4rODCrV0sm-9NV9K5BRNhBqo164=","JIRiDY1sznN0A2UqNjpdDozU8jZzlQpiySw3zMefJJY=","Np1-_Fe8oP-wXLX6Qi4lWrWX7ux3NquQe7GM1AsLKIc="],"cm_t_vec":["2nLOpib7pc-iqnom87uSmCapa0CeNohtd2CBszZ6Np8=","kFvL9TZotRqr8YbeYia28zp05T37o8yW8hLIViSZfI4=","zsX_OuyV3C-jXYa_pdYLH2WfQjAhS3BGQPYZ6QvhQwY=","_kf16SAJ0CaZ4CBYn6bAIg6MUy_8e4QYWLMqjiwbHJg=","9IdEru9ul2hstFSjHMvzgbK7BmZyz7nNiNlkn66AMQQ="],"cm_z":"PgADawsGgzGQXfbp2FW0ssxBobVyUCRplUqNVYAekak=","prk_3_poly_eval_zeta":"_WCuX_stw4zonAEkAdWixUW6DgRnL9DCuwLm4NFwHw8=","prk_4_poly_eval_zeta":"GPIi2gK3RnuW-hvWzDtNN15-XQ7RQLI5pqYWH8ffjg8=","w_polys_eval_zeta":["iXjzM4aAX54FfyevRBukEw-B4cIoAyXCxhEbJc-u0go=","rEaY-uiILGVUY-8KumYG7BS-j_ytMj-RCuPQJLtexxs=","vNSeqvW57tygzbgCMTMNwInAPygiKmbdsxGeUkYYaSU=","xqq-gjNzhHsXrLf4fofa4-66Jt2tf_9UeiubS1xX3gY=","DV_Dsq8IF499eM8v8WMdQr7GoxFtgrgRNMEP9cuUZg8="],"w_polys_eval_zeta_omega":["ZPBB8cghrSdjPJ8eE0KvdxzRceTlkQN8AGnibdC9kSU=","Hs2XtKxbSBUyRoWIaWPs7lVZTN78s3yMJb2Nm4c_fCU=","QQAp72RoIxrH1zZuAwPFI329dP47wLlytiqE_70d8wY="],"z_eval_zeta_omega":"IqKgwdIHQp_u3NmX2dMR6E6C6QrpGkP9uVqdsgKkBi4=","s_polys_eval_zeta":["VVxvdChUZ0yZJdUzZLRGuBELYN19MV0bFpTbFuPaVQk=","sr2YmrhgUhnp0I4kzE8XqlSOkZ9ovH-g3UkfqWxrpxA=","vZf3l6sHXo8by-XOEUvYkUuz4LL0qyi_3ZYlJuc0XBI=","R9BDmMg1OO-EAjdRoqoDCLM6r8dT27U2rWZz13KR_iU="],"opening_witness_zeta":"_0gYkJRphWtK9mA02aaEvXzpqxHulecEJ9KXeIPSzaY=","opening_witness_zeta_omega":"9r7l3RMCucibkseF4tRwxVgLFFxR3hwR1TzWOZb_IqY="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"1dJ5Gmt22muYfBmViLH9ZYZ002CmRRSuk5xswzC0Rww=","randomizers":["8jE2K_nPhfg5KLkbaoWF71M3P_K9W3FMAKKodNNrl-YA","i3ff1n1w-0Bj_Aia7H0tqPASXToY3PleiEZ89uMbm8CA","49znr-ZNsBLuTp4JbATwJPDxSUVbA69K3Gd8reAgsmUA"],"response_scalars":[["dxHUYChEad8HObW74W8llBZltSTd1Q-Y4EzLslj9pAw=","uq5k7T2F58f33aauDOo9WrVUfyqBMlWFOQ08EdarArk="],["isryKbbR7zbnz1G7ihJbsfM4gSHIcVak-FRO-p3APKI=","4SzTwctJ2eC-AB7jnK6xCPmoswfZyBfa-479QCNHpt8="],["fMKBxRLIkKEb7FQRwDM2Ravl-GkHH1HBiBDkTaRwFNQ=","-b4fAo68ioBBRBuBIzF8XiZS4cOzUwx1zP35XMNyy_o="]]},"scalar_mul_commitments":["U-OuEQ2WicXsHnNHFlRcRg5vI9URGeY32_c339LI68WA","GI51UczNN1NzGBO7AJVuuGPAg_dc5zrl0QVaH3hh9HKA","qZYZuZ1tO1zvrcusjsFTwSoI04wRVfcXComtLYT_86KA"],"scalar_mul_proof":"B7d6_XyUPIqOahYvKnTrZVLGbxprr8LUAjWh5-2JoPKAahC1oJ4TJvvJbmZTwQKufmMzu9UGFb-bpnamEJbq2hQApQZxfCwh4wCWnDo-pwvf5roPtMOVzLk9epc6tY2yGY8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA-r1K_fzpOA22Obg5JpMsOGo8LxuA-U29X93QFyGKau8ANYBZtFp1MB7Sec9_BVC6Kte-m6jciNy7A8T38lAuNq0AYgPYhZlpdloAjRvY1UlnePkXY7bxYuIY0Ups5wTESXEAXcPflSYY2ghdiLw_qUzLGKps4T0WWKL97al_5zq25_kAO4kxWK3k_07H3S2JjbasHG5lLdHkSSTkE2CTEPahfG2Ae0v09_d-rwVbBq_b9975SeG4pHlEk32qbOb5YgNymio83W9pvTEKMi_JTGQvoba602nrtNGmHXwuXl5Rw6DxdHXo-mphG11cV72DxHMOZjqUj6QtjUk8wqlsml903O5OCwAAAAAAAACdaH-HFYx1yw4wTetM_g3GVKwIW1FvUScyNOM2FSwn_4ACMoo8VjUmmTZypk3s1lM8bj-bXC-YjK2BdU30G7OZpYDSQF9wfVrnDjiOAJU1LGgk7VqrX2vGX1PXo3xMJC5dDYDcVcHj2qo3zmLRU8HvMPuYk6h-LCvvCE14jAvLOicRbwBkS2fLancmHIsjZIbw3CDv4zCH8OKI3Rr-gRUcIkrdOYAUIpzEBMyGf3eRDIht5aNrH1ETQRDMBQhc0vWb7B6rY4Bwgv_bF6ZHeIz6taPxW1XvcLpAo3HCAjCQ8yhAFWw9bwDpkes8rnvShsGeFDWEtenwLkZVp4PSv87V2USKxns2rID02m5oF-X__pozNHSK0x_J7XQ6zL7xVD-2QEUE8cG2XgD8YuW9qNbJkPbE1EsfbRbXW2_vrzcYnrt9niBPrCOQHgAuc17qRxaX6oJBfwEzle0dOLBnniBRG2eAS-XBQdFVZgALAAAAAAAAAAdXqyz3zw8UYMHrou2p34bsMfYBAdtjBt_J-nSjttd6AOmlcTKpTSo1779XcW-0XqrnQSlqXz20Y0NTPCSI8pnKgBKnYxjvR4lKz4ogiX8GHHdnhuu4kkhIzc3PDJLSQKXtgDGXFRjqe5et3D64GgPdTSVAVsaXVhyC88p_1oLzj5zKgDn2RI5vwML-ofBHQ5o5-V_C-Z5640jhSVMTffpuOf4fACG_6lEOg9cyHIzZsSrK-eMitGdIBmTbO1T9uxekX3avAFQi3pFQszV77VTWdq6eKCUh1xReDEIl6GnNCgx20zlcgOaOrU5Ohag-yzQtZ6LetcrJbnviGtsd-T0VLoAUtkcrgEWzkC5Ozxwqy3UKVgXsbfFseeehkf2UROAjjl1qLciPgGZ5qC2oPOeQHn1SpjhCHjRV4BNNCnPbXVmCH68VHRfaAM95XV3o51RilxfJP1IvrFIVtNDLSxuUhXgd1IQ_3YJugD21IDwQilN8Bc6qbY9lKyoFKj0FdmQ-5txLZ-wmS9WpJ5E2MTsDlPkp1QJq0-GAiPlV5MgXuHcWM5NLtEC_4S4="}}}
        "##;

        let note: AbarToBarNote = serde_json::from_str(&note).unwrap();

        let address_format = match note.folding_instance {
            AXfrAddressFoldingInstance::Secp256k1(_) => SECP256K1,
            AXfrAddressFoldingInstance::Ed25519(_) => ED25519,
        };

        let verify_params = VerifierParams::get_abar_to_bar(address_format).unwrap();
        let hash = random_hasher([
            129, 9, 199, 199, 195, 61, 168, 138, 50, 167, 237, 14, 26, 191, 15, 75, 230, 173, 197,
            235, 124, 64, 230, 4, 208, 115, 171, 33, 82, 89, 99, 176,
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
        {"body":{"input":"dMO_TttNyHzdrU341ln8SrrAfoMTjoUn1TTkj2m-zh0=","output":{"amount":{"Confidential":["VoVT1_xpcPy2nYK1EUbzt0k-9p6vqALijm1ieRjBpxo=","8jCJg_zkbfceHo16Inw2SJQv_kAoVJR0VF2P11gY_yU="]},"asset_type":{"Confidential":"0trcXtbq-0qxnxDe_sz7PStWdRu9spu8PYKuqoxc6mY="},"public_key":"RUmsx9o_1S1yRx1rJ1Sae4d5SEKrY0R18hiU2HVIiUE="},"delegated_schnorr_proof":{"inspection_comm":"mg2NkMkO7fi0UR2cMN4-WVoZMd-URpEVFeGJaPCTmRo=","randomizers":["VCaQI4vX0yoIYLNBhjEOGJe6VQbONBAABYc0lR0N5AQ=","AkaH_eoMZlOSkZJx91pVNZq6rDIVwQmQPKf3rR3Ap2o="],"response_scalars":[["M5SDZpEy4PFWSupZ0tGbjUubIjDg9b1dT-UPN-3gPgY=","X0_C1_PvVhTddK0jcgtcqV-HwJBw2RlyIOxEBkO3pQo="],["Ew-3f2gWNiLbrx2Buvmb0kvc8mIZHJL94dtiYv4bzQQ=","G7cBOB0YKAyTTbEuqqSkQ1K211lhB2pyPkhUj9XfNwU="]]},"merkle_root":"3QsqCGTUxjMfiw1vHqimNvbng9lK06xg-up405oTNwM=","merkle_root_version":1,"memo":{"key_type":"Ed25519","blind_share_bytes":"1UXL7u3IehPQXZpLesz441yoQ1ES77s2-zLcADs882Y=","lock_bytes":"RbiY9f1-LLT_gkZ9CTOYbB6JiCV5Kulj2NjCk1VdTyBWnhwAxqrPOHE4USr15UYtIz0P4ceM2QA_Qws4fCARj0LT18GeI9Vm"}},"proof":{"cm_w_vec":["KvcfDOTKO0UtsiCqnc-snk2iQDNjRkpxp-7ISPQS05s=","HM3iiHu-nle0I0SS7ONdXO9kD0K_XtCO3iX0yRQBlJE=","f9exo-JSlZdOf5p4P40dgSCoNDkwPCarV2pVZqEMypA=","CvILV7l6hMj7sI_hZsd4CPgiGu-pQragwBLw1lKH8qw=","Dvc-pqkGMph_mAVIlroXv_vvr91BkmsgDF610uh6Rpg="],"cm_t_vec":["dMZW22rc0ebMwQ4KT5yiv6L2u2am-qAIvGRtY3KKm60=","8jvB8mapKa7EriCdx4Ivn6YbCZ9-JZs-7UA0EL-q6wo=","t8XUBA3VnquID0_mLR8m8FqZB4z5cnoMbVS7nLBnXJs=","iYEHXRz_yby9wv-NispE6eAXEsko12Ax8jeGZCTknS4=","GA67UGGliHiMmk270NYg97A5S3x_UvNDWQzWZcj2mhM="],"cm_z":"NJeTvjVHbBL85uhxX4wYv5DdYmy91xStE1psO-vSBgk=","prk_3_poly_eval_zeta":"JfcYzZzk3HgI2v_NEfklCVv31L_yk9oO6ubdXV1OdgI=","prk_4_poly_eval_zeta":"W7kVmo92GrQ3wIOa6aS5NYx-kaO8MV7raxBFBTvUGiU=","w_polys_eval_zeta":["VeHqFhK1LFap5lIveUBXUPdZHpGBX-RXbMjS1QSirwo=","cZjrqnF27PCAObSND8Iov-OPXH2e8kHcrQ76l0agVxo=","kviFJTCjDVo4tl_Z21-uwlGqqTWnAIFcOy9WtUQxdCU=","I1ltUOgMi1zu0kbFYc0tGNolF04StsgQp_tBnO4SMyA=","SMkt1gBs8AEEZ2iPvWCfSUuhl_PfeFYVIjGMzaysEgg="],"w_polys_eval_zeta_omega":["mvZzmxBNKfAMd2IX0L_x5CqR5p4mQOo3246dPgUb6i8=","7UPHjGjAEPHVJGyOjuPUc_5vXL4n_1WxKrKMcBy8Gx4=","74hWmWP7o2AY3_UiBp2qunc1_SkAr1lMNuZ4feFS9Bk="],"z_eval_zeta_omega":"3YArX7Sbogx2gTevsoRBm_58lGqpo4ggUC0NU9SjgQU=","s_polys_eval_zeta":["MCQYjpJIvO5pKDgSzzdEcPPjzAW0X9lnDZvrhyTF7Q4=","tzkA1PIZRBNVOPyjykp5sbg7DeMI0R7J9SLPKgpR4hk=","379zsYs6h2AoCmdVQycngxrn9copXxIZ8_mLASkGDwU=","U1b2VoWWZ0U7GglUiTLBsIy_cHv3x01R1wLWc_3W1So="],"opening_witness_zeta":"GIVN0b53o9Vkq5CSBfPd7OUPPUb_AFntFYqDT0ucjBw=","opening_witness_zeta_omega":"z9WKizSrPd1XFotrgC5fhIspkAdalEHfhLrEgUZrPio="},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"hUgUcN_1UbwE1TFG4hisFFQ-SJrifcoTxpyErP_A0xE=","randomizers":["ti1fIrjYjKEnFT19WqlWRINtyYKr1rvF1floKzgC7m2A","phkm0vGCWe_vg59tX7ssTZmkbSI0EXTZVeI-qSLv3A0A","WCYlU2Zcy0GL0miSL-K94I2-Aw2ZGKDUZCgUNL8qcGKA"],"response_scalars":[["sSrI2Q1bXUG9ILcmTDc3udn_R05tsk1GhMyREQe5IkM=","4Ru8y8nn3X6WOQYTRd700ykUMFeYbw271IAmyPNkl00="],["BMNw6Mf7F0xCX0dIadLKZEfBlmqHanLgTys3Ak9VYgA=","MobtBewVxZ9Lff0RGQmqhm45SPanHwBAlTfWV6bDzDU="],["4N9XAHaVHHlWCx4qFH6Kro3RmodtoMUEyzXoK1yWkls=","Qb7KPbBNt_jdIt-85lR_dDfniLiA1XanUwJFv0JgvyQ="]]},"scalar_mul_commitments":["bV5RYjwrsJeq28rrtqBCIxex6W-0jdf5riEWz1uu4TAA","WuYk1xKVucUZiRrc6KZE-VnxkTfO9LvFC3EfNE96iQ8A","1mPPl36vha1a16DkOlfwgJKctAr_bhYHkXm5baONng2A"],"scalar_mul_proof":"Y5ROfCnrVuXFxN6EpKV0DoNoXGToxbPwONKvORjovm4AVz2ftPs5EUrnRTls_gNmwjNc4nc_2MZZgK8LGyWkt3MAHSlO5T9hmOoLY_4mSDIqX1M0JMNgXNBfXkbGaZPX0EeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAofvFbQe-gVr9r4iqScfwJxsc9Ayo9QLo7ZcqyNkcKA-APXOdAw1TxWC6wD0biKNn0Ty7HQ0HFS2dINR3zL-d2mOAQy9uF-QJPC_fCTQd6J7ujH639QKPowURsXVn0bnXyXKAntxKvlulcEpgqoCEJvMkk_tdGh7mXpskXp11jFwbb3iAA2NeTA34PfRzqm4nZQ1q1ALT2mjaWxK7Q95x3K6yb2GAlp_n7uA1Kbsta7gFujjtnjKi1eIeebIh4O0gmxRgs3V0tAAvGKzdvER2z9BPaVBsTNlZEYqNenSpBaW8O0b1Vo8l1SCHLs7P3BALODwrh8ul0hHnucWvX1dxvLTrXLhACwAAAAAAAACr3UP2iu9ZJ0QkWU3_TURn6gj2jAAUBmlD5iMXdxyAMoAgCQ3r9WcavcUC9IK5Ro734o7isxvW7BTCf39R-QmpWYCbS1oAvQXXZ3NOmuZL651kt0Gt-fMi_doPEH_1RDP7LYAuVUsd393jkSWi1jos1Jzh9nN8B0ZWQcSoQ-cIWZh0AICrcKmNhPx3MeTGgHC46lhC3xBd47XBh3NtFY_LFhRUDgBsXs5-ZsnlSUcm3Rl4I90TjeUc8R0wxLSyNbJwOv2ie4A6XJH3UxY_Y8nE6vDus57SetjGA8v8NT9dA64mbD1BKQC14fUqyuC5C8cJYqmqSTwTMvvr_q8MHPKCoZfk6eIHJYBcYQdgvg35XEYltkqZfdxKSOTCMjoyUXyUI8SQcuhKVIBnQKTp3c7KLeUFIvzCLZg2DLB1C1uFOz6sfuRs_22ABYA10hlj4FTFKW-1BVtTb_jUIqtmB5RRcWLdz_Da93qrfQALAAAAAAAAACW30HOafcLtauYke6tmvI0gt4316jmdY9U5yJKzRGAqALBlTLmfI7643amtYQG4yqXXJfYlgSG5R6xg6tl_SmkLgK_ZK4CLW3Vr-Nrtehl1Ovf0rvsC1W4cdrWAohOU659xgM-epQGoHOaZ2AncnHIAHAXwBaXpEabEVykbEs2EXfpJAELEoml--BcqEDTKYNO4y3rfhuL5OJtqswMZ1E4nOyBigCkgEFP190_cj3nqYelz23-6ug_eqixHcyBCwOX91ethAH67FQQuXLZhI_KD7l3Ut2-Bu6Af4WQIlufsTlDV2Ew7ABDYqn2B0g5E6ZbUbvuN4osmLHYUC8XJxz3hlNDcEmpNAJbqUuROYlBz5ES2_Cs9Mo5axkivaClMrp7kYwIjytFNAG0uQcMN7EXMy2rQTEU_qZU23_oU314FNV1itqTniftegMfueJQRyjluygYqKJspXRfsnDOZNEnJxwrTDZIQiLMqAMzT5252QOzjDpEAOdmamVaO4arvk561ppidT6s8H0I4KihloqjXcr17w1P_Ubu76TM5XqDtatBX_QRKoOm_qFI="}}}
        "##;

        let note: AbarToBarNote = serde_json::from_str(&note).unwrap();

        let address_format = match note.folding_instance {
            AXfrAddressFoldingInstance::Secp256k1(_) => SECP256K1,
            AXfrAddressFoldingInstance::Ed25519(_) => ED25519,
        };

        let verify_params = VerifierParams::get_abar_to_bar(address_format).unwrap();
        let hash = random_hasher([
            129, 9, 199, 199, 195, 61, 168, 138, 50, 167, 237, 14, 26, 191, 15, 75, 230, 173, 197,
            235, 124, 64, 230, 4, 208, 115, 171, 33, 82, 89, 99, 176,
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
        [{"commitment":"DufEDEkqkJNf9pcaPqirZKpZX4bvokkuOb7LDbj8bBk="}]
        "##;

        let sender = &[
            0, 91, 79, 149, 66, 255, 163, 41, 44, 56, 250, 227, 220, 171, 167, 201, 161, 157, 236,
            112, 210, 238, 214, 115, 39, 215, 192, 200, 205, 121, 53, 234, 57, 8, 98, 184, 186, 90,
            184, 62, 164, 72, 108, 223, 113, 196, 248, 179, 187, 157, 164, 197, 1, 223, 111, 85,
            180, 230, 103, 160, 28, 198, 33, 74, 78,
        ];

        let memos = r##"
        [
            "6ON5LfX0Z7bYen1rD0EAvpuVOCbUm0eDshU4rcZ8JcP4C10OCNgByJ7L_wy4eMT-nzlwBAkdblgBAkQ4aWgGVHZFPxjTBe8sznaDnwlk3NUFNDF9xDMMTYvSCj18j3l8EVO8JVPaycMEvP0SQDbWrEQsWAxDZes1"
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
        [{"commitment":"TRBshWwloMunQJdI3WaCo2rq-0L2U8SEQzweFsEpBSA="},
        {"commitment":"Q1MQqPxMqRxNk1Fs1CB6hEUm-TinCHXXw9rCl390pwI="},
        {"commitment":"4Nnb2farrcPRGUeRZ6LtlddfkEDuXyMJY0pZVLI_fw8="},
        {"commitment":"esARc3NiGmceCFaXeul31Gvfgc0zqNxnyuFPqKswbi4="},
        {"commitment":"NBG6sDxVJ9lP-raJ4716E-FdY4Qis3zWwkqvSW-K1i0="},
        {"commitment":"Yu9jDrXar3tb7vll2YwYdFEvLkRB5jPu_3NViCNQqSw="}]
        "##;

        let sender = &[
            0, 210, 172, 0, 197, 159, 58, 237, 250, 249, 13, 222, 195, 179, 250, 254, 59, 165, 97,
            22, 211, 68, 100, 126, 83, 105, 88, 113, 62, 37, 234, 137, 174, 1, 105, 246, 38, 88,
            148, 145, 131, 208, 16, 75, 52, 236, 20, 13, 97, 84, 243, 144, 131, 139, 68, 92, 43,
            145, 210, 141, 186, 175, 218, 132, 255,
        ];

        let memos = r##"
          [
            "aTfrjCGd7KFdfJmmGvr_6KZDVxTJtSCjNHLJK4d2EiE74DfNs4RVa2xDF8RTIp8zhog0m2G4HaAYDeLMU2WfYWnrzVPkZJXL1cMh7CNw1VDkDZQ_L4Lhl3bLc7GTAgFtALtzcn1RimUXxgnE0LbOUwriowaqg-SK",
            "tAejMhJfFbVbP4fAe51L0cxyom8ZUAtZk5kucu9YpkR0k0-IrBwfb-rDnyL8BlLZRtPvUGf-YhWHWuEfnWzyiocCrOrWoCDUO7dIuOD9btTNXU-a3JaAnW3mmbhqIptirbFv0Vc-HspBSBWpzZ8HwCqxSKlCJtaC",
            "W2G8-fwNqHsGcNVQ7Bwd757TgnXFDyVNNrUj-CkFxynbxlv6p2w5yrkbrv-NAScj7ZUUjg84JkS-yGX_4xyq2SF3mREpOdyWy5jwUmpqLZJSCbeLY2efqqFFDBWgiH_BY3xpHm88DyAN47TpXiylcliw4CUdr0Wg",
            "1rkwzr0L_QrK4kaziRZ4zO7pWOf8hTNxNBJKVXErYWMHxJ2xfEGbxTJCxuiZgTtRgMkZSu4GA8p5bd0nWS2K9kkMptZwPVTLZYpkVGpklxUxZHzgRjyMgE0nIt3c2l7EgRCu9vC6Fysk3mrpk01aRbDhxQQ2bQVY",
            "TbiEwJBv_d8KewuNRs4wqRzOAtR8RLJXw_ZqFr9SsMUlBn9cW3PJzLw1qFJIDJrIJr2FXpQmT5GrYlxtkm4gckF5Rw-NeLTeoYs6Z-JN0gLbMToZ-GCnIJ96TXkIHHXF4EJBvOnPEHr-Q6ytsPkDKrDoQsFBvDMx",
            "RD5aZ90bVNkuLhihJlnRZEn1XM9ystI0vpfbMCwLs6YR8unkCQlStoka9IwB1Qg4O8OOMqJDg1zc3p_SKAGfSp2f4S9wNfbpNjvB_RBrPNywIPw8NR65WpXnqUWPTzNQWIzFSZVmIIhqQBbyzDEFBa_4mMrdzHy_"
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
        {"body":{"inputs":["5uwoVnZyk4p7vxY-YhPwia8TO9V19RFFlDxZdF4kbh8=","9HpQ7DwDZtRAxUzjR0xngyR5JCoLy9ZS-zVa1HZhGQE=","6hy-iYizwSNSZdFEOw6dlvIwPldsO1M4LY_ctIhDECQ=","sE66sXrcDd87Aehy7x0OdbDGu3mr6rItQ1Oo4AE9yws=","24wOfsiSXJ0EGD19reyAlNQqASqlr9s7axcRjNHnpxw=","9VXxPWYqB0tM3yq4emrQEqx5kl1n7kKitl6blUJATxg="],"outputs":[{"commitment":"pl8PX6LdmnzlEbtpAbE4kqWTdAUbIEW00dIZffZIzho="},{"commitment":"vJuHYKMC1dtEnuIFUhhSS2yFijIMfKUOkOqib1UA4gg="},{"commitment":"PzQxF-ofKTCDRpEURE-nFIDyVk41QYtyaquiE98TDhQ="},{"commitment":"j5ikUeXUOy3D0F-K82wpBfSK_NnheHze8hMnWbhi_hU="},{"commitment":"ODX3X3bV0A6fItGGUK5LWbl3-Ru2BIa8VBV5AezRixE="},{"commitment":"wRMvbklmHL92gV1I_UEutH1PYVoGmPfzg9i5ckh_KBA="}],"merkle_root":"vQj1XFnjadD0692EQQN5ded4Hv1s20JVninAgJgJYQE=","merkle_root_version":1,"fee":23,"owner_memos":["4xyrIa0ngCry78PBd0K24OwLNkPwNithNniXi0skWoNnubqZ-SQyQtQ66rJ0X2m-IrB9Je5vEcS4fqYD1lGO3NTxawzigPWNC_VNSz1lQGk4ElMZEssAr6ChBQYBaOE5Z_t9YuHziQR06jwDl914kkgSoOgej8NC","pdwsmjsXCYBL3C4c_VbBGdQDzkN_eZlATEtqZqLIC8kAtazitNy2jg1xmX5JnAun2A6hofhRU0-rDy56dVDWFbC3vLTIbYO6h2zTjKX8ZMkufJYUC91MTT8A6wQKjL9wuci9UWaDinaIc1FETWkgFEtIiMbggyPPbg==","YNs0oVFf89z9XSrR8PHPGJiQoMeudnLo5TVrLIFwv92AKnFaoRCu6Sczyrxn4rsePJIsByAUAXhtwvR1RbbKwqzLoIEgvSuCgj4Jh4fr6ONYivSS7HzyHjq_BS65FE0lOCNKKfCgi1IZjIaJsOqB7uNSVy6_bXr4Hw==","Wv5yCAK5OsJ0xK_AyVSH9x0dpqK_XGJyj1hGh1mqMzwK1yQIB3fPNIyZy41Yp-klevCwnmU6PeKTB8Y0loJLTVtRooTQr6ouzeQvqHOzTSm8oVPr5yANGaBXR_vcvQohYOf4uNjXA-kkBz2tLP4bqCKthIJKu4BU","bpmbJmY1Xe05FEAynMzP3USDDy3J0qF_CNMczVNY6JUx-jY6MMJJDnzPRU7y5HqvCrfQj4Y2_HRw-nN4LcIZK_bwv8Oz0VBTWr22afYYQ1Dxj7qe1rhh8maMYSKAsg9XT4BB_JXmKblIsHuIfyS8FTUoEz7VR9xZ","BXL5vEeOeYCH1-qygFxFQM0PhRARJp6t3yQKPmkY5fMA3_lrfhcsM7l0vuza4gqGha8p73GoZWxBRXLb8TMuHYZcOrwQrnaCs2OtmTYpsSclVF1AKQScq6l1YtBhJ2Tv7HIli7fVLB08JONsvbBxtef4De60xjFPbA=="]},"proof":{"cm_w_vec":["Vd4C257vdK0T7wuxGIU_RuK5rjvPYobOZvOT5W8SC4w=","jt-F2PJ7cdTdDP9rK64UxA7Oi0edQJcib2hAVBLhzCM=","VYgl2S6qI1Li6eOVX4qomCHxa6HKRlnOBDC7cjOXkIk=","9k-HbbtWTny0tiEOOsJ4Eu4AJkXTd2SAFGSL5MW3SgA=","lA_reWun_QtxDKejyxzacm3Mul5KztIwZt7q7Ae7bYE="],"cm_t_vec":["wkTKU2p5kiZUX27DTLPBicenNJmz_vrTlv508SzlSCw=","nz2k8u_ghq2-_xRkSsJq8vBHpU2F2vW_yVZC--DuwwA=","8kooe0R5q5uzM-32XpEeVwAta3Q3_wSGJYdKeW49JAk=","ii9023949aW9dg-8lkaxUPrHdWXaMtiKmJ-zzOjgLBE=","gFD2FB3RE9Hk0Cj941Go4G76GDbdldsONh9SES5IjxM="],"cm_z":"t4SLX6fsq0RehOvkpaE02Pq2N0tTrxneXULcZhtSfJs=","prk_3_poly_eval_zeta":"butJJH3zvZp0UufbmY_WiHNFcN9By_nJhFhn7VbkmBc=","prk_4_poly_eval_zeta":"evCGpebXuzrLIFYvCFN10WyHlyyUGpC6SYK1X_ltNR0=","w_polys_eval_zeta":["qSj7TrDyvZJmMO8PSB65qBMFYtudjLtELtnIGVOPCCE=","w3kSC_T6D_ZLDJJK_43k9vTXeR_dZbEfvrISK1O2uQo=","39Fi8GTAel1yNPKAhjMx8IxJmtpFrILxzliwgvzwBAQ=","NnonXlNwVXPgl63Qph2pINDkxxJ7G1-Exu0BRMwDixw=","2-P0tSKuWTjkusyqH2EqNXtxPnwZI4jPmG51Orwt1iE="],"w_polys_eval_zeta_omega":["MSf-GvAaGmmIlh1wzD1xKsx8gihslC_0jGg9MF_R-yE=","b-0SWGzVjCcq3h-VEKzygZzogjEqBB12nFO5wddYgxQ=","Ae3eYz1LgYKXKLFgakT6Jt5ch5eF_LtXxwZRNb5unSE="],"z_eval_zeta_omega":"A5vh9m0yB4F2lPIk8S2d5dPjruCVYlw2XP1wPDN19CA=","s_polys_eval_zeta":["tSM3Ty_ir1pVYVMqUzgm_Lv5hhvnftJ0PwRgv1Codho=","c-iLSkz5wxinGZXXKebeWzXHZtluMlP3ai19wrXVHwE=","PXa2CqyqjJWxtknVxtmyWsf_luVFiIs5PAX91Z5tdy4=","ZwvdqG9yWRpSbtXXGrq1ldoyhnWaoxrEPOXge5Jx8SY="],"opening_witness_zeta":"a262pdPiJ8xkuMGuN9R__hC8MVxGLTyQeK9AfD3Dt5k=","opening_witness_zeta_omega":"-SSFYNErwzVNb7e50PPlVEi6j_PEsvBU9fXMpr-osQw="},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"-dt-letui0tVh-guCiS8b6-2ocz5LFy4nJMWE280yh8=","randomizers":["P-H93qrdLjyxoWmIgZ541MYFYCDZAeZvnws2RM5qjXmA","S4Ng8knditlXAVapUzgXHTspiaCZrvX7Ec5hzCAglFAA","46AUy4N5gvXFAQvCERheUASad9wb-N9ZPgUhG5nFuROA"],"response_scalars":[["WxKJa4Ef6VeIgYgRvRhJYkNVg_UD5NzUcdxECilSJW8=","tn5R3Fq3K9l2XCJHh3HtsLlD1hft_Jl4OtQJj15Lf3U="],["Pm4OhTLtqE8S7HMMX8TwRK2aTdbNP-ZMd_s7dItvVg0=","JXJL-aQSe7aIZ6269Wb0lENFuQ6t8L3NPZWBie7pmxM="],["-eS5awzkURhTSSEh6X0QxHArCk2bUzfY6tCM9kDsyxo=","gr5ADRjyhq3k-wEfPOCw3HwERemwxkWbg9IwLAV4w1s="]]},"scalar_mul_commitments":["W1E_dKepJjVIHFIdtHAWYyOqXRaHwqDeds3K5t4pHAiA","XRd7yCH1J2W-YUGF4DOQu3uGoI8tboQXsg9GQQOK4kCA","5d4CBeEX1Wo0DL5OShCHlXA_Jq2QG3e_RhEUrC5OLT6A"],"scalar_mul_proof":"B3tYtXmo8we2f0QONP_QcbD_o8KS2FcOyg9T6KidJWAATkZUUJ6DHJc6usaOC98R4HI_jO1ZW-UQoxY0-RG7-1MA5O-hmEYxcL5NIBM5CYUkCjTFpne9Ib53Oi2ar_jTKRGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA4TnqIKD-n7VF7aQXu6tI84zO3ygjLLVoTrequsucaG2AocxItQV-cu4GbGJ5-WfPk8qDabu0ZnqigIfxpLtX1WmAo_sT2z-ap-i_N-VGM-PIwYq3v8DBuDQ3-hisdPaB-ECAS4cObHe0ad7UMW00AYZHLHwCMiOImwYRb7twk7aZNGQAdGHygXlb3jGCDZu0ONlODk7fFH6UEmKO7lyWyBecZycAiw1fognieVIyGQth5yqrVpQXOcwCbLUVZP3O_08saipgsm6l91zl93lESlU_W-POGQAnDVyM-E6oBLak95uHVlEevNthJjITgmCVPTyLwAtccqDLyGjAhDdm3c0ToudcCwAAAAAAAAAe9NLUtvBk9Yna8v5OszBvzBhtQthqGahkzVIEYjWuM4BPMLd3gF45gGHDToXmYuYD92zWW3-zASfxKlSr5xVCVQBRTJzj7DfbZHYsYCCBwchAgGjzmAI_VmEWbH_r4JdFAgAjjt1GDBksAbBpR9KP-OG01ztEUnR1A4DQlMCVSxyFQQCbkBWwk3JxAQLElojeUGuN_2z1gjmp5MwY-nKzhAODcYA7bME2WvlyroXAsQ5ug41YsK8OSrtbjR7qMe5UiY9vIwCtp3vJdiBsW-Zgiy6AhQzIVFnm3mqz9jH1W_grBwJue4Dih-PlILkOnZf_5iVxNB4Ot7odULiOCiO2_XSc10vKawB6paF79H8zvvXoU43PP5KE7rlhdxVOgQTT1JU94VeUZ4BNov77wjqyChwzomBAJS_QowrYdx3igjKOwimtfdWUf4CseQa4frkN5owScTEWtjbQGWBvQumEIUCaNJ0u_XIEIAALAAAAAAAAALTXWYqEyQNftvUPRPtzleuTtqHzkTfgtQMhhDIm5aRkgNX7IXcdWFa3TUj6KQz6VGciomFxQY8sRhRTBHmaOOoOgNBIwPf44AWXMDxZcnu45epe2yMPm379Zt9uD1o4IyBXAOVHbiNJqDVP2NPC-mew_JNOeIbV4GXvJ9g6WAujhalCgBh_8St1OHQ6D7NgOs4MSDbFVsaJjGzmFoxD_ziR-0YUAKuMHRAEQcRY1JPCoNaCAqbMRMcNvxZ_Oy5fSr1oHsETAF78aYNzAsieYxvG409JP-SRTxfqWnJr4V4eEFgGWzkBADDb0utJe8mgNkb5LRvE-VIuKWqeU3Kvk5OV2k7RIEQngPcXQDV3pTyKG4GhY5yvjTGy_E1Qb2ASXiYhygmLcNxEgCbaLuvgqKTwQ6MUemYA5u7BZ67cXMz_Cvq5CnYgn-gzALy8I2EtJtDkpt46vrTTNGI7Y5UQ6H1zwvstxGLFFzhzgOntYn9LGpM7FshOgPkDxTGrH4nNSE7hd3X6v1r1D6lCoBHdPmzx4m-5vfBNUeV8TA5sUC5BHgBxRia4pYf5DVw="}}}
        "##;

        let note: AXfrNote = serde_json::from_str(&note).unwrap();

        let address_format = match note.folding_instance {
            AXfrAddressFoldingInstance::Secp256k1(_) => SECP256K1,
            AXfrAddressFoldingInstance::Ed25519(_) => ED25519,
        };

        let verifier_params = VerifierParams::load_abar_to_abar(6, 6, address_format).unwrap();
        let hash = random_hasher([
            129, 9, 199, 199, 195, 61, 168, 138, 50, 167, 237, 14, 26, 191, 15, 75, 230, 173, 197,
            235, 124, 64, 230, 4, 208, 115, 171, 33, 82, 89, 99, 176,
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
