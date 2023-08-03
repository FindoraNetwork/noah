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
     {"body":{"input":{"amount":{"Confidential":["kpyetyax6wVuc04blchEI31NqZ8_DeCK0vJVpN1AnUk=","oC6sE-8vO_hKizYXyhNN6Ea87kFQYMWq2u1tGlyMFC8="]},"asset_type":{"Confidential":"4HpWEbCl-zJ_3ikchArmBaAx01AdZ2A7-vdZ3TAiU3I="},"public_key":"AQP5982EAiMjTTtSKtpRKK0fgHoWowemrTx0EV35pqun6A=="},"output":{"commitment":"gbXKq6IHEAemi_puRgfLqndK8Zq88MhLUnMvD-BgOBY="},"proof":[{"inspection_comm":"ag1hY-XedWwsb1szFBNnSFQlPLX6l6QjqYjd_nHw3S0=","randomizers":["wFl_A2k5XGiIS-jQNTKeZ0_X-gQCxFaaYg_O3KLh40k=","MlF0nUTQEUbeI97a1lrLeukBnQKM2aYsok8BMHDsvQA="],"response_scalars":[["V5Tl3po0IVJlFJls41QTHXBoEeir5fMNGI5gteQ4uQ8=","TBu81XJ2N4PEoi8p4aNehBE3rtYjjK9q0Akjnsapfws="],["3n5GtzeIPYeb5-g0ksP_tXu0QY-w7GLvQXFEFR0S6Qw=","XBvSVU01mS-cuw_o0ZGdTBJW6DgNUrWQG4NuXSuXtQI="]]},{"cm_w_vec":["77BSZ8sLE5VpSnUA41ZqDRfSsbh6EJahZdGusjUILxo=","aeIeTbF_DJMDGEjF9TWTQy7TsOODSc87TWgZhj9uP6Q=","ah0522266BTq7Pxrrl0pkpsPxze7l0lE2Tvy0JOEcpU=","YC7BYBLNqFqaSoKWwOvwyW-RghO2Xw8Y-bEj2Bw47Bw=","r-0a9DM_hgRAsXYkuRO8xsFS7XGTFJfyIEFQcguFYZ0="],"cm_t_vec":["pZW4wasMyLeSLZeRUeysGHDeJ2DrdeopmEKr8I1-NoI=","DEvhbYP71p9SkzoXQ_2772WcRIU0XsAR4P2uBLZzIQ8=","81LjSSp96QbsJy-IbJ_17PPQoHMr7Esx2wvMviCQNyw=","XqzM7EFJp2oAqIIV1wY6VAnY89Rv5OQkytRPlmZiCyk=","yugvsK8iEfOI70t04e0sVUpa7wkPg6Kq5Rcxi89eWgE="],"cm_z":"YXveED8MoKuUwQzp3DlU4yioyrX0hzhIYnibZZ5q3q8=","prk_3_poly_eval_zeta":"mw7P25XpmCXD_DBW5aWlAizsuW-lVZRQbzkQ2MYOyB4=","prk_4_poly_eval_zeta":"-i10UXEk_tmpd3FsQvLrIf-Tv74vU8tpJ1-yxqJLWQI=","w_polys_eval_zeta":["RnFyIhdaGhUhQRuMt8_57w1gA75xUNjUnJOFAMG0nyI=","Fa9dfpJBU5EYr5F23PYui97-SR4aq3oGVYr7l7LW8QY=","immc_tLID9jTXVZBuqJrYFEcv1tA2XGbx3R0ZEwSByU=","c1nY1hswlXXxkW4UE1uxY7xVaW82tEHxDUaw5oRvXw0=","GXcmqizgIh19ia1dQk2swprMMB47R4Dg9JFUe3aXeSE="],"w_polys_eval_zeta_omega":["x74d4eC0reM3u9GENqkjCDnYeyYum0wOwcFDRdlNAQU=","UKONqGY5tIP2kmIOf2CV-uEM2141WQ6wZ5pVzxgSEh8=","mHmmZgYDH6t20G7-dlL9T6qtaseydzHyjTh4CRLv6y8="],"z_eval_zeta_omega":"EyWUnBjtva8lOW1JZMHTdIlKB0SSHAwn64X53vMoyxI=","s_polys_eval_zeta":["R_K91z4kU88bptF5R8U1HK3kLs3gAnxyMabYYpnmOyM=","oSuWaYDG_1B9AMt1vtRcWrz3fPR67yk9ug43hsmw3xk=","cbezLXoztD4L8Sqs0z_zV2hQcdwJ0tdVReAA6xAgaw4=","btui7KRSe77roVtpmBwmjg-HSuaJEHlkOTUcbnRQXCQ="],"opening_witness_zeta":"caBESRJ-sZipjQu3NO4T0LQ8-weNWmspiMm60_uSAiI=","opening_witness_zeta_omega":"bd7_A0goddzbwdzw8SotLGn7MZt4V8oTH0CVtaMmHYk="}],"memo":"tmCVCCySofh54qT7ESVF4483rrum7MymBjgmjZk_cmyAP3rAa24HoJwWlIoDGQvK9VFnfP_5BrAF0j0kQuwnFz-zuugzUHcHihU_GLFhwYQKP6098fBM4PwiYBUteQk3z5tdatPamhcpblim7MeAQBPQ6BChhKyj6w=="},"signature":"AcPjPkHH5AYUiuXECXfAbM6sMgtCjxsSMj2KkisMJmHcEvMCByBQHUguhHbRLRYZBQZH4QFp3ZNG20Rpg7oztLoA"}
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
        {"body":{"input":{"amount":{"Confidential":["wulscl1XgDDGolkx9wykjfp-9--UwiP0YuVpyc0IwCA=","9mUR_8j4g7DK1YI56T6Ha4A5Z7lTXnFxBjpt3cNwURQ="]},"asset_type":{"Confidential":"eLl6KW_lHbzkQVRXL8JtZsed7IHe-9kwtNhO9vLgZgY="},"public_key":"N_NN1H1wS_6fihfutMJtvY-CZj_KvcEijZANR84gYs0="},"output":{"commitment":"qfopPq3tpbX3hXQwvnjf5w7aYBzT-P-7pcnyvKOtLx0="},"proof":[{"inspection_comm":"OXd611ge5okomt6W2JHgqqCOk1WwVPotWu9Pr4Vk9Q0=","randomizers":["FL_cr2GrLRa3IDklRDrwo1ERsL_zxgWi0RzQMpHce3k=","PGQG5v-XVXs0IWaC2vWkx6n0XIvLy5PeE-bzqYPxZC0="],"response_scalars":[["sFeKbejSyCImHAFNjmbFgOwT6GQYo4Hv8cWYk_Pc9ww=","ihbXKwSElZKKZ13cq25ZiYQuNimygCG9XlXMuIfIYww="],["D2rXLSQL6f4MMTp2jRv2V08PArU0BAjLSTjGg2GCGw8=","jXnoZlO13Q3fDGmmrjXpLDcdsHoZOYOWihNJlt9haQI="]]},{"cm_w_vec":["mi5GMBuxclYFfTYbjWrf_cSejdfrw0adUBGUYXoH2AA=","r9XRlgwar8FxvuF2lo3hZID-ZqFDv0W5Oj38N2E4cy0=","AgU3x7LC2kG2RRk42qUHSkv_icC4Dd_66UeZRYe0MxQ=","HNaZpl1t9d3EZSFgfmNzqGAAhaJtlfUfim1DYc6c2g8=","Kc_23A_tyCSepFr0jK45EoBoyXTfjvmEj2AkNUMqPI8="],"cm_t_vec":["z_NRWHUT3-IXKNNWi0jhD8VKE6CjzEt6aRx10dffqYQ=","88ono_8zJMkOfv-P_W2Rg0xTuNOrBmscb6qHpVMCfZE=","uPM9pPH_k-VmU9cGKdkEtQwwmSEgj7Pik3kzrua-rIc=","qLJ1bXdmwX6Fudm61MU_JHnC1d8ebCNmeop5RVv_Rqc=","B9IR-1efVUiplB-AZBqmaW1A5FnocFcAI52Ciw8qCQQ="],"cm_z":"eN-Jk7hEAmTM6mbFmerhr7kBKleWOsmBGpUlihVuSwU=","prk_3_poly_eval_zeta":"U-F7-yiiKrV-oHcCLgOjOtj1UwieU2eQLGmznuCtDy0=","prk_4_poly_eval_zeta":"JMhFzL3yNznBl6bxU1AC_O5MDsX_ix1F8LJcKKL6tRo=","w_polys_eval_zeta":["P2W2PGyMd3-wTQoZxurYNsYAM38fHnd88u82v7mynAI=","3BdZnbpcyb40yFe9X2UfuwUTmgXt8eWp1FrdpIW73SE=","og8O99GhLQk8ixzx6-J51RhwlR8YA8GKB3G2t8HWUyw=","78CPUahtTAf9qaydJUktdKChJXkZVxNd5_4-etFEzCM=","TA_MMIWTl-e6H9IUSHqWXz65dW2AOpl0L5j_UIMHMQM="],"w_polys_eval_zeta_omega":["0-UMqDeo1JKOC8XrP8W8G5WBNkwmKc2exlYNTLgUEAQ=","oXgtvBXuhEH6gBoxzaiQiVArIGWLOOomYywhdD2NRxg=","hPAsfKPINf8Tr5fcjdKhFdeKNv1tzmRHfrHfE-RMVAc="],"z_eval_zeta_omega":"TBwbJyDHiE5r3tvB5L9CqLuMipXR60KSbs6H7KlCRxs=","s_polys_eval_zeta":["oyzP2VocXtTw4zpfai3Zcec__2NyBuz9SBaBjWFBEhU=","0XASDicqtXaEmek27lV83HOQ7A4GQspfH8yQxyVmCwI=","IpOBm50tLUKx1UtoIh_4qcj1Qnl0zMuunl510wBOfwg=","Gkyfr7cDyya8ZavFMwx6Bv2cf1pXYhbTVr2GpyaaGR4="],"opening_witness_zeta":"ojNJZ05TJeQw1oGMF1Uytx8YiCsU-yhlSUO_jrYP3hM=","opening_witness_zeta_omega":"r0dip2mXAMoGg0tmjNh8P22afAzqTUsdnedtJn059Aw="}],"memo":"qnZGF2taD2XurrKz3aNQJ62BciTQVnu4vxclKRq9PfIOlJmdiRMSqt_18BHePtjhkruCqJHIOqFnyoEa81jAb41FKpTCgh1sIWti8fM2XzKUl1Oyr3CqpU8BJYfT-751uwJ11JGyeXXf6FVdxlQSQWDqNxox33Y-"},"signature":"AFQbaUxl87GhecnYn_w0ot-sic_YxNA0TT0AOXpkMrqp2x7dqJrDSYlHvkKpPbAiJUx4loBGZeNzGOtkVlgl9g0A"}
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
        {"body":{"input":"g3uotMWEBLFNEOpoJiR4AVC0Sb6PpQmXnWYQ4ZvPXRU=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQIeUyTwGhfIVFOuuvOEzA-d53eY6ze38R7QPMPumrGDRA=="},"merkle_root":"emHSOCycPu6wmbmC7h2WqY6U7c47hDIIVKgyC4IAvyg=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["3aP6H4Xa9GDo9OzysTzW5g0bT3EB_dnnUqHgberQTQQ=","w3G14vzPOoo8rGoQvi131KkAbx0QuuTcBT3G-M9KICg=","SnZSOsQll2pZ6pA2mzfKh69VbIZ9cYi196mvqt3ZaR8=","F2ZCvg_O18kWeNBXInw852sLW67vlHfyRMUvsOVFtRk=","N5z5alwJ7Bz_37XddJYQ63l0rHeN9nOnkf1uD2hk2qQ="],"cm_t_vec":["O6qG6lT3H1BvChzp7q77HDVqpsnQaH6jbVDmzALQcBc=","JpptE7U9auoKeOXIMhB-faMBCjD3J4-WWy6IlE1L0AY=","uuZvaNNXiY3VxHFMujtQFAidTNPpdd9PVCDBmvS8yhg=","PDqv5EKD0GSABP5Ddnm7zTbK8aq6KKhv9_pZUsCelw8=","0BW9VDp1my733AKapMZNMsY9tFKBfkP3aMhO1Khpeys="],"cm_z":"Q0zrjhIPRgl_vi9p3iOa1J9jhzlngMEcLLdeVuSfqJ0=","prk_3_poly_eval_zeta":"II1qoMNf8iSrO0HLYxsAYPB-9H-ho6HEjPXrQ4oJCQo=","prk_4_poly_eval_zeta":"YCTo9XYK9zmuUV88LZPXMhKe3KbNVxmLxZ8UVVTEqQw=","w_polys_eval_zeta":["ZcSgy8GVUV-u_eOdx6RRXLGNCu0nzFH4YGVny-F2gSo=","bxBUv1VToTAryOm83r42oaA-fcHHh_C3IDfjyhbFISY=","vsXupreKOPzJsXLxfdnXGVPbh3wW152g6Pg8e3FihQI=","NEP4gmQrzNE-V-yFgcc91cpx97O7GuaRkM6tm1B2wRI=","NfHnC9PAwERo2b1ZK8RiDzGJf_QQqHCMv5BBPaTZgCI="],"w_polys_eval_zeta_omega":["-u-H1Wbf3LRU_4CrjEZuQEMvUheKWs5jFLf7qQBRkiQ=","FMapYCSUslA1aPufpe-ir2Pe1n9U9OhG53rmTyOgNQs=","LilXwkGgQEUK5JGwT0GOUHhYUqzOKhnVSmZk42Yg3RY="],"z_eval_zeta_omega":"kEJh3Tcb9Aa3DZVoLMslBDgSjcWnVCj2fB8VUt2UMgs=","s_polys_eval_zeta":["PWMtut4FOjtHhtEa80lqu0WYe1b6nTV8SudbkhkP7xU=","LlE0pYR2AOgrH-jf4yZJgOxxjVCf8X2qA2ciQwcSBRk=","fAeC-ZLKnEhJiPKouZccjdvE_hT2H09an1u343S58Sw=","4101xlkFr4Mwa0CznLrGxD1bPOv2vYcQE-YvYxnMuSw="],"opening_witness_zeta":"ytuNErU-dpJRk0OpltMccSDS2uTcLKxgGRg6KgzdVSM=","opening_witness_zeta_omega":"vc20Xx8G6-rVRYslHRpKYGrEjPxUr1Qi6nh-Y2ZHL58="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"AGhjSA11tYHhduDojSdDleFurGBid6xg8CVbeTVw-Bk=","randomizers":["r4mKeeWwAKUqaSQRvEDaSZRaf6NVnDS3wHAkOBjuXxKA","pQIKzwHghNseXbapsacmyZkqJfuCbI0CnolTtq1nC9CA","DGhxOt8ZTFRX7kA5Pn9HkxsnJWaOGHHKvdPAbkuc57wA"],"response_scalars":[["Y0X6K0Dn1mZlbC1X3mwvaP0tceN48dh6xuctzlBt24U=","vZ9ESo-S_GIbZvMmdHbranIBwh_hB9zJgpE0t8QU8kM="],["0GoNroGCbkH5_HcDk7fUbmGgKtuB8fH0_JaOwBBVNm0=","_te-xgi_XPo2ZohANPBuDtO2GpmuHXoEWK2MlznSdJ0="],["LqtHlDkpMQcwzKjdUZwBA6Yj3C7ofiHZwg-2nvgR-MI=","c_AqjMwMuDD4NamI0fTsmZsAsSrhX7HPfWTMXRLHdDQ="]]},"scalar_mul_commitments":["yZE93kfFvlr4rBzkz7afAaL9CU2air5hyqJdXonMlneA","cbNKxIbgbjZQRQSdvUngQnIelDDrJHx8AmhVd7PNeUGA","iImCxHmZocaGqQc4arzIwXx3KwwBTaJXNytUgCz4xDiA"],"scalar_mul_proof":"Hn9dRIPIWsNMh7kPNt7-P8uJ8GjArOWKir6GcCY1DR2ASv25D5oMb4Jo32icpi--vSb0pVoC6tkCvA4D_H_DxC2A3HTXxcKr-4D6ermJL7nKtD_VtXtuQDt7_4_cQaVem7eAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABALO4j_s1eiez-YDcDpHnOPiy8n3PabmI5igPvhYpfyuIABcRVqQTtYscyr5ntGI2accmAVAuc6zPDTl2743d08UOA8wo3_m1ZZQeoxquvabRcPrXiPa6BQm-rOrhTwkhnnKEASQJdw7RoBT0R3hErevwniIxews_0FJpmrQa8hcB7Su2AIS3pS9OQuiIUAKt-Fb7Jdao9CEsEjU7P_768bXtvemiAKwWL_C_6r23PAbSwSj4TVUs42KeL33UjRNYk87-U8IEBZq3ME_w94QiILvdPZFsMEh20DhqHBdXBDRUqThhdJ7FGoS2S8qBH3D6tcVT-a2Oewck3byTmVm0oIQUu-_qxCwAAAAAAAAArh-FWLOVbiL3YoqeERsU9s40OngWvkDgVO6XrLjDK24Bt96wq0jq2BCHfOzC0nmVZyh2njFumYdaFyU-3z6U3vIBhw14Amu0iKH4LMTnhKKquVszKYxTtpG3DFvA3BsRwJgAfBUv9XzOqOTbK4jUQv-LpjxiuzCp1lPRSp2hH0dxTmIDaUach4yc-JfnfP88NC3WbLf507nY1cILf_hEVBoERlYAF2ps1meMuGXloBWOeqgoGS6zX2vuIlSK-IsmFpX3k1IAH3T2NHgkbrCvuNCmYJCBKgfeCHNJ0riQJFJjhwn6oAwDUzn_J5d19svUe3FZAtkaoiSx7mfIXjAlypxO_zPnVpwAlCe2uj5l7Kw9OT8MQs_3x8BZNnLvrmW4IBJZCAadAN4A_drDmhS_7j1HWKYJNZpq4zkji3abzRaMK7fdxx5L31oBT09R2bTfAe42kf9a4c25cyYa-MOJrJV99bJMrtIX6ZgALAAAAAAAAAJUnfAVq3xdJaTuHpUeK0k9ADQHyEUtGCHRA0nI1r5rvAJme_mxkPYzTXiXpCFG-lgwXkfVVGM00xDHxMMsfX0AKgJeHW84-8NySkKeX2cmZxJcRyEbMcyt7kxP3GX3NVg9jgMQ3Y3pP1HqRm-DiuriOte05bri4XyVMFW-eyURqxODeAGrFqgbfr2Qj9i3T60tLOMSksooVAlD4G1PCZ_ZSGjBTgP8juISboHyISxOa7GQbrhSaa-OUsfU8DkT0-bIwv1GRAFJ5oMrJ56Eq4gYenUtBO1AtfBUXPGnWJFV-AJsENeNDgJf2bFCf7_yPrGRYyw2xaEoZHS-A1V0aFEfK4vrjUnaqgLHTcJTLT9oiqXTDfvsZAxoZV7xNdKzHD70kzmckrkHEgM5UdjCnfc7DPgaXLrFer76lGkAM7S9P59Ykaz6IgtP8AFNz85hjV4sSMmGp6IhF6ycWmEVdgxdTUQwOtbPSOiwNgCeUM-VYtCLpstedk91EC1RFQbmSUHXAZcGvBFcLYgtNxfBguKZJcl-U9p-FfDXo5RsleZpnFLulLi01TPpeco8="}}}
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
        {"body":{"input":"4y7Zben647ny_WYSQIbHJmeaFzUAFPBlx5Zl5uAmPhU=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AB9LVfkm8kbC2HFQFqTOstER2vXxih6s_yYD_0wbR-8="},"merkle_root":"9aAdhJmV25AoHOXXe2O-OeN4-4McFQTuMcurcpqAygw=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["Y9kUs_tVRImWyg8v7oKxU_N2qudmaUVN7yE_9UTwwIs=","P3mzn8lbkdfVWjUTAPNzZBErqGBsZsUBJnNg7o5seYk=","Y3m3vwKYV7wjZK8YCihZcMV0uANTJtbUyLAFY2nHyA8=","a2rBPsZa9QioNDeGo8HM-6-pcTfahvV41N08h67KIJU=","2yiiBhbMb1SaOHhWIux1cjbQWBjoyTM4hxdkTTCAMAo="],"cm_t_vec":["qaPdk1UWRBqYeezeyMuIQ4baGT2p65_nGJTOANIRfZ4=","o06ovovMQc7udTvEPEbtBndrwtH8laFuVxQOuX1JWK8=","RTv680P8ILHMlRPyzcmaoJbdJET5ybZqupxjggH09a0=","kpa-svlC3KmZsnoVhcRLIMcbPQofS8FeVc6NRQgxqSk=","s_FMyM1oqNCMAHS3Kq_EUzW_u3xx10NABkgECckC6Qo="],"cm_z":"fr8uErPgBWaEHKRMjxXB6zHdf7fOXjdJTP0IhMIuk60=","prk_3_poly_eval_zeta":"EXTrxm368jaNUeJCOUJ6oPdMdnUmyR0CTHkeuwUKsSw=","prk_4_poly_eval_zeta":"TTrGahf1biXHXX_zKmhGzEsuFyuPKajwyBBGRdzSZCc=","w_polys_eval_zeta":["3dAZWZllwXamlWCcNRykMN50rh417ugyytQnz1F0tBc=","uZ502YmDsJp3sU3i2bdKbpHb0H3MS_1XHI86TtFrehg=","g0rikX3ASulpLCesxUFNM0jHCoHZgeMNDjBFd9pLIgg=","SHI8dGYDPk29vY3uEUIqqqJXWIPfb2v4tgozF4XNcy4=","1X0KxLeqrtOCa0Sph--dS4I0OtfKON_Ct-gbXiS4sCs="],"w_polys_eval_zeta_omega":["ElFqPlWzhc40TljMV51uaPkaQGkT0Jp9q84or_Da1RY=","OoEQiSnGAsp8IBc8ai9Z7DMXNPx4aajmsG2K_P_WvR0=","34DnCTmKUgBufuwBGcZsyEZeqBSR2DnLhSzdMXVvTgw="],"z_eval_zeta_omega":"8VshMPDkbAeL7USOibZ9FQZULvBOf0hwwmeB0lCokQs=","s_polys_eval_zeta":["P8axlB6_tkz9Brfe6R9v5M_Q5y0Zr6-5T01aS0SLVyU=","sBxMHdjngPREDwsmw8EOJWH6_qilA070UGuoDJuj0Q8=","7y5-Kl0yQgdpGPd_IhqIKcHv-Wt9LEf6UiAKo1tnxRY=","QTef8Rw1c4wRA3wODzTsIwz67-LDkLZ3jEZbVyGqwww="],"opening_witness_zeta":"fQzA6PUNQyvM52GcL9qM5MutkfM3u6ihbcEPCCHb3RE=","opening_witness_zeta_omega":"_BAFHpRvay9e8aezTRW7vrOpUgJCZmBRCY6BuLwAeSc="},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"095FmEql1X7AQMPkHZd9bYMhKp42vyynJ0-ii5pwtgs=","randomizers":["KzEgKaI2zQ_JsDT4Ecg8c7xBt5XMT7hGn2Q76aafEnmA","Y_tzr8yExD6F0JLG90kl1ikxrNXSansY6pdGtY6JmycA","yRSiBupLHbLA8yXIJtxeMQkdLzX_fu46sC5eAmVRz12A"],"response_scalars":[["ASazV-bRxuFuKwRjhpWqrBF0-2fQTODUHcfS7MuI4iI=","TRfHUOhjAhrEmwrpQ9amH3GJMVWcp1k2JsPvhVXSuls="],["2Wf3XDRTiwjNhylYczn45pipD7YJvFWw27dU6QZYBnY=","RNwtWsQv6bECKlNBBvAmcAcaAGKij2Lk0MHxvUKnFwU="],["xYl5eyLOw5FGk5_obbaPy09js6sq1S7G3yObFxFc7z0=","61BsHMGedkUzjBc86dYAiL-VQAd5LlDcgXw6FYkRmDM="]]},"scalar_mul_commitments":["nKohwGmX_A2Xh31o9PTzMwZ46RXBZhJDqhNs9GcRSReA","H0gZj-ExfBa5_bbpOTTDKvjv9Zb6YblFDPSkP5SYBAKA","3VqCLsDondNkWY1ePlbjEF6-mQOa4x6wbRep1LJtPVOA"],"scalar_mul_proof":"1iWVUL1TrW3ZrDVmnp07r0MwIguww7QOO7Lf9BdwGi8AIcSDkp0Vt11UCbHtoggJv8qKCFHBicfZj7yXnucGAiWARfZcnlNYowpiR5FrnZDb_HgzGvw-P4y_aqEB_LJAUVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA0FA9rjS4NTpbPTr-bgi3KEyo5fI4Bomvb06PF5_rUD2ADW_OUgPBlftM5-fYc0iYpzJmUu2Hd73Ng7lJclKFxjaAw4lOhXTwn0ix52D13BQEKBi9kisqmm5WYfPxSkC5MSaAd1ni3Vjx3_ClGQ9sZlYAGg67173zBCV6wWCQVSVLAA-AEALaPwL8UmsIm69Boo0MCpuM7Wi3SXXY39xy3_O12UyAxlrMS04czIM-ZVK8Rksu9G0y5M7ntY_op7lgW7sqNCl4xGKD_3v_FZiPLoshSoNW1q3l6bd10Lz_oQI6VqorTQx8M7nKHy-FhMRcrzzK-UplMTY1x3y7OeXxAL7Jmn4UCwAAAAAAAAD1QunE0ERG1wPuuugZ-sHsgCpDg0IaPMUhQdLvIJHqfYAsOZJT25_o3_4MZBKOrFka3t93yiSbDEDzQxwGDB71AAClq4UQRxLJhkk8rinI4rc7nIVRMfCGltS85bC-T1lKCQDFHiGt39eP4zJp7A3W8xniLbD3UIN0PtNscLIVzsLVRoCBxH_lmpCvTV9rEIzeFiHsCHnllk3bhVSAC5Br7ndKcAD-DJMZfpzu-0dwLWZ3MzaB-X5Lob2xRlhqrDJkIDL_bIBhsd-xoI82_4aLL2eDqKSP3RL8cbszNum0EzFSPrVKGQBn4soAHb8ssuqt2Dowe5Biz5LzhQTU8tgifJ7j-gCERQA8ebtl-LQ38oVnT1t1pZIyfURk1X18nev0iIcPNRYlC4BWLBdx4BZdCIfMfq4wgymJXaCjlmnkA76WAU47hkKoewCkVIzLmklXfAf2EiaZmGD60-cER7kw9h717n1wxRSWM4ALAAAAAAAAAEohOUXHc-R2gAf2O_C73GFBfogKmgnSeUGNMtiy6n5xAGcSIVTRvRwlhIfclK8rSM3-Xub8nEVyC1F8-VFw41RnALZTiK0y7ToOGEBYR9smMA5Kdjds8TUnVDwqaDUONjAdgJ-DarEAfurhSt7hb2CRGMoqYbqr3XF2sOw_fd526QwpgEseLLiPcgiWv4KlD_YO_59PnBQu4jBgefZ5mGwzqKxOALVQUAaKnt1QJFDL_6LaSi78imIFjbtTN-UEVBwIqCwsgM1_0AGjpjimrFIIHPfPbKBwHngxa1Md5bOp2awYLh0PgGkxVlcltSyRzMh3wt5M4tGbk69VMAt3p-IwbqDjXSBlgCvbx_Ftiddig2DMrMEyX9N_zujOc6cWbNd7XgJyg45DAKg2GsTJqzAyCkOVmfhxNKeK7OeIBx277oTh2M_xJSZZgPVCwX9dVabHFwbALpHKjA2dK17fzJ87NCBuV2V7sk0EgJOJDMn2e65o71uyC4pvHTGy3oWGQy3h29JMtvUvNzQxk01ZrmTNQHWGe6E-bq3rZ_j2-GlToYzbGoQZCSdv2TY="}}}
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
        {"body":{"input":"ONHvZvS53B7petFUCYcJfrCYftKt21nIq8OcN4jB4ys=","output":{"amount":{"Confidential":["XMK32vqbuY3Cz42hrWcvFWPwFyV9ZefFwO0hrSzsf1k=","xgCzR3XBExOF-GlfCtF-_p1ltb3t9yg24Ovlk4O1Kik="]},"asset_type":{"Confidential":"rBRUZe9vAR30tOMV4H1pHC5mg6qzfJ3Kt-seMx8HmE4="},"public_key":"AQIfJo1bu2YrwexyLjrcbUkJQ20swpALHDOzitclLsOb9w=="},"delegated_schnorr_proof":{"inspection_comm":"ftx7pmJR2T_teCfg0HRpLTZZZJhNWMqvB33IPXHUaAA=","randomizers":["RKEItQN6AlkwWDo8uzL-V6hro5627H9svMlbZa41pnE=","5Esth20uhX8utxtMDFA0Ic5rS6KY2yMN7xaF0yKMwys="],"response_scalars":[["cC8QdudqF7J6YfFivvxr1V0UxuOlIUHMZCbvnzzFuwE=","JLGEHFZhjQlPo7-crI_k0AvDJQJF3LOVkuJF9VmAqAw="],["p9P27tOFgC8Yf_CUCzDBnVTv3orbNwmuhC-Cy8L_lA4=","3nngmTR3qf0INFo6p7EpUsnCANKVDleUT1Avj9i0AAE="]]},"merkle_root":"SbDAylhsCqDlW1BZ3yOdnU9ghQ3edy2AjThxLKVtey0=","merkle_root_version":1,"memo":{"key_type":"Secp256k1","blind_share_bytes":"Ag31KHJeGzrGA-bXj0qiOg1HRgvU5JUM8XVS6GcQ110A","lock_bytes":"K8T1WwcUU3FZFvCTBbdyGngBSYIcGKL5wlvQftiOOrUA_-ZxBBnbC7WgiQKAAAfOqMsosSAy86jOfwUFcD3sy9xorh-iWeQb33jkJ2T_rtrUy4ulvXyTEJo="}},"proof":{"cm_w_vec":["xvVve-HJ9fR2ESyd4gJ1FeUGKd5CIqqT0QKTws_ow5o=","ugZl8RbWQeJ_lx7Mfky2Kt0AuX65i_Xz6uadb_sucSQ=","kQQGpbVwCpMOOqDvyeC9aS-LaZUaONo9w8QV4YijVxw=","sTL8gKZcFlHpVUlE0QWMIIqDbi1IUw24n8xIge3TQiA=","9pjKrLXVwPLStQHB-eevDM9pxveQK0-OWcu230Z7Eao="],"cm_t_vec":["PbDLL-5_NiUXCc3fRI7TKnCmHoPZcDd3gKOX8P8elq8=","0eESotYGNIy1dhV3ZCIzdwYGLzZZfDVruZApPeQkdwc=","abCqnU5S4WX9Nxjl-0SCtNt8Hg5_s9UKtJnv2PYuLy4=","ge63sQKeuDEC_Mxm1pczAh5ywCok-mg1oNOKCm3Cihw=","uFoLPm7t30qR_mrf7h27WZZQFwYiHT0qlHxfyp_TmYA="],"cm_z":"_oysBLDtOSxCUF90G25kusV9khjbcAR8Dmyxh-S2qYU=","prk_3_poly_eval_zeta":"eSxOWCfdIt94Kg01a3l5g1I1KTf54I2VGk_7aWTBQSc=","prk_4_poly_eval_zeta":"0VtdUW2z_hSgjF_C8Bu96QQb4vff9-daE_XgXD4i_yQ=","w_polys_eval_zeta":["B6mSW8j4jYo91m1XyTP03VkK7vLTSY2Abf4LAV0M5Co=","IhOHWMA95c8j7TJIn-ZxZgnLfE4ms_dI8DKFU1E4tQ4=","D0HvxCuL2PwGI35c7jbVazZw1GOpN_JVU7M5YNTMKQc=","5arWZI_b3HG7jl1eGz78y4xgfRABycVf0YX09X4TES8=","iZbUfEAfvkADfRT63jQi8rgmWM0vxHkkRcBqlChlsRk="],"w_polys_eval_zeta_omega":["TPvr-2VlLlrhyVVoDA9cOJKFeKACYLi-0gbCvv9jwxk=","MWe9plCDZx1-9M5_QTWyCgYFYjqfSY4AVrGKU764lA8=","imiMwVeuLyh86Q3sljz2T72I5ovQXiIU--8uHMoGNys="],"z_eval_zeta_omega":"D8Lxei7gZYyOEQAjkNExyYgVgAPZ9qoBpWY0nzLooSQ=","s_polys_eval_zeta":["azUGodSzU31WY7OCvlIJ7nDDSM2V0tRuVzQXL6_3cRQ=","_6Ek28gr8K0_fZE_bTPWJATjelnR7uajJ3yW4XzMsAM=","ixFQYk3ltqqw5TwQ7qZkv5KSNPtvNtipNqCPlt5tThE=","mSgC3DQCjZUG_1uTl2bANBcWOAkeMWeLnz0aXQR5VhU="],"opening_witness_zeta":"hOduR7iEw0vs9URnDsctVexcLYzTYPI3M_U6djGhTII=","opening_witness_zeta_omega":"sVHWVwovc8CY4dbjmOE9nNuv_KM6Ue2xDreoCcqt-6c="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"w1Kw10lcXDednhMoQcxudCo5aM8efu1nQmMkvQD3lSQ=","randomizers":["1Y9a8wTueHYTVri38phHpdL5IUeFxAkDEiaJPKTwgMAA","Rz3Z3i2Zt5iYRqku4PgPXSV7RBV-dsyFM1-hj2wnAzgA","3MZsQm4Tlzoj3ACl4gtuDSNgN9DHn2LdKq_Lh1M5ekYA"],"response_scalars":[["zUAapr0XGSkfylbsdnWKepqCp0BM9NbdtL2FRCk_ab8=","FG_iQx_pHjumZczgGhP1S5fTs5Q6NyV1MABJ-a-nNu0="],["3mlkRV2hhc9abZet72n_UXVWIuDqFxtdHFx3WL7jVX4=","5F5f1-UFCFNQu8UTBRRscKSZKljT5EhKDlKIeSYowj8="],["Vy8KOppgI0Un_4uDnR0etc3GY2k95pOy_9ICubgwHLg=","dTeE46lYURJ3mO9thisC4PYuBBmTdFbjqMIz5DCBDog="]]},"scalar_mul_commitments":["sVI5TK1NKhWvfFYsgvXY1BV4X1pdrBPQJNWnlf91-6YA","G1zD4q_ruGzAnQPFL5ODs_bfTdmVrAKAZXMrSRpWtFAA","z14faNBqC0h_3fxDvIfxMPpqRwR86pZY5ufI9u8xVweA"],"scalar_mul_proof":"DQ5d4gOP4X27LBRTrjGEYHfQe0gIYANsb7AdmkhP3kMAyT9mG4dIO8ZpUCbOe0T6WA_vd6clinzSUrM8CqjajdkAut51A6fg2wWXaXJoEdnami_NIv9T78-5CWIEGe9UmyuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAj1ZnU5-P92ptXr01UpjkQfKM8uc_ZTjScCALU86tHIAAQoCygksbbcn8gDHlhB2nI8NGcSHY954AkhVpFIdaAxIA3DZq_hox1Mf-QpUJ-S06N_o50DgNxBR7_wjNgIswYooAJGuUC87jUcmhFl_Y-CqXXRjXelZ6jVGimMWpNdEZbmaAxxFdNf6z4asqcAjQX8kV2cmIB8IBw-GlJHSyclQFEMAAdcsKFvZ71-oWz0ZEuU-KS5mgFt9Ls_Da9L02mHpVaAN6n0Ep61D8rP-lVgSn9u6bLx_Z6NJ7cCNAO43w2Pz_yIn6q55tgpyU3PlnMSMU72Vw5_dz_ghBVIi6sv4t07lwCwAAAAAAAAARnZhAAQLA_rWU8S2dSNBcrM3PPCkLWqcYfXF7SuclOQCpRIQovsIhQPCjxTpXWMOMhnYg23cds5tssaAiIdTTWAAYQ4bJlHplFQCo_jRxLJ-qf7BNVP8YaSkle4EnWEWrsIDFMShzEFlaEmba1hiZDdrbmFgbLyhOIqu7opTdWHVIWoCZU15FRqJStGqfywO3v8HTtrmHXrYQvY5gu2zm-uXMywBuGvX1uAFgVYuiaQoN29uLyt0cGyqq45ACVcgv2Z0vtwCktV4Tp5CRyx-kBFKGoDisoRSsvbdr0r8KQxBRkUsxDYCja0ChyTzaldhWyUyUzxzaPXPTSBKelqTDefBa7shybQAozlmikOpLCiYCp3aiUY2UUiHKhpuV6TYZx-RqAm8aOYAkMpkvC4vkJ3KJi0tgP6THGmc8V8PT83p0PKoWhLyRjoDUmi8QUPRLmBrXzGI0P4DfSDTAurg3wpobDu55-5vjnIALAAAAAAAAAGRZ7QiJWXdnutsGE53FhtTsTFHYknp947iWFNSFLfM2gKDyxOE3hF3BtFARgvxNXWg_4kIg8NHdwu9oG6Kds37hAA557xGt40djryc75Elmjl3tRgeezdxj8FPc3KnipnKygFdzVA4znW92UIcoE5VXzISCkcabV-jn1ALOzM9Ky1_WAC5cJnVZ3VEHla8mKHM78Ru4jM-cSa30RLMelb9eefOjAATjiLtO3sv5vEv8Eo5O0yePV2IkeZrQn6Rprqzy6jpVgB0s8gyVwq8hrhwGhBdpl9UeiwShN7ftuEr71qhuuZGVgG1RJmGCCEnSJ5WgsvLIOR6RNT8KXZ0T4bpNzZNRYk0KgMttA5GR0Dur3Za7FJnNbvFIvD_JZVwbo3LGSRkftVE5ACyeAtqbiyipYbo02WSDQxsQ_ZkSX0Qajt-Xa9NgeN3wgFsDTr6tyL0of7WSNH49TgZLQfaY0liJ70HxQeEx7wBoANYxSiIIrXgR_W_Pgf3IUy-hmQWQl0hhLyJM6glKvdwpWMrWBSI0z2gDWpxzSI7MqnvSFH6JynWEppbK80y8n30="}}}
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
        {"body":{"input":"LHI707aVCbBeJx7UP4IQZFwg-dz50FIeDPaQzLdJPCc=","output":{"amount":{"Confidential":["kFpeUM5VeepiLMZyr74g4x4AdEyDFXk37ddckdmmODo=","assu7BkPO4W30xNywcNUXOwB-IDcMsMp13HAfmQWSRc="]},"asset_type":{"Confidential":"vL13SwWK-PRDkG6SXU7fNzVmSaIISLA9jO5clqf5uH4="},"public_key":"07y7l2Y2iIa77iS1O2InuHob4qK0D174-9ZA_phKKKs="},"delegated_schnorr_proof":{"inspection_comm":"m9gS-FbWtJLw96uaRFiNoYst27jMtacz2gxwWPRuigI=","randomizers":["FMR-i2nXteadEW_K9NIS5xwoQc8KC_lpDyimHYpMFDc=","MPbG7STys__P3ksGTXl7hc4uKrfQWVnhWGNYg7EeVnI="],"response_scalars":[["DYh1Vlnw5O4jd_gE9vtK1beCl3UyTHVr2-kcEnJbGg0=","CPqtv1ow9rH-FereELZ5YGCQNoJmGTB3-GHnaxPLBQY="],["OqBRH-g5IOJ71UPMLXapNOjMjsir_Nafe7ziyLRBNQs=","hQTq1-I8d_A09nAS4UwONL0u2EZY61lbJZZq_iWyyQo="]]},"merkle_root":"-47vdTAatCvXa2KOG8jU-e87U71_KJ3t1iMJevNxGh8=","merkle_root_version":1,"memo":{"key_type":"Ed25519","blind_share_bytes":"xhoK-BCWm3MfxFUuKUBssg7oxMXskWma5hbiRTNFE58=","lock_bytes":"s6OGAJ7SfPaxY8Phk7qSkMVHmt8d6Iq2RBj1xVVjyWwunlKQsHdLW1u3-u3ZQ5l90qpWxYrxOIDaU8JvfBgDsQENfrnMx-lS"}},"proof":{"cm_w_vec":["Vna1i8lm_1ID4h-z1QC3izDSvC2WkzmzobL5-4hC0Bs=","5FGBJSbfFY55hibnURAgQJkicKZ7oJuwLl2CN_zoXBk=","6nyKdiA4aDSaAIGD2MqpaGu5o2xcdqU1101kLoDJIqA=","73zd1Jxk9iz70qNqjL3fNRy7DC9WLr6WkgpUcji9mak=","T7H5ky6PgCVIq9LLS_5aiE40oOuwEsLNyTXlSjbg75c="],"cm_t_vec":["rRElsh1qhTfGnMgN-n5EES_5MWTHPeYTf-LQipw6xYo=","0MY0B2cRuUZ73GY763Gpq1pbflQoB2vAZWelqLvDhaA=","p6BsjI2MJwMSuOmo0NO539gxX-hkaafOZzL-3dHXoZw=","YE7jR6mefIpgSt6zPcLuwWebn6ExBj_HlP2DIiMxkKU=","EWwpWc6p1vnDRao1Npxnd0EhLP09gPpb28rhGBakESc="],"cm_z":"jIG33NvIRJI3PHvEoI0Hwoa4HJ3-tUj24jv8z4iJ8iE=","prk_3_poly_eval_zeta":"LTTfZBQZyXuuH2VRPmTkAjKUo9ts1bRrDaUu7JQJAgA=","prk_4_poly_eval_zeta":"x-wqT_8lBWyllVaXysu_sQjYlH8-k0ReqJeMcexREiY=","w_polys_eval_zeta":["wCIQCK6xMxcnxV9vtYzNypuzRd_SEZnjJeFLniMMCgA=","c_VLU2Di5sHEM9eMk4wuxPIH6H6HOgxReMwy_g1oiAg=","Uaf0aGPMl_4bNRBEx7G0zysHvLDKamKXM4EK9ykfpQ4=","ghtLiH-ImoNUD4P5Zj1gps4yGa17iDMGp-hlNZfqmBg=","7KkeQdz1Pap0m-OoFZQdGSGgoip9c_3CoMgJcJiUACc="],"w_polys_eval_zeta_omega":["KQ9rZ0TL4PvIsf0FKN6yPxW7XAVZAdXKF4lHjsSoGhw=","v8q5rjVhL8exbQGiRz9z1ZeKJD06zbn7GeFPFaNCAxo=","jhFSKWGBLBQiRz1ZCDHZmbEKxzYa_BKNK9-GAuqxwCo="],"z_eval_zeta_omega":"Yhp_Ub8lvqfOkorJJiOa9pTd_i2x2g4Yd1EhzIPsMxM=","s_polys_eval_zeta":["GUNBzmHsTH__IRXLflX6EPir0XIWS3hqOfIIYF3T1RU=","5xpnTSywxKgtd9YVr5zalCVZsPIvfqnumjnhVDn4Dgs=","PcKDRhqRIQtxsAlubRiu8jNX9clpplkCQ8Mqz4H9ag4=","kttcinMIz11j1PIaZDa2Tq7WQg_EIh3UYC6UpI9-tgQ="],"opening_witness_zeta":"K9irPetpsE4UjCGMI4Su55At8gSs0bdx8873Axpm6AA=","opening_witness_zeta_omega":"CIidLctcLUi3fbkaHwKVccquA8fvRnwsKxRrQQdNKJk="},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"CQojtxR0ua9oxW0GMTeiccL3MBssM5MKtDgGGEIQnAE=","randomizers":["uxlpXO7jn69rjSEWTy3tNcQbiWGpVgGkzgThIjEni2-A","ItBBVwJKI1l8CzVCLtxHZGBbqTbTsutTMXv0BwdZ6FyA","MwYdq1D_L3L-xnGyZ6cf4s1uLLRx5ufQbCKYxeyn8jMA"],"response_scalars":[["qfyOwJo2TUNeuI_Er5U5-KKYNzwjwulG_DjH4NU4K1U=","fylL7XyHfxvLm8dqTzgZGjDBexu3pF6hEmwH09J-Fn4="],["33rRT5rbcKXcqVZjyhW8ldm_EbaLDH6EtYLYJt_lVTw=","yYRC5371t2x_qxlv8KH2unNPB7z299K7h3gCASYcFl4="],["SoznnV3EA-b-E_UOf2aXuqjwv-WrH_U-4fxXT5UK1kk=","Yn5ZbjxyUxFEY2BQWfS_VUEiKXCREWAnbrV7YQchUCA="]]},"scalar_mul_commitments":["b6ofsoSDkLK22pGOxxWGppoxVQ0oPIzjUMG4sxm6-1sA","Jm4dYDCcim-gPjEV_zcEJA6-SqbufljlTb9Xh-LXVh0A","vharJ-fj1ZNbyxqLQwl7GJU7Wga_qpEIh_ozS7spwQmA"],"scalar_mul_proof":"LscW8qqsqw4Ge_dkX52vOHdtQTS83gKCfhvjD2ATelMANCd_natw2jtEiez_INjnP5jigd7b0QZB6DkXUeH9hUAASz4PVVb58WODjxOKrueS3wVhg4z7Hn4hhIspvidm2lsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQSKlMW-tgQpXy_3cqgH4EqcS2Fwb-V-7FQjOZ7jYW1wAdIvJILWPKpUp_nh3CGOjjsQSEdtD4_JkxLhUKvbKqn6AqmVc2kbzEujCHTogP3vKMsZQ_qToJPAYjMYpzoUgjxoAZ0Oyi--Z5XAbnfmc0EaHR06YIPTAGHPwXitkIVSqHE6AKzrs5BwowjWDwEOvH1q4pqZ67U41pJb74KZ9PAloCz4AF3YNtulzan6PFMQ7VdI8LqI9WT_cdMdDOVwIvoPDgicbDCzkVvE5nrj_8jHEog4VbW5UChsvaOi1k2MqJnZnUILsob3OftUxX-qrv8PgmLPWXB7ONlLh9kxlKxAK4EsECwAAAAAAAABM6uFthrVMjwKlgIjpxx8L4_WrmUdHJx9OUtJEc48_GYA8fq_CNI-mAxxzmMfLg8NtrsmEFYRm7KayKUNaGPeAJQBgYm4R0wjC15yNHACtgIwzVFQFRBPNSdKFM2BZJzu-IIB2ot2mk0Jc_Va2HPvCOkx5miY7ckzQpL-Prkhirf9UfoBRpWzH9DjFsrXGZJyBJOxwS29UyabludCa5d1WqScbZ4DJ286CAOaG0supZCdMtikrWFfMnrVNxYIUjthSvUbGWgDckjciqTL31S_aH8PCLLRan1BxLTyrjQvSBT4LxHatD4CyRDuIn7tXhrZQwa6gyrkkIXTk2BU_xEyXpxul4DSDB4BUYKMswb1Yq4HgqloBsjFzOXXK3-PjrAx3PVYKXXuHHgDNe_hKaH1A2U-DjzW5Nvee_3kzRuZfqJ9VJoccE3w9SwD9RAHmlNHgn4_iiofmxIVqyznwhyprgh4Qkapk36aLWwALAAAAAAAAAGUZ8eFXCCj0jARA6NlssdgXkqL7kEz1mYALnXOsMPoMAOVd4d64MSRC7J7FctfsZlXaqPTCvcQ4fifxVbFCw0ItAIJLS3jXnqzL2UKN-AXyLNMMk7v1p0QEoDccpAhJW1Y2ALUOmPF75QtWW-YbtpXbWhw7bWAGJvqMdlMl1aF9EYgTgP0X7-4giNMuDUsnp9rGSj5Ut9WSPepxgNx0pM2vducOgIj_4cYmsyNXnqwxdHwZLBRuVm2nd2VpbPuJbQzj0a4IAK3TXlEht_RoxZJHu5rHCjpNO-ioMy2MqbepUqQUgz4igDamzIYfydTQr_p4D9awKJ_MkQQ2R4irb_8yKoJkuVQsAFXrjmK_cScAbWbIKPwDmOWo6kZpBNn0JoNCRQk31BIaAHfPQmKor9WnXB1o3L6Dn9JofP7Ofi-bdjr2fk5-LVdlAGv5PJgut_tLwxRheDmiNdnPT04vavZC0yntMdMV1yJ9gNVMXO9EHH0QXzxk0Tun0-Vh4nmJAaRAlKw2vrqmktdT7USxwa1CqgI-b_8tStdLkZR2M7R0htReO__2LyfkVhE="}}}
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
        {"body":{"inputs":["q54jjc0RVICENueX54XigM2LPG9JfjT1wY7xCEuJ5xo=","F7eXeL3NF2SHVuj148P-xVIpM2s6mGD1zImaiyMI6iw=","C7ed08_TIe82WIkRQF-7pD6SLUAeb16w0-Vgk0ZdiA4=","alFUMuSdOEcEmgsBqmX7IWe7ZNkvb0ZU8d_LUnNuvxU=","TJdub6wHBhFBSwtNH9vqbWwCbj_XfV45DaOOK7UGIiA=","7p_6jqhQU9cYIGjLlujoSjJeSfxSir-1AokVyFceAhE="],"outputs":[{"commitment":"EOGPGuEQ6F01fflCrD_L5ch0jeuuY8nfqksBEBAB6ws="},{"commitment":"zdqjkd-idCjuIFo9Qv8bFAa7pnLiVXTTp7_7FHToGy0="},{"commitment":"nCp05ngG5ZDnnMjyV24ZB7aReXF8DTpq3El594XdOgU="},{"commitment":"m89JlXZlNrtGCabhoNKK9xR5qAi-Q8RoKqWpswy6ICg="},{"commitment":"ibjZfUDi5ENxfIp9VZUQB8GhARORQ9qFRGG7eTXEFxg="},{"commitment":"ZNlJ1mx_HFsT-L3-rWauy_ZciQg4WZEmu97Zn0mulRM="}],"merkle_root":"HLv-PTNnJn-M8skhWBqjNpKq65DDtFaiJ4XpQ3Gu9A8=","merkle_root_version":1,"fee":23,"owner_memos":["1YI34Hfx1_xmiye0YLPfZllSej3R6TokxysXd-6iG-sqxUdXOtIyb9iC9GH-W92isfgdgb3xo2I4JZeNynM4VO8iQKuJ67vpy-pImVDCkkfxPWUt3hXwxYK57TTwHQ9qVbiLMx3N_nWwSQ8IsaMfe1-PTYpUuCOv","Lfxw-xz3XErABQOUYdCUOfpIrSOgcrL0Pb_N9s6LxL7RRYeHGfs0sxlph-i0B7Ssv19Smf5Amseu2AkQ64MizPlbC03sYpPN9Mjll1miA6QUDqhjTAowPZN82MjUMTwgGOKUA0dT7HGcNQaZTq-BNwIK8JF87PkA","gAEmvIC3ntKt_O84Fd7dpWEqVozHDADQeg_BXKaseHEAuhKQ9rMTkRpvccWLzbqDf-Aj2I4ucRPZh2WYM2_wf7QAe-gaMIbHBlPeCzY1_H1pbSjeU_gJ1P2gFt7uyrQ5jqNJZhlp5w7hlnR2PwCAQdjZiMRTNM31_A==","Z3cW5xZNnAWrSk4TuBa28x_eZOYZQijAhd1sfv0vfaCJP_kqLcgWF6O7yLbPZg0ai2S4pzGd66x2amernYyjXabhlSHyDIJQ9owx3XUkAlnBqYMQ4IMHXO3zPTZdqKvzCfpLSGQFTj_Ka4HGMOZ2u7hqGl9BhD7S","puOat9QK4poNddahzJNHCVe28godM6B8CXziN88810EAiDWSKq2FKCyK-W0SN4NY-nQFecuJFtBeOzBOzDcGB023PT6QnDfmjV8TlQXiR2SAADz9PnzwiJnrwrzLzTqSo1ghlu2TNcevwFlqef-rk6u5n__GLiY1Jw==","NG1SO2FMpF5WKje18rpPbh4WX3YN5xSEuwxUPNVlDUru5E_mFHb7k3l5cOamzUs6T6d8kehC2wBHcnY5qGOB1D6icX1Le-aGLq4esfS32cSx6dCUFzrPsukIyJ1dCaz-Ap1OnWOC2isJCccfeC3ZK2oB8KpT_1WJ"]},"proof":{"cm_w_vec":["-h-rsBLlLOdI0hwyZYuzJq2n1HL4aTWae0tGuhQ74So=","TmxKTJOs4uBr48a310sIOYD0QplunBu3QUZozEg1SKQ=","2NgC1jTFYgBirMMoMetPiANxMGsdC1lfAxsch9zQx48=","lzxJz8dVDh74wHQ5qmV-4ns1et-3s-PCcyocv0VePRw=","zQb86ejUQDvLiYo1eQVjFu3zaRMwFHyVVDWQYUGTQJU="],"cm_t_vec":["YGcJL1jFUflWD1ZG66zHMxUAOK-viN1kb9qQGJQRY5o=","rqxB71jUikm_Cz1xD418ukU5qXJDBiOA9sDhQBhy85A=","JVMuxQ2LD7KR0pBzkwJAZaddLOoVk7iLjXC0RRCaCiM=","QF0JOPEMTk--SKBFWEv2Q6lNq2ap3gNsU2NoWR6GzZY=","BFGf122z45pkpAkCz2RiSPE9wqgjayF4NWnmUGCB_K4="],"cm_z":"Mox4cB1V9Jj7AFPUJT23N08pE2hKjF2x0dy45qDR1oM=","prk_3_poly_eval_zeta":"1fEprpPQ7rkE8j7lctJic98mQegMSIhGVxngWUkT7Rk=","prk_4_poly_eval_zeta":"nciDLwqnGsSgs7x--sqRDwfZibpv3Bp5kieGygqimxE=","w_polys_eval_zeta":["RVfd23K896wkyp41X1ykN_VQTK_7toFgIdUWclwZMBE=","TUac-0K0t2Ice15UI0iiYtSxBF61KxtxF4bJCo_Jawg=","CONeH79fwKMtSGK45CDr4RiSxuXRZa6K61PdcrtmNx8=","Aagb8mycunhhCEsvBb1s4_b6nOfi17zZf28UDFX9SyE=","M5hZInAsX8ni1IiklUxfgudGTOGEYXHFyjYtVAXrGBA="],"w_polys_eval_zeta_omega":["J4FK0EcAtfXzH5mOX-eYwkr7xaWVpDeEi2lzUmo5ww8=","QM_ppcBnmkCfOHD-7q9o6l8wRhEENqdKF2qpdwKCoxk=","U3Ho6mTEfXaimFOeAZntsh4Se8qu_wcAOZiS81vlhhc="],"z_eval_zeta_omega":"SwCUnLRgHmuDHar68XDzva1BZKNHwKqOx8VeIVp3rwQ=","s_polys_eval_zeta":["6pvXNuw3EUfUMdodd4Yjod_pZg6WkUncuZpY-z8YUho=","jApgfTR01U6461gXV-Pqrvi2c3yxSIrfpg7swdOLtyM=","pTu8AX9CW_SYY2ctrZAhOyLs6Qr6tOaWFbNnq_Lh8QY=","1kuYMqVO7rOhX5BTwsaXq5aYi26v5Ad09S9mwzflygI="],"opening_witness_zeta":"iai6pA48w7GmGVFRESDMpdoV9V9BNBKuGNUIUao5P6E=","opening_witness_zeta_omega":"C5EWdbkCLNpEoATSUZ5rVvaqSAIREnd-ijwZVEbtT4E="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"NI0a1Fop4jObdwdEDmgcYc0wqTLyzQ6_vEZt3pfeNAo=","randomizers":["l-Z3fTb3zQz3vWQVQoiQmpzVppds0Ect4sWrGGw0G50A","arJUxogG8Ee-vHMoJotpttxgtiwnqzhTmQ84uZSU8QkA","x_5yFoFtuCY4OVRGgBqAHIaEemOtwnX7JNKISxeMv6WA"],"response_scalars":[["5mjDsWwzbmEKnJigP08ewbL-DbwW1O66VOh2kiCkabs=","0kYzVZTv2FyeTePURoY-M2jmaRKXoV0xIgdXpe2y9lI="],["OW6khFRX7h_W3aLqQeedjgy5ckamb7f_lQdX8mBZ20A=","DIzbmD6Uyoltq_jbqAP_wHPPrfARUKMPH8E6Ky_yvmM="],["-OoFsMrEKTfGH17xOWpr6jtAMprhaZdcr3WT1mz7zIo=","uHK7ASpnbOPz2l-4NmsUHQwa4jAhMBvAllpN8LraGEg="]]},"scalar_mul_commitments":["OjIVgc3fFcYvr6x-WWMnOtVjuDENac1D6jsW3B9HNX-A","vu4r6VqiYNfrfyMxbti_2PfwKqdJxLDeZRWvZXtWQjuA","IBXQua9OPnT4m16jMdl9-Rl9GNBy3chzRFaJ6R2_5xkA"],"scalar_mul_proof":"Jc7dRTLx2HPoeoyyWNzi28PgtnL6Jwvuef5fgK_ZShsAPU05kuSFQ5iNSHMmAbTFZa8NimuWSuF94vkdKp5NBFMA4aBXbHtnA9lLGxI1x_58GWaeziM0d0KLkDVVofzPjNeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABACMatNrRPB8CC4_zX5AT70CIMtPDvFke5jXZ-VE_oh3GA4s9HxD1p7NqXDwA_AaGSJRT_LaHD4zVxH258IDY7f9-AT4vl6wfZWSqp3P0Rs01RhI1zLAjvT9lgmodnOld2iYEAnThj00DNeWTqlOMSrSNIr49GOjpvruU2h2v5t0Fzk-QAk8yIyxtsQ1KMzfy-RDASYcVoBrVl3-Ng5Szl7wfqqbYAyDp_fe803fVIkTXbnYP23B2wsIXs5zlFHemS0gx1uMvfIV6k2XhSumvL_xL9loawD8RwZJDsGvTVZ-Uvg7cXuXKdYp0fvN9X6moMXmoNIsIl-bMB3vIEEA9ufKIS0qLhCwAAAAAAAAAQUBlpaebvMkyrSy7ExHCD6p4-zkpfSuUGxB32Zijr4YDxCTS1O_E8AlilztqKhTKwP4nY8_qctdqnCucC0agm0oCloRc-buqlDQ9aVIUni4lHE3C3-XTqFh1Dr0BQ-5705wAWPYfAcAc9cBRZk-aP03orjIoaRaS-errzFNJ4kJDyp4B1A_RCXW6puureyeV1wUVTTQNCJXtKCi3hlAAn6Q7dCgA3lD7thej2vg-wV6qwQJgxTCHhCrNncwC2nH5tBw5tagA0b71wsrS7uOQRDKbDnLfZ0pWIoNKM6GPVMITk-M9wbQD2GDW4c3LUkOo0lol0I1LXbBtHt1-7D15e2OlaHsbd6gDXf2Sj-Pdkwczcz9WJ65H_FVYrijroYp7kT-qwwc2x_QC5hCrnHjpBcfPf7GSeBLzneARV0H_Vy2u1SwU5w09294BI1qC8jnQmr4lpCW58977ebmh9Psrha_tAOPLhmfcNeoALAAAAAAAAACALabgHW2MxdnIOd1RQNbPNsJvHNpDMYWVYw6iYfMvSAD6rcjJ7rYibspnfI8lGqZYQJXs_YGKiHsj_9BAzoXCBgB51whYt0jb1AtC2VRs3Six00kAqSPiZcLWx40ZernOpAA5pbI8dSVY4Sr7e92rEWzn5MZ3x0igI3VbHII5OtYxxgLYyVdBvywDi6j5NHHyiLzzkaE1OBZjqxQ2TsdnB7EsqAKFYvG4uc7C-R3sn_KLoWXBSUqcPzkmvxTANNvPMIa0MgAwqVL37mN4Zo8aW79TgRqhhhsDf8lUpb4rRUPxhtg87AHqpGc7HhqAJNSE2GvX9QU5jBtYuon_s9nGefjoRXi9ggIgUF5UNGruXazicCnjFWmAIa70PWBMbphLxkxRmcC1MgBXFs85D_Z4NDUQhRFYyLuAT6i_m-7uIWWfjuJjxNYn6gF7p4FGb54HfQZY_1pcmKHuT-dRJJQnckJEkIaeZx_wWgH2COHIuz_pXabQzAR92sakvkICBKHc21StWeYpSzhPc2CnzNrGeApyYDkxgdXL72O_dS6uAU6MlrUb941At3Ts="}}}
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
