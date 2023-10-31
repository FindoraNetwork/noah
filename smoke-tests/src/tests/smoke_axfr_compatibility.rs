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
                {"body":{"input":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQMh8P6rjrVJ2oYi9BmneL0NOM1HQnVV0a47-2wCe_lmYg=="},"output":{"commitment":"tKnwG8MGlRNlb2y-1KV8Fvv4f3h8fR3prREDEmFEqBE="},"proof":{"cm_w_vec":["5WQy6_NXcFU_vjKPF8vchnFk6_Zlo371uA2DmYa32w4=","oFSM1dDrbfaoHClcYSm200KOGrDmAazEQGNqshdOM6U=","TNmCI1_AgfVKJSTAO-3PBUaAjZkZZp5t6Jgw10cIpSI=","HhFjiAcF_ulPy5dQlr6IMJ1SuXLC54ULdOpdl8-zuxE=","95WaSIbwo6eVq5F4i4qgu3OoHpZdalgjF90Pq3VE_AE="],"cm_t_vec":["iilhcArMUK-rq4chsMh-_Y6bt58FmKH7kE8HPYG8jKU=","v0CT85PsKnHEaRx8m5G1aFH8j3p1D3y7cgYjsvRY85Y=","xlNNmwF9iTes84RGpjsV-46aY0Hpaj3NMt75Hn6bUAw=","mZvhkBmvNu4QEKC7mEUEdHuebedhJRS6rqPOHS-IPa8=","VI0-M3oQ4xAuA39hCG8TtmTqc8nLZnn-YEcRlLAzbwY="],"cm_z":"S7rpeyXSa4kclwR5KRIFyJav2xfT-8iKv7uujYei4hM=","prk_3_poly_eval_zeta":"1GwCiFw__02iXsgaW2NNy4uOgz3MS_wAgH63_DZQuAY=","prk_4_poly_eval_zeta":"Ho4kO9kZkbhpvgtDbR6UOxU0e4vZ4KyO19axGGn0PBo=","w_polys_eval_zeta":["o9Kkfwn9grxJOBrae4Y2IpSqSWBOcjC1RKq83uNIYgY=","-7DZ7xSVA64hdYkZIiex-GG-eiq5E2_pBOrIn206DSA=","BOMQz1-OIyXXLpufEDCsIOqRqga3hmxPseUKqzELECI=","777b0zaq7_1chQFauRbJ9h-lhSh5BaZX2jkQwS6PMyM=","jlFQiWW-o5ZBxp1_3TN5OQGaFhduuYasT1VUdfoSHgQ="],"w_polys_eval_zeta_omega":["-hYhV88B14ASJ2PkKJBifOcx6ooVaGZPucqUJ-2kcgY=","Y4dy9MjvdXJAOcFHcNwu4-lSSP-sTku9jpr0pB7IVhQ=","ctHEyWO2zNGHKFomBC__2LdOJnZy7Vo-7jKnxed_JBQ="],"z_eval_zeta_omega":"rlHFFb4OmWL_BZRXWjd6_-22geNPV6CXfaGPzPcB_xc=","s_polys_eval_zeta":["tiPvI9b3jdOLVmMnGc7NKFvaB16GjiifyIBCBveCFhE=","KQBT0B1xSblI9rEJU7PQcs92bDrdIh9ufImfDbNISA8=","aiBD1Jr7z9EDtRrAT7l2C8PQxJUH8kdQIy0nt5Tadxg=","Il-yex3vFC1gEk0R9qTcUCLXLMmpJX6UrjTOu9i_giE="],"opening_witness_zeta":"EwW50fA_1X5cbFx1kZ8jnVzjvdADCYhdEBxbHvQm5Y0=","opening_witness_zeta_omega":"tZTTsqFUFpaROLiqQVC-cAPc6YqIDK_-THGKeHF4-h0="},"memo":"NK0AMSEND4ZTnUcc2Wt-jelIn46gQZs_3i0VwqYc9xaAxIabZh3nJ3Oa-QIB6NpCLL90yRT69e5nUmtcL9ryGlUWcFNWFpLEXDMqfO307WbvjQZh316qKAcuex_GAWQsVA7Yg2BCgHp0XGDr9nZLpcYpHhSedO1UYA=="},"signature":"AW-iSJ3NILl-mEP0ZUXnkvoGOl87Xl3L0DaN1SFDxbihZ1wFBHSVKGtGbNctOqgFPWjNwyAGk6WmV5-iOkW-dSwA"}
        "##;

        let note: ArToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_ar_to_abar().unwrap();
        assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok());
    }

    #[test]
    fn ar_to_abar_ed25519_test2() {
        let note = r##"
       {"body":{"input":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"cRVMLV78rnQkFOVPLzRjHQnqSuKBaeKQ8MgmjPVrxvs="},"output":{"commitment":"MvNKo4HQhC-_qEUCmXf3SVnAiABPttCDfALkamT0-hg="},"proof":{"cm_w_vec":["IuLnZIwnvLzIWiMPm8qpXK0H0XfwczQYPvrY_7cswBU=","KLcySgOZe7B1xnZi_MDdtj9FoQdDzpjGEJnFifVCoqo=","F9-mRwvkK6XDrrgOGp3CVxh60Asp6ssMl0vEbrMGoKU=","P_6sBghwxeRoueoMPrywCpxt6mS0ZpBNXfEk-6kxMoI=","8batSn2mCjtCrYqqq8y3dt2AmmLkJ27VaPwJroDjXIo="],"cm_t_vec":["saAm05PTTyDeZZKtQXrPcwgVoC4OGN_j6X6d8ZqGxBY=","Tiljz3UeqDC5LskR6Tg_p3jDfMp9H2Uk_Yd643H8Ka0=","VRnEtrojxLYv-NLujlZfCJVgdmJmSaIyjAZ0pDjmMJE=","xQE_tq88q6l8qJJTiA12EkR9m-1fSPFPVDmsZf0ipas=","FS0i2b9oqGSqJ2NsNzejFAqL_6vIQTGNe54cb4OFMII="],"cm_z":"QqidQt_A1o7pwtEIq7fTiF_GKCdlWxdfWATQ-_w0t6I=","prk_3_poly_eval_zeta":"qFjzaw04xdxDJSsGMSOHj4LuGmqXzjzZMFlN9YOSZRM=","prk_4_poly_eval_zeta":"uPHVCT1dNhnW8xfCxT8LwcbYJ89FO79hkZbwWAi2MAE=","w_polys_eval_zeta":["mZg-w74ehZw6cIlebk8VuDg438KS4bTGI2Zhna3paQc=","2LRM_5t3gzvJnpjDSRPosrcw9_gvlZjToql37zgxwhw=","XHxVPy061ctKovE-30lLt7jfUxImTGthKEDn8ID8dBY=","jFJhNqrBj3V13O4UL1S42WzMxvlPDdesWr5kc_TBgyY=","SPuzKYVyrm47VdigIWeDdzQHO-Pj5iAf6pFrIbhFRwM="],"w_polys_eval_zeta_omega":["zvMIvCW4e5WWTiQz5Y9A1E9DU8wD4NsC3oHh8iJYvyo=","-IGjxsPejNvZzf_a0DAr1GxHf265BcAF78XhasXiGh8=","COCq-ADsYLr15LwHcIcjvpdpOGYQ6WjYGPyaRFtpKiE="],"z_eval_zeta_omega":"z6uyVZ4WEMqko_Qiv7DvNbTpNwiMIpW3Tbg7Xng8rhg=","s_polys_eval_zeta":["MVJfNlzjUdTX5aOZ4CX9lMOiRhalB3RaxCSLXLxNigY=","hSm0W8n0FW_RvXWolhlm9O5H7cJ4jQFDFPfm060S3Ss=","NADgJBOV65az_yWvn-h8jzxpuhgYCmglRh5lVuBdBw4=","8lFup_VvKujdvFSG1I75oicJDPSHhw0s9Rh0HgSfGhU="],"opening_witness_zeta":"scaOWfLWh_pVLwzDe0zti7pQT_ICki69WWkHvATeWqc=","opening_witness_zeta_omega":"2ZPOQ2MOiVjwiqx8_SSLsTgOHUlAXuYHqbBBhk2tRRs="},"memo":"HAX3lOWteBP1AsPkNeLvMHeJgJDOVqimItczXG-xpFz_IvxzH8_pmgMNwgoNFmxbzZoBF4_0BiN8d0V35vfoGsv7y7rUC8kjAWGumTZ7C0tUKc8pGBfDYCmdySkBLgUFSu92WsequbDYDWLkLUR0poL6VIvbGKK2"},"signature":"ACwcSGXCtlMQmHFaeDgVKVDeCkfJNi2wPN1XpYex8F4ra9fTSwPydqjNX3nTlBdcJMAC_Mdlr_2dKJhlTgMmcgUA"}
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
        {"body":{"input":{"amount":{"Confidential":["FmLHgeJ_qUTkm-WTtViHWcLcHLdyJllt9mMHJaJe9X8=","wCXEoK4E92jU9EFX7ZDiWQKht1JDb6ZsNxnho3zyuGE="]},"asset_type":{"Confidential":"zmneoM23AqnmwoB7eISd39OADxaz68tf4G69dW0kf0M="},"public_key":"AQKySH-pHt1F3pDeoXIWCY9eKeDMqbmETcb1RAqgeG7_Kw=="},"output":{"commitment":"Ww5KSJ870Sll3yOQNr4oy3LZKDFXoOpoLivatqYVViw="},"proof":[{"inspection_comm":"0gAdvfeTg6ndDtcWMDPghgmmdYKDgT5NnRhnR3-4SRA=","randomizers":["gup_BSA7OyOetcEvVO29rbalX_oPP7k_pPM9m8J6pws=","fLpJIimu0B1GrXQY22QChVxWdkl8syEMgwq28kMgHxU="],"response_scalars":[["CaAMgWEv0z5dcIjCIs9txLDeD1DWBlM7bVwxA_KGZQA=","X8d88-iXUhmjv_wCiV-Tlgh5bUYi3AUKjjDziZ1MrwU="],["uZgnS1DMDCH7ENFvAFYrGu1HxF9tNaGu_XNOKpm8XQo=","jLqpWeq62fcJi9aafmOPPZiJaHvvCPK1_nocNda3mwk="]]},{"cm_w_vec":["73bOWCFaq5X-YD0Km4wTSVX8mydfTCsyup44t8FaCRk=","WCG_yrBJTfFlWrTBgMzGxm8eIW2OYIsamsye86X2CQA=","FCtKjfKrL3YCIFX_mwXFI7Ab4EDPd8RANx9D8nnb-Zs=","iEmSDlhst4a3CcHjb75HpTVRdEL-OyVsS7ERAPxo3K0=","ZHrQxrVcctcj20sokkGMchLlUoazbU3OxGHBLoN4oYc="],"cm_t_vec":["ZdQ4AaGfxS0MhtrIAL6lHFlIKRgPk9GSf2gT0VurLI8=","7RlSDhWE9rg4QI6SrZop7Y3HQWJ7tRUnuukyoyt185o=","QTyuCFpOCHy78gjifkXzuYURXqfTY-pKWuCRZe3J1qY=","1svUoRWFz4RibKO7uAUpqjBO_5KYD8tUejD6rGg0RAQ=","YKzLtGPZM77_8EtvB-23c1d-H17aW2WRsR-kWvRYnwM="],"cm_z":"qiEHh42RsOBPv-BURkv_09oJK9-ETfT7waZwqwbRghg=","prk_3_poly_eval_zeta":"8iPs3BdWas6GmH_n66Eq02KmSCCp94nd3WF35ln7bQ8=","prk_4_poly_eval_zeta":"3jz6zk5Q0qi4AzwJiFZ6CpK7GpNvdHZYXWMoi_93Oyo=","w_polys_eval_zeta":["83hwa6V787jejBD3W3Qgkp64Nwsy0tv4UMqMi4KyCy8=","xgEx_h5-HXSa_XDCVwlpBvi_wi3Mt2iz-sV0jYxDjS0=","K1BdNl9G0PFrlruIs-FwAtXabQ4vywcLBXksCBfjUhM=","U1dJvzluwBmoIb11BYk9KVvapOvs83CcKlVF7mu61yM=","lh-83y4WcRFoVKCvLZCgfXU-lrd4e4R8WVxDQcAR3AI="],"w_polys_eval_zeta_omega":["t3EZYoLzj2siYw4X-E77P9iXIAYQJ-vyvmHgTbGjcRE=","yl9RWE0YqL8vthRWvg7hXHR-KK_SN_MxZ_pKMuviRgg=","CkyACPNZZHClu1SlBAcl68a7aZSqF68xYJ6xsVzUSQY="],"z_eval_zeta_omega":"3Yrwp6eDvrDJdx7MjWk3s8cjmu1c6IiFtobNghZ5VAU=","s_polys_eval_zeta":["979m8YdWuSUb_nR3tGagsDIWEj9UQAXilFdHzFcobyo=","VRP-4Uo_xtUgHVR-xPmdkNxbXnoxdKTcWJmOSjniQg8=","CKOl3VFIcI3BEiWxjc35o-ZB0e8P-S5-QiPHzKHUdRc=","NO9t6goEaQgBqPirCtglX9SMGljOtq7dR8JiBDnf9SA="],"opening_witness_zeta":"UdLYv9TWgLu_h5I1Pk3pFnFE9CEN8JHTXR7iUWQ6Op4=","opening_witness_zeta_omega":"wND0gJHbMby7nUeSHdoIpai34-b9UnrgJPZq_kmRKJA="}],"memo":"4J-5hWOiIL-L8UjNtWFjoTnXIlcs8gq82iUvG3C82EaAQzUt46VOsL9z3MN3B4o_VZ852kyQ3M0KveaYC7PDV9yuXeEuccwaRA3EA4hAKOcj18WqMGgeHj0rjbiThuCHGFwyoPQi3lI-wdb1Psjhb26opo_YGp7WvA=="},"signature":"AUWrMDBSR7YLCJLJMbfapk8hm916ccyDUAcmQCkagodfYss6UUn_Ikytkpow_GeYD-1nrXjGob60yM9Me6Q6CSUB"}
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
        {"body":{"input":{"amount":{"Confidential":["suuwbfBk3cXGde4QLtpFVQ8CcT70ulKjtIHCeBiCD0I=","1kHPAmCjg-e3K3wetBwSHBSS7Cd70jJqVxSDpxOlfiQ="]},"asset_type":{"Confidential":"GtYo3aIaQY_8OKuUPyHdZvC3wT4gtnXM_KK9XC2XIXA="},"public_key":"kkdptBeWeCfKL2tdq0ko9fbJRyiwNzS6MxA8Ho7H_GU="},"output":{"commitment":"DTApsFyT-SZfEzP-O69-l8C-XcmZ1YkPmh5NVSUUGxk="},"proof":[{"inspection_comm":"FUwbSqplfjgDwSdRasOXB-G-kRoyhRd6Y0Nau3hJVQ8=","randomizers":["YFWrH85owMIVDd0b0YhkkD4JRIrUxRrNQpSNEo1YFDM=","JOBrqYdu4ddyveeILX8bvjZ-i3Aotvxv2HEOHftOJnc="],"response_scalars":[["o-9zZwXqRkpLA5J5kUoUk1SMXhb3Adi7c-WMnd9z5Qc=","r21Ux6tfc9KA4OxSExYeVH7RhbMhxqEGP5m_kRwtvAk="],["6ecBxou2FD1ssAyaOCH-D8EFtd-cVDdXuKvAcbR5Iwg=","7rbCS4lfnDBFqT_w9QBQaFgkUkbxFVixDqR_XelMLwc="]]},{"cm_w_vec":["zDbMX58eY4tQUDtp3nTFSRBlEPOqPl_MaSZtiqtDBiA=","b2OsxAXSjYMmdihqOH93GCNWwv_dvxq_ykQPuRx0uyY=","ep-7r-vkuxLBHgd51051pEjItKo7L8k9W7Ssxz-wnYU=","X7TdhhpMfIsHYXS49UwDgxtN2pNGDvrhxb1so0ABjqA=","wqT1e5mSdRdtdg_on_njsaap5-eJSqYYETKJ_HJKAY4="],"cm_t_vec":["bdcDu7TWxCZF86pOmChUehUUwFW0VWSdNwtyJzMDdh4=","S6gHWQDOeM84AeWcLgwDHtv4vwNCo6xtlGhLmFBaIYw=","lgc75sIVUYfLwY2datwxox7C2fI0IGCnpMlnxXo_fSQ=","teKkZjszZfN7k6Hb3unW37oKrkyNdBJblj_3-Y-2DYI=","lOxAukSpff_eZYutZmuYaO2VVYQvWP_Yve0qV3WErBc="],"cm_z":"voLB0fwq4GkIlgOYAp-Mbl3k5Sw6mxFBXb65k86MmZM=","prk_3_poly_eval_zeta":"Zx2n3XRbRUfgNnEMhjG8HjIu-ldj3XiQ4M2R8xEh9wg=","prk_4_poly_eval_zeta":"_A7fsyU5TEqHsjD_WCJLAGg0XSP1iPD_hqFNukHClC4=","w_polys_eval_zeta":["HsQPh4CQlKl7k_V3fgDEykEJDiUmvNr0NobDrIS-lxE=","YHUQ9N6wiOvbO2OHfXQw33rAYLZDOHSq2Tf3DEzdBQU=","_lErqujgiVzJcrzOWlmOhqQqKN0EF_fBIEj56p7orgs=","btzJUsvlkXHX9GJs0WGyN5NEFpk92Q_LFkxSniC1ZyY=","v6oHQNtW6PO5eq4xyyoUTwTNY82u1Tl-3TzAYiV2HBk="],"w_polys_eval_zeta_omega":["naEYK3VbKZkGZf_-WM0OqauSPBB4QB-drcWwbtcp5Bw=","jbdyhWsnYfLUgHCNya4Ywk7qwIkHwBO7TJ4qYeO51Ag=","wCZjja08nY9a8moWFRCcHNWTZUeYX4IpzKYWzOjMFi8="],"z_eval_zeta_omega":"1Le1DFCZ0D_aNNiwxXP7M0uvoHA0v37J1RcawEQo_Sg=","s_polys_eval_zeta":["8pzQTMTpZh3jK4bJDx9_XsYtNH89MB3KsEki8c_n6AQ=","KXnAC2pvCfJteuaYTJA7OpxqRHqRkF5SlP2GnQXKDS4=","k2EBuCGZf-Peg2aZQ5ekQIRlY8Vbf_hkSg-QzL-NcSs=","05xvju5BcUzTgcZv0AB92b4N980J5-46M0VtmGPeJRA="],"opening_witness_zeta":"2an6IggE_29w1Pivm9QJBmq2hCa7m6sMe87rvuALfI4=","opening_witness_zeta_omega":"tscPxaOtKTKm5ZqaCnY2D2LFQb4aGw3jTVT2OSeY7YY="}],"memo":"O4hjVik4iLg7cTyRJ_OfDFeindqTVXldNgAxrbicvweChVZvieupS97x3lyBNDNp9_VAleVw0fc9j9qO-KhFe92XhKYdmrhCevF0gVUlcG8qW5nlzkV_ECB70kPX6oJQnE9Msx5SgwJno_f5cUTaHwX7tdkLNldC"},"signature":"ACq5ahovPKlApWFCGm-U4iiAr953AQEf62D9EDTkdqI6kU4UP5-Xx2n-gwLRtIHNycaiIz040h8jSclbZQEyzQAA"}
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
        {"body":{"input":"apKWyQmGzAp_KXj8TBtjYZ4MUoRx8GjUOeEi90ph_Cw=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQM1q7J2TviUpyXr-h_I1Q43co_cdRNzunox8koqLo3TYQ=="},"merkle_root":"uX0Td8I-c0xrMwhSXGw0ZB81soiyqgUxG3315cRx9RI=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["IJqz_y0Qgq8P6bVqhZWM3K8qq4a7NY4qk3tpbi-g2xs=","Tc5-8C9chHzDVCxSLBVrybai03heSHleOBVGSfz1WoM=","8I0ISAhqKVAtkCL8j-oJZYosfSdr5C4nUGods2GX0gg=","RnZl1DqrMBQYQVB0apMpiqDvZNIxMA0ethOr-frWjyM=","DWlc4HMIPIrKoQ4PFUw7aLtZUQE7-ffdbUny4VMBphQ="],"cm_t_vec":["Sci3c-xbYaTGmA_qnTBzY0EoMbIi9gfpZOfK3YBQUwU=","FESynBaqEVVG-FtN-olM7K7PjKPy2VU3W92TZlCAsgk=","iGc5ml3xr_M2j0COucy03pFD4Ae72t4rSRmjVxZH8aM=","xpWY02arIrGvaqQt6Qyc72roVN9pcj97lKKz6zaWNS8=","9mnnaW903IowsNBkkDKWcUea4dcW1Yn6-KzTP9zl858="],"cm_z":"IyiEfiX527A2yq9oVan9F39MyAbRKeMUvyYUR2c4lxs=","prk_3_poly_eval_zeta":"AgNv_il_nMZ53qJscn6xBSE7AgW6zN3KeHgP4S8g4xY=","prk_4_poly_eval_zeta":"ZPCEfWgBImxlB8G3d8gik96M3M5xy-qARe3D8cokJgQ=","w_polys_eval_zeta":["mCBba7p4zbAxZI3G8qhwCf7UC3xNLdqIyKyn3uRCFhI=","aYHOsVCuxjJp8cmCp_YNcT4mcPoL5Ce6daZ6j0slKR0=","C2sGWqSGIApEVuXKW4l350OhSu8RBKAOXAgsoau2kiM=","KEEsP3qJ-Fxn5li_R0y-Fce6S_BsswT2EU8sXs9yngc=","5iRjO3Ul7ZvQlfyEivRaO3lVFttdiqWYJf9j8KIojSU="],"w_polys_eval_zeta_omega":["kC6pU7zf0uQvEXJDg3CRTPLhm9jEkdVDCF1FQfuIAS0=","RRWxomTAQLF7eglHTwILD0G1Rcr30li-KIcwPmmrqA0=","bParBRPZ1QVdOZfpjkZVfLClvR6j1HtIObSy9X3lLy4="],"z_eval_zeta_omega":"dYYW0q4LY9RdZMc_hWLav_-icaAHFcMjtonJge6Nsw0=","s_polys_eval_zeta":["67E_HNCY-LpSgB11aqmwtNZT-D81EQKNEpnTH-PB_Bk=","YUb2UOkAiNBMoE3u9XmPz2BoI0b76y5kV184ygp3EBM=","DGddhgrgV7ZWtQ8dpPFHe33zLEgWIcGCaW9g8BmHahM=","2uYotgE-bFq2qN5NlKrSir3iZSJDMgVYLea2bSGbFRE="],"opening_witness_zeta":"rm6VbfWC-Gh_51NwHC4TRzko1FDSbmIWO8gfX3PHXqg=","opening_witness_zeta_omega":"O1OKEthuOrUbZ87RRIMSbchu7nRQGVBft7qor12Cpyg="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"miM_HQ2DkfTG3JumIIvX1ryLCF3_k2PT3vpYxmLXdA4=","randomizers":["yptmHBLSla2IRLftNlkTXm94xwQzgt5zVlul7sK0SV8A","2fcgrBBSmgX0_9UM8bagtPi5nuVJcIyDpsmMzfhkKC4A","nerjA7hqSArYLbOLigNtGt3Ywtc6bwCeclRD0pQV9hmA"],"response_scalars":[["bUWLDUUoEhslwH8GftYg9EdxI2Y5qMEhT5FpzXXI1Mo=","GZPfbgikwLQ_Aj0KYt-NVqH9DpSKsWET6smANFczsm8="],["dA9jcal0c8PKHjDzOfHUjoyLLUkaZXPUwC8zcYG1O-k=","K9Ao44gzn7CwjLEl0euC0WWngmr98k9LeEuMwcnPqYk="],["3KfaQBZgB7HV5VIKvup80xvK6JC7X_Rg7tx_6r_PUtw=","Jjo51zNTb-RktcOF43yt68s8jnXg0AXgDV845s4vV4Y="]]},"scalar_mul_commitments":["5EegY3L_-RVMYaaHcYL5LQIB2svQsaqm2hEVS1jf7PiA","1Ozx4zPpze70fSJ-xs3MkUIDtsfmJZZa-Uus80mQGNAA","z_ymYahBZVisCGdcUlYl3vSCu2WSPTMd5SWFj5yf0yIA"],"scalar_mul_proof":"jFArbC_QQfC8FcRWRMEEOaejN5IEn-Tt3Qu67UrunxaAU_NXnbXEd5n_DfoMQdwfcF08Y8F2fuVvwDqbPYEB3-gAKMT9Wv893R8fVaqn4H_TKZZbCUS_y7qPLwvcx7Rwrx2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAcOb2NlD7s8qh5SJsvefGuyNZgIDAyS7ycEkVCB-t2Y6AkDuSImkpMYs2lVxFSWxo_PJLei1wxbXcsqQ-1k5FCASANxuwWpDHuFUdf8nX-Il7Tnu0NWyOWZG_X6Wgrl79MsoAEYhbVzZpI7T2WQqsGxoEwBZKfTqSAxlbWPBqq3cI21yAzx0NNN1tXdPdHUw7XFAanUAgOcibfwhYKM3zzth4ifIAo-BvtwZM8IM_Gyny_hMF2BiEJIYFury-NOL9bgGmJvMVgh3ZP0Yn2pC9Zg5pJCjDjo64-pDwQskWPP6HPnzLz1bJu6A0QgYnw6lBcvNMt2vf3N1l9NH1jMDv_tbzOHALCwAAAAAAAABEcq7ApBn0bTlLGp8G3Q8THDNVW_33VkmU2I6BWo0oEQDYgNgvWXQG1pcbcbDPucML-19VxCk0PHn7Rq_7Xkc8lQDv1aVWxC1wF2so-AjiQQZZZgeQlVe9TL_maNU0ckKpBYBmO_2zmhYgg-cmRtxu9H7k7Mp-nxlC18XqHFCFKCDRpICrJRocFL3F0hPjVHFHNM2CrYxvSSnoE6KKF1GGDF7F-4Ckr-iHRj_DYPZmxkmelaV3QoMJaz8UUHoDQDAvfpE7WwBZngbN1cxILFLTayzTyvXIZn8w1cA4dugN5uvUo0wbiwC-ITz2pFNWxGRVO4DApPQ1Trv6pOgOHOIN0u2yeYCTwoA9T6wwQbCPtacN0vYYHlTH7qfvjntjdTisSlni5mQq9gCBpxy6bTz2gqYlzQjdpS0rsg41vzf577J5ECkWLEFZyYDx7p5NVPCfCqXjfvUjTlME3lgRigSaMUL5MtnkzQGe0QALAAAAAAAAAOC6o2Hd5IX68EOpYu_7Zbm0cIX3BKICfEx9lkas1sj_gFxQuTb0iJGlF3UswLoSPu6yvDOlqG0nTK45RnpmxSiegL7sTjZUibOqYcia6yiujsBKABjXE7jdybyoTp828GDcgMo92qN8e4SWzEAb9EpbDLissZIjkqhXiEXcAzdmRIl1gN7LJHLE9YW4QJna6I_ItpokR21emCDzCvyrz9buyDHXgJgN6_pBH_iwZGtX03in-OkYY_Ik8ftFQZL8JQxyV1ykALtImFpzSfHjrGBRDHP_6loqtIbqo8zfDX7v-9DDN-GBACC095AS8TE7LK847kJrE0nvg6iUK6NfNpfHavebS7nRgKwChCY2phGFtgnqugL3rpAne5NiC1sznXzMszRpFI9CgOxQSg5KTZH6iUulA2UNNvurBkR-JYPE9mSU5sFRN07RAJfTgHYOBqaNuF4UtTfRke1QtAEPax4bZ82kgvj86hcrgDOeAzQdyYqN9a6fPjNgSpNQAdX_ZHmCvNtd4diu7MHPKenL7sBbyxHQXnatFUohH8XfIwgAdQpiFo4eej5LawM="}}}
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
        {"body":{"input":"k67PjKPuwWYaWXSgQYXWr-b7nyWSsAFF8kN_kAZ89Qo=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"K8luQvyEzZ9kNmR2g7dY3nwloWv34uOtwekcvy5VqBc="},"merkle_root":"fKM3Bgmr2I5e2J0314SDp_fSnwyH-OpYDWcEpm20wxk=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["xNSNAnXrLt70oeXYcCfn4MvkdV2BU1unKAWMGXFbexM=","rbhKmfvwFh3QkwiePzX8bdOrZ3eTKzCM8MqY1J4EWA4=","6a40OX8UAWEu_R9Ngt_RV11rZmoJNhhvFHl9wwwtU6E=","FNbyLceRtqrHPAkOMYqXohIxkrfHOJZKDhDL2v_vwwk=","kkIzPcvLpY0BEtctdLl3dXbLWvKPTUfcupZKXp4HGCs="],"cm_t_vec":["oG6svfd7eSR7nkGZ-HBEJLC8AlSoNCiQnzKptQnXlRI=","snh2SZ4zn9Uuk20ShyljZPE4U6pIfWRic-Itkpd_NZw=","dBuR8x3gmfsrHFWBVs3WIIDuZ1lZTkKkH5hYazjq4qI=","FJ7n67Q-AKXYILrpg12Gwf3jJ2zCSpxmhwemeNWVrSs=","vkMEiKPH9IxeJ0QfI5BDWfA0Pmu8d_tNYJPqlbCnhaI="],"cm_z":"IXom8VcObf9QVcnybGuwFXSBrTNQCpV2K0BmE8isGis=","prk_3_poly_eval_zeta":"UZ2WIOz7ksPgxrsze_dgQdjj9Hls2L_UqTmmJdbhzRY=","prk_4_poly_eval_zeta":"ap4uqb6-JER8ihwuVR1066yXlHcjCzU1U9PdbVRJbyw=","w_polys_eval_zeta":["S0IpQ7UqKRXDTaGL7lZvWNzBno73xcninBKXkvOrMy0=","KpM-Kgkaj0skrpsh1x_bvyPOTlu9hh2YmZnHA-NZKA4=","wc6N3MrL7LdZmKbDaVJUGuunsWw9HTFBhigZzs2_gw4=","oaR-VW7GPndu8tCI47tK-TQWIzpjN8AH_w_PJOzaQig=","4jsrUyalZbRYaYvFyZi3T2SHyWGgWQ-5iQjROXFVCwE="],"w_polys_eval_zeta_omega":["Ywsmw6xh6BiWybsQE2elqP0UXkkdSnKAUo7xvA4Ggyc=","7p2XZZ5oOTMGJ2i--abMWyptY3sdV9Jzvz1A74U9cw4=","KhI2ezu_JTFPnPFXjLbu4kexebr5MUVzvUK9X4CnjBg="],"z_eval_zeta_omega":"VbljoxvB_7EiTgPNSaVaPL4VpilRCrzKF0-XL09qphI=","s_polys_eval_zeta":["HGbrhdWLIRZvJnFJcspgx8BWRTh4Apji8KhrTJfYwwE=","93zspbfDnXssPofLL-LFJ1exSiB9ygChYP4jNhcybwo=","dsk_iEickVIk_dN7ZoupGfuN1J_UxtA4AROGL8gEbwQ=","ogJ78oiamR6xbCvz6rNPqBiTTnVyIQ5pcnfbj2ZzrAs="],"opening_witness_zeta":"UDkJQ_UFYoo41DKTnJxCsDXpfUtz2gIcz-XoztSOOCE=","opening_witness_zeta_omega":"lHjQFKkA2hEYZ0CIcEuf0W6ljXvHJv2MmiFf0rf2kZA="},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"6URxMyKOpGzcCbJOdH7XAmAc1GM8oMe-adIONJ6WiSE=","randomizers":["VXprI1uzAvH1_3TqR_DDuJqzEiIbNiWxbqUpYOzuYluA","mo3KSBnxbk3Hy2AZZiiMoIcySHS1KSQncW-a5BHS9ROA","z9p97lFc-B6zvWtAGYX2W6ZYXvR1kPT5yD17eGHsTA0A"],"response_scalars":[["L89EpPlOurMF741lQo3Kq7KKMux-61hbPgHklL0fDRs=","gSQaHfnDgXZRHsGzX_0VAc9Zv7jQha6StGGXJrRK4DA="],["QlnYXMwxnCK5zU9r2m4_-rmUWu4Ia8W0ebEVYO998QA=","kRrcuaAFqZvV-fAs8ieYpy52wWe8jAiLzDuMJeVIaHg="],["OZZE4Gt1qV0Lm8kVeJuakI8Ev-So2gmto-d01FFyFgs=","ZMoHvbhIaazy8snbrcEtMRtapkjZ0euOX1RwT4_Kw2A="]]},"scalar_mul_commitments":["wc9pyskAdulHwD-Katm2xoDHhRKD647nBqPB9nlb5GeA","AKwC1ILssdBsGYEyJCEnlvQHWdFYGrVRb-leZrgCW2UA","c5LP5CVABAmxXoug4XjmtyJewNRcP1jgl-9IfW_HwR0A"],"scalar_mul_proof":"N5CdJkjmQ2dXtxgvtl0vbRjqrw3IdWvmXIaQhAu97DCA4izGkywwKGUkGl9o2zAtRqg8uveaYlrTIrKbmXO65Q4ABxboWzMfcaDiqYHIyOQfjIgpAgWUtfOBkHUi9WOmtm8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAix6fb-0XqgH7N1pFnE8bac-oQNACF3JYBW3mGo4VWmSAbmTjHhinn4jX0-HtzJPTgnhz_EtPG56O_x_diYxAOzGAYwm0s2hqXgnRjV00vyKKctemrBrph7-WqLjf3yMzDxqAdnsZprNuM2xZybLiDYMb-1kGsUivLeeShUIah2DndE4AP5WJDA4pRxFfDr1QUQ9ffWf-AeOlWb6rt2wq7hu0hiyAC6tpzm6yozRtuOgdE6beBuj42oJzS0YqBRC25APrcSPUDpz9QlZoQjfcdkG_B-ut59tSIFEgTKnE8nVTQgfzHyR77vDn96gw3zmIHCLmKMnfYjx6bpqs-jywIoVsGykyCwAAAAAAAAALXsW5lR1yeCUegrn9AX9hz9UGl0MQal2UvOB9ggWLUIB5qqJ22MxshwIKATQ4QiCzOkh_IuYpS4eN_4w3JixcPwC9Ee1NrRkCGZkVIB-AGMnghO0AMbEH3HiHtJ36kkcVbwB7Nq5vd_uvMgd3JBjCTYphqrVNcmp62FZ7QKYYcFf5WgBSOuomraj9hWVWckD-d6OvlkMQ_Aph2VKMIF5pYGp3OQATqL1QDALtIl5ZLWz_BD9AFgzicQCZCl3rYXw3SZ2GfQBip8ipHCYkdY0fKQQcNv2ZcBISvPqnZN6IYdLSOedQBwCAED895dh0WK3JoYc2-6S2Fyzg_BUgOj1KeOeuv267dgCO6zXJ4qt38fRSQDeFSsMVX8qYqHsBAb-1sgXUgOfUP4BYwZeZi4kHksI0bqlFijiylXfP0c3gqv6-LDkqrRs2bADtbDCppfC0j0Z9aVCURDwLT1uMI6_l5KnPADrNl1CxIAALAAAAAAAAAJmBjP5D2BIg_iRkbPtZahaSuQHeHOmLa-IHvMQCLr59gBJav6qKF_VDAPv1xbdz9b2F2UP3eMoxOGhzjVb8nelggM7fDKivMenV1jxv8VKU1CYg1TDxV60RX2GjSZNoXItKANXAY6jMZJAv3hoJhYJ4zpjOsZpU2NMX6B7ttvmbfSMZAGizwHArjDOhDualcPGKwYtXw0otTL0qJie5O8S7eCBuALdwEf69P0xNqekuWmAdwxU0zPTM1KCqY5ef9D8b9VxagJqwvpFURaMIyeI_YlqH5Od91MR7nGcmjweOhdc83jtkgH9uLWsJ5bx6tUahFFDawRdQO6JzdXE4XqJajRUW1tdPAGBeo7COvfw4xzZRobZnRPn0Jca5_sLcS23NiY1NlD0SgMXagmbKzftYwMseRB-WCJnmjiAiOGeJ6WMwC8ATydpkgKJRmB0SI_zjxQxT3FUYig7Mi-U53nmPz4FMEsA4aN0XAKpSjwbigyoI8VEjOI7JemiWUEIaIHOhde_lmg1elh9DLCY8F9ejxMMOG5A0Y__LBv--TlndDwUFTVUbE0UKt2o="}}}
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
        {"body":{"input":"NDJnXDf9z515A974JjjscrYVPV6pVuTYq51P2Ozw_wg=","output":{"amount":{"Confidential":["UkEWKj_qSzR-o3GQjLoMm3WJ0QQPDtFoOJ-AvWHPHng=","-jEAWL6filqLblas4wYU7WAv_lRD3PkADv9OZMHZI0w="]},"asset_type":{"Confidential":"kL4C8ISLAdpUAIhSICHgEVAjflKys8iKMOUtW1i_Fjc="},"public_key":"AQNy7Lpja6NtegnvJ_fFpqBuaLnuTF2-gash_RtNV0bBVQ=="},"delegated_schnorr_proof":{"inspection_comm":"EoUsMr04cuB7LkPsmqVx6nqUMtBg6Vrh_4t59_LGGSg=","randomizers":["_DkQirSpO6u0v9qBzmTD5ZcSBtaWdOdxQc9WHUSAlHM=","zEc0xn3FwYe4_WcaSCzR98CGyMCYE-mUeog20lluKiY="],"response_scalars":[["DN-dLmuReBeHmK5uG_oHwic3Itvj8rhikdMvRugaXQg=","IbLy6vsSoIItpQchz9NLDf9VMuEoYaNKdlFmzZ3_Wg0="],["EVWs1r7SnUIkVPo3hgUrcUausimOQKD_77QRZ6xxhgk=","MGxuUomRU6TK5ezdiiVsBWQfKRNN9dD6oc8yY_9uWQA="]]},"merkle_root":"p7jr5GZFQMs9-uFTu85I_AmvOTnDWQZLykfamSTYLwo=","merkle_root_version":1,"memo":{"key_type":"Secp256k1","blind_share_bytes":"KCIco-L6RrhRLWKGAoKzkEBw1_D58UjT8MOsQKTw0iKA","lock_bytes":"gqkTa_mEtyHcgupgX5T2lh62rPB3HjQdk1p0Z6K3FX-A6oZ3xcGzNwqGcQLF7uj7gEI_NGH2FMy3akguObXqPm5PhZ6rRacWQ4eRkOa-5-gNQEnhcUGBm-k="}},"proof":{"cm_w_vec":["M4MkzcB_14NOBc1PHuWKBW2tXzWdRZopXgOMyX_VKBU=","XYo2_z5mxvzhEXzqRxY3xA_8PNuD2QDVn9pGIf_PGpg=","y-qfSn9l-VI5yz09dH5zKLITll272BzhZ3DHdRaOsSk=","0nd7WgBcPBIOX7KgENhnsYZW2CAXu2uuwSPet2M1ERw=","TDWv1_8SJSQSu_7lW9Ple7IG7EEWc4_L-HrBXIXEXyg="],"cm_t_vec":["uVVBPQBpiMuCFFiQTpiD-6q1lkYZ0EKrKZVmiJaoM6g=","KezVf7mILhvLfhVv9YDzvAg_4PVO7OyUvXaKo0yeVq4=","30K4jEWid7SNJvAQeMveXqsab8MdpRTpFNHOLZXa5ZU=","ixlIH_uo56gEAChrppG0oP4atijQ3m-jE2lgJ-k34CM=","BxpgyVQfkQouP3jb1NIm5Cro0ULCUxGF6lsmWUw0V6Y="],"cm_z":"tm8d5OKNkL2n8X4kprb-FV0lDGlGt1S70xhcMXsRUYY=","prk_3_poly_eval_zeta":"Gvp_hvjqcC8GEJPyd0eVJXi2gw5hbhagmBPZC8cR5RY=","prk_4_poly_eval_zeta":"kyRYCbGL-fRwUDA4f4Z-Y-hB4qQVNr_5DQFq89arHx0=","w_polys_eval_zeta":["zdKCGQruGct2R3SyD2FGuez-pe2nq4MNbXA8qza3bhM=","xBybXoy2DFBhyQ5MEUpc77LVBYbpS03mMKsZ-81bUAY=","4xkJ-S1H1oLVpNidwZoW8TJD-KWOJrlBuqKub6ysjQs=","ilhPpzZsZh2xJWulDVbK_NoMGtISy68NPlUrb0k4phw=","qm0WjEV8H3e5k8IzB9R7ycGhFbZ3ZsRS5xbVTjqBmxI="],"w_polys_eval_zeta_omega":["GshFsqNliJPRTOILpo9QRdEVrxztD281N3aCehsEWQE=","pFNxvWxfoHg6bFQ_RO3mG7UiS59TSCJeDgedjYgH5yk=","vBPm_jhS76swYW4KRpDFcmTIaoDVkpZZaRhqhXFk5BE="],"z_eval_zeta_omega":"nn2zi7WBuNAhBUJeuECR9GStwxXIxUXDVWU-RyKoCAI=","s_polys_eval_zeta":["MdxIyvqJoPhmc5w8QsP3Xxdjd_WLSdDrEFKl-tw7qxc=","QvdB6A4xqu1KWIoi0HOIoKQlTZ59_zMzdeMMi2NSAQg=","7ykxqEXUokOnLZsg7mhHoUSMjewUrv6oXVCPFM7jSQs=","bIC5CHSbeoBjbV4BFW90N3aCf15KcsounbtqDJ05zgc="],"opening_witness_zeta":"nWkUmR532jsF_1FoRw6MbASM4CFyIgOgN8bie1ENcxY=","opening_witness_zeta_omega":"9PJz2kXIiPUIPw9kU9pokE7u18vzEmwjJSEdx6Yqwqg="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"S9E_mpvcNq6nTjh7pqJhSuAhC1H7_V2iKwbznMR3Vxc=","randomizers":["Xe1GpNY4uk8HYTwPMaAUFi1qC1gLC7xPO0YeVmX_HvKA","v64vxjzGYJrZMXJ19RjPH7bhbNaM1K1KGTf_apqWJQoA","M3dR2Go-_UL9p4QmVf9DNnRuEDP3eNI70XgzM7-drbEA"],"response_scalars":[["ZnttzmaDU5qv_0dwpWK0fut05LO6XB2BNdgvy6OQpO8=","EpDMrmAWPHuOtC1vYunLwtyxknzzRSTbWlUR62MNmR0="],["1dCHJEJvgADJSrlwF4b0o5fA3WSEdnl55pzSjNdC7UM=","ZOXntSgP1WGX9GbnF85myi0fx7WWFjhBRG6KL5zhrOI="],["1HJE7guSONS4HjOuPTWH3TQFwm4X00KxcF59yX0-Mgc=","JLwVEc9RU5F2m9eas7vswKu7FNqEbBEtxgpjf6hjVrI="]]},"scalar_mul_commitments":["04TXzHheU3JAc8h9WE6ak9C_4HtoD1VEvufZYNsdVKMA","Lr4NXY5uBof1QLM8fZ5pMJn-Gc8cPj1YoQrNW68C_zcA","-HG-q-5_ciisV8-0-MXEj55tKdkioxbRW7LDvHv-cvSA"],"scalar_mul_proof":"oYxvqLzx-o3CJPNMLVi53lBB9mgGO8_qFjbXQIbJAYGACu3hcUVWNXlasVWlEtcfYnpmvWBrEa2iNjfEX1G3Z1iAZ_IVwO-ySYyhw3Y8vmH1-I-HEYhIjWM8Cngxb6uRn7-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA_R4Zj_TXLQUky2gSz-tylJqlWrqKBKk71GBZGDZKC7sAJ5J2m5eZ5xObYLdOsMT_xGcIVfpjGnqgTpOee2cDwDuAdBkOHb6MPRkuAyxw_bOEOcnnWUTtXAvLRY9y2ZskHoqAvZUna1fnIqYk9bi3i5lSFB-qSWOKC_kPcN6lmdyzk_cAZ4BdS7X4xcQEkx3JPKdk1m6rIi4aIw9yUlHgqmaHrQeA_E6LeOXQLiZxgsAC1ofx0fJr9LoGphtbLDCtRA-_YdEfKIY7fF2cNMrmNFl0EwDXszpaD2gYlGM10bjRnfT3qu1TDpoRMBQTpDsyUsiiz0r2EoMsvuiK0IaEuVXH4-pcCwAAAAAAAADshCMUuhQqJtz1dh2ueNcPV8DghMRHdIr-Of4MCmGk5gDxfA9lotWbyQN2A_oOufFrrjSVPsktGx2ohvIWdBWCqoBO1h3B_aX9pNAUvb36rMqhJzuq_JJHJdtA4q2N1u61fwAOyPkaRYWAP-gOGFUwijS2NZ2GJCHkMhjBNKpFP1iHjYCwz4OCOJ1ziSjGYkOQ_iZNsIPyVpQ6i9nAwlOm9mdpigAz7WTY7W33u4fQQXtiPhpM1bgOJolEwGDpXZcJD3MSC4AKxfoCO3tvlelhBmpr3E26F3HUBf7tIgmTqtIDNEwkxgA_JAZ1yV_y1cJUIMKEmb1JBoRChN6FzmoPFotj_pqSyABeACdUP3rxdTjlVscmKOcCBQ3JFxpSFFw3GP35kNIy8IBqAm__9kWeHVLTWLxk_XuFbhiVVi5A131G5LprMoePMYB2j3iK4BJXeAT5PsPUPXZJFh23y53xybwqovZO0v4nawALAAAAAAAAAMFkGXocL6AR711HeAhlRDtNNJYwMbvs_U0fGxpJRzsIgPpLZwy3aVdzsDkBC8198fOs3tgz4fwZb_JY0ZLDfSyZgHdVB641Mt9LMB4f73HUku6zfLyhnKG6kn45IrXctUT7AIpXc3W3qvVmdBlFvdCkMXMN0FADVuc6Mb6zmfHTLKLZgFtt_ZkrimCHOBcyQVYfKL-hw8daO87zXOpFekvhBo4SAPXVOmz4RHSNhd4PQdJumSROg0h3VDq7CX1Kv6SU1DnFAH5b7Lowly3GSj0vQvtUoN_jGOhgv0nZgqbE3_rGVFxPgEE3QAFO5DDsOVm3dNw_YGsa7jweg2L-dBCxTx6kX7DzAMxyQkS4SBOHzJOqA6424RZOE5bGJIwGh7hgLi3maOjugKCbMnXJxWwt_VP6H-FBKhZbpHwNTsL46vQ1TOBDixmcgM0U6o7gozLkFKKHDWjLHjw6wLN3pTPk1RSV9baXkvubgB8TN729CgI7vYGbgqeZyG2i_MgDkK9ypv7L-eI6Mm3F0iTfIfbQZlOp4ZhNlalrBCuLjW1qfM-lTqFJDaWJqvM="}}}
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
        {"body":{"input":"faXiwzATNf9uJAKpOEMlfzgwloOyTFyRe11GcF2aJSQ=","output":{"amount":{"Confidential":["UNM9z4A_mhW28CN5f1_pAKFWkEl_qgt5I3RRoTaMEAk=","nMxRt1KB8PtaU6brvpepYNYmIIB5UsNan5picLbuJWw="]},"asset_type":{"Confidential":"qFWAWrhUBmhIeRIJrK1TxsO8EVfDAgVu0fLU7GPxBHA="},"public_key":"neh9Dg5H2Yrz4vtERIdh-7fDMiY2fM22GcwnPnbA980="},"delegated_schnorr_proof":{"inspection_comm":"y7RDds50Wchv7WIFUHkTXvJO2nQLmYxwWMNPPfP8MR0=","randomizers":["TotPpENZo6Kgm5BoT-g3NA6qO9DLCNsFBRnoyWbjwlc=","NnC-PbIOlgaKU9vuawzwuZDCAvppBTW72FLdiMldkRY="],"response_scalars":[["E_58WBgykkxUmlhPxxmM22dZkrSzOYmj5TBxn151hwo=","n1q5rcRkXNf8UUxoEL-Qm107J3Sr3Dmti-o6DGmvFAg="],["iPxcXZVNaF9g5wc_dEYwAvMdQOI9_2QCg8QMm0Bb4gg=","J41wksXCaSlcfJmWjO5sVzTTDEABwtrLH16Z99eVlQE="]]},"merkle_root":"PrUqyLkSrn6jrMfqLND5767kbpP2Fubi4jt0jV39Uwg=","merkle_root_version":1,"memo":{"key_type":"Ed25519","blind_share_bytes":"u-s4kP7MJ7bY00ytmf93ZyPIC9UMmn1EkrHeJeDNc0E=","lock_bytes":"xjua-iqThOpcQqSHSBIHXffAoejHxskIaKuAfSphVQsGpSdVb_Ol7mej-VYYdJLKWyUhbJz3cTnFXayoeAFyCvqfFCqdjThM"}},"proof":{"cm_w_vec":["HiO9E3vFlBXnW40QU3gezwzVF2luSlXc4AA3LMKnMwQ=","y5x1DelhVV9CnjkBtSJN4ifZgGjTp0adNyDrETw78wE=","DEmkOqm78kWSRpa0YXErz1CP1xbhbN90gvUlPbhQqoM=","8OVr21oZfvPn-6Lte96jl3MA5oPNCl1b4MCJIwEqt6U=","Qh-m5J3dfWjF0O-Xen870toNXO653okuBGTPqIa4f58="],"cm_t_vec":["_n7nb8oMi7_SwIwAb9uWwjKekYVxg6wbDwKHbzFLCyw=","iQFqOZfGUXbBMNbIYwR-0JJHtDQOk7J3SITpS7hJ6qM=","tw86DDdEN2vs0lR8R4K8yEimFEixG-IeOJWdqtcAfoQ=","fh675aIZTgdnsqxbpGHYn1mDT6ShAQJb5kvhqpdvEi8=","87bMqiA0LR5RDW11R5ah93LRMBlvhtkr2FWalHD38S4="],"cm_z":"YZjlO0-PXC1UqUDl3W2yWmKGqmMqJqRBwAVx_J2yFKo=","prk_3_poly_eval_zeta":"ED9tieZuYRD5FO5yflZei_wLrhIFMoAThiXbqxCtdiU=","prk_4_poly_eval_zeta":"FNjXZEAaG2-eHfqzuullOSzvEAJhlzkdtQMW3Wzs1AA=","w_polys_eval_zeta":["S5P13uCh7aA3cHjihu2qoO89eU3vllhwitb7qkKa6wU=","aOWAJanH1JboQ2PfF1I5-7V5FQG4UEyKWiqBxyNdNgg=","tfm9Kjl_4hMHBab-rQAg37Eiz3Nw9SGsvzG7h_8guSw=","D0I9agLS2fjsTHDtah48gqoKP5o0lXwvJ19m7OWUdRg=","-IN-JBynWddRvjYsVe-xEkf0hDBRxJR43a4rJq9eWw0="],"w_polys_eval_zeta_omega":["tdx9OnqpmmK8sLzLpmjDNv4RM21mGf0VNG2PK73NuiM=","NDiE5mv0m9to7xnG9cWxH-rFcse6tRvVJ93hZq7H3wY=","nGuCzWfrdUETpJiRq8LAz79oFsGYxdWW2Vn4vX7_0gw="],"z_eval_zeta_omega":"bhbhxdaNyme-i7MWPUBoxEp5M-leFkD_9b6sWq_gLSQ=","s_polys_eval_zeta":["fyM8xO94LclocgocmmX2DAtuTC3YOQcUXZFBWH9mvSo=","yF-tNnsCvelT9HAW0GQaBmeK3DmBtW5yUTd03hJOwg4=","Mws6z12HgFJ8uqiO_OzLLJpFioV7Go5KicGswc4QtCw=","nK2QxjVg1wNFXzbNRL93nL9W_xDzWnxE0noBm_yeKSg="],"opening_witness_zeta":"jNox-JmwypUhoHNduE2s31W4zmkxe5xN1v13IP6CbSE=","opening_witness_zeta_omega":"N4f-by0--FolJaUTaA0elFjvpw_3m3gbFNWbbuuzwYM="},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"ykVmdSX3Nwr3kMRtZRPEfNnj2mHZBJZD_JfvV47h2yw=","randomizers":["E-prcyQFmRSyQKjUS2VFCMc3ylzqskoLv6E-SypsHRSA","jhY1c8Ma-OoJ33SpAm7jeDO2uQkM7yYDGo1InX4CnGcA","RX3q9jH01PUPZZjLriLQRU2sdLzlXn14a2_Rq9uA5nYA"],"response_scalars":[["8DRR8uAldZogNI8dESPwoW6Zp1tuU1pyJw_DA6FcJic=","Dm7OT8pbS75R5kTUVK1WE_J21zIA4kpQgVKQl4U8WF8="],["DN3a59XxZlFaTITZB3PXQZQ9CyK5_FBXj-FNAoYOAU4=","8Jy5DJXRwyzadQPfOFSF-c6LjX4npNRJmTbUhQyHoEM="],["dYgYttP00WHo9v07fXsgIOMNStPlAahoAiDwX9EGWn0=","Ndf67kSWf3MX3Wtn5J844m_ZR9buU6t_5G9TuSFqmic="]]},"scalar_mul_commitments":["MztKwBDpoGIuRkE-Fw_MW9kzYclhoXUydp9ZGusngHSA","HMcdNwqcs0FhjRvl0edUiPjEoej3bwgnZdZds8JkdG2A","XaKJ5nLU-eNKfu9RNeLueXIXtcUo3_TMW5qnD0a2r0MA"],"scalar_mul_proof":"F8GFSvNye3V8GCXuhxAxzEucRDRj2qXZ-Nz8vedo4x8AbcnaeiGxY1CH4vCK46XJUFRyldafnGaNE67xCaevzxQAOYomLjLKIFKP6VLFBUuhKDNIBQJ4dci46XxsKYktQmGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAoAEIgLpYE3gZXuKGyyHjHsGC1G0MAxesDllZ9ZA6En6AwN8-VAKXZcOD3Ei6wlmp7272i3WfthzoruF3zFIWMh-AbDwb_WSfpBYD8YVyDnJESZ0uwCb6zWngFKBx-cfBGRAADhDEvIegDe0c8xPfe2bey0MzEXPsn7DQxSF2bpt0uD-ASKS3QtKjaoMWvebeNtiORbjSk6N-mnBNzi0x_hw2uXMArxqSzmGj4Eno7UFYS1nDtmECQN4GIIXiI9dXVqX9ODuQz-A4h7g4RjXtl1dhx7kW4Zfr_pSwAi6VN-r602oie7JgZZFNhDNrsbUIWuMqmuhSVdViH8aimsLSdX44SW9OCwAAAAAAAACmNxcdIMVDVM4iQ1NOnKNFur7zrXu4ElD97Siw7d_7GIDr0a0ZZFFZ_uCzv4Ua2PaJ_FwF5Wr0kS4Aa_5UqaR1cACR3EQ4Mw-qlpATtad-WiIo4mse3vXHKeMujFmDtiuJcoBJ5q6s0346Y9X-4I112Rb9Tb-V85BA3VjVZb66JgsUP4Aul0FgEFvfeLnmSwvM49Slkn-Xipwy4tTdT1dyDnkJKICig9NR8rpBpbsqpbMsWDM4MK9Xt8uL9iInReR5fp87OYCAgc38CRe5Q3QfaRxcrFdxSGJHRAi0rV2OSCEaUMdDEAAFsTb6vOFNFqstHubCupiIKAJDOiwbq1ajywa8IOr_c4ANpS8Uz3U-X4zvgs1uOk9YQ6fO4WTy7MC9WC3dlbraRIB00tj3ync2nFTds5v3YMcRIVE7UXaQIuGjtzRbms3adQAV_RmmZrF5j4DIq2GCxXxlMHoDEYI2AJ-kWjPTQPJlLYALAAAAAAAAAPPH8v8sEzrCwAOU4HrBjq_lq1hc3AHna4DxpTRc-aAOAArSZaau6W8FIrak5MNImIQwzJzs0-d_LMBiV5i8TS81ALfYe4W1-w3B1p0qNzk5Ip638xINd0tN6hNmutJmsUAUgCAwcB1OZNd0aPrbGTmVuXbumUNIb7tDzvAti5WP1YYtAIYYvgULnZBw79OQ_4-PT8cH_0ur5eljfiT1bwD6rF83gCpeWL1DBzJLmOgmwtsCOYCjUu3XwtWtmX3Hjce3vfcLgKvpNxRUNfnC7WIc7Ww3N6JOTWKLkJlhzMn9AjOXxcEUAMcbZjIeB7tiLtVesfwDAMK_yh3o7lfffnFRRZL3Fo5oAEPqLw0655P8xRP84aCdZz5bKok7OmmhOjmUe6n3p3xdgCCM0ocnJKxqb8mUE0K7W3ljnn4NLwzEKF6H85jeu6BSAJNsA9u2IQPO5Ake7lRQ-cbZWIqxX0zEdJ4sxFz0LYsHgKub8l6m-sp4SdOvGZ1J2Zi9b7MHPyIpdgimLtQjj2JpZu3o1ZJVACEdppgOu46uw2S19X7mBahesybBB6U-PDk="}}}
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
        {"body":{"inputs":["D6zAGbPFMavUWDC2WrvKGeTdfqqXXgO-h7RkCd9aeCk=","MUIoOro6YV64wB5WoTA29pL0LSvWqFdlGrZnrpebWAY=","16JHheItKQBj73Evo18-XcwuNgD41p69s3A9WqN8Fwo=","Le5__YSWEyZnr36FrIZmRiIouzCwUjm11BmUo9x2rgo=","xquO_zJ38zOzk4E2thUpia7xGHUhVRNsty55zInvLi4=","Ho7YWEpbeoZxxaIabZwgYfrFgCfSNiAZdmesMsh1SSc="],"outputs":[{"commitment":"oqjODCzagccOXDpu-PDSGMPseBH5p8dr_m6U82t1ShM="},{"commitment":"F0mYfrTs6YB1e_cIlbt9QII5J7-91W7XmjcfKIXPDgI="},{"commitment":"2DIAIwOnfKKUvwS31TZ9X1l9hWM5g7xvvF6GRUhsLxo="},{"commitment":"BceGWSQIFbJrY71B8UeyS5uXoRGfUaDNeAAD5oXIixg="},{"commitment":"UZCuZSZ5yRhBZ-XrjncXEpVAUNbogc31yHY4yhr-cBU="},{"commitment":"fUBoyFPwnh8qqZUdgqEfFGvjpKiSBg19i7HdI2jHewA="}],"merkle_root":"HLR8Hcresa5YUFb5NugjLKBP2xQNUzJDiwv2bZ9xlis=","merkle_root_version":1,"fee":23,"owner_memos":["lCsUriB8MDjWTAw_9RrXtt38qhwwSZgAFurFm11mZcWAOMS_Kb5nNvhK2OXaBkpUiO0PHNm6MrReHx2vsKhHh-vu1A-TX55l7-c935-IDlkTGvhc6SJkZuEb5LFKFjhAlB_8Budt8ztl9221xOy7SNSSEfubp1v_DA==","4EtG6wkp-UlaDI3s2BDz-pLNg_hhTpt9M1jYQCGOgy8AVWWL8evAAJzWmc4HLlC2b2m9bD9njd8RRu8kFvhCna1MuKCim2HXDjvEM64AP0sxePWRAAlk3Rff_kO3fChjk5UYD75RETxtaWy0WHKcvLGyhF9HOK9piQ==","eP1PW2xKKyM_X_eZ0ZZ-4tEQcizpiJJZs8U0aZ3NaMwLEhE2iEhlYRVXdhpnM5N7oQekUUUpcQTkcyOox_0q7ABtYnkwYJ8c5vxrOr1X0_-ltSUZvk53qhghJy8rQXCAzCw2Cxabt527KAbU9K9XXyRNRo0PH2A0","e4Pm7qkRvxcSha4hwWVJCabiDLuE6HtP6Dtzlz3_zYXjODseu7bKASPr15kDLSrUr9mwIM1zbHyHj3EF5nKGRE-TQRbS5nSC7mBz0gGklIj4rnXWR8hLvjzAcoJVUBMszGkOsuzIUm3JNdQtEvxpGc24EnHYoqIu","LFZAD2dJvA6DNMBi4vA_2LkMeAJJHqtEgaOI4Oo0yRDLsY0rvP1VMskpfhVa0pIl1kmjPBG2zW-zBPOerWe01XfchgvVuTCQySU95yo1nVtKXFV-V_vggQit-5t6qcLr_0ZYGu3UvnCXUklv7JEpRt0mmHdtvVCb","cxNOBRRE8o523F-TizGGHjWEC3F1IQlwEPVR7mSWynVKXgyv64V8IryRR5TBxzinV_60wjj_30rGBgyED2aEmKALuwwoe43wkOkHNxkQX2KVyAJyTOH_zgsKFt4EKNgzfhPOCoA6Hf46noGYLZ3RE5_NzDARO7HR"]},"proof":{"cm_w_vec":["zmcqzZTfKfcNocDoCRQAnhdTNgsjkd7ATEUmIwJ6z4Q=","uJDW975cJW2dMeizfPw0XmsRqn9INVEZiBG816qVWSw=","HZ7cSJ5SgHlbEBCYmOX3gFCy3LRnQrg30QMxUCHzXwU=","2gLp5P5z_xMFGPgFpMGRb1MzPeXaHQHHp8KGELSSYhU=","YzQxYqW0VMCo8E3bK11Ng1wzx8zbbNmq2omAeqaa9J4="],"cm_t_vec":["UPUM3EbUlanFavslj64s9-zEfHuBLHE4s8FbtJxOjSA=","52bCnp8WOsdLoeg3TRgKdWdvAQ5RvoePxS2s32WCdaA=","x2LidXOuuubCJTH8stG6bqDxCNiOid_tqwTrBMRAmQE=","3O9M5uxt6QGWzLho6YbYTc-KNJpGgppU7LkyuwnnnBA=","5q_-YtwhPcLTbldcSq_9dNnUWC7hIS5qoYD8_hw2ihA="],"cm_z":"YuM791p9ABknLB_n1l54S4liOYC6H-sJq2ELlckrQ6U=","prk_3_poly_eval_zeta":"v9nuY3RwwlMYUKweOy08Tt3YhirMpDc9jsSYfjbJLQo=","prk_4_poly_eval_zeta":"UAqfF7Bo5HoPCk8kGeZHEsug38pux_9sL6yXvYkMyA0=","w_polys_eval_zeta":["8X27yTE40xg1vLyC8-hoq6bSvn7aT3s_bSVXG14GTB8=","XEHeFMzC4RT3J1Ql1rtnKwFQoCOhoXGVVwU1Ikf5OSI=","eJrK93vvrN_LKfsqayAYz_CGzj9gtzcLyutTMxZU5iM=","VHDIgvETeCkStD1hqh2i6ws3oeCUuFW8n5-WM3BXZRI=","yR4j8-o4VK5F1ce-I3dl1LdolmGY0xy-4aO12pD2Swc="],"w_polys_eval_zeta_omega":["__PNXwk-1VG1cOqEc0x1J_Eua9t82GNen4D30DWJhBA=","8wgtxf_0t9H10cWq8dPJhqV_N2UElpRbFc7HTdlRAR8=","FaYGQhLEhSA9BUQTfas_9E4FcyPKA7uLothb1UZAfQg="],"z_eval_zeta_omega":"Jc9RI8TMIJl-f-y_l03AVlSDQM3REbh7NBU7gL_oiQ4=","s_polys_eval_zeta":["shPih9_M-eTHgTCD0qklOE3kRKX51eYH6d4-u6DbGBI=","7-QJaH3Qr-yNKjsmGm_AQxBDRS_gXQ8zE0Toorr_JB0=","_GwYb4uSwn894cp_Cr2kwQr5KMAkuUee0nxh4LeenxU=","6Mw-X3wp4fn-De5TQwAKn0wJNFdtHx1m_4yRZA7MqSw="],"opening_witness_zeta":"F0AAuJ4lQIhFOBhxmpJfqvbxclNNcnGuLLO0twxLBhE=","opening_witness_zeta_omega":"sRPkPyXnLEo8V_X9VKr9oxboza3ylhrMf6R_Or4Rvwg="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"aGWMofDrsu4KicwQK74rVJeLB94JFNgzZA8-iUdr3x0=","randomizers":["spRp8mixAL6DnVXh-bm_ofMQkWkwSqy-OGe1N8tLdJKA","c2JVbRti0J_5Nmi0RbumNzMx-OKFB_oq-Ni9jxzQopyA","2EWOfG2y87j3lWYSEK-B-V9mIUfbGyKvAmLWmFjrZrAA"],"response_scalars":[["6USwW9uNW2vbt2m2a3Y-jqCYstqkqoONtpb2O5NxhOs=","LB2-GZnm0EinBNfNn6BwS9P4u0aTqVEFycjFmgknpVA="],["bd9fBRiDW4ET9qpuODl54_hKmN0hRMG1PCkg8eTsw1c=","RlgfNNpVN34jS8XRsAAadZZ7lrs3FK49m3GYiRDHCAU="],["QSzBMD5A9WtIn-vETRYHkA7Yy_dPI3jDUeW0ZQGSUnI=","j93SApNZqN-Qt3nfqAyImyInjiUsifd3D4mGU-AmVIY="]]},"scalar_mul_commitments":["BB_u0UJYBMsUe8QMa7rPioTpQWGLMJMgEsHsj2IxaRoA","7oAc2IFItJLY4GhEUarDfB0VXZxNGXVb7XFvQaHpFCmA","ghseN22ENpHsJNsHVANLuMnCvaGJWRB0PEUz5Wz8PrCA"],"scalar_mul_proof":"ZQ194edpFS8FLo2NumAHPgW0bCOWsKZo8M87IMMObFYAL6xrTsJCQOtRm_rhwxXC6cZZFEmUP-qlq9gOXI5eOZKAgOUO00TNtbvatkW3zoRyLXFw6B2kNJGJ85TFe7bI4x8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAMqqqjwcWZ9lK5ImX5bEsgvI63hLGwUF8ZqRwCOWTfHOA5xElRum1sFB0KiD8UAanLLi5OXCxJkG3LFzvwRkCZVMAzt0dl9PHhIC8DZXWR0nFMmYdt-bKZCEBOQH9KO6BUQmA2ENn0mUCvkoU3sAKeHYJVqmtIkEvqtF1n2yRjiyHtY-AWiRifTSqvRHehi10zXIJN3HjyC7XiehDF2rycSeexeSA0B_OBWUupsrRqwpTYy2s6Wh4Bznu7aSXNbgLmdnsa5cV1BxJZss9jaDt28GCmC8y8df3ADINB2-0yyxigZU2qoBbxOWQQDwYXgLG3EF4-2uP9ZmUSlFWQgzSiXEbhm9RCwAAAAAAAAA8G025KvpEdErAflNijx6ndyPXvlKlL5ke70JwiJESaQCdOr3UKaiX4hMHg7pqJm66jWAcVr9Vg29m2cQ5_aNWwoBVMz8Tge75EBCiIx5ACI7-g3J6lRd9jP4_HLwFIzVLnwCtsat6RGpTvHffKyvC_lWfWex436GfSrrnyy5AUavkS4CEDiUdaCx4fxQaMCfu0Auv1QaGOx3L90q7GiQon0DOqACptvy_e0ZloBWIpYgCJVmKRTEq-bG-4kr0XP9jh4wQTAC-jhzhyuA7ncSmX1Q-S4NniYfrbuHc1Zogn5dAbhpVZgANwTd_PM5yZWdxCzm7rBrPCB-U2rEtnUvWhXRa9xPm9ID-5LSdzYazZ_y27F1uG5FeQGwtMYJ8zipKKe7CA633r4AmCizHLEscCe-Bq2QSJcFjuv98ugo60kGreIIOao_awYB03cT-eMR0vpCxYOeeMGcpjY8x24LJ5AGP_Cy-6R2tZwALAAAAAAAAACxE_jNn3rPKtY4enmaAdSpD49HbDJceYBbD1nKiCgEngKxfnfssPDzkWgs8Ujqo4arzyKQoKghXdgr6_9cNzRLUAHIF1dvlQLIF_tHqK9iqsTmN9YzFux29afpGuMx8pnrLAOOJdevNWT8Lmw6eD9KAgYpGo7ZGjs0wwET1oRSN1kV6AJ01hfJTlwcF7n-OBZKnFMdCp0U3a6rIOLpemJJ6ujZUAPHb6DBT8jdQDjRThDwVUMad3_c5ufR6OuYwebkkuH2pgALAFKnwWstrHoMElDrdADrnx3BT5KHV4RacP5xBSEFpACX-IJoHVRt35sAtFhtdZT-cKg5KojvXNoi_jIPDoV6AgJ35freVZozlxRL8gn84mYGDitVzr2hoeP1s9y5l2pvnAPsrqU6cpGSreCZFq5BofuH1Bi3D48qfGlTHluEIhDhxABDNa0vIcdKtdfdEpqJt2yRzIUyv69VADXkEVWxfl5f9ACfkql2tWX0irmPjREtucyG4cXK1EDbKllGnud-n-Bkf6Etkuo0gx_MGr0Y8ZzCl1h8um46Ij1Y2iFUbFMgOoN0="}}}
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
