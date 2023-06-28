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
        {"body":{"input":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQJcui_FNIqdTXSoB29nkpDVK-wHz0bwNFAfz8Uxv7QocQ=="},"output":{"commitment":"E_FBjeYOaTFR32yTS90WxG8rTotu1njLkAODDHVoxhE="},"proof":{"cm_w_vec":["yGrXcv-3aCQ0Gpgkaeeepeo_ahWv4x3W7l0jDGalrQI=","Tu6kYeeFJvhOvKDUjPnQt1NsydlxHTo635kWXn8GZSI=","TWCF0RE_Uv-QG_TG5ks6cyT-XVY-lERQbk75y-KP_hQ=","8jteczjsncdwrpEzIIZ2awzOLVfPEHN5ccvn1UEKZLA=","8zdxnFEnU_Xn1zXf4UedA7FsnKqzhozlE7rglUBQBZs="],"cm_t_vec":["NeVyYDxNY6fzvfcxCMOdyZeMPmbLsvR6nAsGC5a5TqE=","f_EOTTsqqdags8ESE1hC2bseeBGCM23FQkUxb49EdhE=","Lm7VpOO0Jtu2j1oVLQo-bKEhPgnqRfVRxA2GIxw3-RQ=","slJA2IHkXzzSlbgclix30JNlTgH2iX1oaDpTc9byhQY=","XTRO2VHf2qhE8BDjP2ImmUVnV6EjMUPC4gdbq0vTEhA="],"cm_z":"kGf0SOmcUvADZhUCaxQnDE7rPEd-DewKTmPXIsR5cIc=","prk_3_poly_eval_zeta":"jyaXtVYBdChMwsQSNkS7-TVLOyDrZAHSN9is8AuekxM=","prk_4_poly_eval_zeta":"YhB4QoylXv2QdndIzv9DJjLqzA-JoPRuq6BGKQfiIRI=","w_polys_eval_zeta":["xP42rIecZyOEJSZu3CS4u4TgQ93xuF0d9Clx4iCEByE=","ofS1UZwlceixfJzAOiZzqqiv0O1Vo82ko9HWnMamahE=","bWRwgSC2pF-_Wljo1gsudd28h65YX1gbJpT06ju_cwo=","UJVa32P14kczmMDKVzc5r_TQFbINKQVUW_TuA-st3yE=","giZHL4H_AKgzG7bpQJU2OBuhRv-Uqy9ikULt4AXVdhk="],"w_polys_eval_zeta_omega":["WXuYoqpoLDmp5YYJDSPs2f-z4lnjENO0R35kihpHmhY=","RbSqRnCJWJ6D5NCnt0TDP7EOHoFm8Fq4YY2wE3imcwY=","DH23sHAqB3gjqNDp7mla-oA2Wj-Md-KnyBXcR_J37yc="],"z_eval_zeta_omega":"KsADOLao6_PPKm8WS7LhdKIU_9_eZRZ2A2YHQryTzBw=","s_polys_eval_zeta":["9aYmGgbfRBJlCk915Xje_4lmCs-nStYneJa0B71P-Q0=","5LhvFc-SfuE52JlxtI_VKUj56OhONtIl87Oj9K0fPRU=","iOVcHWczV7YTheW99QekVHQpnnPb-qpLM45XEu4YCS0=","EfT7vMlV31CkcWGS4wwoHawrTfVeYt7M-qCt0CJF-i8="],"opening_witness_zeta":"GcHy3xmfWk4hSEqgt1Xl4Yvx1AEE_NamOkwwlFQQB5U=","opening_witness_zeta_omega":"SM23aZPJczlzAH8nbdFOVHT8k7v_7p7fD-rU-oGwg6k="},"memo":"JE17TaIWHyCVlRf3V7tcPhojx5mxAsgI1exzYqBTOxcAqgtCgyvmHn8q9qRU7aSyocxXof-g7OsRRnB7cvUHWrGBWl6O5uueW9MG2vY1_G88xHOxpP8XJWYAft21Suz4c0o1d6fh8uu7PBloOK3BOBD6n59hZZD8jA=="},"signature":"Ae0JKd3pOIgbfvcuLwlR8LIkzrV9pOrZkut-7WalUE0NDqUWD2ngpsLzOx79aFqnXp0Z84GoyoneXP1psJ3oRmwB"}
        "##;

        let note: ArToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_ar_to_abar().unwrap();
        assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok());
    }

    #[test]
    fn ar_to_abar_ed25519_test2() {
        let note = r##"
        {"body":{"input":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"fwIo1SjdnSq8oOUIN4t0U5xnN8rwj7mh3BcUL42CU90="},"output":{"commitment":"cx4SJuw059l3rWNpAW19wMFqEl-Hx8tdcLynMjWBCAs="},"proof":{"cm_w_vec":["kBWoyfsW4XrXhfxp0BmXh4oR_oi7JZsDhnwd26oqi6c=","uHrIf9XWbrkXXcFoNhq0V0a_DM8lerGinolABkhFbA0=","Dz7KOLnllo3MPvetLANod4iUPHwLLuKZ4stjQAm19IU=","rXUw28i9RVcTHGlaq94fugCUyqS6JkQkArKucjIE74o=","F6WjMoLx5C58f1VyQgwOMXNu5qkBivPyBcB_q1-uJ4o="],"cm_t_vec":["J9So5pSe2QIQ6BLfmV-heW_e73W0FizvrVDZGjlc0yE=","gHSu7-283TExifjcsLDlR_NPo6em6ykrWZ42WNGnsBQ=","Iqaesb1aJ0Xoy9NpCYXSlp3066vbMone1yQILD6deKs=","lXkT3sPYetsAY7AmQ6rhRwq0sNENuuZtImhADzhb3xw=","WkwdimnS8d7UxvmzdXSZdCxrcUMl4a9XpTYbf_HcRxI="],"cm_z":"jcqaPfur2k953iFaIQuVw1DmszIgLHrxRZ4K_d-9mys=","prk_3_poly_eval_zeta":"T9A9WNjIcdSvVSSxgcfm1xcuWsbgsHA4p3a-keEyHiQ=","prk_4_poly_eval_zeta":"e-dmST2Nfrh1TpbS35QIrf958P7-pEDefw27U0OL4ik=","w_polys_eval_zeta":["jvR7Yfu8iqoNLMqMITU6kMslEf6ORpThe0Fc2m5fogE=","FALVaBBUV8EYGJg0y1RY76E8BMsp3ljp4e7nlOKIEBw=","n6f8yTdLAncUqIuECVSKAEOz2sfCCjmQKZhsT2A7xAw=","5G9hrEB5QVOnnQTCgx3vU3JSEL2e63iaLB6UZQNl1Qs=","hUnPknIb9F3GKsTCP-5p-9s8cPL1X6d9ZCkVQP2rKg4="],"w_polys_eval_zeta_omega":["NXrtIUgXqZpEHfrG7CwSxiVPh9UbF_9Tzc9Rn8k4sxc=","cWs8G1smddm29-spjUxAuGPSIdU04IMSVoBUJy4Rzgw=","nR4FN0JpAgkT_5MYVPWaH6JETbx1BrsyXZ9rKrTmGS4="],"z_eval_zeta_omega":"MCqLODnkQPZOW5c4Oz_ykr0EPQcuE3T9V0zkT8O8Xyo=","s_polys_eval_zeta":["-r5wxiJpTABWFw87V_8BgHad_LkvNisj0kjM9saURR0=","kLzhs3aU5DGZAraclKKuPIh4nbTQWL8xuIIcCgPumxQ=","qiPXnqGhzDLTjfdFLC14Yh6X180bKafgDL4RMfC39R8=","5cULvJm3zjhV74z5c10y5MYJETnD_NESVmXY_H78Kwk="],"opening_witness_zeta":"YIN9uTZQcfrx1-leE3R6GETWcoqNnGwCqyGOLQyDaZU=","opening_witness_zeta_omega":"6E2ILcpd4CZoaDj7AqBUE37OhC-J5mcz1bB4pX3qjCA="},"memo":"LQl8mAhL8MvQthx2TAVCKq7UY6ynbsAvrlmkXxYqowZt6J34vupPJP7Ucoxlx0bRANRqsGjLjwKKa0zyyoVhgyar5JqsUSO4vWs6HtnWWUBfWZawaOFFFsX34rwllU4eK6TtPmab0uwVYbpQbKkhtfUVZ-svJ9iT"},"signature":"ALmQWAWgZKIynJkE4axve4pMWNi7dn3NcYM343Xj_m-RJD0BOMg3A7nFpgbJqKYxVobbkmIl4_FOL9lb3agUCA8A"}
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
        {"body":{"input":{"amount":{"Confidential":["eJNyy364K6GvlSNNCsZLhkOxhVSNHBPyRvKnJfgmRCo=","HBCuKs6rd9mc1Lnr6H_sSnjHSMQv8mwPl1RDCf7k9Ts="]},"asset_type":{"Confidential":"7APKWc1C4ZS09Gf4AadRz_0V0aGpssIYK02fgUeBiB8="},"public_key":"AQOt-3TXhQhCr2H7YfeFiBTBhkDNASe0ZhPAG1XWryje2w=="},"output":{"commitment":"4iJxGMufAaGE2UJ4rRBKl4cfJPke4ZZPy0zAC8ACOhs="},"proof":[{"inspection_comm":"53MkkV9JYghVm6IPJz37JkDsdxhjjhMKKH4rQHgLrBc=","randomizers":["cEZa-SCITlvgyDWU7OgjjkyhhU603_94LgHCNe30dDs=","cq8wFoub6rigsGcikeEh4KseJRmavxGKOCL3_hE5EjE="],"response_scalars":[["jY0jpr6_IdVd6RsrQ5ZmU16vbunvft_5OgNgxhJDUQk=","QLCoCvJS-D3y5eDirDD_mSPDnD3zB3XGu1vZWt2Jbwc="],["mPPku0wtyy0HbPCMrbjPc-QIJBinAPMVerpD7x5jLQg=","gVRjYwTsvFp6yp3jUdXFTmLO1MvzzqBv2akH3IYj6Qc="]]},{"cm_w_vec":["wnzboNDaqDVUq85bSBxxDP7EnFRZmXnRWeJTubmf3A8=","1GdcXGiz3u_ep1nQEEiuStRs5XtO7Aa22R9PHqn7_aY=","-TzNjsB1-lvtpyw7K3P_KXbVOglOfIxC8jhCOeNoC6c=","OlWIvWbVFnNQXIEFaeYDyUeBxmtTVVLkjP4INIZOcy8=","PMY9BYmP6ATWjvUSp72pxvDHqKjFKOqpW8nDZ0OnpKY="],"cm_t_vec":["MrCQLUeWKpiyVqZ2WqU2lI-WSjJb7f-kwn2IwM7Ynwg=","FANb3-GVSPdc2Fyvpx-WtodivMGWQXjD8WsLVTHgnAs=","Ehb_q_ut2HYoHmLL8z-czeKP35GiYUh4whnK-fhmiBQ=","_4gUOPfcLJ6Xd3FNFbz3Le-77XORo5LM15u0jxJ7siA=","1SEXOJUZOyTbaTg9eNqDKG9lHctZhwn931ozyAFKSQE="],"cm_z":"UluijtyfcYEPl8D2MB1wQsFvAcDWDa-D12MT_y88oBA=","prk_3_poly_eval_zeta":"5hlPGVts6it0V9-W-v-4Amom1nwk6q6EKRt1bnNkqAg=","prk_4_poly_eval_zeta":"ukD0rVpTyLYSKc47KH9_cpR-RAx3pmBgch59vbycXBA=","w_polys_eval_zeta":["3QpUlVC1mUxDN7hMsO-18m1qpbDUkhSN-QeZ-ZDS-SM=","59tvQMvCRwqd9ZzZVQm8rEKpNl6dQXYpUfDpVFJDwxE=","mxkxdPZNi5eVmMxgl4BtwveRvjzTYzhwdhHi-aZPtig=","L3CIJFZNcnmpa2YgJucijKTJgthjxk2k2VBr1PvkPRo=","Cp_dTAaNNe5EvBthPor3mabWbVnCoaw70CGikDUh1CY="],"w_polys_eval_zeta_omega":["mg0_jLrA5Vc_Yve8vicn19MFc_tW3QTaCXyynin7nQw=","h9YrBmfdZ557TyYOuCYqRNdzUrcTp3Eph0qkMH8c7A8=","eUH5D-YOSoLcewM91FwecQWbVGeAfUpmCr5DQZazvhI="],"z_eval_zeta_omega":"OJtCafsMNHriy9X8_C7Nb6IxlDPCQeG_S2jDyFHnSB8=","s_polys_eval_zeta":["v4Hmlt0CU8Azj1asITrxO958V4av4cB0YQqy18LcxQ4=","Ln1SDMGG1Lqj9jZu76hxJaTn-Z8T7xnuFaI11E7laxM=","Ignaw2kvf49SLUtTtlr7--sGf-bhC3EV1BtUXO_X0xg=","rQ2zq-iS3San7XlFCEGI3wiYmvni3vkj4WQfpc8_Oi0="],"opening_witness_zeta":"NfdSbHkBJiT5b1SN6ZwfutIRMxwmiMocCAI0HCmIPqM=","opening_witness_zeta_omega":"uOWxAvchuSd9bBXhXrCblKLcyxeD_4aD8qfiGJ_sTQY="}],"memo":"dz3Fj5r0Ex5HtW0PJ6QZizpWkwvPKU49zy_qCdI60sgA_fZ9dqv-KB5CTjd--CsUgQZnc5tl5qz4aR5rS9nECn3ZdcIkJkVQUI8iHgO2ayZrEUISrvp89y8WdI44PTQGWC1pIfJ0JUb68lGlwsRc9EUhARBVzeN1rQ=="},"signature":"ASHCAsUFr4c3riCCuThz8afPNKtESgT-V34awG42hgQNP5O32AZAhEOoHYBE7WEBOXCMUgj8NTBSNB2zrTHHEf4A"}
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
        {"body":{"input":{"amount":{"Confidential":["TskV6D77LQP-zeaVEAWGWnGXo3FD6MpdKxKn86Igx1A=","CKrDYa67mT_vnYxPHWA14AUd99iuMdItvYa7ae5RPHE="]},"asset_type":{"Confidential":"Su62WqlFmCOPZ1RcDlUnR-4rR4gt_8COwtZuh3e0mj4="},"public_key":"BynmZ78VAam2d8aWx8IJfh2LQh9VSGOqJASXfQzeqg8="},"output":{"commitment":"5tVb2gBR_I24IcPI8LnEB4nsD--_nRedTWi3pFHf6xI="},"proof":[{"inspection_comm":"mnEs71E9k28ONoAflNJqBBq-jxDAm0oCxSrmIZ4L0wE=","randomizers":["HqVcbQonZXuKUmWV9xJjTBdlBT_23auE1e8j_2twlGE=","ShFRMDuWjHBVD4m0cWsdlAf-rivNbx2OAzixJkfyV08="],"response_scalars":[["SOklgM_zgY0j1gY1ZZZKR8jZy9nujPUy8ZPOpOeSuQg=","H2HGRxqzkXMZX8Flp1BO6IvsuE5VHzQeDYzrjIpYHQ0="],["YfTmJye2x9Mev5ibUu2CAVgDRL7WCeYmn9-kfQDRGwA=","ThYR3pZbTJzslBhAU4K3QImRq_oAValJXMFRxfFg4go="]]},{"cm_w_vec":["xFM5pWFoFKDBaWCCI7lD04ewwiRzt8MmeIB4_SaizZc=","cwbRDmFfb23gZUE4dJjUrmse1BjS29e20d2ZQFrqFQM=","aHnHloTKu3F7CvtC9BLagqpQbZQrG3-vOHlIWKMiyq8=","N_Hwj8urecmEenVUcKPJlIkl7SJZIEG8DVxdtmDX9pg=","4XCtb6_TwdFyN0JkH0U0w6j0P619e3Z-WlEHbrBd9JQ="],"cm_t_vec":["y6-tzZjti8-Te0FVGeu7Vp3zlYOmUo01ShxRNqTpQKw=","RzjC5ly7pR8uIGWSAnGA4GFAiGZbbWVUXpBuxJzjri8=","09_fTWUsOkfyj1dUMLwE6_Bd661E2ffR1YjDSmEhmCQ=","orvriiorz75p-vv_G7HX9jaYaT9ZaAy8sPVzMFYr6Rw=","Hgvb6oC3CWBCgaKa13uqt4l_gM05Sjmz67ildcT-NCU="],"cm_z":"qxT6O5_nfEKgi2PdZLF6ZrHhQX00htM36Z-fVvZGMRE=","prk_3_poly_eval_zeta":"Za7dZiU2O5SGsK0h_U4Z9_oRPdgdr3Y-BXoI7amiFiI=","prk_4_poly_eval_zeta":"EGK20rMkea6bWgNq0n0eaDwN2P_p7h8b-1jGR3iKUxA=","w_polys_eval_zeta":["hwn22N6oX49Svg1vt07FZdUr7lDHFaDdqYLA31cIsQ0=","3VnUXXUAghHqNxTDU28HcM1VvMLAaJYZzOBZfUHmIgo=","0_emihZE0loIMnkZ5YPVDssCh02JPlkwkDITGf9HYi4=","z6HYZki8eqxD-fyjgJE20klEeTDI2RUyrkY2zE0pyQg=","WZu3H7J4aYTPBj4CJGdYe2lc3F-W6q-qaG1XANm0TxA="],"w_polys_eval_zeta_omega":["ZkgNkv9lR22fMhR2yVLPswsdR69zwyhOdju0tfAdRAk=","gcOoDp9yFeyRRWtZ7up8aMmRQogCdIDBVr7ItwAFrRg=","-0-ZGThSYuQCBc1LIltCuJCuGjA8YmAyIb0L3jFC8CE="],"z_eval_zeta_omega":"dwGHSNIhDl9QyrYtl2U91lkhLJKsLxCk0775cxXzYA4=","s_polys_eval_zeta":["fYhWAXEH7XS4Ux9u15bjjmBSrg3Z0SO3nhmXd-dynwo=","mf6AI_eDTxk3v4W821lRDNsEf3AhKNnWMpHtyAg2-AM=","4iUPaKjMaKCVXq7uOJKH_g4ocQJIP4Kupz0Ez8p0wQA=","A7u96ExJFwp2_wBCYbRv73Zt5C-J3Wyf8SFXKxNNeQE="],"opening_witness_zeta":"hgUSA9LAfg1iOY1aJh9vDo_iQdGl7sVWyAcRjLnGaog=","opening_witness_zeta_omega":"ASNGPK4ek1kWiYo__VDTo_NS6rF4wd56p_merEPls5k="}],"memo":"y9Wlwz5ZGA-BO8dHgVlQB2Onr8yIzfdO8gedEd6s1WC37yLAb6A4AEXOwqQfqWiqocZEgLursn3HAAKrQr22nIl4y87z1Z61iVhddQkA-ivE8znadQLF2d9QTnz2GYEzYKb3HE4gQi2CsRA0hDXecFeo610XSn9K"},"signature":"APDteeDuffXSXS9oms66AyFJ65rtmqhu__aRXSEzssG1e7mGWh3T7ZhYbcflaHtmgnabCMqNGg8RBL-UBaHIuA8A"}
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
        {"body":{"input":"dRlcjAYvqjdcjXDhhLPPO4S--sWWJ9-Iu19leIRSMSE=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQIcRahvd7lTmE_02FGgJ6-WCwKaxCAYhn3htA00cFDbLA=="},"merkle_root":"k3j0jJ-MH88No2ROCyAvSHNVm5GUwdg3UQvIJqAxABE=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["PMYljdFxLwnA0dWnngRCuU-l5L0IgtzmJjyLo8gA-Ck=","KCxi2FMU-RajRSsCEOpkDaIpq1gBQDEM_AVb2JC7kgw=","WJNfdh9DaLpyZnBN5t8HK7zDn2ZjcUnoUXjCCsMMyCg=","fg2ZedEMihQE0Lm9c3-wXHAZlded99IUiX0nGKqzTI0=","GWHsiIB9Z8AmGUV1MfkHASw92oj-3DIKUMkIyouv1p4="],"cm_t_vec":["mcVbAWRO7TQHwSXeZ-rq8r9ARJ_I5A2e6xyxakT23h8=","zM_V8W530CHBOyk64NYdFkBYFDdYa5Lu0uVutNmbDqE=","HMBv_9ga-mDaNjfMol0yPKMt_4Zl8vzzo95nQI-0UBU=","0SUaWNAlq3qlIIuHgkBMQbWZeyFVudLUEo3SL7E2HRk=","PAScEo8otyBCJrX6qJPcDbn1lYspFCSmo71mz3f575Q="],"cm_z":"q-z78akUts5ltUJkHJdkFu_LaO6lRD2heD2ELpxELSs=","prk_3_poly_eval_zeta":"tRN3KFFOKC_a-CWTga0BLffwUs5nRQ6vMBFpjEHiAxY=","prk_4_poly_eval_zeta":"959w4xqPoec86YOEKYXREMDdJd6fvOJ_4rfYLCWB1RE=","w_polys_eval_zeta":["Jcj0sjhWLBKoNLItanxNeFRJ8F09mOjE6K3bo4HSNA0=","VZ_IZ6DAzWPzSdxUlIoKR7BUdQcZhdFKkQ9Ihsw3BBk=","rpk9JWaNiM-Nn91UCp6f8rCefzbLlIrUvj_tnDi0NQs=","W0CJWZSwqW0Hrg5soNK72uyqiaBHJxnD1W8ei0H-UxA=","raezUim_I0WIJmOJMTWFgU2e3_WNiXEl2gQrSwHG_SA="],"w_polys_eval_zeta_omega":["-xl7cACVpTVafNOwOkHzevDzLtRY3z6I16E1B1nGfAo=","DhOtmMH1GXNoMUlhhl8MTPewKOAXIgDuiyGvSkSUiys=","_rBd7h7xvi1BB-z22e5y_fkZIcuzlWEQQfTX281F-RQ="],"z_eval_zeta_omega":"sNLe_cRvPqJiwUwiKwTTAv6Ib0uR5PilWXseMb0JRxA=","s_polys_eval_zeta":["-CUqcXpf2kfzzbZY_oMjTnLRWl8RG1F8nlMh-W109wg=","PAEvI38mLWD2C84bDAp6PDEubdcQEPXm_2ET2gJRPwk=","ZF9ypTkrSk82W4MFA0j0qA5mRSCd4AwLznaFOmTgRSQ=","jS_Xn3QxadPcBni7ccKyeN7t4EtpWsc0LVfC2YCVDhY="],"opening_witness_zeta":"CCq-Ssd_eouPap8ilfazyv-Qtino0uI4kunuuXYEE54=","opening_witness_zeta_omega":"4SOr4zBk_Ll2OBcV-KkMiCRWrkupAsL2TbLDa9ucEwM="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"jCPqDyqeA10SthsclTNp40YRQ5-uazJQ-5Y9RschViQ=","randomizers":["F50BH6mv3sNv-bP1dK8k5uly2kxsEb6dZqkrQ3t2MYgA","4CcRYQey0vVh5TYE_XcG8yf2k70ekTtw-ESmJmgVYrYA","rApcKbjVz0qhP8opeFWi-tCSGsAvK9AJK_JoCEam3OuA"],"response_scalars":[["M1guHOKLmHN-eeC2MbYEkTGmaxqWLUg42abzEqkn2yU=","R07Y21PR7p1L_bZ45hTceOrvU9TvodxVM3Rc03tdvyc="],["MdJlK43_MdRDj-Zf5UuTVYgB7BN8ub6JfkDVmEG7ieI=","Ic9-KD8dG6wp9MF5l5RIBJ3m3lkhLYbeb1CsbN14Z7o="],["6pYCA17qSXoPsDFfnBcsjDnuP22hHufUQ127JiUZAkU=","p66PQv6ZH2tZPTSfMu-G01ENZEaNNP10dn4-nsC30c8="]]},"scalar_mul_commitments":["ra5uboYz-pJtRhg-pukWwY3Lv5eQJc-h3vNsEqLJvKYA","L56phhFXytWTph5k-Sp2-Z8vEguwneFSzT5dqkXAA9eA","-Wita0xjmK7ofFWWBlJe9FyVNwT-0q2Bh_TH9NeJZNsA"],"scalar_mul_proof":"fWXsQ7LILninr-g1mwit9q2MdDzS351OjeGWbv5r56SArkRnvwsrOoMNbFdruJr1WhrVvSPjPJYDunLHjsnVC2cA95pFbenpPgPrwFLKUpXFEeiFkMm4TQPzQb-7lIialmOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAzKwfi7ZgmEFOMDfsHZ3-58iTK8eju28gvgJWQpAIpYkAaqSGAxJODh6rZL5q5Kc0voUxsRIkAK_yK9AnkcaWNK-ALCmksmor4kIjaZbI6njCqj308nyqklqL-1ToDNqDVMWA89z2oFpEAuWYq7OyaP8oGvahozkEeJWhUnaKAOZ8PtyAka0PAIM8jVgS1iU-rWvEwOYnzHnvgT8KvTRppSBjwI4AG8JSkehFGkxsNMcbZk8w08vevjKEh7-PjD3NdVfEq15kHi_kvi7SKSbi8pIM4QTi13T4ysGBzY9hiffue-_ckExsEE1QeV1yqOFG6zmiezA_24eN9I3fBmP8pMF65458CwAAAAAAAADrW1leaKP77-TIK5NvkONjwK4Q0GO1pLt1oOV2E7bFkwBE4i2QhDP0ckguoJjJtDfYnGcpv2fbv3afnw2TENZ1owBBIf97EpU3trJFtT0tmJmV1AJ8aoyki4PpsWJCfpEUUgDVU40KLTc6GW_RRGZBWp5qBu3iNb_25lK6ma4zkeQIfYCv7AF8LQy7D4ueWujVejSosHNIN1r-S9Bxjz7giNYx6oA-EKXrXQxvCAzVNw_fs-pSCeWsT-1qHMQoDZBpHO5RXwDUG0niKtfTjlVqccu9Zw6VOXfJjfs9ohcufoeDSu_MM4AtVFhBoFG28oxOflF5BqtVzaPoTFVIcSZyElYgwQno44CU06_Kc47vnkhdMKRu6HnuuVRYuO4PUyvnCR5b73b_dwB88QASZ8-E47Si3rk-ShSiFq_sbfPj1RjiIMx2ucjDfgDVN9a0VD2Exm36h8ZVYH1n08F94P5n6ki_Y8wY7PHRegALAAAAAAAAAIv945NorlYZkG-MjVdKxOdwiJ90YhD381LAqNCKx86ygFvtDffqxJZjzJcy9FHftcqhEfbQ-CB5RoEhwy428U5mAIBmKOzFpq34gDijOJCdroK7UTznUm0O3cWXKoCfyHPaAKdWP-I8fYHNaVPE34H2tFU8Ecy_NTK8MBU3UClJkwaEAG25T-lgwExt6Z_9b6AGMvtmzyng-tFQQABLIajmxLs0gML19SeDpD6Ss1I-crdTvvKNGPVFXX_OTmE5gaGDp0cLgNcT08Ij11PulQeyYOxTerSCvKv55YWUHO-RFHBnscKpANOlqJaMGE2mx-hnzruaSEWxhzb98H0NSEa-FakU1tnAgOJkGa_9925BQ1WSzJ79N3NI8ZdR08Aeokx7eKGM6isnAMTwIB8XqNItSFmBPTLcpwGhQn8345RlU4q7HY-kHKJhgNrtSewjX5Ana6_vLMS2JN9eGZMa5r5CsforeZIMppSUgM4OCTvaJG1i9mYyFucTtcVyWqwm0NnfhNbk-YCxeVc8cZMlWioJHTHLtVPzM3YJVNs6uVQ__8l6J0yCnHHpRoQ="}}}
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
        {"body":{"input":"ybcrkAi2mfNiCjpR8hzL97IVsRKBUBkoy1lXuZVJIyU=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"uTARaEkh0HJAryLZ-BvGpj6XUGMDkAr-7k1-QoJv6tQ="},"merkle_root":"2hOCwzVNNtUIzzsOXwRr_-ryjqv4XxR5AimIKygkYhg=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["7OfZj1xmJPcx7-mx_mevV-zz_MDhGDIZdFWvHHMG16Y=","OnGV_UBFbkfYxsFX8wHH5AGep3S--QTnko9RVevjnI8=","Z9Mgxk5AEs4Pum1kg-akqh4yD05i6laDqrOsWQcYHYU=","ctKHJBvoDeaNsG5yzLbNNXnUq65OE-wSW1DGrUwigCA=","qtuu2l6Q-rPbe9gt6YOc9-sR_u_6oTJRKb2ay_Oyoow="],"cm_t_vec":["DZiR6uMmhGLZWIcQSx3k7NJ7PTjjIS21Era2NfSD05E=","f8iChHNZpITMDp1pUuYrJ7dU0FgMKSTSCGS5LdCFDJ0=","q51XKxxaX5b5qFP3qzfqrPyKvlW4PZ_Z7lIkYlZgcx0=","uJuwUr5h4i9nrmw5pzSRgLOwBq96cnPC-W9ypcznlwA=","1lyWrK25qdyuwMMliFykmq-ieduee7cwEdmVJnbryQw="],"cm_z":"W875k64nwkWs0pW1qTqFu9CNsO9jPx8oqh7gFKlsroM=","prk_3_poly_eval_zeta":"FmeEyowJBlf9LPAVrkHKAQX0KofuIekUMhdctPclZRU=","prk_4_poly_eval_zeta":"Dc8fKi2B3GmaIFw904x-xNt86wbXUM-T-MSDWBT_6A0=","w_polys_eval_zeta":["e2d76k7SxcrHUXqKjSxo1rmFC9ecJHSx1RMo7EMvNAY=","ceR8PqoR7k1tPkfa19ByUJKMK7iwqWM9fI61fqpeSBI=","356U-my_sjewEkFqQ3C9WGLxNFw1LPeS3N-X0HslTxY=","9k91VWhtHo4bxkM4V3a8SYmAslFKG4ymOyfvgj2z7CA=","nYH_rTh-8PYxrF_hLzQQJp2WNarUv4_tWCqyV89P_Rw="],"w_polys_eval_zeta_omega":["1EkG3Bs0boWR_tuA4DSwSf85KWK4HUIrQ6V9ckrQkyQ=","CaKpT9CtdrU0pCYnyR5CXm2wrMup6WnVX6mKwnHLKBE=","8xeihBl2R3rbhb9HVHnFEZ6RaVgFtmSjqnoQvL-0ECc="],"z_eval_zeta_omega":"ucAk-WKEoxcpf_hjQPuatpXjq8zmZStCA395v2YtZRs=","s_polys_eval_zeta":["wj4hEm1xHxgT-ZNVxOZZYj4L_EAf9ppZeNFaY4i7VA8=","1gC4B_-snicQFxqNO0YRZ56ks6Zhx5Gzt3arEgktmhw=","Sn75oFWtHesJx5KGGlO8dC7824DgK8uljX0q8zUSiho=","feR_Wh6SIn0u3h4H0Ty-dqEgfiIwd6lcyuP_jELV5Rc="],"opening_witness_zeta":"bTuLlRKapA8Zy1WqBArNDV3eoy_dgx1Tu9Y1eZnuHzA=","opening_witness_zeta_omega":"hbIvji7lO949Xo9ABe6Rz6S8b4o51suPfW-fi8IwaSI="},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"lrKNzC9pHerECpwk-8HBLG4XH2CvqYJVG2RDk7jqlSQ=","randomizers":["jqmwjL0e19GMhSIFWmV84kU8woaAAetdlZij3eRJqisA","hfvtvTCgOxaRhdGk1Q48ESueKtKLuUmFrVDa7W-BVzeA","gthpObIlN1LTMsqSuF_5nmUXPvh1CVawNmKhuPAonk6A"],"response_scalars":[["9egQbmVsBYcUQR0BBuJjNqThE-qMzJUHi5afNSkUgxU=","M9s-e_oY5TxkwQrKqAQzLKEmUoDLlh5LIP765zFYTQg="],["WzRFp1fn-4Vhg0cUj411Ezr57AN4XkkLsVkskYZrFF4=","MuYiKJOXd5Csn_S5ALbQ7UjGU2MuiVQ_wozGwWPIF3c="],["6J0RrPeLr0V3xryHyO8nvmK7Vv4CSXv1qq6I1FCobz4=","2jsEBTCZ8KZ9jc7lHMCiDfO6FmC4B74LM4SnY-7QRVg="]]},"scalar_mul_commitments":["9ExKOEtYsK-d25w_op1htXkHSASuPwRMcEwdmNCHf1OA","PQb3BFVQconDJjsOBiTbeXYulYq4Av7CjVUCVx4ueFyA","VMXQuglyOQqVik3nUO2qj_Y4mf_4zqEianP7YoUK5yqA"],"scalar_mul_proof":"eaZn-Abva_XY2YFofrXXxfk6JfQFZTHs-qOD8wCZcUsAo_FbJryRMsBEOJkSIYx0nsRlYlHcEBMpkAPyO3doaG-ACDaCMy3QqxCiNrrMbscvn9AMinUJZlCCjuoRamLQsSSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAM0RrQGEPjPCkd1cvtrIEmxF-6MHsaohIRV1EDqO_kVkAOp_0a8MONyrZ3Ev02VGxaiYfsUZ2I-a2wHbaJxWucwqAStwYL8QTjmIz8RXEhKGJgmn35kBSuHocxaOuPVeuEW8A1FdvoXCzsWVqhFzWnKbMHSlixAgd43fvi9E7vBIAy10ALq40Li4c3rT9c_C7U5GIAFzm77skSiplzHXMbPlE8nwAo1L2O6OMEAfAaXf-qgmyc8_y4q3qdnj2u6g_ZfIkGAFpX3nlgYfgity0y3dHLWdx3R8FM6V3quAY7TF94C0gBzfnNn6eD6e5OPcIxT6OdemwE54PNNcKTDDnfb1VHqRrCwAAAAAAAABjLOWQqyvPywMAulwb3oiYBgOtF0NXSywQ8zjkb9fhJYA9eJkJWwZqweTXXIwQLz4xRQOpLENfGB4jxeQ6SUV8ToDBk7Di-VF6LQK0r07ds4Tt1kNnr7wL1jIeUY8UIUKcBgC3SxcMtfBujPNfxjljmfdL9j3Gd5KJUjn5FX5owYBWYgDgTc6AlnTeWAc6KDnBfGkEWZn3LX7v33W7JBU0PjXOFgDuiIEUrkf1cLAAtmWGh2jpTaNGKCinvX8qqiAMBQMKV4BrTFdBxUzsfWDXZH5DEiwY4F8mj0d5OHnuDsUfojH3fgB8LnhMxLwXsUzS4CsEGMErf2NID5mkHp6h_-2Jh8beE4Cw3Mnlwo7h4zIW2KOaGsftsLAV4rsyFi4P8cu0CvysFwAHIWu1G_QKOm50uVjL_3EjSwHdf3voZhiDnCVd5mNlU4C33MxUESJWblRcZO0uzVVkcoxDFHYS2dyKbjDIE2hCLwALAAAAAAAAALeufs3r5w19ShInKT4dMDBwoO0vaFYO3u7hTzAdhNMbgLxZIZl8pORoH6ra2xfPllFbcnRWiAWWxEuuVIiQhbpiAI_VE0SUXNSOFRWHeOcKXANTSZdx1Igx0T6tT-kFfvBBACiJtjz8qIpBmIyxE3IUuVkCn0gf0mDVM3Zvn8FV6modAFC-r4Nv8bOmep1wjXkMDXb3JTspqU856hk_zyyLPhwpgJmYVgOxhG8JyHMg1aHifThjj9ShUH9vsLnLAOWrby12AGkmsjIVDrvNeNdOpuJPnGnhrskYsKarEAk9tEwNY30FgNgXYzvpcpx7i-egNTuTSe8ZhTUmuw-2vPYj4GLQtaEaANTCrURb_Lip_UfZUcz1rZAWX98oDMvx7w4eyA0LAO9qAEwIPLG17JCH0EQUBezyfz1rSFUrpxZkOpCO-rslfPU4AGEOwbjGUsIFIZBORR9E3piXvhKPvkKDtRnvOuNszSUAAFcfmWCnUfJFSUreWAdSciuQowWs8emrQXWimrAHH9t7X27vcTcuyBLPxNMdtxliMUzh_8rDwPsv7dncPWtbVFg="}}}
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
        {"body":{"input":"YsjiNmuVLbFVJmWkfM6wzxAifuNYSlFNPZp9KSWnKAM=","output":{"amount":{"Confidential":["clLLb1ccWnRj6tWeU8nvqn30nvoN9-cDwuCYoW_VuBg=","bJ5OjADPvNuQgpdf2T63l4x9M0vCU1pClLov6RmgV28="]},"asset_type":{"Confidential":"AsnmfHSvnCRx32ge8nwoOpE0--nNVQt4dFM1XtYfoAk="},"public_key":"AQIUuXebA9BxkcGtCu2sWqTvFers-dIc3azCXQToq2Mp8w=="},"delegated_schnorr_proof":{"inspection_comm":"ChTQbUSF25Cq0i4NUsBQMn5shS93heqiWo2gpGmeNQU=","randomizers":["NCSBrm8k76kDa7uYurt1WBO_6GxW1u8vTOeXmbFqkSE=","GK7zpydGT20Q9B2ztSbyrfeV6d3sBkTgMmCDpHR-DCA="],"response_scalars":[["nxjJE_psW8yClr20-lM41jxOklmS721wm1LbIflnBwk=","Gu_bu5pQlwGKtQ6w759w2w3R1AJsPUJ4ZXI1C6-y5Qs="],["XV2h5hLVpwy5jRn5dMw2gR_u3oHAnTLb0miPN7lk7Qk=","d41lmxdJJwS7Xgb29RVVezJ_L5CKdcE4lfj9h3_QWgA="]]},"merkle_root":"g-D_xEYGHIQAspGe4ijxdV_ppGMIm3QL85zdjdfX9yk=","merkle_root_version":1,"memo":{"key_type":"Secp256k1","blind_share_bytes":"4GFXHI2a1v-6g82fc_tavSXNxx5XAmXDGEafxfguU66A","lock_bytes":"DHxa8PKvneFTbtg9B1g26nNdlTCB_26JyQeTW0rqvJUAoIlDiKfZyMdEgIkoNGU665xtqoUViObCWNpFSNvpemcLXqGqVgh3awZ89lhb9X0cVNE8M8XjPSY="}},"proof":{"cm_w_vec":["_ig7U37WSQ81rQ4hbM0teLf0EQC0vLEKidrGFDU3n6A=","RiZKt8hBSQTkmcgKBoPAP9nJVsJsyuZyVCFPz6tNca4=","BZefQ5Y0yGi3GeAgMq-3FS2wc0aA6MliNI54YleFPA8=","12AEencbKWuD3GSOLhR2471uYV_9UkbD9AwfGV3Fr5o=","xdT5wV9fFOugPWXOfIwSifwWFu8ziWDF-VRosCwhrQo="],"cm_t_vec":["5EFP4YHsNRJ4SAvS3ueo9P8743tWFXOQ8IG3eUTTJK0=","TwSjsalM37ltlOmtysrA8HeBqtudHaqY1tkjfe0Cc54=","_SBjpA6Oj781yTW6LS7x_RD2OJ102C_ZTurjF82dwpM=","4jXNFbqtWJax772D5YpSlAg4Gw7AlDuj84mRJ6nKjqU=","c5YX6gLtXGLvjZFFww9xNAdMPptfFa9JBM_j2Jh6Vpo="],"cm_z":"fij5EpFWM9A19GY7SwDarODbI6z_EcEvFog2O5nbixI=","prk_3_poly_eval_zeta":"m99DYH2kBymz5TrrRwYxZXpp9HyblceMg3Jmj45qRgc=","prk_4_poly_eval_zeta":"ES-s_VfooS1bFwFzJk7ljW46_7fkqEb6VBvc8uK-SSw=","w_polys_eval_zeta":["e65pxaWzCfKnmMHCpOuSfvQJnvmC3X42jOaFccdz_Qs=","1EfUa5VK4W-Ht_-kmm09ijioOINhBf3wdNCygVXvCRY=","esT6BHGbzxcfYtXEgixIObl1hra8EhmPB0TH7rKK4SQ=","ZiNoRDLcljtaXnIawTPS9fF8hFoa6w_qufgPBBaddRo=","lR6GV4CyP0pfNP2fnn2_X4gViX23k6doNIbfBDxauRA="],"w_polys_eval_zeta_omega":["SdSW2k_mf1rfCtnEFR7hJyh5th0tkKVRgi-lZl4VVgo=","K-BymLP1iFOMoQe6rLRvM-NNgOczhm-eJHkYFN9twBU=","8QojJbz8aBV7PhZQBikWBUBM0-MddFSD-sW19gkGMBs="],"z_eval_zeta_omega":"2VX0mwJ5W8hTnzQ6s7L9gfeyM76uGUThfcC2gXInQg8=","s_polys_eval_zeta":["dvCyZNJuVHgYINaTzZIbr9iaKdawtcByivOtxuRO2iE=","ix4B1eOi6qAbsbeYpCMFrbqjpVOsP5vWsAl_2JiXHyM=","z7j4NRP7Cy7kxOKU8iJUr22eVcjTL0D66t4DnoM8rwI=","YuRiIz5VFYv_WtZLP25GxalY1qPRnoAsO65T_-dvnQs="],"opening_witness_zeta":"kG8YrdeVn0GcgLUKm6IG8_mbsgbar6TzYxUODUq6KRY=","opening_witness_zeta_omega":"qvY8liKDYn5hmE_2WrTCSBqvRDOUmRuP2HlaVnLQfBk="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"R-O6QuvvlsozASV0yqINvdiXWWgnt3KVTKvEoCnxYx0=","randomizers":["hGDFnkgJBbivUdhF7nKymxA6exTDQGpBN1ovG9lRgkcA","l2ZdPs8MGEKlGcvV9yk7MerUCNdPkjzwSqXqdM0adAwA","hJ9eeR20fRgOGIF3sjeOlhF7eW2xhpP9_MMgjAJAI8-A"],"response_scalars":[["RiN2zYLCdBT7ZUoCkoAn614YItU2BPOJ3FHTs0ibQmw=","mIkMOiscXaNJ_0ncjPIYnGxjPdxnISi9kJpzT0UJOq8="],["BvmomXWCuSR5NKmBHWOtUYyuxNYIHZ16XUOy-4VldGA=","vJ9O5D9Uwnen5hNc7Xy-YiEyY3QEeC_2vdBGioIqEaU="],["VmusbPCwxEZw-lyY4JQONH9ccbJtnDN5qi-hOMMh2x8=","7wIx4pkPV5uMb4hCt878hCM14v5foBpkEJ_MQTODiwY="]]},"scalar_mul_commitments":["YQEDGrNFaD_dckpDSDxIe48ddP2teNnvOyUFO4vvrnuA","ei7wCg5cq9puhsh2A2TW9NY6Qzl4ZUQ04eOlqfPTMz6A","LMkIPSzjEQlcVIHgBxdxo5XNT3dFuxqfGKi9YHz-arYA"],"scalar_mul_proof":"6ciaUXyn9tup7iZ5CroeVcEkuuNs0svlkkxec-YBD5cAUvAA0olOFpYuuL7XrsO4fekBGMAYivvMXv8PKZjwWMuA01it1kFeaMn9MmaeyOO1WDXxmOAYckMRRGNWUKPmpTkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABASmT8VQ7CwUG7SZ1Wvk8LqowO7YRoc0k8nv0fMRrJOfSAaYf38lI342z4nGJKWd469VKWEA6LwHID34BaJFPtREaAMFY_PUgKN31h9hH1EtvlhDd3lNbft0JcRft8ahCxm5EAv1L-kssYoU6MVQnmqTVPAg9UjpiEUwnHTvWh7-jLYnQARzoAsRd_3KAZiRfeL7Y_oo0HRWeQl4_84tdf1XJo7EsAiC2SBEW_unIn6E4JDdrChnhlBYgKzrkF15oKjBRgCc9dGX7Rh6fZXZNH5AqeR2pPYxRBLHhtcmM3gBYRJ6tVBi-cr0DxtM0DUvHZPP31UCbsF9o0xtz99BmDg6oBC9JqCwAAAAAAAAD9BqQ2zwV8skWRhGneQloECgaNcnLMD38sUWZnujmXFgAB7c2fhW6u8eoqN4FHq0B-PB6HyF9JV9msSTWqXhQm6oAHSG6RNEwIB2BOCi2MmKTwuWA358Ei80vIQwvFU6KXTQATXlWi7Ms8DR_5zOLNS5X3E31aV36jER9ehLIYwCkLtABoD0scvBDUCPL2eqCE5ICyl1lFJVflUHMYuBFFMmf1WgCFR3Fr3QpOSwYPa70zSUD7k7FA1A1_S2i7qSrEpuOH7IDJfY5rWBGAhxsFjdLI3SEYjJRZW4NLSstgATAf9zZpTIDmEgKeGE1FlpU0_h8yOF6j3Q06hyqk8pRjboO2fu7twYA3KTbQm3Aw6GZqmk736Y3MCvOh2vRfm741-Vkf8TJ4IoBwyTc9kQNKwsbeddHMb7xTpaqWbhmmY8J_DxpeKNu3qoAj61Dxl-i3aBdMCUQmFJC6Ts-vODhY8FGke8nlhPzkqgALAAAAAAAAAMBIZ5cPssFb7dozRx1K5h91QXQg7IcePqkMkHO6E7QhgMXBLeXB4aHUMvpTtersybZOehnYKJdcjM-dqDVnUdX1AOKVqlh_E_jxkBTModN6x4oxV6Ae8jflNkfw7B4gvKJfAJYiGiwZzH4q2ox2BDnJ327Z6i2QMwCq_ZvalNoKQAK4gHC_MR5HNoI1yDSZUon81ktd8kVlaijN-2PiIc8NUUIXAArsJ-wjBRUTDmbcpVYIwXFRj3OzIR74GRwFC86Fyud9gLJcx7Mm1QwzsT2rwq3Ux_7rpAHGU3363s4cXO9w0r0TgFi8BB3GXri4gqoIezxaBQjnZay-b3i1yFvHcSLt4mLPAP1E03hniC0o84qqqtq19vYP-C3UNjro05RGKSVOuKYIgPuAejqtJJOrZ0SuAWmOVdgCWuWVZoUnSZX3xrm1cvwKAEtpDMyyfPdvEB7Q1-gW_M9ufDfx9QuLnpTr3MK2lYF0gE970izgZIzH6L8i8j0KdJUEZ6IsijfmqW_WeYbFpeD2_2DbCMDR07EaKN6ANRI3EXjzW2JlPFcAVCtM0xChICQ="}}}
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
        {"body":{"input":"aInEUTik9-Fli-SCs8C9k0D_EmJMlX7_QKOiBBzSjBY=","output":{"amount":{"Confidential":["1hOBhUiROfQRjtoEo7FxSEX_JSdnTioWEprvfhT75xs=","8huGkeYIQtqW5RTsFwHoqiLBwFvuyTu8f3aQG4f2eTE="]},"asset_type":{"Confidential":"SpNlm5dte3_Xy6f1Cgqd7jVYh07c5UQss9Ws9BO3HmA="},"public_key":"k5_SJhhXASN0udlcm0apAhSn_vGYOKXtVzyfXd3VkS0="},"delegated_schnorr_proof":{"inspection_comm":"7LvhtA3JKLIxi6ZAqxfM2HzeJaqyJw5ZCJnXEaj-5Cg=","randomizers":["is8XDAGxYsx2wPQRAF2HD2noF9JDTk1cCzjEwA2uQUI=","PL7N6EWnY_Jl9QhSOj3LU7AspeAu5oQrei8VtB32gmQ="],"response_scalars":[["8OfbOAH15-rfv0tYpFINZ2Z_NjHaxqD6DchAwdM89go=","n8Xsl9XJCJgn8mM2K_1BxVovjmre2YYrWP4rjhDQHQ0="],["rN-1AvnDfWT2WyiWLoa-_ZtvwNFfLT4I9W179SktbgA=","Sc8wtFsIOpJYKt1VNY4u2mxjgnSwP6b1eawT263CxAs="]]},"merkle_root":"VWBqDtt9eDGvmHiggzI5t-EDJhwk_w0_zpixTH4fmhs=","merkle_root_version":1,"memo":{"key_type":"Ed25519","blind_share_bytes":"9yv8rhx5fShJJB7DzEqG_p2Q2gdg6_7MwH8EqMHmwEU=","lock_bytes":"gP0K_SMtPh5R2NUkVb99RdYtE1sLO88bCeVMTHs5Wx--el6-_cffp2SaIgHJD7fUZydk39mKTMc_-0geIqDWCT0tug_3MSXv"}},"proof":{"cm_w_vec":["E7X8EI1ThXvs9OEgk60D7CPNfCmdbmfdjvGDe3vbcA0=","6NATxjQ3MLlmXrfdtqd4g8lbBZxXi2ixthPfydG4UYc=","jx2loYmEPXqYLcXbCFX-L88F9gwLxdUlhmeWO9k3bho=","JFPcQmZdgWcEcd3x_34b4fl8YZaQhdznpB7CW1IGxYQ=","298X4elLZ9EC3OKHC4EKMvlw-B9ODQH6NP4McwSkdZk="],"cm_t_vec":["CfqgMeWcuQ_pLb-QY7x3BNivG_25YMifj3ziJ3mCRJM=","95y1MCf31d1390w7cwiNJKnlRd2QhwWiaK22QfWWVac=","SFjIoqTwYaMlBYrG1-S1_dFqn04o8fvJeunkzN-TqyE=","zRNQs5K8sQEOQkOJYrEnHKC92Vo_UreEiVoVSfhGwK4=","SqgnjTAdNhhcYCjUrTrt_ZEba3-2g3E9wUEy1Mq-tZ4="],"cm_z":"p7go22MI3MrTmFEE267h9p5yJgdqQPsKfndRwVDOPSc=","prk_3_poly_eval_zeta":"_p2HUDX7ab1n0UmkFXAiTIjTO9PW8m5tMSRRGMI6kiY=","prk_4_poly_eval_zeta":"VLgpgz-pfPyyIpJMtguLidIkKE4s_CR636VU_7LvRgk=","w_polys_eval_zeta":["rxay5Ii6e97BOxSG0RgKVoyNQYEg-ls0LNfKdc39zS4=","lQ90Pr54Z-slKI8rE6jbVr1iwbudxnbBf0UXTpB_Pwc=","lOOu3lcu2RwdTRG1lO8NStR-un_CIZpqWpHAnersYxI=","LI056D-rSNoFBjtKo5-ATM16UPI6upd25B04lvthpQE=","Y7RKT0HoSt2I3mg50zKr3M3CspQgLAOSeodqqnqNwgE="],"w_polys_eval_zeta_omega":["sl6KssIp9-S-VdjmsWL6Abrmebt76HctdqybGyJ5sRY=","YgzeCHfz3vEsLnA7XX58xJen0Q_VFDBBrMyeFhvvRw0=","nIIqYpC1wx3_yj8shL7jIft0KyCDECSScPMeTU2ZZCw="],"z_eval_zeta_omega":"3BWch5lnW6s4oTWrNGbgNLpnLly1--hkVNFZBg5nOSI=","s_polys_eval_zeta":["ugYeBuxFCpY_wjNxn1WNjg1_Dqfb8BgMxaMjD7KjjQc=","JBwZmm1h5PQYEr0Ag3z0ODQvlCPbHrckMKjR9bxrMB0=","Ab3XJ18y7OwO0vWzrHldlHLfs_ZzkmR9g0HdJASsry4=","Fxj5oj5c7KEfg4Pow84mwS3qjjJsAn1xJwK4CT86sSw="],"opening_witness_zeta":"lxsldFpsMES8aDObyRHbh-jyGKRMuI2QGighpuC3FiA=","opening_witness_zeta_omega":"zKdS-KJvyWW-bY23J3e5uH_ym4M2IAJPLU8Sxq1qu4o="},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"y1SqMwQBp0igoyBA5Bamr9oxXx9JQjwTVV0STb-z1R4=","randomizers":["QB4ESuxvI2DEl1ZLO1YhsRKnVOu45ApfV4v1ZcmgaA2A","og3ulFcv6ws8I4Rc-t-kSdeqopoVsbok87h0qjxU1FEA","6wcTEHTaNLy3PD5nKZguOuX1sY3NtUkN4miR40MGjyAA"],"response_scalars":[["l0TLcvYUvEc4H5VN-TP8mrZ_ZzYqMYK2o3N7hI1iYlA=","2oDF5377Pv6IQdwgPOJMoxg6VQA0dB0yxtJqxdhL5Ak="],["wIrmU58Sihe2uSu8HqeiCz9J0kR-dg06cE4YYLHB1Vw=","ey0z0qnQ1cnVfaSJnxSLEBDx7LPGMJEClfID6xhUdnA="],["PO4bHSQigXHCku0i9jXfpO26OPCG7JQXGp92Iy7Wp0U=","Hcc5G0mH4O-aETPcWUCb20_rMoFqrc6OGVD8vM0AaGk="]]},"scalar_mul_commitments":["dBhSRC24QGOO37YRd9_JFq2cSlFd-PZxNIGSOqs_IGaA","NwyjBF4-nqLZgc4xucOSpHWvGBNCGkTAO1ESubrsp3IA","7NP_DIJ1mcZDbGixa7Pn9a1bvnUfYcIxJNEHi44HUTwA"],"scalar_mul_proof":"I1HVGTDhMWB-vaTPtc0vNdGwqA2NclKFb4qWgViZJE-AkIiaP9J8_OsoxXNcxUwJE5Pf_DyUSgWX1ND9_9fVGVyA-hQ34tQ8L4YN5honhqyY6h-mmATyCdkE9_yh6JIJD1MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAg3l592-G_rINunnRvwsKOVaV57V6JVnoHLBmhelJmwqAIWaHSJC1v46uaF_r31WXonZVcr4MFVTjsae76z5TlwyA37yytMSH1FqIQFmmntaK51vlsPc-6MQrlUzSv4nECHqAOhdIsjgGupRIkmzim8tZFS0ajP5mtd4NjM9VaPdhiU2AInF7mOqGBtdBF6UW0BEpl80LMIPti9Ic7b4N_e3vhS0AZehiH8rx4J5FAwdveNo1JnZ-50lNpXnZbbhRvSPu6A83rzZ7JDHe4fM8zgkY__rhG1w983ICADjip2M9S-LuM8aTX3CxlV5weisib91io3f2a_AbtwSAVzD8mcdmmLYLCwAAAAAAAADPHhZbPfP1HMMqNVc1amgxfLDY6L14vcZleZjbtYb4TQDK4f2Uht1qBojEWVQYNCEE1hFMaNwQDrn5YwpgAw1lTwAztri4ctERwNsC0redEzQ2RiY9b8pEITrfM4KDP4z2NgCC_3YkAbpjIDOExPp1YNMZF-bGTdlmR1sawrEbfU5LPIAdWZoLrhSv3GIH0m51VdyKws18LEsoUuaTRIxhfwSxcoCeVkuSqps9MVCbPo_TqIuP3HKtZFxBxh2pB6PZOT6xSQAOEschbvP7XfnbLhj-_MXVMCYHRp9ZgYViFn_Lhi64OIAAW7qEVTADNjAcYBJ33TOVcLSp-FTnIbzvUj1rtsJ8AgDzx_Lx2lyHva30fdOre-qm17lBBn4Pz823WufEqjqDAwCOTZxyBD2fQf5EJChg4Wy0dAHtC-wEIeAv4MhFgtc_SQBAs7mCNT8Kfg4pAQkQ8W4GyxL4IL9rnu9RcM3geyPWZwALAAAAAAAAAFTBuGlKw_pljHHcPRFToWYYpKuXj9XWXSLuHFoUnlJxAJ1Cy_roxSLMkTYRgPRnI-GdOHGpoGxvxNmXkix3qmFPgAbOoqMHisiHkQwfU2-r46avmsUvhZl7r-xuj9l5NOJUgNPtIiZTUhwy4N3yM0YDvN7jSfjN59zzFlnU7qS_eJRYgCp5GilUZq0tIYMdS38EzoW_oOsJKAgcOY2WcTPzU21dgC7rO-zx2bkPjsy1tvIN2PCCjjDBBDQ-J9SH4IO2mshrgPLHBC8826PUAn753OP8A16QKLV7WkFqrIcirzxtLTxIAL4BwmFjTNC3N0ALm09_MuaGzcRYCwqPHn4LWjBEi286gHhXqeaE7GlwKMRkDbw6D5wriJdAGJ20BBEAOWy0a6glAOYyr6OPO9yJm6nlNv3c7IWTQvDY5pU1TmSnIG0U9soYgH-xbanJo33gN868zKWBAEKmbVeJtk5dvddYRSBBpjRsAMkEUhIIOa4kZYv0qB9F_JbRGwqTzXFhtLTXkgcRhr0bSVge2J5xOSym4Oyut_L5KhDx7gWNp-sTrO5w7h6vRTA="}}}
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
        {"body":{"inputs":["KeUkjLZOr9oamzYmpflx7zrhKBFBXHYe8Q5Y5YQ_DS4=","9eT0bAUsAn4Gimg03J1Y2w7xdqgwwpBw254Bk7lkmg8=","9uDY7E23lb48y5XtqknC1iYAIKmdxR2koPW70IcWeSY=","WlvMOsBGxv3RmEGpgqADkE6clhk1C1ODZI5TLNJ-zBY=","jn-xyhpYM5j6g1WnFeE5mY5DzR1-cg3YbXGn09Jloic=","ARZvqEa4LjCoLCDzlEdFWdNIAc-pCsua2zlv4oVwjSs="],"outputs":[{"commitment":"mq0T0t9gM-Tvfb_OvHKtPNumsYji_wrGSO1CX3oRrAk="},{"commitment":"kvhhD6rDN31Akkh2o09Te8oynYBs0Lp-arqCv3-erBM="},{"commitment":"Gy10vm1xy9JJoIj9Jt7uf4jthloX_NOxgbunEsfDECc="},{"commitment":"GyEyadJiIaVXDLPzI54UPoxaW35TbKKgMzLuq_S8HCI="},{"commitment":"Nk1sWk8ZQ7BiBV1yKQGq-RmpzHn6VluQEaGTEDhyUyM="},{"commitment":"rzG4-TrRsTsHjEvquy31COewTjx1tuNj2ZqUS-JySQE="}],"merkle_root":"dgtsNOl5D0xNV3gdtShna5MkG1RIFHUS_nz2ALVVwQc=","merkle_root_version":1,"fee":23,"owner_memos":["zSmONksKgIqOfzZlsnFMcgIZVk9YzzXkzBW2NeSNWKzPq4DnvmFxXOi2d58xr6FkwtQ7Ffwj10AWyCu9RaCo7qGlM4DhY7TrtpOml-mWbHpp5A__VOJ35XVBXRN5BMl_X3vIHm9wc5gIsnTladVbbF-FrUpzHnPR","4sXP2PsnKnW9Lqd9l-aSIsuuvazOV9EoPdr-RLOAWNAA7yor-OXDzzTALPiyF81JzZ76Pvs2ZeJ5Z_1FG1Yztv0o0OMOdvA7spSNMi5lRuoAZ-HAhLO1d01J7L3yrHjy2P87TjurnDVCM2_YFi6qC8HkgGibX9akng==","-JcvmApIIFxNbUUv1FdhvXtbMF2pwxpKsDpKWSXONsv115hlRn7WhffVPsJCMtKPq17X1G8-3aaVoG1EWJUums3jRTpyYYzES4kte39H7EcKexSglZOHzXbp_rSCJsj5kpQvDSY368N_EzLC21zJfENDUwIqyAE7","au6EzPBX8nVzCZsrKUH-wOxEee6Wx1K8vL1Kbg0UtAQAWw3F4WhKzk_BcHCAdORkdke4r7QCUGPobZdlWcJ6ZgtukN6TnkRAEj8LaLMJpd3Pk8U1OzdxXhcDQTJxTrdPWU-96lJbae6fRxxxlfl-L9xMf51c3hNzsQ==","h5USds9wxC6DMjzrtp1hBEQ3jzuxZ9TRfQrxsZVlvDxRlmL_ZpRx4fv_4_vLiDBkHyE5cOpw0dt2f7TwNifmisXswX_C7P2Jf9E3xXGup5tzhp8tQWhAlgq10JlZmvkvWbkMHpAUDIna6P15-AIo0HCZuVzlwr68","sbeIrCotOFfq0KvBD0qCZc_IP054_AnLS_l6hK94-vGA45u3yg79KxfeGACTw-e6MwHbpDpEb1wMyUJO_lq7S6KPklBZAntPYFtGTK3Rsg9doP_sJJAmd5eZmJeVkkt1moCk3c-UwwkV1UmWWX8mW7x0TFxidGzH7Q=="]},"proof":{"cm_w_vec":["FbtAoQFdgaMW8GMmGsXbWLk-D4Tk_euoyfEK9YFM_ok=","MjG7OcN90lZ5vBpRBkpVvJ2RKnwCR45PTveCdKDJ8RM=","smCMH5znBE1SBW2orWOyVTboC9qfOwbx1cwSX0TmARo=","18GxH_6XrP7P-mkEu8KFrcCZSPYI6Veb0fBDuwoB9Jo=","25JGtbewWFXU0CMTGI6JNLHhfsvuHodYeDErtBo8sxI="],"cm_t_vec":["oAP4FVAJ7mwswLGN5A0Cc2de6wSyru5cOwOTjyDhbaA=","Fx_Dt-0BKrm5BjNrDKuKPUO5NqOzSujURsvwRFv-d44=","6sVc82ARRnDoKWiKjrf493B1NLQq861NKlDk5UmkXAE=","WzIavyFpHHOeRAc6hQ6ankQBlm0aGCOkRgdQDBdyuq4=","-8nPjeGXHWpnqjx5XFRafSidmk24bR3twOpE7XR-CC8="],"cm_z":"E67A61dy2p3i3gjwmi_UhirtYJieVOeP3T3FKt7nroU=","prk_3_poly_eval_zeta":"QT79kDYv1BP0iD3JqMurO0Cum9k2KVD5kB75FbtA8Q8=","prk_4_poly_eval_zeta":"GEdrFQRdDZDerwzbzlRjv922FO4MqlRvCa8ieYrYkS0=","w_polys_eval_zeta":["bbxozb-DWf4if08KwHHdSdaqnO-Vzgwn8BcaqcIopSc=","ycvrffCwbWhe1004MdECPxxVxFIvm5OGBs5jHODIuRc=","0U8zzZgEp3wjPdTwttAZbYLzyBiLSKNQ0m8SiaT_Hy4=","1u1j2w1Xo0PH1RYVmrL51Nrm8W-x_xR7prg9o9OkQg0=","oQBZSlBVXz5VZA8V3g6w0baST57KPT_FksRkbYJBrik="],"w_polys_eval_zeta_omega":["tg7VlaUC448IL4pYIExEjas_VKriVCzDENXmWdLHgQI=","oAwuTM3CAE1k82peChpsHG07dlhWcey3FHd3ekL8Gwk=","3ACAPmEK8ojvTmHd8zaWo0kbZFMUS8cOyCmS4On0syw="],"z_eval_zeta_omega":"piEEyjNX8VkZDEnj7mDhb5UObkEhRKQFv7Z2FxKZ8gE=","s_polys_eval_zeta":["KoN5fDAiJ_CEmTD0xq2z6aXME_JWOTztt4xwWY8WVQg=","z_r30-sQSrFL6SaQNEklVW230Fuz_AOGz-p3MLcOeyM=","1GFBikoEYTsayrD_Vei0n0AR3w12eCGQGSGXE6eqPBY=","c_T1W71vdtqe6xyvhF3KUAsx0AZd7ob_o2O1lwRNPyQ="],"opening_witness_zeta":"ogouidNVglE0w6l21UyLy3teWdNkL0qqAC8zl0nA2Cw=","opening_witness_zeta_omega":"cO-3keeDkH2satDX7pXaa0xsIo65iTGZ7VTl8D_yooI="},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"bYUNr2Z01DreU5HFIllqeZ3KFi-ruNOtFCy_ZRpcAi0=","randomizers":["GxQeVmaW3hk3XpyqrpWrEg2Nx5aMNcNq1vU5pI9YQoMA","uqBPhZcegHmA-xpzc7zD8eA_pxPunBR6TlkuLEcoWSCA","-4qJC2P7gACgSVINmfL6nDXHwLLBLWvd49ydait2NH2A"],"response_scalars":[["RNk8gxT50nystLBuYFKWz3gIQZt7HbQOOtW9bNPbtLo=","e98Q9GCLRcpKhnu-0Yc_snfZVHaCBy1bI6U7RK37AE8="],["Q38lQ9jE9D0ChUFXbROeG8F7ha_QJyZErOvRc65ALYo=","NNtN3fl4pX_Iv7rfkY6C7gMOeYNzyEqiOqEo91-p594="],["GU7NyiFLneTB-vHDFn1gupSyt6u_i05-V2Iee2-irAY=","D8WT1KR6Jn871enrO6HOLQmEGFyTXRIp4ocKY1A-_zw="]]},"scalar_mul_commitments":["0qxjsh-a7JiUp2KCqMOmB6BGoWvBX2XrrG-8HLcqUh4A","dHkR1bE9l3svVPqIeBYGq1K9qTVxtbl_lfOYg39okQ0A","RE4ITpz2INZk7hFpYAeYKFEmCQDwKx8qutM4wlokuKUA"],"scalar_mul_proof":"m3ov0wEvCUUiho2qopmBfx-RSQZ5UVBBQXSUWmlBZucAqHkqP3GCyYRmlIgJUENwWFUz8rnqL610G271ectBwVYA98qlQwFq_wLOr_QgaanpVWmuix9S84G-_HJ9LpefNemAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA6VG-QUNtwVTCamJoBUb9w05jNDOoquAnLrkkSV0z4W4AStqiCW4-Vm0mGXrgEtV9cZhKHvhlKYJ5pOofp8hqGHeAJ8dBWRDiN1wFKDC8YEg8eMk5jyutGF3SSoRU1PRkx2qAxMPp4bGWEostGYAAvxiOgxiWibmIwTV9rxKIIhRqC0sAJByRDTrPeMJuBFBCCoSZShqs2ryntdOFuhnj4KVehsIAII3nkdmS1sbl0DLHDAqQ-1-5ar0Fjmt_zq4Iuz3w9LHqketbdkg9kySHjzPZMEIuAQbxHCYtVoPAWwA8mg2jms2KbWidovK1CQq21MdyOD2K0iNu6pif7GDNx20S8i6xCwAAAAAAAABvBT-tTuX9xSoPlUsQXlPsSP-Gxj2LeaHp5ZJ4bGY-3oADEDSHAospXSzOyMpewkX7xsNaDfPQ2DIzwlSRJ8IEFoAyQ_xijZhRpPvua0RpncJ3QeyEaVC2Q80BnOQzDbDZgIDLaU0b0HuzNASLZAjQF1Id5oNyIu9tgoFI00eM6PCMIQCc1Xp_gaN9I_HfmKzw8DM1vOGobvmUmJFnGYC2kp118YDbNMn0uiWrs-dLuA6qQph6_ynCYQ7lGT8FGqqtfWbm5ABOzRw0ALysUlXR9qfsMhk3ZSJu16PkK0Pcdk-VD-NTPADlrKOHRy2migeZt_XfKxrbsoMx4tUTtTQOPX7OA-QMsICXv8oTRYlz2BNh5TohFP35sf394A6v5OxJ8GTAhjE5gYBffzy3na7JiXxoyAHHL0XLhI6ANwmLLloqojudEV1ChAAZVLr75uSorCQxoGYbRCTktFMckzKbKqccBhRxnqRDLwALAAAAAAAAAASrXdW-RiEd8yG7lbjoermBAjekTNVvvfeRlAznHf8_gPoCpT34kOmlbExMmJBtgj1qF879bvxSGmVqBcUm6tRngJi08DoX7xQb3umEY-aakhJzF4NUrFoxTbhUtp-pg-4AgG-VH5CQpko_-kXwN0sxt8KO4u5MfHnmC_XGEbAgzQPxAHkyLa3TKMVRc0Yd6gnA-ZGMPmq433gPqAFOfhVE49mugMLdiMMcQFy2DXUjyK_De81M2YTMmzO_sqGWDNPctLvPAAVRT7bja845yNZPbJY9g210puDlaNLoUYNcLgz8BWlJgAkHpS7V3fn79ZLgzgXu-Kuj8x1YgQsSUdG0xRLscAtTAE8a9BionUGLi6NBQgGMWpC3kOedfWKIJI80jpla_m5bgNzyBxgRfYwCfsCRnBzixJMZ53N_pZ10xRsdqeTN85TxAC3vboIM2Zf0AtFfEF8j6MslwzoBWp2Qzbb9EITVrUojgIPqbU1t_7iEUqz_1JPqoGaeV7UPGOQVmQI1VE7VDYeuK18TjJuXPMM7TObRfXeT2n5uMcuYDZobDaOhkfkvxLk="}}}
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
