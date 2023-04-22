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
    use noah_algebra::{
        bls12_381::BLSScalar, rand_helper::test_rng, serialization::NoahFromToBytes,
    };
    use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381};
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
{"body":{"input":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQMHXiTQp9tlu3ox1phwlIZysgqqZbNzBHJ5K4I9yT_fnQ=="},"output":{"commitment":"hzRcdHRDK9H4gSnkmW1h5kMRrjiObz2iq9sqP2ENR20="},"proof":{"cm_w_vec":["ojGMD0fe8EM7NqAdbTryKBtjthtv9Owo8w47VqzLaxLRIwXy6Nvqz_9o4FoFPmUi","pRec3mBzdqLvX13w1aN88hICBUhA5gTEON2DDYhtJhT4oIBSwtSx6BvqvbIfVyCX","hvKWojEI3k3Pk461F32ypZiD-ZBLiuCHOKQrSupmERa-Xbb9XhifJgCb6wY22bX1","ka7vWPEXItHvEFigW7KOjkJ43x7KidDWiswMg5fc68lgLE5JRJYtz1orm9P1LvSM","jlU9rMXTf9bk7_mcNHc4hDBt9BebVY4HeUuehRu6Dh7gbPDK2xFDQjC5_XdZGr9d"],"cm_t_vec":["kPZRjbwUUaerB4NOk117zy6-HjGONIlIl3sH5qj1X2UqBUA5MCRSpA0QxbS7kIlx","pFKeAJ5SEdkEWjZ0N71f5hOSNHMTPhOaZpS8D3satPbpONIFHG7N3QK49WWQO9qd","mPpRtQmstVW3hx43Yjyk3F5JQx9sA9RB4e__sLjpSt5la0NrTlPo9nCsb27aEtKg","tWrUP94-WPuOOFKgakIMCcIMNsEXp22fr29daSK_n4lIdwHYMCSOcBfrGWS02ONM","lYdskX8utzkW0Hfm_eSrNMpnm1tW5hzMYbHTclODLsWyM6kG_ESG2G5Vv0MOpDMk"],"cm_z":"qk2CAOzi-qRVa8uTzJj7XSQIWtTCJl59HjN25VqChvtJAHXp3dvXXpvizbmj3sHl","prk_3_poly_eval_zeta":"I6uDj4oW4VJ_CcvIj_lTvknHAhAdIWeVhz1TkOgBVWo=","prk_4_poly_eval_zeta":"dw-VkB1DxDiAfyIUeDa6Wm0vFhlN2iF38htPDiFHQyw=","w_polys_eval_zeta":["HxbAeHwG6zrnHX7IArAbk7ge9gbj_yU0HQMWD8j1Jg4=","hswSqZ5efZ-9IMhfxBRpCoP4l2lGkkgI5rhlLXWPjBc=","Ir9flH7HIyggV3f6Tn62S3YQ4YvIOMFxytffZ8ZaSws=","d7Oioa2dr8F8KHgnCeyXrdqTZVD1p8XMv9LMXo6F1WI=","bVk_GkgjpD3lKn0P08ovubRuE9bwlYa2LBnFmnC7HWE="],"w_polys_eval_zeta_omega":["gtPvsn9c4YNdFJZKER2JFTPN5fHdXo3qei2_TJZeH3M=","KFLELN2KdQLitTje0gwc4tX0AK_7xBJjDhwd3cKmS00=","_J0jsJjoN5SpMLnqPjpycMwrRu56XdkQ5nfjxqIOa1A="],"z_eval_zeta_omega":"2zCZKYGvhb8oRrxhydJQfxSsuWB3Ib43m5FcKdI0zUE=","s_polys_eval_zeta":["pYG3po68rmosop81V_ntV4LbBs5Fssb3TwHIjbbydwg=","AbPHOoKvf2G7LDklqGhxfqeDe2XGn-Lz4058N18pInE=","QccP9MbX0U6biUuRQb535XKv7wmeYETsjKoBRlUwihk=","nc4UHxX4eFWxCPZV-jkN17mXJpl75nLEYFC4wcB6Ckw="],"opening_witness_zeta":"j9Neu2_Su3eEUo_LDfN-1eIUldVejby7hitQjup0e8nBZOFlMXweelKEIu3J-ilO","opening_witness_zeta_omega":"tcrx5j7DnJHUTnzoGZ3bNkVqFCl-LKKPFnyLQUloMOp_pyhuFP-KCedCQ0rusIQK"},"memo":[11,68,57,220,71,205,117,121,65,179,63,74,27,189,65,167,80,46,36,62,177,59,46,146,84,81,230,19,20,247,237,35,128,68,227,193,50,63,186,101,184,24,191,179,98,113,156,27,180,230,80,41,207,4,40,149,90,214,248,188,80,111,217,164,200,150,212,136,37,235,221,167,144,29,65,146,167,169,144,135,176,158,187,21,197,160,76,181,33,75,247,108,76,171,132,90,27,61,170,230,246,131,64,120,136,4,124,14,35,9,215,77,33,203,194,202,199,244,149,185,51]},"signature":"ARu1tuwcgQx6sh1P826MUk0K36JW7NCJZ10AA68tg1WwZCW35GFYLieF4QcRlJ8lEabtJqtgoX2CkZ-INOXOxlIA"}
        "##;

        let note: ArToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_ar_to_abar().unwrap();
        assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok());
    }

    #[test]
    fn ar_to_abar_ed25519_test2() {
        let note = r##"
{"body":{"input":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"ubm2g73DTf_FgkgZzvqto39CFUb6oZivPup2taoQnmQ="},"output":{"commitment":"e8uW0lLyLAs5EuTiEsEaV9J5qF7CB49zpkWpVVHfJEE="},"proof":{"cm_w_vec":["pOxzJ5-UoYsAIk5MzhczX6er_H2kmk2Xal-dTNZYm2RYc6V14qmlCdgQ6KG3T7LD","pzGHkL8fzQdtD3rzc0BGVjrYXX9Ma3WE57EIaRPwdvyS8-iWg_2IfmPwE8TTNd0h","rO3Pr5_Pn29K5--k7UUa3qH-f1Oy7PeL7aKvAwyffVrVjHosTtZGnO0BY9kXsd2_","sX8B2snP4RbEYJaVKF0mLu6pkoH0VbZnH6wfGMZkjDIXCcfbj2kalM5uxvRFH2Qx","uftamvzA0PO-350dUk2ztwS1CFkmdfpvJEOXwGmmNC_cujKZsPtOcSjqTrVmkwZS"],"cm_t_vec":["oNs47GncHWB-ul-DmVuOmEm0QRYTqqXRhM9fqJ2w1UOaR6ZuGguFixG786gGSv1v","qneDrH0pdCLy6268WAOfGEMwlUtcWyqRuJlQOKvEwwF1y50qUCjkEb2hHDGVNm_r","qMjnZ2qx53ONuXBJ9mwCbi5v42vH0DYVd1ycRt587NM9pSwiMeVe79BX122HOGjo","hEZE6qlA5l3CwPrxqKMeCaJr2kF7If18VBZOaIetSuyLn63RlhCB2eIAJE78cASi","ow3A3ILwVNi1KKcrgfpz0NAGWVY9-TZgHqIvAowp8SI-SCvfmuWnw5P9m13brSDN"],"cm_z":"t-XmiLY9iOv51vwJ9hFRqDBH6tMRi1y56J-tn5S9zPceBPKbYuytDh1HpuXIlV6I","prk_3_poly_eval_zeta":"UJ1wAysy1rZUErjJzHdFvgOc-ptqIMl5Dk0jEQxXvz8=","prk_4_poly_eval_zeta":"zGB-VZqW-rxzm8WWJwL64sALGgCU1NECHe5n749XJkc=","w_polys_eval_zeta":["KIayNCqH7AIL0a2ZJ1Eq13J5UmPvuXpL0zDd0QNXako=","EtqlkYE6iy2Qg5um-ulYUw4Jvd9r9FPBy46Hs6IWCBI=","kbR0BPWMcqH7d9rzkGqF3g7bcBCGXDJ6H9gren8qt2o=","E_ZCI-dDz1lMsnEj17YhVoY39857TWkIT1UNlwW5UGw=","X1y_cpegcwCIf5IwaWQxj8q3KM0ELMPMGGWC9jGZ0Wg="],"w_polys_eval_zeta_omega":["Z74adSAiCyqXVnH9antzsi3PjEWjdL_hu8UybHF3IkU=","5oOOuJl1uk92DwF-gGvHvHeSHG-nhbE56zIMvUqqKgw=","jz-F9aXUhyXs4YNxoV47dutZs4DcHGlM9HwFhW3ag2o="],"z_eval_zeta_omega":"puwZa_8_RbPbSmpqZj_cAQu9NNBcm9-Kp32hvIWKElU=","s_polys_eval_zeta":["qLNA13BfPLXGK-svtS71yVFbtcbqdMBH0kFudSZw_jE=","1IvXFc-VwMcxfC0VyoPTn_jHc98ruYpwb1vyLyUzXnA=","CdnLNBEM4O-K6_-ma2myXRrjIvnEYt4Zs9ij6HtXCio=","4GKUv4cT4wa8Jmj7zEyTOA7aKwypIMZBpRouADb7WFE="],"opening_witness_zeta":"q892q-P2InH3OqsSr6fu48Zhdap4e9_BAkuvPSiUhFsEtMvZjF8nrYu6WNSasXO9","opening_witness_zeta_omega":"mOK9XpGXGgm6cWXpW52ttyLxqYAkCe98-cjuaRPn2zSgHXcNtZiikM7DC0zqZn3S"},"memo":[245,83,177,232,86,46,33,102,38,91,121,224,3,98,178,211,35,79,145,201,173,68,46,164,222,141,57,2,230,64,210,236,216,177,43,248,92,107,52,151,128,188,9,45,165,235,59,202,253,61,225,33,98,162,59,254,159,74,54,109,170,228,134,191,122,44,165,233,100,228,25,255,106,189,217,154,165,189,0,82,236,83,10,162,230,53,214,49,255,56,20,93,140,56,231,28,97,2,35,82,82,76,214,167,191,214,248,109,19,73,217,121,136,148,135,95,11,237,89,209]},"signature":"ANjOucy8MIF4bcI9kM_1Im8H-O4kT0Gw_IpbWd1LyJJKpj66An2Iuxbh3oHXGxhdIPC13ErmxypyN2KqYcGfjAUA"}
        "##;

        let note: ArToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_ar_to_abar().unwrap();
        assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok());
    }

    #[test]
    fn bar_to_abar_secp256k1_test1() {
        let bar = r##"
        {
            "amount": {
                "Confidential": ["ojTaP3kGouDdfBMWl7I0b9fsxhJbxwwN0cZT5zS5ghA=", "JqKpgpuTv1ivR5v82AMxaLHoLu5k8nqTbzYclAMupSM="]
            },
            "asset_type": {
                "Confidential": "aJsmbMvB27fhDBIB6WQSKNq86PKfGngLe-0XwNwvCCw="
            },
            "public_key": "AQPUW2OcZVR0xqTHveZJ_RuU3yHTLX86DbtaDLDaI9QoBw=="
        }
        "##;

        let sender = &[
            1, 216, 123, 98, 180, 6, 253, 208, 168, 152, 95, 151, 23, 145, 117, 227, 218, 134, 234,
            219, 116, 238, 69, 10, 6, 206, 176, 71, 132, 246, 92, 206, 173, 1, 3, 212, 91, 99, 156,
            101, 84, 116, 198, 164, 199, 189, 230, 73, 253, 27, 148, 223, 33, 211, 45, 127, 58, 13,
            187, 90, 12, 176, 218, 35, 212, 40, 7,
        ];

        let memo = r##"
        {
            "key_type": "Secp256k1",
            "blind_share_bytes": [219, 127, 70, 70, 81, 137, 62, 23, 70, 185, 35, 3, 201, 105, 88, 129, 165, 237, 255, 136, 251, 64, 235, 66, 7, 0, 106, 7, 103, 9, 161, 121, 0],
            "lock_bytes": [101, 126, 98, 114, 184, 41, 201, 244, 212, 18, 14, 15, 172, 92, 171, 80, 215, 163, 192, 141, 126, 115, 105, 16, 245, 121, 118, 12, 242, 72, 54, 190, 0, 36, 222, 171, 83, 138, 196, 26, 169, 177, 142, 97, 112, 202, 179, 119, 96, 232, 54, 149, 15, 189, 154, 104, 13, 7, 130, 90, 87, 69, 139, 77, 218, 163, 187, 223, 12, 109, 44, 204, 31, 223, 215, 68, 4, 4, 165, 176, 99, 110, 39, 3, 178, 151, 152, 71, 135]
        }
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
        {
            "amount": {
                "Confidential": ["PKcNgAkn9NDRNlRxnYbhak2_HWp__5A4Yb47BsehWAc=", "UGiMx87YbRF7JJ-3P3qBrQxWq07E1OVKH23wWkFKsmY="]
            },
            "asset_type": {
                "Confidential": "prdhgrFp_Ge1PNCrJNzU6APcaglq53Xy1AhjnYTzTxQ="
            },
            "public_key": "9ZHspz6GwREmKQA7jhhlzqW9PQ5BjC1JdkilxkqY5M0="
        }
        "##;

        let sender = &[
            0, 80, 46, 44, 217, 255, 85, 183, 201, 10, 216, 222, 44, 93, 111, 196, 82, 211, 172,
            37, 196, 66, 235, 96, 26, 159, 196, 173, 16, 71, 117, 123, 161, 245, 145, 236, 167, 62,
            134, 193, 17, 38, 41, 0, 59, 142, 24, 101, 206, 165, 189, 61, 14, 65, 140, 45, 73, 118,
            72, 165, 198, 74, 152, 228, 205,
        ];

        let memo = r##"
        {
            "key_type": "Ed25519",
            "blind_share_bytes": [47, 209, 173, 178, 193, 11, 106, 71, 111, 113, 180, 65, 1, 198, 193, 156, 48, 181, 126, 58, 93, 67, 44, 77, 150, 249, 254, 145, 65, 40, 116, 12],
            "lock_bytes": [79, 13, 209, 26, 228, 82, 10, 235, 151, 245, 50, 34, 219, 16, 157, 152, 77, 155, 44, 182, 131, 67, 200, 69, 144, 167, 246, 167, 159, 195, 31, 42, 164, 206, 225, 1, 234, 181, 189, 145, 255, 156, 159, 151, 48, 33, 3, 47, 220, 64, 211, 251, 209, 74, 246, 163, 55, 237, 125, 75, 3, 47, 165, 0, 175, 12, 89, 66, 92, 88, 117, 207]
        }
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
{"body":{"input":{"amount":{"Confidential":["UKNKaUYuEZskGZ0MSqkBTIOgyZ3LabN8xYgMbfs0Vlg=","1LV_IDLSuLufFo9A2bCnQxOiX7XBlHf4D_F_2CEThWc="]},"asset_type":{"Confidential":"5Euax7kOqCqHVQ0ecIi6_X6nY_fn4Bu7cNMnvqOSXks="},"public_key":"AQLMX1GTi-kfaotwqVQeGLK7gyQ36PTY1RHYjiCjarOXXg=="},"output":{"commitment":"5LerVsg-Rii72-hpbl0CElgobs5e9WYryp7f51KM1jw="},"proof":[{"inspection_comm":"wgr2IPEk4H8UKatW2thIY8vkvbqJoWcRIjRWBWs2TQ0=","randomizers":["HsZdqnmbiSCGhhOsu1rjP5Mc5dY8T7ahsIcuUqkxT2o=","MsR4yQJLMwyuiReV5MCRTOopu0KBuoCcbizCLhALBHs="],"response_scalars":[["QeghMIevHnySeRXLbF2srGQCLlplGAcULCVCnDWM5go=","Q5bpaSPxUU_0wB4I-Y1T8WzBmxMv0KRxghkgV_a5iwg="],["LyOPURD1cDWoP9Lzwe8icMgW3z8VegDWRE2q6NNJmAs=","awnHKfWRy4WNipzrOA-vnTXTEnuGMco4d-qMGrkQ5g8="]],"params_phantom":null},{"cm_w_vec":["tZoYZGT72c_6YLRwMclT2CBbfTuz2cuIiz413rIyPt_3wPaadV-IXLeCWDIdm4wZ","rcV2u3E-TWAR4iiq9VgeJBZNPe1hQn0uzFuYezcqquBltf6xVBDmutjmeLZkqBVO","mN5bwMYE8Q72_wqtgiHnjMRBjnwGDK5Hlq2HqI6l1cqUbsvGavmKD_NmBmZ5aAgp","p8UTKdSa-ho1w3GK3SxvjJL_z6MxxDM5JuZeUhHyJ3BDaLL2qAve8xnsqxESI92d","kQnHV8NqznbkdF8ZG5OK8EDzkPwULwXPYqGWCGZhi9PNP3G-pyP9Rwoq5YPcfh2u"],"cm_t_vec":["g_aALDsjrv-8Z74WBQLCMX8Ez_YKIFWvJE8c9njh7CRP_c9xJPf1NOZOXhDun3ya","lhZd8PJ0u9yYmYxsR16YTfIvFoK0oXf9WMSe-v1jkPGY13bqIjKT0VXiGsBcTRQf","lgJyMXR1uwzx02CFH-EoptFbnuau-a1QtL7WCSKIQ0gswmch90Hjp9B2WeHygZgz","sxsu99sI84b7unED7PK9maBY9uja0isStBL3aa94TOgoeB1hgCVa1s67eaDGzbYo","t2FNrhWmWTkRlKJYirtsDuoo_KPayO-sbgMO5OSnZ7z_xFe5m8FQ04x5Exwk30GZ"],"cm_z":"iCoigZ6AxmdDxYCcY-fbnhG2WPxB87ru9J-VFRbrSJM3zT6LE75i-4btrK2gyPZ8","prk_3_poly_eval_zeta":"oihE1y_SOS46CYDxHLDmOspThk4OcpFm1YgPxFiACWc=","prk_4_poly_eval_zeta":"an64wfWBB0KAEUZ5yn31E6EqLjd2NTDW0EzWYSDPCl4=","w_polys_eval_zeta":["l5Baawz1FKXX0HDJp75IJX_WporLvtYyg1zBs3pb1Cs=","lqwEMmYQriGLSkzTaEXr6EM8oKwcQGlsPGKN4hCIjjk=","272opvBpJA_0NRMLDMi3WABBvdjcucbcQ-_cj1gZPnA=","PzVAuhK5gbQXshesVZkggb_DiVM5N9uU5_ShFO6Kv1Q=","3Kfw3g1KzTEUxzWPuNpBs40FqTtwK81Y7y6V1yMA-Sc="],"w_polys_eval_zeta_omega":["6n6rbD_sllkCdfR-0FVKK59sjNohYG5WqIzUFkSykHA=","S0qAznDl_YMf61wjdkBNZKtwsbRqzwyvGm0ZT-RRJjY=","zwSSsjgjQCAS_BVBB7zzAOz-gklES58GzWV9Ob1q3FE="],"z_eval_zeta_omega":"z5MFv1_A1QByE5ix46dmDZevBTudUJxoCoWliqLidh0=","s_polys_eval_zeta":["l2h2DhFME2ctTjIWxPx6lFvCaJPZ2ayCJ3EuYL4CaCQ=","LHBYWLAtCs5CIaYC_7JZbuU7qh5iBT_C93uF4GCwvzo=","_kKFCFnG6-Hkeif4xghyL_3Ib4jufh2OWFpsRL1yiSw=","K4oOA6f1jqQhEQsfsZ-IbvSb-0_RTx-816PI4pCSnUY="],"opening_witness_zeta":"jFAYW8LBCMNdh8q51dwU2VUQgL-g7bkAky1LGAUolp7-xKJZdIOw03FNXdp8Q0F7","opening_witness_zeta_omega":"t2EDj1uch-AynyriacNnt5u4TcQ-u6Z0jg50w5v-Q8eC4Gosten04mz8-e5dk0Ma"}],"memo":[254,146,129,202,23,253,210,140,0,83,103,224,6,105,235,16,14,175,31,208,109,198,156,41,224,200,1,85,140,53,117,12,0,131,32,171,93,16,158,23,14,173,189,244,154,254,113,55,20,218,177,138,94,95,231,186,26,222,15,230,81,194,224,124,186,32,180,247,84,173,132,41,107,250,79,176,96,178,180,81,45,126,32,20,121,118,100,8,83,194,251,42,193,173,107,32,10,158,18,106,147,153,67,70,250,229,253,42,95,237,194,248,75,201,39,170,0,245,254,155,8]},"signature":"ARwBQ6EMV3dYjVVRYb4GfmRpnS7f1I1ZhAFid3Hjjl5ffFZMfcIqaPUDx3GnkDjSvKzM3D2fpSPMIcpGJ3q_56wA"}
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
{"body":{"input":{"amount":{"Confidential":["IkbeA_mF4cbaBxLP4btFJ5uV_F-q_ZOOnsHSmHRC0Fs=","bP80DwomCiPErXydhkuFkR5PlYGZIj2cwgDkIZgdGjE="]},"asset_type":{"Confidential":"uFNhTJxNWi0kwZIgncWxDWlViovH1ToDvZTm_vsAZUI="},"public_key":"nR-haY160VM5g4Fu2lnQc-41b2zmeaYMWdpf4eSGWK8="},"output":{"commitment":"kun7vZ05GIxwLE4BqOjLo0J483nYLgce0oBir5X-omw="},"proof":[{"inspection_comm":"RhUExah4zs60qaIpa9a9j1iGjSdOGqQBQMoKhDeZtmg=","randomizers":["9pPlHw063AMHmrrinDxzfFRF4zeT3Fin3A86mRdJ1Sk=","6saba8zFEC-eFq0gB3rxcDe3avN1EKPQNgPbyyeUFVQ="],"response_scalars":[["W-knDq4vhBEvX9-OU3UYXSxHmMDRc_GWgNLk1pYBlAA=","S8dlI5AODjrMHSLxrptVQtlOuxNCQgeH8mtydpSJUgc="],["TowDYE5aeuLjl2HuuQJGgxxqNWHRcIBZRYpq_hhUTAg=","aj6NudxS2kuf3jDVDh19bCCcHN5jyiYVHZoU79Ak5Qo="]],"params_phantom":null},{"cm_w_vec":["s4ZmmyxjdMH2rvlK38CWtRrhipkaF6uQ9izcoBvXl61CsOyiA4Xh7zE8t7dQe996","uVVBSjyJYInnkYVca-PWjIT5lyV8Nv1x_dMvaYKiNvj7BcqZLk5evnL1y7L2XtJ6","k6Rm9EsVt00sGGiPxe-vLLrndOrFmSnD0MWY_mVbUVXUOjjtf0OCMXIPgftlvy2T","heT2K9l4BqJ1TCvrOknx7kMbUZLTQXE6fPI_DtxSX8TxjsN93VQSRFjz0yi1gHjO","p8W1RRgSoVkt-l0h0T3OYZovu-Mrcx_zmhpzl3PKZDaGb68tkOKCFQLNxnjAjgS3"],"cm_t_vec":["j_fP4NC03f3dAJ39RVuupjylCBBHdohrHSvZ-qypd2Zef-maRMVsDPtYMm11LJEi","lx8jsKRbXpx6W7Z1N2rKroiSIFVvRjXhXrpFiaBap8_GqNObKI76LA2IQxoSOOId","sZV_1Lu-MqUGLIQPapYQgxl-dTd7kblkGZPHN8AEYL0aVquwiBs1_NnPriY1UmyL","qJvVObI2GijpBhoQSzsNrbGBohqoXI7LAOjYhKNsQ941eo7AG768vBP3IAWXZvuI","pe14Ci_B-rBdLixTupE_e5fwWxYMlp_1X4oNzs38bnR-KWOTEGZwiBV741D5SXV4"],"cm_z":"gLEwnSmlw5tN9w0T6dX96RisLeNO4aO3BqGVbgkoI_QLDJ-tp5HzM3VuXko7Q44M","prk_3_poly_eval_zeta":"ZKcCSD8slVoKa-DcIznlsOL2_7m3wcvYnRgdZBN86hE=","prk_4_poly_eval_zeta":"z8tQUKX-E9mVlKukQC29H-Bu_16ejIeXPtFKtvLL71Q=","w_polys_eval_zeta":["XW5ZlF9ZJbzbiRZ_fHAGfFhT9Q1ylv6zM09e7KO_bCk=","2k9MuzGEBSIxHN70eos3cxzA5QG3c3di8AtRPcXiqjA=","pxLdnWbotvNawpcVMNymI1YiU9-bs0nDM_o3cgH9CFc=","j_Bdf-NLQTX5zY0UsIwvY2S7Nxgdo5lJaORLlpglkUQ=","65-f28j5s34VnUxhmw5Dt0XKIm_R9TkDN0U_JCzdGT4="],"w_polys_eval_zeta_omega":["zQu91umKSVTf4HmLkLKFDoWSewLlQcgSfyFRzSkrXD8=","q6KNSplSuirS9CgNIqTCvV4BKF85YJpgLpdOasd-i1Y=","hroMYlZF7gj0IAq31qclDczFPks8g6jBcUx1EcuVlCo="],"z_eval_zeta_omega":"C8opZDJX41Vct-yFfvpaGGF4SwddYVnOZHO3qnXf8RA=","s_polys_eval_zeta":["BdLKZPjBqhYW-LI7LsOD9yRIW2ZH94J024PO0u8qy1o=","RJhYCxJvQCv-_PGSgNrDaLcDgvpyAemlPd4ksoxmI1o=","RDsWjLn8miMiPP265hIwOP4i9qmJJBc0Ve39EnVoYEc=","6I1k39yGcvj7Thj_JfHwf1rcVUDTbUhnNSZHSanNbz8="],"opening_witness_zeta":"r5xw-SqXmHj1md3Fm3funKtcqx5wJF7P_z18uI7J2VsTTHdrmmGWcFkQ5WwzaHbC","opening_witness_zeta_omega":"oBjsEzNKNi7ul6Xi-TkY10Xr5vheWEmcGLnH-hcy8VqZ24d0xEaU8xNfigKOlkIX"}],"memo":[154,57,159,17,237,165,77,93,37,116,94,21,156,79,44,184,205,107,103,66,75,94,210,102,166,161,100,100,156,248,111,46,3,194,117,174,20,173,130,185,209,69,107,76,30,43,155,134,173,208,63,150,181,19,120,144,19,170,227,60,15,212,226,237,212,91,204,46,41,102,134,236,52,99,171,255,5,169,14,36,234,181,105,160,72,130,39,36,177,182,215,55,246,178,208,16,227,153,99,148,71,57,174,233,70,230,31,79,91,22,146,180,127,144,136,139,235,254,112,251]},"signature":"AN7FseS1IPmG0X9f6wpIZMLluXyMevtAId7T66fTlj2w-HYVS13bPFnScnLhTsOcKNJZaW8pMi9WdRn54QGjug4A"}
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
            "commitment": "pR5zmuOQ9IuQNCzC5-o-DGQLcLZcEzD61m-bszngqVI="
        }
        "##;

        let sender = &[
            1, 93, 249, 188, 62, 16, 114, 79, 151, 250, 199, 168, 1, 239, 122, 215, 191, 79, 96,
            174, 92, 125, 155, 98, 33, 99, 6, 61, 251, 204, 63, 214, 20, 1, 3, 160, 19, 53, 182,
            105, 135, 0, 122, 248, 29, 97, 139, 179, 81, 214, 147, 235, 158, 25, 116, 76, 12, 63,
            178, 195, 197, 96, 112, 131, 44, 62, 255,
        ];

        let memo = r##"
        [58,84,43,3,228,90,38,139,137,72,53,193,80,171,7,215,195,74,171,108,224,37,225,59,81,16,93,119,87,200,193,214,0,1,35,51,147,193,51,193,184,88,41,118,229,171,143,150,237,179,37,96,235,255,243,144,171,213,183,128,102,32,71,4,185,52,29,124,190,56,55,152,18,238,54,142,181,118,241,166,183,130,142,229,118,252,16,205,125,170,74,4,225,95,205,150,98,47,128,126,127,141,30,200,198,10,204,185,133,66,58,82,34,125,138,216,105,115,177,127,47]
        "##;

        let abar: AnonAssetRecord = serde_json::from_str(&abar).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: AxfrOwnerMemo = serde_json::from_str(&memo).unwrap();
        abar_to_ar(&abar, &sender, memo);
    }

    #[test]
    fn abar_to_ar_ed25519_test1() {
        let abar = r##"
        {"commitment": "MqDXmmoWaaWJtmmTUycn3IFHKuQncHnvl8Gq7NtIXDk="}
        "##;

        let sender = &[
            0, 71, 127, 50, 47, 5, 51, 215, 80, 53, 19, 188, 213, 0, 10, 217, 22, 21, 196, 47, 26,
            81, 114, 20, 158, 103, 163, 164, 51, 1, 254, 200, 236, 248, 149, 106, 83, 191, 150,
            168, 96, 137, 34, 6, 156, 72, 235, 178, 118, 238, 22, 106, 64, 204, 170, 241, 142, 124,
            183, 232, 195, 186, 173, 18, 237,
        ];

        let memo = r##"
        [154,166,6,228,86,224,236,53,122,72,208,178,168,253,191,101,246,220,95,224,64,173,186,69,216,63,10,101,139,110,198,57,48,80,90,47,180,78,146,12,55,55,200,251,85,116,98,91,13,167,80,230,102,196,233,4,233,50,11,248,205,75,17,204,70,93,158,63,167,38,153,107,162,97,193,17,192,97,210,17,219,238,154,199,103,209,239,63,43,154,158,5,97,68,75,245,33,188,106,110,6,219,191,249,243,249,14,136,90,58,238,201,171,4,16,6,123,175,100,8]
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
    {"body":{"input":"crBGphOnvDIn1GcxTr42A0qGK5yBKuF-7eX81W-Q0QY=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQMnEdO6Hs21UfmN8fyOKyObLCQNsp2gRiisQMUb2ZXblg=="},"merkle_root":"-PMnQ2DCZTYcZ-orwuvyS8fm3brA3DuydWxxmBmdPxw=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["srNZ8wDkuPxag6pZ6ZPqjPhQAMAicVk5WDdp4SLOGO4hWYUfNBaSAURD1KJQ5sNd","kkBTGJIJC4SbD2VBvFe-YTbaFvA4RJ5wB-HJVCW4ZoTgBQGRVC6ERNvLAEJWQcR0","rMbvUmRltqwcsHZmbgqprCdcgVViXq7FlQMLFHFuC8Z8vpfFoa3NGQFA8tgP0xe3","h1uB6QQHd3SycibqNhOuBmR1qq8bQHx1p-6_osj2khOOwI7I6GhtzEPvYxlEkCZL","gHHDP8iaCww7fdcf07wDQJnN1nyXEOZNzwOrs6h3kxy4t2ucQqDoNF7pLvEjpLOO"],"cm_t_vec":["jIaZnqz9oWbZmlMR6H9ehIWaPWVts3c6_9uYdU4XBvSqCzVZRFtE05zKpu_JXvJ3","oE8S841CArUZXJ3PUsfHFeEwbDeStSDg3rQRtDHZLRyOTQY3PJ6ag-adep_V5Vbj","o3KLrPTcdIntW449NNfKZCM1EOUw2l3eKSx57PFe0UhpDQ1CIVxF-JLhxU6WPddr","gXXzo982nYGTKTatkidk9bQWqrLjUNbBiQC72ej8T91dMcn86GBTYBMjNGreBWMH","puXKSDtBYutJp0rUbNl2OfrGSayBcPXCfXqeNjqDBWuJ_6po_LzP9XnA1bdKXXFf"],"cm_z":"kRr-vF8O4pWFhdJlxaQBeHVePrasLeVcReOwweHq-0b1uxMcQX86niVv4lU0VA7s","prk_3_poly_eval_zeta":"wm7B_zq8_3VQV6MX0VzT02kUUb86B3h4Z-2ul2KtDCo=","prk_4_poly_eval_zeta":"cqnvU-8Yv0Oozg0sAhE_2Do1uj0AW_GQ02SXN-9Vh0A=","w_polys_eval_zeta":["CcrWvo3pLuQ8NGhBGT5XATbT2wjXPRys-KCmTzwPoS8=","w35TvXlUj_2n7QfNUBhnEISEgJXdPt2YEhE0RvwObD0=","EfejmquQ_6rtmVxXRkH0GGwqs7igi23jesGA2-QL1Ds=","chN_Bmw7_tPZOUX7wLWGHKtjRlymAwNCJfW-Q9AWQmM=","5bkzKj7VdG-cU5c9XZ_0L7U1ruuLykMo2mE6gn_nbHI="],"w_polys_eval_zeta_omega":["qRyzGO8tAIBJgDOsv5QHYx7VBiL_rEz3ImKKIcg-wRQ=","02fr6iot5ow6DcWLRyRbSxGzxgvwEx9RNmHepRS_o0s=","nxSNxktPeiMdPb4Gp4oKrV8dG78Z92Elkoe_fo6Y5BQ="],"z_eval_zeta_omega":"ukwWYVWkj-aHfU2K89c1lT_w4XkSDiELQaSl1l59rkQ=","s_polys_eval_zeta":["DDdnU_QwnblYTzKTogJCrQrRkHx0LzhUkS6tsWXfWEc=","a2iLOP7znOjsGq5Ft5El3T8KT1Y-7ouDIL8j-h3hNgo=","9e6Epk86pB3BfEsyUQ1iPQyN6XWcopYlPJWWS22QxTQ=","B3M-rPNuLtPs7fJLNCocF_dZgT9IPNQD3M3yJLmHzwU="],"opening_witness_zeta":"i8P2zsv4x0lWLRx0V8ROYTX6VQSsOin-2H_Dq0O0vb1T77QhIpkUUDJ79eHh_52z","opening_witness_zeta_omega":"hFgX3dr0iRMRGmnm92NGEQ2eyGmixvRXGEhdQL84vSgzS-rWovFVZTPmEg0mlJFy"},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"KpgPeWtpNdI4FetTFr0jL1-GHauJPxymbDbYa91npmo=","randomizers":["k_DKLzAs2tUaoi-zSseWZRxC7NoVChlweuDT7dvFCO4A","25pK9vZQI-W0381VuWXCu9j2Q4uyxw1uG4UNK1rRRE4A","6rfoShIyAVbHJqjGN56gh72-xZeKGWy4NmQ8tUBldvkA"],"response_scalars":[["_tw-VMl2tm9d2t8OC6cyat-IlwnfcX9QxbxfJ8bGXX4=","KtvzE3M7umsNKxyk2r2jCadpYhEfFCeUXWcC0p94ySQ="],["UdvCtyoIcHNuPvTwgW-Vbcgm1spI0jUDDBV_E4ysswM=","2d2qahvYwPAH3LY5hb8m-wq5kLrFwoGPK2Nx9CTOpYI="],["b4Hxl3oRnRFhHGz1n_Y7eA6sTvMRlsxb67wMYh-A0Ow=","poCxKZy19GhxDJsc1-EiXbOLzlOmQdJraH6m6nxzoBQ="]],"params_phantom":null},"scalar_mul_commitments":["zVopOdLBQuL77tHXlkXdJwlw9c8Ih22XBN4W607yH8wA","4ZUkyFD4T-gUHbYmlEUjQIS0gNuTcxMg4_DiaPdn0pcA","9NRgMqRuaS-EHm8DNQE8hx2b2wW58RAF1aS7hNS0IhUA"],"scalar_mul_proof":"HzGu_0hVO8Dwx1LEUgCSky3EXJfNVFy2qQH72kxK7TEAB4_KO7FwvV6snAoKrFYiTp4Y4xkAUM-asncnyhLkHJGAe0xW_FnXq10ZqT48qyGJif4vAXbZFFYZSfFCitAIZOOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA0KHBbGdzqCG8qmg7M9P1Q_FreIVtCSRBtPPO8YTPV0YAYNNuvYKwsc4V52bLftZo86x5btN2T8cXeagc2EBFqpcAX_Nh9v6-GHBpmbXVi_xHetsk16FwE7TCHThrb3lC8bQA0CcK1WF7Vh2FeCZvawjnTKBczeHwPLEyAD-PcqkahS0AEptYAUP26mygK30mAVZuBlvd_q4k3NApb369t_ypWjYATIwYiPQAt2f0oZpcfCfaV8jUjvgAJurZ9P-PBoE1Q1Sk13Vq0MCkBevMSttsrgFJ44TDcDvr2nfWFg7ucrWQkYCcii890B8svhTh9FD05Aue5YuE7GLYWI1W68k0esX5CwAAAAAAAADP9kGQ5mrymzfMeYCFc3sgGnJUgtE-a_VNOhOa7_aPTQB5NGniU_LwrZMEBfqqzen10ZBivlwC9qAbkhUFl7ZhfICu19JPBB2r6dxHGNrt5bCEbcnFq4BBUAi5hRF5tgGMSgAaMIdc1e2VDDbz8b63MIsUnyg6SY5b2W0wkOwBJAzzwACufT-3-VhmbEIyzGW91UMYfNJ_c9yYZk5qhHh5BD9wggBtzQDtxw27bJQ_zgRpLV5pcPT0J9hoCRKTtZPsZXAk2wClSj9UBwc7N-w1x2Xwe0_Kx5hXEABn53BsqiXlE_i_zQAGGHjDzS_rnZ6ff8zDsuksURk8GG34zoEkw8RXvCJLsoAUBdr_IF_c-Z1_pdSAaGg4zweRWdIuQ4_BABpHZJYrVQBq0Avkl3v1wxX2chgsj1QFHfR7KX3JHiKNfMZRuVWt8gB2drd2ymx9nJa-OcMFYopRUqtO5xLMFXEBZDtjNsQ_mYALAAAAAAAAABskyEolM0U21N-oR7VTUJ7LCUzG2xMvzQJ3ciHrrlGbAACdakLO1vs972dWhPSWvAxFg3lA7o-uBDM-ZqOqJxGmgIs-vF8DmKpOx2qBk65JQZ0sD4ebKk7oAeDJhBr6kMjqAAdBZRk9d9cncdijQHUHRGi7YEteK4GbuRcxeEApzOesgP03on8fHxwNj0CpoRrjE4x_YXkwJWJeEd4AG2d-WxHLAK_hgYKRK5wR6QAX6S8ViPaTp7u39k48ENMrAjQ_tsERAIAMEopWGwN2Du8fEhIgzfXKtw-SDr2KD6o8jlj2ag1ggLSRfey_cFK0agcerm2PvGUPdsXec2nYKS9CeELiD1VIAC-XY7_LjLnlP-6rTmkr6l0dzGSPFh4r0t4kdiFBXVJnANor8BsQV6U7KENosjks8N3JMuYnMgLYDJRH5WbUct_wgDug6HuPj3lSwm7kF6G_qMOli2TODL7pEmkwpsy1-5uzgPVirKYgh1okk-tnNKqQtlX-C0PMLBWB_131GoWEKzBRMb2A1uMowWrzrllyOyTV1InJo-JF68H2FU8oyQgBosA="}}}    
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
        {"body":{"input":"0D9n7usTjwfV42_512pR2N71NOG8g_H5fEKxknqnZ2M=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"t16ulvJXCGxpmyMORb0niSyReHvW5Re7Du_-2EKPkvo="},"merkle_root":"ZfjGZT12HwGhabFzLpHoKkla3AyZR-47zDnI223cdzI=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["s5SpAEkWdIruY9rhZ3zuxY8CJzGnyp1TOXyTGd5HG4iUBLYVC3vt1dvOlaHyNyDD","o2-1bJpdWg-YlEoc1QpTde_yYv1V3u8rKP41BrQ3XB9JRgId6Kamzkaif2swwGHI","lBqtKXeOavXSvpwGgzpDb0ArdkDBab04LT4R1sKu5xZva-s6ejXZrqLE6lR7dgm4","o-Dv30Y0IvF1iqx-4nMdXclGdpcg_KRFpacg7yjy1gipYCSb_I_2u5HHjipPXgne","pCOpH0yiXY72HnKEvZTqeBPx7rT3KdlmUefUhUCSIdlu_og_fN8qjk2lWzcvAExj"],"cm_t_vec":["jWSPLqg2f7urVsj25h_Drr-yny84DXMN7_lvWjr-nMahS5DvdQe_2mz7iVFrz6Mf","gb5wU0V7O2nnyMEATSgpgzlTpSsjwwNov-FPb7Nbxlf4HtDbEo9TWMNwrwHTWD1f","pVu427d6lvPGGli88KzSYmQycuLbAx4uFevfMLyiwg4rCMFRY-6F3iNItRsgiwL3","hIQmeZV4Q_vpC-duFSj2DMcIAQKL84DxsBpasiNntIfTwKrOCuefjq0E_qZMxmgo","qtFaecoKajLDz-K9t1sCr_2utjoFRM9WRpPy-URVqtFTZ-TJm55hXTjkBVNXgWCA"],"cm_z":"qeWR8gTi6eCYTS68rxghw42WTJ80NM4oCyJqD54d4uKKQTMxd85Bb8hSvP2QpE3Y","prk_3_poly_eval_zeta":"Wfkmo9tepIWku0J_uDY6bxe8iRUd_TvK4Xcngtzr4SM=","prk_4_poly_eval_zeta":"3phNk5hpWpjEE8ILVTbCfZNa09OI9jqm5JH7IQJ5tQo=","w_polys_eval_zeta":["zuEOvqhIs3pxSsftX3JZiagdvnlP6tWUrVaJ0qZEI1E=","KdKOSWLMxyg7P2b0RXI2VWFYBV2nsqlM5HnG6n-bJlQ=","GQ3MkRXfcYDYGIjrDSTCff7fuPQWr2BdQJf4yQPsxFc=","v-8osjb4FucOUqmrfKhgDf74fUSTPbHSHgEcGhSUXmY=","tYJFoFjQzM2YX4GncJNaNW2uxByXiPbeL0BVRRQOv0g="],"w_polys_eval_zeta_omega":["w7ma7B3OI0nupax7sdFP1Lro7nkbRc0WdE5cehko0ig=","LxrXS_HgMjvzylUbeM7Oqo67EShZzwOniLFCO1FjG1Q=","6toQzzV37yvf9IJKDYBA-94yypjHIWkBkR1G3PmcLCY="],"z_eval_zeta_omega":"fHg9GuHIjxlhNORXU-zTDqrNDaCBz-pEWj-mM5CBEUs=","s_polys_eval_zeta":["jbYF8jZFQkzmw221qB80mBHn3dCkDoqf3N1IDGYNxSg=","XdRs8G-Ls_bsyxkl38LKsAGMpZK7MR71ptwBqQPS8Dc=","JuMHRWbyFO0aGaw0VZshzk1eTk4sErTYUiKQgmze1F8=","S6pHkRZ7iml7q0mi7h5QG9sv2Pc0LAYDEVsuwmIaTk8="],"opening_witness_zeta":"uO_2V0LX0JNKXEOUWsDgbiapyZUCEDvuXSwLik9EN6uD535IA4eX8mS31YWr6-6W","opening_witness_zeta_omega":"qKicZHw0mX6nxP9W06Ist6zTwRV4KDu5UikSiGrywAMrTbWKINt9gBARC_d2xaHM"},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"P3rHHoq0ZqksY0Sn5OZmV1T_zGetLnX4ymFbKimmdiw=","randomizers":["9pEXNILrr4W2axO6G7xkJSlzeOTUiOaKaqlJjfKm7RsA","qzuWp-CIj9YlDuy58z6m_SsKaZKse_JS1jhCuWFtsSEA","s6qeAIKVRqVooYx2W7pePYdkawMOiCuCqoIKw2FE5HiA"],"response_scalars":[["Sp79Kn_2mnT22cmxfVa5mJHCmSRiFPqznxflEUK0eEc=","O6UxU2hqVkbZvvfACQVv-f1YJJy25lAeZCnwncPGPTE="],["xqCZeQ_AAA96eItgouI9S-AQmHle_cz6Sti366YRgQM=","Py-heFj3jF7ZgNizAKITAIIw-MfwzGDtVuczwoj9jHk="],["3D7U8mX1IkJ5LF-KWMTcumIqnX3sxcHpQefxj52Su3U=","dwO3f6BIGcesykyWasxIO1f6vTYYzq1GKHQIcxHJuEU="]],"params_phantom":null},"scalar_mul_commitments":["XWt-6qejWXtw5xVxoG6kCPo3pfmAE4A0UBrKmBFM0GCA","66arrGulx4K1DmrIfzEBZ4VHTWgSSUKjZryRzxpH-DEA","mDjKPP5mgR8p1sEmuU5Gr3inMkZn_wvyX40B-fFufmSA"],"scalar_mul_proof":"J99t1GanxQCdurzqsRy15tgO6W1uadNQgDcbVsPPQFyAbRbELsp-OoKruLqcw8dl0_jJdhJ_EPw_15ks8J-IDQSAANMuB6hEmAhlnngt1JaD9mch9JanB8yA-M0NwTwO7X4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAjLG2o4u7b3WD0jvKvmSBb0Xs4sAc7pYGwS7dkx4NliGAPk0Sv4_yuJv00NxWtkJ-2CFhOY9SnURoY4xKTtPq2EiALvp0OKFApkxBj_tFovIdznszVZqJd2ujtPv0hcYlqUAAPs7_ITeyKXaXwFJJkkzh67Tz64XsbWMwpdALMXXUo12Aru1TjMa6uJ66kDv9cv-CKqPTWXl2HfoLPLc2Mw6ozkUA35dc6CCfrY8ckAfyKNgQQg-1ucI-23bq1I9ujYlikFVmlMhGeao0iJ9m0qr-7mCLzS88BIeMfW7jD3YUY2kXMLk_z7dwwBTp2t3cM1Ttx59LkrGN8PxJBht73fv-jl0ZCwAAAAAAAACoHU3l_f9e4uhptRKwSNNewNAo5CVEjGaz_1l14tOoe4DRh1MVmSsxrh_cVJXpCtm058RMSIkd0p0LpHccm0duUYA2lPDYnZ1SMnM8W2h-NskLZL11P84zMvBlFKR_MajaMgAjLRh5nA3EGqxm9gqrsKulw96DMBwLaCArWm5WAVvCFoDR-DNtU6TJOA4fibXRdSmw0GlUmMOqGMSzzAw7htGNeICSr6clmrjXtTVqlI-Uo2apKEAf6IaCT0sH1CaX6fdMLwB0qBFojB5g_Tq_XwbRodSo9cg4aSuI5WQxC8-79JA0B4CmVzGF8gn-feM9VIiEiKMvudjcdt16j4fD8dmEcWAETYD_kS43eiqGKH5gFAyS1h4dBKwZprgyr4uykP0sROEDVIA57EM_TqhaWVjX7YzaBd5xojuxPhpBz6Yw6C-tbkXlBwDTNrcWt3TJ5CnfT6EdsdAxLiy-oKK4bDXB5imuUFpQEYALAAAAAAAAAHzws4h28WtmMISWp5tZ71BSCvuTkXTKxSMgm9UjaawZAKn20tBsFyz-6_azJWfBL--soZxe0xN_aFOtjLObnmdkgBqXgJBKKeXMyFtpm7vIsAUYeV4jrP0Egz6bng3SYHxFAMuPTdsxDdX0NjqZ_gIXrrSrIuXCYrvPEl54RXEFidlFgHblRJ0NCOVBO942O5WMwg68ky2GimgDmj2tVKrwsigNgGzB8Kp48rs2NfGCDO6m9MsuGjtI1TMpw4VyalM3VqpXAN26aR3qscWp4RLCfhsrYN1l3xAPz18qmRzZ4mHd0exzgGAra82a5a6C_TfW4yhPnWdeMmOxmXdBLEFbzRk9sp52AF9fSeZQXWC65bPb1hL3IGROFNYL3GXD97B7v9i88CdSgNZEZgMYky6vg7AmyRduSckxVuG0vqjaySqQf51LunsugOcf_2pbRf7BlCklmL10kbMpKEJR8ZQnjV69H57Vel18ANKkVrWty3Ov9JcJG1Ed0zQYS3gCddO5ckxwzMH9XGRulWZWYw2512IZDVYOzDCFSUayWrRkU96QxD5lAUNBEkY="}}}
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
            "commitment": "jVdL4FtE9Z55LDzjjFU1b1w1snoAEr4beYZj_NuA2mo="
        }
        "##;

        let sender = &[
            1, 158, 10, 197, 168, 100, 167, 116, 29, 68, 6, 233, 246, 90, 255, 124, 27, 67, 98,
            237, 132, 29, 85, 190, 43, 91, 70, 88, 163, 209, 35, 212, 91, 1, 3, 106, 107, 238, 232,
            167, 236, 45, 8, 252, 164, 243, 41, 74, 208, 122, 188, 247, 124, 74, 156, 98, 72, 27,
            223, 6, 214, 191, 235, 137, 162, 158, 183,
        ];

        let memo = r##"
        [120,114,45,8,206,14,19,84,166,215,135,198,11,148,129,150,53,26,25,46,16,141,186,168,155,56,207,188,120,0,45,124,0,227,68,61,78,107,135,186,138,231,149,115,133,35,131,83,159,193,20,29,101,247,248,121,181,226,228,224,117,197,126,29,137,109,209,131,131,197,131,235,201,250,172,9,63,20,29,134,80,251,107,241,74,56,186,18,116,87,71,222,28,107,237,248,223,102,50,201,42,29,200,221,241,211,138,250,76,53,20,198,224,58,134,110,169,122,71,242,229]
        "##;

        let abar: AnonAssetRecord = serde_json::from_str(&abar).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: AxfrOwnerMemo = serde_json::from_str(&memo).unwrap();
        abar_to_bar(&abar, &sender, memo);
    }

    #[test]
    fn abar_to_bar_ed25519_test1() {
        let abar = r##"
        {
            "commitment": "MqDXmmoWaaWJtmmTUycn3IFHKuQncHnvl8Gq7NtIXDk="
        }
        "##;

        let sender = &[
            0, 71, 127, 50, 47, 5, 51, 215, 80, 53, 19, 188, 213, 0, 10, 217, 22, 21, 196, 47, 26,
            81, 114, 20, 158, 103, 163, 164, 51, 1, 254, 200, 236, 248, 149, 106, 83, 191, 150,
            168, 96, 137, 34, 6, 156, 72, 235, 178, 118, 238, 22, 106, 64, 204, 170, 241, 142, 124,
            183, 232, 195, 186, 173, 18, 237,
        ];

        let memo = r##"
        [154,166,6,228,86,224,236,53,122,72,208,178,168,253,191,101,246,220,95,224,64,173,186,69,216,63,10,101,139,110,198,57,48,80,90,47,180,78,146,12,55,55,200,251,85,116,98,91,13,167,80,230,102,196,233,4,233,50,11,248,205,75,17,204,70,93,158,63,167,38,153,107,162,97,193,17,192,97,210,17,219,238,154,199,103,209,239,63,43,154,158,5,97,68,75,245,33,188,106,110,6,219,191,249,243,249,14,136,90,58,238,201,171,4,16,6,123,175,100,8]
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
        {"body":{"input":"luoPA5gaNvZf5eM6fofNVmudCfc30Dr5V2k7xOVDgA8=","output":{"amount":{"Confidential":["bFbexW6ulFuXKdbQEPpDOQX_knLvQAPHwxDNT-7qKXs=","JJQN3n51917KaFzD418scpB8GCg2nJQ9t9Qgq4v_yTk="]},"asset_type":{"Confidential":"jnn9FZdIYkkGUh72Fmtl0beCtG56DZ8tDyfoK2SyGiE="},"public_key":"AQJzOEPWMrEJVm6cyoMjQXzJWcUoVLB9I0ng64YA1eC60A=="},"delegated_schnorr_proof":{"inspection_comm":"IZbI7VnjFw6pFb4BC1_wjLmUkHqnuPhMi4VY8xRxPSU=","randomizers":["YCQec_2TCJkiTmNqjBw1k8tmt4T7T6jRQmmQ8nXMrCM=","xA4MJWN0BmYbsihv6qKlUKrBfcV4lCrop5O3s5Az4C4="],"response_scalars":[["pLrSGaKpyhieYkajliFSG3h5pc2poyo2nbzqDE1_WwE=","ls6JZwp9m8kXnJJmSPOSwUJu-J5fgK9-OChnb8J5jwI="],["nmRYzOGRBZTKBpN28aLaf2OwvnkR4eMR3vEG2kvwOAE=","THRTF_q4pUN7TpDhyJ7NH2s-JTtMBulvvfwgWj2JLQk="]],"params_phantom":null},"merkle_root":"lKCEywag4XzcBCXNhTVFA336zpeXmwAMKDb7uszm3lA=","merkle_root_version":1,"memo":{"key_type":"Secp256k1","blind_share_bytes":[161,123,164,39,121,97,141,75,190,169,83,71,14,147,238,68,88,32,119,31,39,230,195,28,159,214,36,145,142,154,179,126,0],"lock_bytes":[208,141,185,124,12,173,100,92,153,4,135,130,172,119,239,150,170,245,116,114,153,220,40,138,230,35,18,128,169,50,71,216,0,118,199,100,9,74,42,252,98,88,154,96,14,73,64,51,71,105,103,95,3,220,105,5,231,199,215,10,19,60,131,114,175,7,6,235,224,214,189,215,58,151,226,105,144,148,211,208,163,139,52,163,236,68,79,116,166]}},"proof":{"cm_w_vec":["uES9doTMXd9N5oo6JsFAXAFHlJFm1HdnP8lbIYFNu-JjPLaFyVUZ4SZir-dyTaxL","jgar5p0ZtJPI3DZHuG-LKNEhSbR9E5N4B-Ft9aDIy4WVjt3xC-WBubJmzR-5xE2L","ghmJ5c7tqyyPNnRYTjuhkNV3mZlf5ipPooOVZUd7P3XwtknBiZz1Uk9_JfuIzSfO","sxI72v6xajdRUCpTe6108-g-cA_iAZ0VYtQPo_1WwSup-x5h16NDgNqceUM2h_Wd","tBHALbSFm1xHZ6jW2SPWubXOo_1bjyvzt7mtU56zeH2KbgCToz9Cyk38oeNA8O7X"],"cm_t_vec":["t4HzSdm69qnEZYR3kU0pQU60SFibnSQa8laxcXn6NtyfTsVe1iHdQN1NNQMFeoTT","gysVLT-lKHTSQudCgDUQVOZkmC1p6mp4XBW04MYkVP9hd5pdd_5Re23qhOLA7v06","sqeOus9B1vBFlNaynkf35dimBaqy9URgDlZzWfvHQdPgrqInQy6mJq6Mx8S82-Pj","hf3icl2HUnjoQyujNpgoulqO1jqrKokw1l6nH4l1Q_tJYc7DLiXGbHiPlyScLbfu","pnJIyhkyqVUxxVPvlwAM14eUCZClzpJzrd4K9GMA0OgqsR4C-78qO2pQ1TTQudOt"],"cm_z":"pff0OzU-zaQI_9gzITB_KoWOpav5voW_6TTQepEZgd6dcvwzXSRruI2lO_cwkDPq","prk_3_poly_eval_zeta":"kLcRDAalsKBbIu3_1dMT7hI7Y89cQEkMu85tUgBfL08=","prk_4_poly_eval_zeta":"_s1STTKNCucwO4kZXLID08praVFTIjGKK0gJoeStLTY=","w_polys_eval_zeta":["kwNPFqY99yy4RTvbyNkYOFN82extjPpTuUUFozfelGc=","m2OKwu8q5QO0cQ7IreZTTzO7iz61VyQJjzXwezgS4DU=","9Vyye7g7wPY4wx6ZHSNzyPlG5bpaJF0OKJ4BpzQRYVQ=","oaglOuFh2VPJwTPISXxzrsmCt8_1Gk4enkicNkKlvzE=","lgJzQRYCLL2L4qddGzkUkO_qf8UHRVTAxyWyn00nGCo="],"w_polys_eval_zeta_omega":["c3lixmdfpCAuVDxdBVeQy1pWuemEvXOFJqKoD5uC3S0=","9P4TO99fCU-oW0l3ihZPY5uK-4d24UpvBEiZAiwl3wE=","fh-0ZW0RhDZS1sc-zHaqgH_IKt559ECpjy5KPsJwflw="],"z_eval_zeta_omega":"Ua2Jjz0NEGIFVDgAqf61qVfFPOb_8DKpzSjb6B8NPgg=","s_polys_eval_zeta":["dkHupZmSLPTa2EghsWUF6GiyLYyg55DpBoBczjJ7BU8=","2trGAnMwjTxuHnwtreJ_KCYCw07nX_Kqufx3XdMVcAM=","G18R4cHPqvhnOsYBEAbIBtUehk30SMuX7W1NP4XpAFA=","M__tZJ8SHMjc29KXVDl4Nam3hcFAyRpS5TwidxXisj0="],"opening_witness_zeta":"k2kwUdox8-ndee71q00gZUtxQvsrsp_aSQsjCZqA_W9QVbcVOZJBKCbIfGT1whkl","opening_witness_zeta_omega":"qbSZljnczI1pDi3nYodQ9j4aBJ7ngHopYfId5xWJU0O313jraXvLRPSu2tp1j-R0"},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"_JYx0Q1SKtFA7bgx_WW7_HfGsiNeoWzNFR9Tnr-hFUU=","randomizers":["402bLntvXaiqfnCBaMJo8_Q2OGvyOeDaPo-XjpjKFFIA","KN7yXVy1BnWBtBGUS_8oZ2UnilCy8nl2nYhSYo1pt9aA","8pUah7WECoDEfQWu3y01VnYvvUPw5q4aQeEXf960vK0A"],"response_scalars":[["3ohoX0S6BXJQ0CUQ4mxRp9OS1g59CLVXqmogF_-1awo=","2XLJ3bNMv4LCccU3W653NZkGhrqK6gvn1xeNt3kicYw="],["-9a981I45FfkbchqSUTJfVQ0sA9sm-HfDR94mfMbFDo=","cNEBtDg2tRMIcvxkwQCKDBIXl2VzbQgmmO6t37dn200="],["BIdF1QdHpeFXBuRaiuNt5dEEDxPk_8e5Mt2UA31FqBU=","KrmAJNJzcsQOZpH3b9Tl1wE5uFN7WMiw6GmR8mJcMXE="]],"params_phantom":null},"scalar_mul_commitments":["9rHzeQ5DXkyed0xSdi7m2ajQpmrf33JzcoauGp5FjYuA","9Ww2pWGowzY3gvpmVSixJdu732EqxFSliEg0qgm-q2UA","SetZ9uuCI4tsMvGNF08x7HNVRsRLKnoaOkNlbgLxFqCA"],"scalar_mul_proof":"J1yGg2swtUexXASf7QC4m1JvK4inBbr4SRhne9NBcSWAWFlg6cGZAtRDknz2sriPDidp_s251bcWGfb9xJb8nHWA3HHbFec0KSR3tPpom0D_z5vpun7DTnNLDjoOueQF6o0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABASuAbg1JHPbKwkztWqyjKNY5_2zntI4hiLYbxZaw3iKSA5FFzBzu6xGiF7eHhzp_BLWJp6pq-IwDiAG3gs1nCCZwAjjiuPEplC-FRuiHIaEixV8Uur6ZV8a4meezKJX-Ik1-AnrW9Wo3rGMDhHf0GPPmlCRsCuVHelZHw_C45c8Vp7JAAsB2gWs74XARPBnD_2fdQ4BkDnCduqF3bFeG0UCwgeEUA3BHb3_vJIOpUfYDKvL5C89EsXNT5srBwd3-vK1Q_3P-4v5Y6i9guldwwoOO1uyLzdmWHxzKy5pLqxKG7p3zZo434gDmUariAUyiypCVdA3HlwGtVDU5U1mHEsDMQE1E2CwAAAAAAAAA0W_2aed-DAymSPRORpKbwrNFOcpRCD5ivLlsmb6JmHYDuUPaKoEuiI9GL1EIewD6sKo77YBe1ulTvdS9pW3-oLYD0wjyHNmO-r_dsRzW5bQQu4ZYse0emjv2m9QJKD5mnNQAFrjsh8ERBZ3O3IKqe8uKBLEXqVJH-u6DjCI8Oi8aQWIDA_aOfFYAfhKZ7vVW9d_NYgVIKLPupPyAI9NCn78nXfADIKdhvHnBNn4oclWXb0GRtwr2U_43XxLvmF_FpLoP_LICv4BsjBycrJj2XqK9HSye2F4VSZSBSThw-Z9dM2Nf0O4A89QzPgjnHM_p0zzMzuMbhIcbx0ki7HgzqNrrs3E8yOAAufzdonucQAxC-KDuFWx0KDIZ0RYNW1bbKKjuWG2GRfIAZ5BU8WLty0RH06BmCkEt3NKW2Hjf5f9PmN2_ybQhAmYBul-qhZ6huC_vjnYka419FwZ6djLFotXJpNfhHsxJNyAALAAAAAAAAANCOQjw-TG5FVVqdelq4oYaGtI-lKm3ahsmmE9lKP3q6gFLMTXcCQJYK6h0RHhWlhyFhkpJQEQ2p07SUgLNUtvbjgO1uJgPsg4ftWxJKNDZm2wnaZgWk4EJd4JBjuEXky0K8gJ8S-pPd6jRkAxK359UJrTwgRdqZnS5r6OOny7NRcqx4gFcZZzYCEpgyF2lAP7D1qXvQaev7tBwZ6PLcPmATGs0lgHlzmM9lCmxCK-w7GvmfCUJTxy7Lv2Sf-z3aRS0VM2KPgKZF4Edu5ZAwk464DAYv6iSZvnLEx7zi7u9NOQFe-mhTABHHq4AiFVNQIXteBrOyCd2Wucqxkjsb3jQAxaHY7HW7ANuJ8qLe1TU7Qd6bTHGdQxe-IGBIUAhaI7eLlfu0akrfgK-FUhOA1xPC6l0p543mjzbZRJfuXasWqz5u_OV8tBiBAN3kIBYLvqoxboZ2cSHRobrlj2PcLxS4KgVDLsDEuT88AFoE9OykJEpRiK3epvew_no5jwVTxn33VVcKX0-_4BVQ2WiBNDKxxLDER7dD97SslIJjQ68thrxSrITQ3xhoKM8="}}}
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
        {"body":{"input":"TnxP9Ola9f8BRguA9A3s7c3qElJsAvHWKTw81UHjTwE=","output":{"amount":{"Confidential":["goyg9SQs0n7P8q4p5yQEqiVlukhpH5cafQrkWxzjWks=","QKTdI5eo2k_e_iRHi2-vsZsZ1ZEBXIGjOeqRAU49T1Q="]},"asset_type":{"Confidential":"plvDDIOnvAQvs8PDKDOp54Uf9TP1ryv-AHqBJSKWDlM="},"public_key":"Xq-Dr23s1LgoR9jWFlonz-EC8PqBkDa4NyB9IFenwDc="},"delegated_schnorr_proof":{"inspection_comm":"kIGk3tkQenZVG9C-67sY-Lc9US2WorhyBO917RfqI20=","randomizers":["6kgcBxJ5uAhThkEFKGh4Euw7eqrA8eXm7K9cbZ0H-ww=","4q45XCsobrJVCo5gR1c1-fjc1sQVWxNLXZZlkrzuQGQ="],"response_scalars":[["tNrA0150jKYdjvOI65CS3wx15W9xl11IS9y4S9OXXg0=","atpvjDmCldEOatmh427IAwpn6eQ8HPWN-yKBdfjlQQE="],["ZHKwlficNUnumHiBJXWLJ7pDFwV6JQnSb2p1MNl_cgY=","B0moJh-76w-9L0pIiLkO4llpGT06OeWeaXskN7EQvws="]],"params_phantom":null},"merkle_root":"JZRyUM5e-oY06YIdQhlKxVBcrKxroU1HfAEpo8fB8k0=","merkle_root_version":1,"memo":{"key_type":"Ed25519","blind_share_bytes":[190,100,30,20,87,138,171,184,9,175,12,157,37,180,5,23,41,115,90,171,66,79,39,192,36,109,218,31,118,252,127,74],"lock_bytes":[59,107,118,148,83,62,167,47,103,184,143,71,84,82,96,248,226,110,159,157,7,128,204,141,210,137,105,69,195,123,49,36,32,196,28,138,239,33,143,133,188,1,190,98,23,52,182,132,100,141,245,233,10,192,195,61,99,105,204,154,158,181,187,113,250,215,4,41,111,101,163,188]}},"proof":{"cm_w_vec":["piFI7k3zqwh22S9tFXn9KUz_kHC-DEJmA8IcKxz-FJJeq19LJP37KKN4_VgUHT0e","tja8ND40H8CLSaxnoC3zwYwRftrm9dXiB9aQCRGyffd8dCVJccbkOohVkBbF20UE","hNbE4xKYUhcjYVmYA_9kd688cs55Tu4ZUeQ6Myrpwkrx5HNB9NKTtJ_ddzoSsUCL","q7awfYcVBJ6IcFVa8dMqT6iV4oYTOLpkmpvhLKXQ6fXfmcKSfwGUUSpY_Z1vFRfd","pxY5rFKMWiEh2a-LEkfFClzcL2U2Ec1yBmbIlsOueO97VTkDqiiMPamfm4CMkMc7"],"cm_t_vec":["hhK1VYYMCv0VRNu02vVm_s9dHqZ2t8Estka9rFiJDGJw164WHwToBy2jT5MZXfH0","t8mb6R7gPz8GVqne_QOnRbhBXNbh8IxED8GV6aEVXTEBFJSXZiOQn60jkMslBzvd","kUateK05K3CGG7n05_n_xbdB6aXvo_tcuLeVKSsI13gHTlz42_tCzykOGDyZ88EJ","ubaotItlGDMHAaapjkI_i3EvQji5n4JHvpCj2GyF5G2UjVDuqE6v-9JrElwP9WJi","k-jP6zDefCObnTXB-oWYdDaIVHZtQDYhx8I8w8--DfRZ2YH7N4yS6jEQfJ41E2Uq"],"cm_z":"rqzEyO9x_AeZd08y6dj2WKk5OnGTHIRfnf8oMbzZFOmyiyaeKzKMBwITbOam8pJL","prk_3_poly_eval_zeta":"d3VHaLRNXL3XNcxrt6mCW18pDRX9iw4-jEl2Y8dgTFA=","prk_4_poly_eval_zeta":"NMkx1fVpHZW3uBee0FIyxQgi4hxbGOa3WyEXrfXiWC4=","w_polys_eval_zeta":["72_SvRy4RC0MaiwzunxJrGzyJg500rvKmrOAt6Ggdx4=","ccCTw13azdJxwQ5Eq4lfBquASzvbSIMMU6W24_PUMyo=","WPC8MJvgPpMSm28OaFXqZcfOKtM9nqoC9BRtSde_FSI=","DwlKt4nrpRwPOdx8P-mwwEYObhESBSYflDMdMoSPzQ8=","WEAp4w4bI85i7Sa0bpkTni5yl93cDkcJb4IdDZMA7lk="],"w_polys_eval_zeta_omega":["ioQybFWRyVDanikUQWQ69g5Ki-5fDWpjLDNGIqvlejY=","8eumxZDsUiFfbEYfixs6OrtKkDbxRANetk3acziHlwY=","YCwCcy5Zxp7fVYdjgnTGjOq5tHlOzo1jBXwOvY0Vny4="],"z_eval_zeta_omega":"K0cYlHyUIcjDkC8-oKpdg53-LVMOrNFnw4rdPSXGZR4=","s_polys_eval_zeta":["NFCuHcun0CpjbJw4c2q_xduyq0lJsjkzLr-aeBH32Tw=","AMfNV-SRq3wkwehn3XTQnAsSjcYgL31KHrPQA0jM7z0=","cAg5gDc5ErMxRLKi7wLkikpzBMH-cqQuUFU9jwtQ9Vw=","bg-4dZczYXT7b_gdqy0XoBqvD-VQPvEvqFFcSZrke2Y="],"opening_witness_zeta":"oa6mRrVZ6U2xPJvP0fCtTaBR2DQhTVL3EszCEOKCRMjwIEP5Jc8ydPWN7a9VYUyY","opening_witness_zeta_omega":"qLctYd1Ho562ma09sMBEQeNe6aM7nj2BR3E2JorhsonI6Phn5Vxt2Vq6_qWplEyT"},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"mYje_8jsxCv-fDQ-8hL3D2s_mlm8tChw90XYoPGDCW8=","randomizers":["La0KMRgeQpfPQwtLCjQMwfKktHqKShEfH1_D56kJdw4A","q_g-9Uu6MxWL3LrjXPu6BtNEpDR3l0_UXIa9vJt6Kg2A","fiE-vEnHwHZTFAVYHAqX7LptVvpyAn__ZjeHdnpcl32A"],"response_scalars":[["1FB3-Ih6IrSFlckRy5EVtbWzHx_1HNpbklCpXVxmEDI=","PQv9p1A3DSSMAirFsLlDNY33M3MmEThEIpgfjvhgoEU="],["BaDJPFn9Im0321HzNHwaL4UmPK2SFBqy6Ii5Jl9M-ls=","A0wUpywN7B-IbE5A8ciSZANB_5aP6wQ7yHc56Rc38Qo="],["fP70RoHpuFXFc31OmBJ4uByqO3sk7RX2cfkHSyAaBQw=","wrk5mHI9SK7jrCDbj5xbRXAce7-NM-4DV7sOyedmPyI="]],"params_phantom":null},"scalar_mul_commitments":["_CaJx4rwyj0QFCOgYBc4gOvmW186vi-z--RTGJkp6neA","QNxhcxvJpAF1fdZ_Xve448PSV3uQcv8Bz8bg6Ct0Wg0A","62X5hS4gOY3fwd8PKDnjStiMhfUH_4xuNVq8pgGzCB8A"],"scalar_mul_proof":"ozhGOSIfvoqdwBkOBwR5ifEUP6EiAKw6VzuRM3swgGqAsiKDDiCzArRriYhIT1Cz97uPqHhupfVAxMK5cDPIUHUADy9q8TIDEULA_nyqmqyQu2rp5c8K54_0pSJb6pOEohWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAYgEIWIusY3rxhFt9z-kpvSlP1ugnFrzqtDbsgRL4_EWAhXMjbfcvTBMxxP15Ib6_c2flwP-nCBKcl7_FfCYND2CA7FDQRfjCGueoOPn0ccEi5HwmxxqZS-FMLXkdj-kUrBmAzoZqN7yacmCu0gd8XwYLE-xsVarhRvsA9YQc-nHfukYA9in4Ji46HEOe4-R1tu3wNzcnZu56_z-RcBoUaf4MjWuABJk-n6JQhddKjrMZNhi0UCp2AU8NRotUWBGjNU3MqwxqRB_zr5_1K-Z9w1DyhOOXLdbMDLg3QPf8MwrfG2iAcTcO4tVZFGOXfeF0iwVAIvoJOy8oDNh5qD_IrY3L5GN_CwAAAAAAAAC8NiHQQRoxoWM_QvGa8-szmeyQZ85hmoXjcH8iUgYPUYAPw6fsYX2JSMqR0LvCbJbvcSFGNzuj3K9_2YS_j0yrOoDlvKVd7-ElNkWbiA1CFd0TxVmZqtt_MSSYShIJEBAwVwAWiv9TNJ52XNLEYpuvi4XSZrWuh5TGst_KtMCpERtmFAACbfRez3CeZCMYeBqEjl78L4bf4hTZo60HNnSPO8XZdYBtuVgMSTknYI8cUytt3ZlCI5RM1Px71L8pXtmJma3VSoCRjDlv_czu9Q5YERFo524XlQqghdbUCY8n4hvX-8HOWgCsiOJypJvRT4e67SilA_jyxuNsuQXjjtLe1clHXY2HcYCwpTVAU-RJWDqSdZNS8FEO4BUr4i4CITGIGhHc50I2DADbTwbF22j2AGbcHcqPyLV7VsZ8tnVrj7ElRetQ6fyZJACvnUuEFPfoisLq_xRlUPawqBpT86B-QV1dFBYV5zdvJ4ALAAAAAAAAAH7gLPJPEEHDijUJhwOIIcmYngczD5kuwX9BAsLnO4F8AFcA5po6zz3_dQGgdgVlZm6x5Z3RIZTLe3wKGhzLkNw3gIc-9-Wf41_IYE8ue5S7M3c6r8uXaGHC6n--QctzLzpsAJ1bLIKIe6tRlSoSgCEmsKI9TLt-CUpdOcrL9lh8vfoFgBIj2oukPgxX59T_PrBIJqksGULTyEyTyrbBAO6YNd8yAICsklgoVWc3KrGjzTpK_K5ZO93MIN3XUSxH9JBlnWB0gN3utHpWNbtecSXjM7mEwmc0Sj8BMXvBmDriS3oDivRJAK5sZmaptmsfYPRm-mn5ZgXH0gZXEH3oaOVX2C-uEiolAMtLISXgEp2XjkLNUkYqRU1xlEVcN69axPoJKTe7hj0oABtoPnSw638-XhFnMHUE8Ot56I6lw1PA0qX9IxZucVMBgDcZsdyIwL3V_8H3gPCsxvqVfvEvC9pr9VV1wUnFqu4RAAgp2FL15ViXbrzbm7sGMIBfK_JUUf8G2ocxIC9Djzovd4X5H4T017oamFfZ-CmIs-mWm3i3CHruWYQtqFPYcXM="}}}
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
            "commitment": "TaqMQSZzZzvxtlfSh2dUk0BQT776Auh0nkm-sjHxQUg="
        }]
        "##;

        let sender = &[
            1, 59, 150, 7, 215, 0, 107, 1, 23, 16, 55, 93, 155, 133, 184, 239, 218, 104, 191, 233,
            177, 81, 234, 81, 114, 230, 104, 46, 21, 59, 229, 100, 187, 1, 2, 174, 99, 184, 129,
            254, 231, 191, 161, 162, 194, 81, 192, 239, 191, 175, 126, 52, 1, 126, 88, 52, 208,
            166, 165, 139, 7, 136, 169, 119, 84, 159, 127,
        ];

        let memos = r##"
        [
            [123, 134, 56, 197, 253, 53, 124, 38, 41, 226, 152, 12, 68, 2, 175, 224, 175, 63, 129, 139, 4, 175, 250, 146, 231, 138, 196, 181, 231, 17, 27, 190, 0, 253, 142, 94, 168, 170, 75, 21, 6, 254, 70, 91, 55, 212, 12, 154, 149, 243, 15, 191, 47, 152, 240, 130, 255, 136, 76, 91, 113, 136, 102, 230, 190, 63, 9, 248, 63, 23, 153, 236, 197, 246, 27, 178, 26, 131, 47, 88, 46, 96, 55, 212, 33, 136, 38, 6, 168, 66, 204, 185, 93, 5, 99, 203, 0, 114, 51, 120, 32, 229, 78, 128, 64, 102, 203, 122, 185, 115, 47, 78, 206, 111, 61, 164, 108, 4, 135, 152, 73]
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
          [{"commitment":"GyPKhTuf-z5spLe7xHki3BPIVwodQGMeD9YQEkgpkVM="},
          {"commitment":"n56KE6X7Pi2d2DWF99twIjbybKCCLEJ0CZwX7RFejEw="},
          {"commitment":"ZAM6NUMTiuXMHduCvY4cwpl_3v1HyobOpjV35cV6EFo="},
          {"commitment":"GGcNKvgy6dW6ILRWH0KnDbs-iXgPMdAmp1G_ksl37E0="},
          {"commitment":"mEL4APRvC4eNUeBnE6aQ2j4YozOB2BcJH9WdQLo8Tzc="},
          {"commitment":"WsfA6Oh38UsQvDcxx52a6uqmLVxV78rsWA-NUHe5z04="}]
        "##;

        let sender = &[
            0, 151, 234, 232, 2, 164, 47, 94, 172, 178, 183, 63, 186, 41, 163, 177, 191, 190, 63,
            254, 190, 135, 20, 138, 235, 79, 215, 53, 79, 78, 5, 236, 123, 36, 3, 125, 205, 161,
            146, 119, 119, 23, 148, 13, 236, 37, 241, 80, 120, 197, 204, 203, 149, 226, 103, 130,
            130, 29, 117, 120, 243, 65, 83, 208, 174,
        ];

        let memos = r##"
          [[102,210,31,223,215,211,150,182,187,217,155,29,120,136,80,72,84,155,11,150,72,128,71,140,70,233,244,163,54,23,239,6,63,215,185,70,169,43,26,5,169,238,60,96,168,84,254,189,60,123,67,74,234,156,1,112,58,152,190,240,93,135,32,207,252,107,43,121,190,255,165,94,57,31,200,84,159,130,25,254,188,21,83,251,94,247,39,47,170,165,93,174,206,210,232,83,197,206,135,109,108,18,178,60,255,191,172,155,98,233,66,39,254,27,241,97,101,117,127,88],
          [222,224,181,128,41,146,160,111,215,169,228,46,230,95,163,235,75,74,173,78,244,49,4,136,69,55,67,95,228,161,120,163,91,124,237,166,142,219,134,0,98,36,68,164,47,254,83,167,10,171,61,9,62,237,209,107,160,44,55,249,156,125,246,232,78,75,167,15,21,33,220,142,208,120,174,5,26,127,208,247,137,124,66,188,89,162,177,109,79,73,235,121,235,175,217,132,43,10,56,84,25,173,42,127,179,77,126,0,129,34,221,133,60,36,141,192,148,50,93,146],
          [191,33,47,84,224,94,21,131,251,212,154,78,91,183,146,157,247,70,65,19,128,227,190,73,87,77,14,129,80,75,13,176,29,201,89,212,70,28,101,32,25,43,72,134,74,99,40,197,146,184,122,189,76,51,67,57,200,49,7,27,40,212,4,21,39,215,12,193,247,1,86,227,163,45,185,255,16,201,21,189,126,0,134,225,38,34,126,27,195,85,41,97,245,253,23,219,8,77,158,70,247,150,118,99,145,226,68,6,42,109,174,35,241,47,26,47,55,66,52,121],
          [33,86,117,139,30,37,213,102,15,129,224,17,241,46,113,12,63,180,80,208,208,100,222,182,126,2,165,43,114,106,147,92,23,190,15,46,204,141,86,63,255,157,122,180,58,213,190,58,93,236,18,254,155,185,96,14,221,32,135,124,253,223,198,96,17,29,145,65,243,10,188,115,161,245,125,53,207,67,39,247,37,24,53,173,234,96,154,2,97,99,51,238,156,104,165,196,9,26,242,100,54,153,0,33,188,180,136,130,54,230,190,33,0,38,67,232,90,13,200,33],
          [99,78,101,81,54,212,184,181,197,253,12,53,222,201,46,189,53,244,70,247,176,154,143,115,232,170,241,219,232,4,208,22,106,134,68,216,17,69,173,151,162,78,86,239,61,10,251,91,87,116,33,39,202,102,76,222,85,88,242,143,234,6,92,73,167,175,1,65,216,36,191,21,149,132,105,143,186,61,55,9,93,170,167,57,187,174,59,106,164,78,118,93,229,52,164,89,161,52,1,24,4,74,112,242,31,5,129,227,129,16,136,79,63,23,175,13,201,52,105,128],
          [233,168,229,148,100,155,179,57,174,16,66,32,83,13,77,186,209,164,191,249,157,244,20,194,255,50,62,78,110,205,60,150,195,145,173,81,40,96,250,47,233,144,137,109,204,12,175,70,154,125,125,246,24,17,14,178,53,121,81,17,41,170,206,255,214,9,151,223,7,214,165,109,233,160,115,128,99,146,192,117,22,106,193,149,187,54,96,97,17,253,235,120,82,72,254,237,35,8,245,121,183,75,134,12,1,31,19,173,242,81,238,111,80,58,253,228,35,153,182,147]]
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
        {"body":{"inputs":["GwI4_NoBVNxaz2-0B0wuXyDbbukVYjjuXDN8ADl3rRA=","CO-kwSFXYT6tVGQsaWcxyRNalAPqw-hga0QAeGXDsTg=","bG9FIScIBL4Iezke-shvoUWfGUaNe86kDwdI_9Ub5Ao=","FiPzOQJ6cY4V-qAjiOItt2ms8Iko4MSOl1q6wQ_gwFA=","mHuRBf6vqiPDgTPF9nnIto95-q9pbABPC_H_LZfz7A8=","x4RjR82xjkWslsIIHTdKRcw2vOfAKFTCCjZyx3RbEmo="],"outputs":[{"commitment":"6dFVAn_c7L8hbNfnCR5lYY4Ik4qnVFW_1wM41NpUtmw="},{"commitment":"3KPbqy2FqHo9qp_5XWrfAx_nPw7etnYU7upqUjtSPxQ="},{"commitment":"AUJYj5OQi3phOTScSDnEXQtSUd-HhqWCkwvslzK81wU="},{"commitment":"14AE02eZajJnWOtsBPrF49rLW6JfqksbW0S9Z8qvzUc="},{"commitment":"owFYx_dBSEKww7QgcmVKAtATgnQM-AeC7VVx8yjQ4z4="},{"commitment":"cTMh4CXSxeX7viDqLU0R9FI4DCpeGVRO-ZiHqqlXYWM="}],"merkle_root":"RIPkwaTXZGy3zA3fylohKFxnhdRFNfJV77GNichEnFE=","merkle_root_version":1,"fee":23,"owner_memos":[[76,36,201,183,163,97,96,67,41,70,220,33,189,201,238,169,59,43,165,113,54,4,67,34,230,49,70,91,72,11,195,210,48,136,129,154,72,132,246,117,67,36,122,187,144,206,61,108,184,49,147,215,246,229,24,172,19,139,250,216,146,251,60,203,97,190,135,54,44,21,145,20,117,55,35,12,130,75,68,134,234,10,110,37,21,133,156,95,150,193,87,24,186,133,207,175,192,113,23,56,146,51,189,9,49,205,224,169,64,99,53,1,170,122,52,177,37,156,49,171],[72,10,177,166,32,179,152,194,185,238,254,11,192,35,231,22,27,205,76,233,41,48,8,152,64,223,220,210,196,68,1,174,197,187,252,117,17,36,31,5,233,248,238,94,102,234,254,109,37,34,157,184,119,248,242,175,108,101,149,209,127,172,208,75,57,136,73,191,203,58,254,44,121,59,222,86,161,44,247,170,253,143,134,135,226,195,158,14,212,85,58,5,187,69,164,68,4,50,69,114,213,133,49,203,237,7,97,44,90,13,2,16,141,68,216,113,206,1,154,189],[143,166,203,209,209,127,210,101,117,255,168,50,170,76,81,10,4,200,159,2,194,98,49,148,125,27,253,75,168,238,8,145,128,115,48,4,18,142,170,66,52,26,109,242,154,161,43,248,208,219,175,132,174,148,229,226,4,17,106,37,140,0,253,221,29,97,170,73,98,43,230,187,160,10,151,248,134,163,30,193,31,48,247,92,220,63,205,47,114,63,79,245,145,39,174,150,80,86,14,200,255,118,253,48,191,189,152,135,64,153,3,44,121,47,212,181,33,77,175,96,84],[195,128,178,234,46,87,121,47,170,85,169,229,126,59,40,201,189,68,40,250,173,140,19,106,67,69,16,36,248,242,231,111,89,100,100,100,208,60,204,214,116,186,235,15,185,7,182,114,185,42,145,85,133,115,120,31,215,147,140,42,223,103,193,145,244,243,189,11,37,6,155,209,84,146,35,213,212,164,59,81,81,165,26,149,245,89,38,89,165,79,233,216,167,47,13,20,196,206,228,118,72,165,48,16,255,251,239,116,101,112,99,44,48,178,250,201,170,180,31,211],[248,172,57,80,142,41,145,75,208,110,34,14,191,55,160,187,25,22,108,173,155,153,172,147,208,82,58,100,74,190,171,29,161,104,55,92,7,251,75,12,93,130,80,99,160,49,32,163,247,51,221,98,119,201,215,238,179,92,143,227,233,159,73,151,243,241,65,112,216,237,43,161,128,77,236,209,202,102,39,147,74,248,100,70,20,203,87,249,68,7,17,172,80,238,131,43,23,116,139,29,167,31,144,223,51,210,36,215,217,127,186,45,59,145,31,2,174,63,124,102],[24,101,63,48,21,230,185,158,180,252,61,102,42,131,197,87,237,83,20,26,90,116,65,200,140,33,58,75,49,255,165,129,128,22,6,149,12,108,1,128,252,177,103,78,103,79,42,162,121,184,53,218,207,217,1,32,131,137,190,106,140,37,71,117,134,214,201,112,193,2,207,60,30,184,159,89,53,154,185,179,27,152,132,75,39,240,194,226,213,117,52,105,72,255,69,90,245,139,202,59,226,185,93,204,203,153,245,218,3,70,92,214,7,94,51,38,99,64,185,42,250]]},"proof":{"cm_w_vec":["opoOhiOPdnYHAPrLXbKQ6yOafE-zwy06YnKK_7ILBppLF-NDI1HI-Sg00dD6fCUa","psIxAephTuLgQsGttXwI450CK802Dt84wiM3wD4gyawkXJn6210BNLjo1ZHec5VM","kWejwQNWV8srUfhxh-pm9oS6JZDpsDUZ0T9QT5fNhb4CabXf9UEkwN5B4tOoDQyH","s9Cf0ClWatpEoNIK-C7Rdw69Tq6t8H68HDxCrhieeIAnHzm2yAX4ilOa8R_lOJHL","hjN-0ISlAmNOY8nMg8n5hFUnKmof26fDyVToDrR_VxqcxMg8wayLwBMIKVYqB7yt"],"cm_t_vec":["q_emWMiyZ_RNhE4PPmxe4SP4HPFmor4Z_kK8jvlxzf465pQ1lBArTgRBvb7Dglr5","pkWgHAOUPMPUMkuJZTOqsNNduVwW1XGpF2NQ43PeqKjhz4CfkAYrt1FUcvq9QwqT","tXnxe14gEquu1l3TYqaR7VpYbtighGlk1Ojw9AEK2o7cDa5KyQwJia9Cwwarc7H1","ijWY1Tp9sGXgG4inYsut1boBs-90AyyNtatT2o_pofNPQ1EYnjHiShSzXAfxuvC4","jjbXsgwnhAia7Rn1k3WilOenarL1xxybjKgmhBeQrGZNNDtZACVjGMo-O2Jv-H4v"],"cm_z":"p4bkFGRkKyGAHHGtf3gMQ4fV3ODfH8_qbVo6PPSiq5Sb898Wz0VispURD2orLmTL","prk_3_poly_eval_zeta":"hQvGOVM6VvIEamOlJW1Tc8EyKIXOLUV0383EMRx4uUc=","prk_4_poly_eval_zeta":"ha54EtHa8BGDbQ6tgsMNZmtjbf31qrYcQh_-_5HdmTs=","w_polys_eval_zeta":["GFy0EFQK5GsHwlh6eH0fYN9j-VPazCH_NWzNYVqBsyI=","GiU0tiEXNNVLOLtetjbnEz_mQMiIAiwH9F-lqW2hxjg=","cwO_Yj6bO4nxsqO5Mi1PBzn_jDlY_pWCUt7M1vAuUTs=","j79Qk0T7g1xMRZFH9fe-TbNLDlkZLeFHzJ_fLFHiRVo=","qFYpSnF3qOjg-xo0Wx9Tk-HkIVdz1p79PlKuxp2XW28="],"w_polys_eval_zeta_omega":["VMNDLN1Gd9WKl1nUY6zlU61IaOsGhNWantAzUEsn6m0=","CVhuiHTUKYqhpmzJxu6Kr9CtmR6wE_pi598QtTQJUQk=","DDedjL-9PH13W-jKSQ6IWfupvCL3SsBhHtbZJwcDR2k="],"z_eval_zeta_omega":"zDj4w-Qbk2rGto7s5fM7Vi0olPs-14LERePAO-yX90k=","s_polys_eval_zeta":["HY6ztIp-dqIbEz3fKAOnTMBFwYnG1AqIX_mCnO1sbGo=","Br8gXe-dSueyEZzebcsd_2BPOkDM4T3_iqxWl1ZyP2k=","HS_TB7TWWOmIHQifaqIhYoqI_3FxJdagIp6m8TUPzSU=","IpOi4xuK6QSp5uefce8XsSiBXTUbuSOiiDQzNRYEkRE="],"opening_witness_zeta":"kjEOB8ZcCwqB2KSQNF65S1JJ-P24xwzk9XViBsxGKEGgFULPPjr9F7fEvA6i0hZR","opening_witness_zeta_omega":"k2YKiVPmRb6kfpog9XhCgeybN0OKjawhWwt1FCzj77XOYW7XPkuwsuy-UKoBmk3P"},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"-xGILnR5Jx7PJt3PJMI9lKaxbr75-X8QnDyZYOu58g8=","randomizers":["pHUtlFRSBUvyF5trR7IQRXAxp4dV2_tf0VHu3EVEXluA","IbfjX6kRZihcReMP8uvmiI0FROwY1DVFYOOcVlzISGwA","XTS1p2eFK5V_de4xUzFmFKOCgobzmvOajudLR_mNc6MA"],"response_scalars":[["K3KXTZAiq5TyI8guQH3jMBY9miecHVTU-0xW0QmLKi0=","NEmT6uVBvfhtB9-WCCyXLwaaB1cjkGh0L1dKGNCl3NM="],["rt5Jw-fw-IBeLk3VauaOgXZvLrS9R_mMnH0f2k2aICs=","xnu6FBwXMxmQXWmyy5prn42WceOtAgIubM8CEmm1h9k="],["n7d4s1apLGur8_imz3gPWwC5xllMH7sa6S7RlW9QtCA=","vU50ZzGRSONrEYfwXZPZLQ7TfZr9k6rOEVterV6GEXI="]],"params_phantom":null},"scalar_mul_commitments":["qx5zOg7Y6chH21AQYMHiN6V0Whhm8Meyq0btHtueA4aA","fU45gP5fKhBoMgkhLqO8Urxh7K99D6i9-GKQp_vcf8cA","hXbay4Gmzzp0e63oIn3AkZ273ADyPJzpZGDEw68nvzSA"],"scalar_mul_proof":"ofWCWkcDy2LeM19JdKIfa5AiE0csiIrGR62CKgci3qSA2MI5_UPaJdBN9NSbyu06r3F7yQDr8hFbKrApNorbfhoAp6mTLw5cw2hRoCrnTo47kfdSm3-F3YqUFaRCR_H3Z0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABATaJy-YR598y8P4VLnPKjuf73T9ZmQHJPWx3KNfoF7D0AV6rs_O_8SpvTgk-hYTrOZJGHcPg1Oq2RHTs31BOPOc0Arc7RD9VBM-kCn6z819ylzAZrH61MlWeuuLFLOiLTbgQAHDXCDfGHv4nkaYNFl7IPdCsGo2FXh-z6NWFNj49P-3aAfuURFFl6cgbsaq9bEqwUrUZW7OmOzRSddtZvHkqiGE6APMNU2C2Tr4Xjz5m6eRH5vBl5O1anO9XVUFkVd-bCgGQhUA4svilNuwnbdwtsTNbp1Ic2PRPVQd2iuFspM3nAuPrBLWlOFco9HIRsBfyCKX2Q_Vsfao3nQd0BA602iczWCwAAAAAAAACublstCmqLcgb8xcG6ns8jZ6eXzlaHRIUIVvABjqig2QD3InnGl0BwJxl_yYNbCziTWCrzs6qt5xC2nLHHiIwW_QDGubjktzMea5vpH6ga2dnhCO5hqXH4fZONH4b8aJ9c_gAf_ObWWywtc-WgnLQDxLo3lILKO8hqJhAmlecqUAOAMIAVnrO8EkzGTcMj0JXMU7ydt1PLNKJOPF1LoDbjxUARhgD332cgoBEOJHjCLbOUV3K8nMPNFUNIiaItyJPREK5UFoA6x_qnUdr1ADpQV7-oZTeOc7J_1_matnJAFYMGLULl4YDojpLEkuUB1o70W-xELRLzK0ttFNz2UPrOx-2BaW2YjoApc-ny2S7aXIhKAzCUQuiNYqN_9NkGYJT92N4qTrImgwAEXeMUe0I8t3T2YyVnaPC7uItktjqW8AdUQUKMhZdPvACFPM4l6k7tnv-147dxjfN0Co1tkqYVF19shp1_XGJIRIALAAAAAAAAAAwpC1kpQrRX6qqPGjlxena757epfEwRfdDqdkKmtOwogB0nNgBMvKP8Qw3yHbXHJpMBLA5LRRThTW4Scn0fLeCwAHySyhvzTCQrv2vTSudIfB8EWmqoGXubyhCsbAaVihgwAFuRODSAtqkhrA3FyTwodvSl5LifBrNGZ4bNSZk0MiV7gKipyuCH4wPLoxAm_WibZ15_9j3Yy7a9sWe74i-i9CjJAO6MHLlYXJIsx2eeylzOK9atmFyPRlUP-5aQmbf4OqtGgLJmtBMGrbI6Fz17byRn2DSt23_HZeL2zRmpw7jArI3pgJqg8MZtKEMarRkUM54kK-i8FCGrR4aIJ6M_JaPDrzcGgBAqsmJRaLOIvRCzd1qHKxrPnrEXOhm1rCOeRs2Tkf8PgP9hRqzj3CDSmQuaajZg8-X6O6GT7eVYy0Wp0cNmYptWAFtgvlyw7eaSSwVupVdLCVDcOkWLoB6mghx0V9Vot_EzAE_9Y8X2jyht5dbodeah2o-Z-eWIaLpB-orQtF6TAzni06x6XML01TfBLnaLMjKxIsWSLvB7--nfi8uDtdLp53Y="}}}
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

    fn hash_abar(uid: u64, abar: &AnonAssetRecord) -> BLSScalar {
        AnemoiJive381::eval_variable_length_hash(&[BLSScalar::from(uid), abar.commitment])
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
