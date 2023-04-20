#[cfg(test)]
mod smoke_axfr_compatibility {
    use digest::Digest;
    use ed25519_dalek::Sha512;
    use mem_db::MemoryDB;
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
            FEE_TYPE, TREE_DEPTH,
        },
        keys::KeyPair,
        setup::{ProverParams, VerifierParams},
        xfr::{
            asset_record::{open_blind_asset_record, AssetRecordType},
            structs::{AssetType, BlindAssetRecord, OwnerMemo, ASSET_TYPE_LENGTH},
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

    const ASSET: AssetType = AssetType([1u8; ASSET_TYPE_LENGTH]);

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
            KeyPair::generate_secp256k1(&mut prng)
        } else {
            KeyPair::generate_ed25519(&mut prng)
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
            KeyPair::generate_secp256k1(&mut prng)
        } else {
            KeyPair::generate_ed25519(&mut prng)
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
        let mut prng = test_rng();
        let params = ProverParams::gen_abar_to_ar(TREE_DEPTH).unwrap();
        let verify_params = VerifierParams::get_abar_to_ar().unwrap();
        let receiver = if prng.gen() {
            KeyPair::generate_secp256k1(&mut prng)
        } else {
            KeyPair::generate_ed25519(&mut prng)
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
{"body":{"input":"D8zigEQpEDxFS0bOn1zW5PAm0pSn1DU2lmhOAGbyCyM=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"AQNyvFzIjZZn1I_bK29doY3jEYec0J1r005gae-Dd5JFmg=="},"merkle_root":"klnZdPbxC2PC3uIW1KjuuGkMZLOn-YUv_WcMST2HDgw=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["iJnpnfee49Bki7IpZLNQZn044O0iPCN1JNW0ONJW3zc4RNyrDzCTnk4Au2ZavS9A","gi3qzumQTAuUhRpywFjJt9EKXEJBZbaGTetAJSNoUXPJBADfwNc3_UEX7vbqLFDj","hzU58DB3dfhjRCXHKYiLKrO77yOxkjwmlccJDR5u-RQHHc8Z9WfooIj25wRf64tV","l2yc5mN1mBki6Q2nc8BcGO-sTjg8WpP3ApdNGhZoDZq33wQxUvIXbKpKaaBq-_kJ","r2_wWiHc5SYacSoeUBzTNbVA3djS4n7K8J2rigffMorgPty68uuoWyB8nXJ3ZVmY"],"cm_t_vec":["rGjFAv-W93O9hbbZX2LprOoWvwXjKjojEg0XzI8dgBMeX7Pl7CkrIzCWPAovZdG5","jXxoN9nEy9g_kwS9y--ewx9ZmMSow5jZrHE9jYXWK7zVa1_Myh8utzEhJU0q8v0d","svgXflP4fSnROn5sfy1QfHmhZne0owNnWi_FKxADes-UCLeYNWsrxX_x9A1LBQDT","oEGRJZPNBz74_wkN2hsMt1hJfVBzXdNSxRVx4kvjSNJd4_w3CiK3AoG8TmTgfWhe","h4NkYAipqMN6yRvOdWVyEUbfNG3glyTDq2frbXsLlx9P8JYfvxrhPbtgXJ5EFVTw"],"cm_z":"jRuF0tMCtZFD4ynf8m_vvd9Hn2tM9GswZ1StZHNypRSnV0jybS04_nrOFapIuxyb","prk_3_poly_eval_zeta":"87nbBzpl5p8Ys_Rwlr1pYuVQuN74bVQCpmYARsT_qiI=","prk_4_poly_eval_zeta":"IqNtZp8_0THzn2Asj_CB3lI_gNKrnnX7xZ3vaLbQRg8=","w_polys_eval_zeta":["oLW-BJUjYPDYiNU6fGKRVHMeFsxp6ok2G8whWSp9IjE=","ZhprH9I9Dbs837Ui7JoLNt2rTMHXSMY5ZRh17Ig0kho=","hRh-P1r57yJzNwbqQWJ5AF3aYaHtzcQ5RzvmGdqArAA=","hPlm5HQd90br58iD9v-7vrLZJVlJqr05pk2vaQ9HUgA=","JPQmSm_s8UtZYnAKEUoxzNgk008sQpU1m023q_-5UQU="],"w_polys_eval_zeta_omega":["t3AXmpvOBbcbZuyPCbO5-5UNmAa86C_CdIHfY6iF8SE=","9tGCwmlgh-npp65sLO-uyBbdgIZg_bjIdcM9sXGwv1A=","7WcBwZbO7pgmyYyR0GdoPAcWuqLd4OgR2UsldChybDk="],"z_eval_zeta_omega":"Fc9EHXzIlaQkekZbEZHg7qDWqi5D3rZOH_aejkj5DlU=","s_polys_eval_zeta":["4r6lyTBeS8L05Yds-XuUAKCCbew4ug1_ZWMxcWDiDwI=","VTr0jtI5m5y2DwS6cQERLK6rke3eotcecY77wj1zHBs=","7ZLbEUh3_UVsbCfk4b64x9b_VEC5P2zBheOd3BHVK3M=","XPYQptoq95-wJNiaof-ROMRY3DQUkd9LgHF_2NXDdAY="],"opening_witness_zeta":"rqofJ8Kpi0HDhFJW9v1vaG057PP6lfz3Hc_nPqiB4RkRf5tAZjOh-C7SOC8xNzol","opening_witness_zeta_omega":"uLRYikHTYSCz92d75pVOeCzb6T5aI0O7blLXOZ5kfYOBJ423ucJRHA9_DN7PswmC"},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"PJN2MwHv_rWswCY1kWmESTDtbh1vAeAg-UtXKjEDrC0=","randomizers":["eOM8yUTKF77pPp_WbTMK_yNQOY2okZtXv-OEUTRThwKA","IxNFcx7yeYFCdq8V3vdrs4O4G7Pqm3ooDPFU3aWRWC0A","rQ79DQVhvopWquylTyPUOLd0J1nNhaJNx8qacq5PkAOA"],"response_scalars":[["BRFLU9Hkih9l7znYnY6-OjDkQnxvbGu3WxZ6BYHNZ7c=","j1GMOzfzmYeCOOe4dbzw5EwSm2je7PNUKJqc3OO_mgU="],["T1Mf8qyz552vEyKEtkWoViOTJMJJOkfwuTpuEx9YS38=","4TnSOMFIwOiAPP8dCgmuf_DPcxtkoa6PzvipZyCqsxA="],["7Gfs1YU1sSSDjBwJ1EwqoGat35WL58XI6Ev-L2eaSNE=","zSel6kzSuG0Im1wxjZNUukFtSo8luymsA0zJek-qVuo="]],"params_phantom":null},"scalar_mul_commitments":["P1FzzNTHJUByrUKJrZgW9vU6uvMlgP1KMde2duaJGPOA","wHOlyF7H6xFgOOWdmPwrLiN1oA5vKsn97jmZYZEUcamA","3tcfVhpzxDmZrQ8JgOeybZCJSWviWvJFsV74_-sP2pmA"],"scalar_mul_proof":"l-NMu2wsYJq6Z8EU6cWqvFv2EPcstnEI_J7Dxr2TBh0AXGONznA7adoWGREE4vQbXxld6QQoyk5yiR-naETPkTeAngnzw9XYtwncWceuywTFyOyEgI9sKNgVLzX1PUaj68uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABASgxUU_w6pK-JMxd3wtt0JQKUCJTI3TJ5cMh8rlmeVsqAFpnEyO7l7sudzhIqGwu4ALvUoW7MroVl7htgccEYUX0A2vbrTrTMc26V_9W3GHedJRonikY-TnxaLB7de20BinIA8oXmdybt306Kgh6OwZCBhj-l50bWBWoH88wZE2hELg8AF3jhqkxY5ssGBAYFR5nmd90OGlfcJ2kc8XtbOUpXRRgAvLEPsYSNXXH2nVxi3em7wQnmvtj_Y4hrcYHKUNcg7booHL47Vzb17lKCT4CwjZFIXh2cnKzJXdZ91YCpQdbXD4Yp0CklkEW7coswgWU9XVCb6Z_txWcNUHnTaOEbRAbPCwAAAAAAAAA6tHvlqRzRQL0eukx6QrQ7ipFrux_EyvWrvAqyTst7gwAvq-O1bf6vZ3vdacFu20_gWE2F8wFAEX27VZnIKELEVIC1Sl4AMsk2_OO54ubuO0WJxBndDjdflufucMek6p86ugDJvLZ6jRF1cYwfGjrDhSpqlStw7IJYqRpxLafZr4tU5AAq-LuswMjEqDjg8zo4qQj3h2ebvXCjlfoEXiCwKZfHb4Bw1p8Y467e4oFffppLHvsQZM-z9g9db0rjHXeG_FeqWIBXFVvx3fW2OqbrfZKJSDmdFTZcUor0u-RZEZX9WUC_7oB1hUPzFvb8E8KMbtaSffvEIzTptw2i4G5p33fBiH2d9wD2ZMgi4ZHUiOHeCsZwZ9Aadge_mg70ijwEhjrhPDFI3gCaE71G84ZrUj7moSRozXloxhyGuWmS7FTgouK_ULElPgAh0w1ffEnPMrEnbVHM-_7xQ3pCiY1F6Y-8753Lh1BiL4ALAAAAAAAAAE_kwJIWnZdb9Q3Kubu622-rEW9d9P20Y_D1UI5_Rf_vgK_Uu1zfXidctMAsFkUswqA5jQMxF1Z-8N8IVua--hCKAJs0P_yCXW6weTn_r0ZaajzHG_606c64gQwiBeTSUkuDgI7w_q95VcNz4aL_0YIawe-sQVslsK-6eVExpyu-kYQagOLkl7oyYgrO8xAP3kigSnqzfGb9zm01-v3z2FoM0BtnAEctx54g_iTMTwBnEc2XAPDJBUMhV2H7ZV1MU6e356QGgKndEWCo4FUg8uUvGsyi-6Ifzh4nQwEp2YN3YrhPXOjsgBKwoQAmaQ3yh_mbVq9CrK-AoLZoVVrtxw9DCiYCCapCgG26qUI0VB2aOEPN3omOsUMORksbNZGYmfXVsvuwpU44gJyM-t9jKx0pcaKky1q1sQE4v0EU-NIe4D8D1xBhqPqxAHQgcGIc7jHWxAY0nrSmMQZVjYE9Yg3z09lMVjBjBoo-AJyUdpWcN6Z0-FVZKLj4uGaqBfs3wdtf6IW_MfMWErwZDh5Jbyo3ao2VOcOy2vkbK9xdQ7iYmUzsfZI7I3iE1IE="}}}
        "##;

        let note: AbarToArNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_abar_to_ar().unwrap();
        let hash = random_hasher([
            241, 186, 249, 60, 168, 224, 173, 197, 192, 187, 220, 252, 3, 56, 210, 206, 187, 12,
            48, 155, 105, 220, 133, 237, 185, 85, 134, 16, 232, 120, 99, 154,
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
{"body":{"input":"3P4Easi3K0XdcJcsu5szae9jTrpCqpCOjRS4M4GCYGU=","output":{"amount":{"NonConfidential":"10"},"asset_type":{"NonConfidential":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},"public_key":"ZLbURLDOqGRBwHZteKDK6qg7c4abEXdtDVQ0JxOOxEk="},"merkle_root":"ROFvX7R90SThpDIc2twzOqyToHQNLZ5Z2f1NPbX_hyA=","merkle_root_version":1,"memo":null},"proof":{"cm_w_vec":["qUJ3Ul8ioTPx1umWnRTu0Vzl5sAo2UhAo4J-JDZu6CCBJq0ZOcTa4itCy1Dftg5N","tYvwSauZ27ugDmdgKI-5AwHGVV2NGvgJwpUEU2hhJRY-wpr0W5OEKiti3EcitMyN","le_vAekt5N52yqEtkndicL66OgBNZoAgHxOCK1OElYoSvfaNcQIXnO3O2vVWYf3C","onjJkh9YCcYSUbcrSdTYigyJE7Y4CihFfTVYC8bMnKUB3uHeLyHcmPNTJS3gnnO1","tTHEZKedO1avwziH-qDUm5Lk4tF_K0lgWmNPQ-FRiV2mpEV0yt1izI-2yHIDnvxU"],"cm_t_vec":["iEdbwle_OWGVWvEelqsmrfGruaOFK3VzxVkesbqpIzw7quyb1whd_f9oBhbIgYwH","h8hyIceHbJ8tpMr5Ijp35GNm7BzJTULsDhM-MqmeUJIeaJJNnh1TzvMKoBZtXIKB","rpIHSubHfHCy75VS0YP1UumPI2IJKFq0PWNn-RqNpq-OWgbLczC7qH0nMlJUbnVA","p7Tab5fCZlkHYXX5X2YJuihO0vovncQfoj3oZZUt7R7jAW2Q8RQEC3AcYoR-_pxE","uaRuVKBLt-RsIAG9v8iTTOynktEYS1ljqzLjVu67H5GBFqxb7uD-tXtsdLjwzPU7"],"cm_z":"tr_sNYEPvSHtkZ1RjXRygcfPrChK2ueihxkbX5aNaN1iHT6TzKfrnIkV-qSWzgdY","prk_3_poly_eval_zeta":"Vc_ZPinoF_Sq6-W0BCnIxQaWxeijEc36qsXs8Qk7yx4=","prk_4_poly_eval_zeta":"aHUCkbl0xpcf1I7Ga3ofuM6Zo5Gan2njaxrajg1jmVs=","w_polys_eval_zeta":["rhgpJNJ2dl6Raor48JLuciigH2qY_I6fBksOGQNgLj0=","tCrCGmuT_5KR9o3_kmd2K0Vm6dUn7AGVvFCHycsHrFo=","C4qLT_YCh3dgSycxJI2vY7xX4bNcCkSWzssVWiI1w0Q=","F1VWOat5qnWOecPnb39zzB6VafswsMoWVL0P8sBuVGQ=","jF3eApQi7o0VhCtNlxyl9fvLZQAKD3NGLdu4wmCFpRg="],"w_polys_eval_zeta_omega":["SowrmZnYp3nydChhki_mm0uSXEcsfFe_1EA35Cf6j28=","kSrHhGYCwoDJNb6Hz88k0PiRSifrDz4_3bU-JvFd2l0=","j0cKUEFQSxoz5X1BG7mDXgZ6HGDUErnGEF0K6RLMdxI="],"z_eval_zeta_omega":"ASEvvHm0AE0DTY4HrBYs4NbvjyC9EPbZ8d2ep4tOAlQ=","s_polys_eval_zeta":["kWoG2MJ7Mfx1tQd5UFgp3aV3D3V4TyLWS9trcpxpTA8=","22SltKGF3jMgagTubhfv9IKIjVFwTEbr7hfZrsk04k4=","ddsWW2_Xu9ETZ_VfKUTLZf3oQBivilIEtR39u3fYiV8=","gAZjmEgNxGAzBVXOUpmaLKdT2gEKLJHDaadv1b-7axI="],"opening_witness_zeta":"jqCeLukqr_7VTgYDwNIVCRDZZ31PxGPjjC_b-Rw5_bjFXntf5i9RiPVDNo4lt6af","opening_witness_zeta_omega":"qIlJkeysov42fGSV_utcHNYH9h4njyA-_DmWS8ZC-Bh7YGNryg5QmRNrjgtGAtNP"},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"0oThcaX0eB9HH910AubaPaAY0ADTIHjopW6FNP3OKAY=","randomizers":["cxywUG9moXpU3VUAGOo3WWxjIT1rOSy5sOZqwG5PZG2A","7SJBGJ4fQedoJLZc30DbCaUq00Z0F230B33xH3bG9EMA","nInBHkwPX_loVfXO7FmbFgH2uL2Un1OU6dFRiBYOwAQA"],"response_scalars":[["9d6qYm6e-p5QXs9Rly_9a5wGERa66YpQ9tDk2tslLgk=","defxdtRw8O4a9Rsz8EqM02FqBUa5TeNPqrCj8ohdjxU="],["IVTbQPzPDI1r9UFydYIB3kKfLDeshKRRrTrAtUv3ZQ8=","V9JurC3HJuYA6LfOcVgxWiRNDAh_EPnd2rCq_u6r7RA="],["M99gwl14XQ_YDDtNjQqE26V4WJbQkFS94DQ8IlRPDiM=","UdU9GkUjlrStl_DzqX0g2ay6dmirs-PLn53XRCgpQSw="]],"params_phantom":null},"scalar_mul_commitments":["9_HZmS21rvPf7bV8V_8oI5kHA2RyM4bvbTH31G8KZzGA","zj67U4appnHVz-FQMaqmIKDMpfL9Z-Q_QgfTWBY5BkAA","wbICkDJgvlDqsnUC-ajbv_nYPi3kRrL3MmCxofsgcRCA"],"scalar_mul_proof":"2M7Frsq1rURsqtfiMTgYfGre4j8OdMl-jKWFLz0_dB2A9MgoLH7MVH5ZHrZ2cY1g_dj6Eeu-nPdUnmADfSd4oz-AdiC3wFUD6iTT6RzZqpFH6zNRd0gM0sT4bEJTz25UCjqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAwgZ58vFFUh1ryEVnV12fm7hsnLZpO4pyWf_cBRiEajUAFm6Y1HWpEyEtAaJtICrTfF5GDcvmDSQoyzIuJsueFjQA9hnmaGTUJm9FHC5xYxL-CfhdHhEV94t7bfkHj0F2ZHkAUYoE12wcY_y4_JijKNlaP722FUOUbAzV9ls8HMWaOlOA6UT3ZtDhK9dszBWydjTemHV8SuMM5XKmv4CvOnATEWqAK1IWR1hS7-UMbA0SORgQjSvsx39RMpXAc-9dbniFLHUz3BWoFdUad900EVwIg_bJyG-fikv0MP8xmhg4yLtDcB8TOuT3ZAQtLEhPuiGC1mCm3NfeNY8PbazGsUI0xD8nCwAAAAAAAACeuWF9sOhpqXujk0SQnWtUQBj5YcXZLqV73dFSsQvUe4Aq2XRGv8ZVQDlNngOG_Lv5w1BoPgiY317lOhPhg1XoaoBb8TladZXWMR_L2qdCDnqZD3Fr8FjNA8-D_3t0LCVIdAC03thp7VdMGYIaacEOocmRPMWYj3sGKH0QGDu7W25bdID-eXRGqrFWujvj30cCaxKP_iK6Lmn3LbUL7QDpFpoBFYDGQPHShIPcRkUxXZ9xLB6cSYmtly5sJsfzS-lg7FsWFwAvKbpoXzJAjw1QBTmuEWSpdG6hYp0ifZgj_8keWQBPewBH60Qqx9XwN1huA118zjFYV46D28AvwZIZbzwb6nt0BwCk5xKwNsIJNXTcHUaqyrE9KW1IawiiMLl7_jDiZJR8dYC_x237t6op2teWwNNc44keMFPMWleFUUjbr64-dos6MYA9CghHu-vTO0DLtmCzdr89KZnE5AsJerpPG_TeeigLQAALAAAAAAAAAH0EwWSzU4YpZcyJCTqbxG__R_ILJvMAvzshYU5EVFhBALK9HFqbhRPxhYRzHtiYddSQ_Uxmzm6qI5R-fsyWa4I-AMKYW1VtzRkX2GiaKhhkyXJ_JuVzg33w8iPuYuJ58mh6ANgN1oKliL58QUzDBGCnBEGtwueQrIdIbVnNUQgInG5EgFZ2ZCC8TthcS35O5JGJJQ5Dq2wU75VOepEUCnBeUy4TgHKb0KeG0WGzpeijPDjQHe02DPwjxipuUTlPxB_aYowQABtYx7YJVY4SO0Fw8fcOVPE8J2sZclgVV--lI2Cd1uZngNbIhJ9vrFSCIM4mqKcu6-71sjRHz9fwVExAua8KlL0-gFJWiNhr2dR0gGDQ3u1jCnAbTg8Q_ew9BxtK6txU9HM5AHcjHEG1_FRQToiJkshrphwhO7T5t1r1yNS4rlPKO2g8AHpnSBjQuizupGDZoJM8m-_055tjEC7EZe27FUqr7kkVAEe79AZeJK0_npd8FKO-xuxX67NT7nDbbgn8BsUujMkxnnd5Fv77P2zZnOrhVU9WcHyI0r8r57JVcJYHOKm8U00="}}}
        "##;

        let note: AbarToArNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_abar_to_ar().unwrap();
        let hash = random_hasher([
            30, 204, 102, 168, 9, 56, 84, 47, 97, 209, 18, 102, 12, 111, 225, 139, 239, 211, 191,
            148, 101, 135, 14, 164, 178, 16, 160, 87, 97, 173, 95, 13,
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
        let params = ProverParams::gen_abar_to_bar(TREE_DEPTH).unwrap();
        let verify_params = VerifierParams::get_abar_to_bar().unwrap();
        let receiver = if prng.gen() {
            KeyPair::generate_secp256k1(&mut prng)
        } else {
            KeyPair::generate_ed25519(&mut prng)
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
{"body":{"input":"FFY6yKlx8MfgFrkjDY4zsCFGzMhOW9tN8WS-oPSnqgU=","output":{"amount":{"Confidential":["ookzyLxQzC--MT4acyYaLwg_CrATJ1UXnF18PPRx10E=","qPk40iqiu66GzKjHZzvg-vedGhjOwe5lr933-MsHB1E="]},"asset_type":{"Confidential":"GjrGvV_u4XQgBzBypTfXs22oLB2ob16N5u_XvM36WG4="},"public_key":"AQPJT0jkKHBtB4_mS9-yrjNBK26MpV6PSjoVSNUcyWZlvQ=="},"delegated_schnorr_proof":{"inspection_comm":"vsv2peKMu2KJF_4_svYU_VbAVsGSh5X7gpW-V9iSz3A=","randomizers":["sJ4GR6lDCjuDmFm_PiJg14fCm7kL-GvJOnyaJImbVUE=","IkbFQaOML5Bfu9eUaKJq-EpqGnVBz5B21DajFWVEAmA="],"response_scalars":[["2vi4xHkTWxt1fYbFiFGE0M0USDcQwIuEoBojC0743wY=","aCUGTy-eJrfE7xzKozmORCpKiNWwdfM9RsrRplHimQ8="],["JNpzJONM4LC1mmg36C8CwU4k2HJLPPbN5mC89qWacwQ=","EmHbp-RBj4LfdwBtNd7_laaybQ-O2IBrRXrof7p1MAY="]],"params_phantom":null},"merkle_root":"ae5bRjd1K6-fdydt7a_vwr7hjPPaNRnv7yvgJiACf2s=","merkle_root_version":1,"memo":{"key_type":"Secp256k1","blind_share_bytes":[62,198,35,156,57,210,157,106,199,237,91,189,212,196,233,251,191,162,94,125,121,219,109,51,10,5,253,177,63,113,231,234,0],"lock_bytes":[219,218,43,179,171,241,94,154,34,198,180,60,121,122,253,198,35,89,184,230,160,15,194,176,110,6,94,213,64,93,140,196,128,226,197,13,43,173,107,181,128,220,214,200,226,249,14,64,157,19,167,42,65,236,206,17,123,142,184,68,13,174,58,253,237,229,64,9,235,164,233,245,235,253,169,12,219,237,132,242,112,226,90,188,220,154,83,233,232]}},"proof":{"cm_w_vec":["sybJptxdktFl1dHPwssPvFggzwWJetHfnH9cbWbS28avtANDVrhylS-Dhh8Uxbt5","q-EV3SAiPvBMcP5eN_IoICCcFl64uobdeTjHnyu0IGEq8Dh_AaF-mte499z2yWOz","q88MgyWWsHEN4KIVnUu7FyfjGCOeBCi9frC7S2ZvWiMWlTwnhYyg38b0zWraA_p_","oERSjfH5cBcoZvIBz9Uz5J7p7jho0psYvxRzYl47XQuHshcKECKix7i4BRDd2qoP","gdpqcyfAkXiANfHJ1oxJnH6qZCEfZ1t4JIl8hH_vAdAAdibDLMuZ4aPqnhuMym9P"],"cm_t_vec":["k52nJf3p1eZSibdLAAMqEEc5XSCmcddvac0cdMWy4X6o6b5y3BMRHjJ7VepUuEwP","jJvrG2qGFWYj1w50gHDlWDP8xW_vTuZF97yXGYWjx_-JQBgnwANwDJEwfuoDlX7g","sRyNc1vRjeYVHk0J4fUM6wAYpYHfifM5AWb5Ux0scII-I9vA63EEKHxbKCYB_hli","md-i5WemoM2_bImsuREwELoG-wJRw07-7sPDy2T0OdYOyDpHgBIdDxs4oUcJFNyR","h847r8SeoLlOEonpeHT202i-PsQOIohwYhpeN8-UP9LsoGNUrJEimj7r2pM8RjWm"],"cm_z":"ljH17hMKfboE_qZyn6_SOLd2GAZEz1wzTudG_3j9NBYlhcjTvl23A2guX4S0Lx7Y","prk_3_poly_eval_zeta":"YiYj4D7NhibjPtgl34R5BzTLIIkw6Bj4US8DJI3SZEQ=","prk_4_poly_eval_zeta":"DW3H5ueux_UPh1mst6gl7IYciIxGto0R0J6uzNlYBWE=","w_polys_eval_zeta":["mhHfY1PhHQly6H1cW2PeYjCaisMfdn8mhyRUVR0Kuxk=","ge3H5SccpFAqaqHQ3nN4UYPwPb92MixH83MbDCr06Sg=","aae2B_msNKVL3gUKZ1i9O79H4Opv6tbJuxgRqnMY72c=","Pm8rmug5AxCLCFo4uc31QuvmF3S7YH4M9FYeV8maaV4=","8QeTs9b5PBb5WYM-wdeVqJxR7EN7R2BMv9B2Gei5e28="],"w_polys_eval_zeta_omega":["HMQYEQGkrU0buzuz1R3StdeIM_-tzQiNLQ6TDB0XlwA=","2lT8HOAlfQVYXZZQmg6t34kLH4Z5RHmom0NwMihNiXA=","Db-tmK4XllpGyp51C24MIscuAd7V8-hBosjQComLZj0="],"z_eval_zeta_omega":"vw2E1UmAiKjISlm1-8o7ETYGE5Kdgy6NIv6YM410wiQ=","s_polys_eval_zeta":["OHvQ4cu6STplk4i0-7hP2R7hagbcn9AGFyiSLEHrllA=","9pOHlUeYOQroYHaZDq22xce9jF4hnRjb2Pr05JvFSgU=","Zrj4Z9a_shvmVkFAhBCPAFa4m86ekX8h4vtP40CXSHE=","_YMwwWFSENBtie0jlleX2WSsrhCXn9yyIFK5-ZpS9GM="],"opening_witness_zeta":"qFy1iLfkReM1n5Olk47uzyAu8t_fZdXQThqvIzK0fuZ46a4SCCyxtL0hl7hdNcek","opening_witness_zeta_omega":"rtDPOTXiBulhrzLlyGNhUQTnPwUsV5B0snVs96HMUyxxCwjsODtODGf8pvhhx67K"},"folding_instance":{"Secp256k1":{"delegated_schnorr_proof":{"inspection_comm":"nXGj6Uy33Mj3bYwratTt2YWyYCe417GA1i6qbJf2mgc=","randomizers":["9OJQi7alJ2vGtnzND52bR-UEGh2hm8Tf4Nwp1WZbLSyA","ZLD-q9kmLNOXJ2g8_OfjMagFMQlNpecuR8rpSDpU2kMA","fQAB-Xu8Wq3OfwgW6aNVgdasKAuz4cdjZQETPC-wwZYA"],"response_scalars":[["JFyHoCa6vEnsCd2wSnQ4Jc93FBU1p4zrkgZdzadk4rk=","lyQOMaB4f4Xo3vgrkJtffCRWJohmlwhu2yth8rlLh3o="],["aHx6pIhnbbZbAQF0XMaNN8AdHuRBZYTA7-102Y0Y_Rw=","0s6Ltb_79ji3HBEDa0pYbEPuti3hnlBOJqQbl4FCmTI="],["YX_dwG-PdMSKD9eaOAUOncqHM2H05zuiJAV3nc9GWng=","ghiB_sfY8u3c0dXlptJ3O4FWN0nzKHP43B16RLbORZc="]],"params_phantom":null},"scalar_mul_commitments":["j4x1JFSygioIFeHwr-EkL0EAL2RG9KIXvnxPoDjJx88A","K7cEy7RaqGVxTPcD_78rnxdb7BBVMBSZj4pXXew9ZokA","CrlPwDBWB-0uaZvu2aAEdxjQjSXdrVzFGVGB_HgXxIaA"],"scalar_mul_proof":"y8G9OMBIqwfkMEJ-ij4kLgSaShtpoTYQ8H28C_95QVeANgZTDyHOMQCH7Y_vRd3lcuUTtY5T7HI1N2po-5clDhYAAnuB0K2u_FlxrJ3N4FBsbjsVn_7POrEtUxq5pPH1MYWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA0KM9pqzIDq3pNJelNmKqhL0q_BRvOvf6GwBlFv4x-7MAJ-Lvydq4unZO7rc0-usELRlKSxSOgKlJndR1hv1vjO0A24xftQaIEMjX-1816A3JJNNO5eMUOD__54Be-wWKO7IAR9fPe-nCsalpeqGjUsZLzP1aXSQKkUtrtcIT42PsHWgAbTIs2x7gqGeeogNOZNJJsiozdigybo2h9GEhgQcYdNAAFB2JLw1pBV-k5vnrwZAroUCepJoJZLT2UWOHnrdXV9wRkGiuZRiAZdAoJH5FMxAMaVL1ozSiS0AR1csUxtoE7MOsXw_koefKLud3IUgKhJUU_UgjjjsJgubNuYwM1ABmCwAAAAAAAAB1RpB775yxFRjf4pcaxoMiqHUo7TCigo7FAtUm-AAiIAB6lPoj09DqPx85UXG2z4yYMKCkBOp_rC6YMaTB2qY5PYDuMAgF6_vYwOBzZ1Zb659-AXOPM8DkScFoX1sNXeG8AoBJ1XNbDDy0Kt9P6V15QU9V64DnaKiuiTppKtLiyWyhBoDrZ1T77USnsMyPm9RZNHQikC3Qw9FOo_qIs59XWE5qoYAssHhNIhj18GrB4sOTsF1NDR2jRhL0-9CnZm_ylDhliYD8TczVhKCd4uBr3xFZa6NIdvyVnrCnSMJG5EKxDAOc9oD3-szdXyDeaW5Ax_CPFIUdkdMxLIL9y1DDzxAgkA-ca4Aq8V8NdVC_B-VxQ0UOfPKVlfwuXmq939GuTQXLdebMVABrZVxsx-zTlD9GlDBIT63me3pWaNnQbi7nOKHv3aQB24C-S-OWIpqwMdE7dbBxDjRLYs9cxH8Y0uZ_Jilx843T64ALAAAAAAAAAHhTie7EoTLjSYbwNPwN-K8lPTX9sM4j7ZUpxZhC2d1cgBkd85oKB9TkIV1iBKerqkKq6_EoYnSRhVketj9si6EAAP51ZusqvBTBR90G4BcWp8S3IxjvcQpnGHxX2iSLLS9lgBU8q0ygSLNRai3jGRt_aVLRxF_TpnepdME3nDhBzD80gEXACVbuzWRNcroTMldL6lscmfnjgdaPw19Z5U1JJ2g3AEo1MB6IPnKByq0uCIzrdgWaDPW_1ptImmEHAcrWCHsDAPE92jxFnX8v3mP_9pjgHgoKSUS_e679jV-76DpCcidugLbx3hau7Y6WWKGm28tAGrdouyZJo7khYSksL1DZgL5AAOGPxZmuOYFTVn0h-7f8BW94RYrqY5xFDwb-H9agq44sAPWW4aPXTjvXIZ7au6UWEwaQDlNrgCmZ0zxveyO_-_apAOYVUkxLJILiFHJ6aLSO0JHQwV2aHvuCRiwq8fmiyfo2ALYPDUsE9FtVCGYpw2qkrCVd9xijQ2uiJkKhFS31Xiabq2CmlKb0wy6QAi2kyB-q6NeADrHavSOzfGHXnmfX8yg="}}}
        "##;

        let note: AbarToBarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_abar_to_bar().unwrap();
        let hash = random_hasher([
            88, 54, 39, 9, 155, 198, 62, 245, 197, 80, 27, 67, 191, 205, 21, 159, 35, 109, 28, 155,
            108, 125, 183, 223, 13, 99, 24, 250, 121, 106, 252, 30,
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
{"body":{"input":"B3pRVOpbE8ZS35hl1s8BDS3K2HgVgydNUbc0mUpsMAY=","output":{"amount":{"Confidential":["PLD6uBz4jB80yDFQ4tk9xVXxR25e_gQFfJ3HeT8zE10=","BJ5oTV6Rzw_5uPUarAJ-rAj9nUaH-kKDEc0I9uRbhAQ="]},"asset_type":{"Confidential":"Wg8wsKve-n7SYvoN4_gc2ItOJwkEWCa5i6zmOfiS6Fc="},"public_key":"9RbUQsiIBiqQVGMbckbpPT7uqKY2sD9c0ckEtyrLe-Y="},"delegated_schnorr_proof":{"inspection_comm":"s1RPs3047fSx9hVoP452kHSnPOsl5R3gcW7QAOYZozQ=","randomizers":["QoNzTHZMRBbMzA23GzD8bEUK99R6K617eKH0s4CMgVo=","sMUZgDSfImrJsaf2nuvX2OD5CiRvZzKWLxIIX1uob2k="],"response_scalars":[["cK71sceK7rmibROnE1GAzQHTMCBIklchZD3fmXP1hww=","BrUUGVKC939DUvxrUsx9NtzFEbt-4PgrVLxDsna0qQg="],["wbmvUGlZcHAat4VCpLK0BbL94SoEXkykjL5Sjdeyqwc=","Vzq_bIZs6oF-Clrp7o5khWFuGGT74wvkpbi20Wwa-w4="]],"params_phantom":null},"merkle_root":"k-lK3IYcMNHi1aYYICvLl5oQPgzG-Q6QvYMXrokkihI=","merkle_root_version":1,"memo":{"key_type":"Ed25519","blind_share_bytes":[54,103,22,172,98,156,121,201,224,152,188,242,141,174,15,160,5,133,195,17,26,194,26,144,109,5,175,211,148,233,10,241],"lock_bytes":[177,58,34,151,207,227,87,181,187,137,164,159,130,159,9,20,143,232,235,128,183,92,126,216,148,147,203,105,182,229,174,12,55,57,86,147,58,35,56,36,148,209,190,48,29,197,82,194,166,230,13,199,44,202,199,88,186,16,92,72,62,41,31,86,64,86,217,0,96,218,49,14]}},"proof":{"cm_w_vec":["rzYdubpNHQWU2IaiauDrnDJgUz1RALoaI2ZrpMqnwIcwHQjKlxco2NpmPobLpgI1","oLTRYJDbAUlT7ZntyJdnzsoamHSuj3DpWY7RejgYu-N2_zlxiQFd2CAPjzLKdIyy","lpd_MlfpftCPQ5INTaBTBQgmDs8PBvBj5CmdJJImC9sTfYPudnTNA6uMshiXKL9t","qyY2y-iwAQgOXIh6igO_AMTbaHKQHyYdEkFcx96aLDIJ_h-ogQZrK8Mo_McDmA7P","l5BeMae5xFLwFmpc3ooqeOIvpi2z8tE4WLHHFl-ZycoNB7_7D4it6PKxMgKLrXK6"],"cm_t_vec":["q4sWoQ0_FUMbWeicKB9pjgCrbuCHmmCe1pSgP6VuNh07tXA4azzX1PJMc2bvAzGs","si6rPPJ28UYZzWSIIgaiiphHWlL0heWBGXtUl4XKqs6lWjlZ5Q8XOUi9q5PqdOim","j-rzHhsWrpKRHiWb4N4iriokQPW8q2Ngyob3NXWvpVltS_xn98a2doXRaYfvj-5T","jpufWeXiGSMFuLIE3SdFf9AGQeNeQQnzHGkfLjq_CpD5JC3ODmtAaUkjStC3IE77","oo2C_KhCM7PGMWFwBfWj7jahfXXYWDzis556cJPZcaROg1ak0xQtVRU-eOS39DJj"],"cm_z":"seJQ_mq48cp3P97iWxUFbc8KBdMp0J9h72r_KWI6FOv7Ed1W8avy0ZrkBW_tKNWZ","prk_3_poly_eval_zeta":"byGmU86wJHCttF3bHqbNsIAx2Ae5XAuWHykk-uBV_D4=","prk_4_poly_eval_zeta":"iaADu4EV97h-PbZ0PCb8EYGOTbD1XPSDkSZht5l6QRY=","w_polys_eval_zeta":["dj7OKWXPo0Ch2cdqL23mfvWziqpNs4bWMNEo4jq1XUw=","uXlDUoEsf0FJe_rpCpGwnkudNuTBNJtzexxiMTva0VU=","EM0kjkpi0JVdd1U9aYVPB3hPtQ8kzvjzfeBjMqkWfR4=","S112PQGQFSYkjzRjgd-0f5vSZvW3GMI1wmPL5t29-UE=","z0b0Z5_0ia8XK79RCaiplzq7BDGeqcUXs07AoYhIQCs="],"w_polys_eval_zeta_omega":["4_7734bm4NBJlF9NppIz4kTtrOLEhKcEvLcCWWHRh10=","hjNLEQYeouLgew-csstg10iFtg96sdNpgctaTv7cG1k=","KcnfiH8nGo7sI0BMhCG_vezawLOOsQpxj9U-Tgq7mBI="],"z_eval_zeta_omega":"9yK3NFIiQ_rodvW9sw26jvAF05fA_Zw7VADHRxlr4Qw=","s_polys_eval_zeta":["YU84HwQ5Bxf_7EIR61H1bA694I1ZQaTyHjiDvmPg8xE=","sCvxA2Ff35iDEP2XuRJ8-JCMO8_6FN5IyCV55I0zCjU=","xNvFuh7X3UqPKBd02C9SXvQrYohYEmW7Hiskfr5jlC0=","fQ98_4wIB0iIpsbb20bi47go4SIw_MxxNxmbJhQPjV8="],"opening_witness_zeta":"seNPD_-kS7x1_aK5lNKY0FyhzEANls6nZqaZPPZdCsrDzN7mrhbi9Zew8g_tBr24","opening_witness_zeta_omega":"pYQrMJ7EUDJHiAw3rNvDxgx0GO-8-TNz1ZLOhBHqJ-XeJY0XxaOO4wvRUr83_jI9"},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"h-0kVfvHziXPAGLnK3hWkJEV2iDIo3KKz0UY-ErJ0zc=","randomizers":["Az9tbhMgn5Cnz1No3RvhKgp5BsU6n6ajkRiybcFybyaA","KV1EGTj0GBSTlAd5nHEOtgAijQFpEy2zlTAtazZluSAA","DoP4EflmJ1ntqC-Irs_QgtRZTOOMauAOCF5iAg9S2TiA"],"response_scalars":[["O5xVeTIo0Weh0wskb1LcIT5jEGsy-PG2DXEgCpxSZTI=","07mhCeYxRJZTKFIJ4daQHrI7IkQV2-fV_EmEVcmudiM="],["E_mrSitsMQK5WyVyMhuuWhgK5sxiu3pzk2uADhAstUc=","uWafe-Ll8xt-hwURe1hHi9TYbXCN9RU9GTG8yivJN0k="],["s0gTJHRWl-UW6QzOjmXGC7AiY_dSunMPgEBxI-W8-mY=","lakSn_NaLpls6kXA3rQV_MO5ImdXofNaaJE5idDHWEU="]],"params_phantom":null},"scalar_mul_commitments":["ypDWX0G2qoYD5h9pNCng8QNAuiiaGFqvG-tVI2eX0w0A","wnzlNkv0WDueHQQ3uO3Qs9RvRYyj-wTJVrREBGaWeSOA","y7ja4T7gUyRN847d482gDiWas-qgIsYGDBdAKvL3OSQA"],"scalar_mul_proof":"zZ2Ae3fLFuEpgBGWU8rftr-y_Ume-aF_Av5kqnrcpDGA4DZKcMwtegiDTOJRw_iwbvuD-DsNptzC2qP8xYdxvzGAu2RFj4QUJ6MTD3cfcd39xeK1T6nEtKdXdPq1ykbmyEaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAXYIp5fN6b4y0RRd9RsJHObugqLWfRNR9C0JFMDzQgnSApwfm_vn4qoCgoGJ12GAxhi1yqmurDWrnwmiRqwMKbB2Ad1yK0Kt2NIlBj9Z1oKTL1AdoIfPsVxm6G0nm0-BJUQAA3R5n1Saa3wKpdZgXM-0ewtKQ0JgT6f88n7CcSL5Efm6A9hBwjo4tH919ed8is5GFKJoM2CexIIUETxqYCu0Yo3uAh3KxNPNTfTfjICtZMZ6eSF8CWgXjgBSXhgdnq50bqB9SneuryMgPJbLMiduMkHqoe1NSdFKZvUJtLN00KvAAcg8k8zfkA3uQF_zb3MqwSpHbazP-iSqxoVjxlZDXFIA_CwAAAAAAAADBQLj2WXN_1nPYq5APeLT3CXTawGohMpghyf69XdzgLQC7NJOzL1GEeM474vaXSSKA012-wcwJZLwv6PLAAEgxLgDQlRHLk9kqDBnWPJUxuVWHTSs-YruHgfc-4-Wu672ABQDBFd2vATpygN5uFYRA5ZrteFObPhQsstKzBjBIRnroCIBw9J6KVVMEh7KsNMVZLUmh7upfZQd-5no1xxWlmI3lZIBPTZjS16M9-uPbOV6g6M2G8FtvplkN0BUvZ5VmIe3MRICRVbftaX5uL6K4ztobNF4uP2vE8yJwIDctwBvP0wyKVYB2dTpCTNxRwiHwL7bzIjXfDkpVCmCedIzc7Rl5iRXOAQAKi5criemM9PDUIa5mKSo8zgnNjmj_yPw3KZfpSnBWOQCS2p0s6MVt6rw-5UVQUrK12NlwzK6_c4pUgMnMENLgG4A-FRXclLzeRxVoYwUdxePYfJO82-JuHG47n9gka0-2FgALAAAAAAAAALn2WTIznzAECEOQn2c57Cnk9DzAZcHW5P4jbSNdkc56gJ3R3bEEU_R1CcQbwqUc14Ril97X7ZeSZIJdv9tvIC4fgMOEWuzZsLOoXJ9gFYTpz5ALENCrnq5onSeaqGjYN9VjgEbLPsTKXl1EE_7w4QZ4HMN5U3oY20VeSqIph7g7ctlVgGwceZwBdCs8wgd96Gz0H7T4ykeejR5PqASkUChQbGppgO0ZcOZ5BY9K42riO2V1SUPRAlbKKbh1x-vwVe_I7dRPAECZzmy_zR-oHRe2dzY4TVeRv1GAOBs8RJ6vBL9-c-QVgLsGMJ37M48rJiTjrV0wrUg06tui1-TVcEKCeQLxObstAGNqcjOQ_pedY4h-E1-1TMkEKL3ctELFvEJ9neH7_8YtgDOcB4u_zqqQ4puBFVPWFCwXNdFzB7otqkbjNBbyKiFSgE3fG61SmsX4Mr4vWo9k2WPDt87RuaRUMxMucXxmadZBAD7Prqf_0i9wCmzmhMlZ4dzt1QEloggo-lpTdPgNubJc6Kd51fqjZLQ1SUvc2WL4otMN_ddtwTuCb6_sv9plX3M="}}}
        "##;

        let note: AbarToBarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::get_abar_to_bar().unwrap();
        let hash = random_hasher([
            28, 41, 9, 130, 81, 12, 91, 68, 78, 207, 113, 228, 151, 226, 138, 166, 182, 174, 218,
            123, 40, 236, 194, 38, 89, 94, 177, 178, 222, 156, 84, 130,
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
    fn abar_8in_3out_2asset_test1() {
        let abars = r##"
        [{"commitment":"AtR98T47fPXTV2Oqbg2JxkW66cx-Tjjsmnyz-LZB3zA="},
        {"commitment":"HqK0Kneu6h3I2avNVefBhR_2b2nOFWsX-zZFruGFmC8="},
        {"commitment":"qNYhlkGkgZ6Y6HuK3o9UJtJpuidVA7hl0f9d6TOYxSc="},
        {"commitment":"lQ49FSvucZeUbbm_sErzlV0-iEgBrNI55F93pVJyVgc="},
        {"commitment":"Jrfqri0rt9nRCHlbBtp0D9xC-VlUfO9GrKI8fKOkBWY="},
        {"commitment":"r_Ph928YNpJdDZvZuN99kfEw64Kv8n2OKz1meBxHHyo="},
        {"commitment":"GDubRWiphS4H2X5nAmxU90zdPbeckkxp-xn29xS9wkc="},
        {"commitment":"MqDXmmoWaaWJtmmTUycn3IFHKuQncHnvl8Gq7NtIXDk="}]
        "##;

        let sender = &[
            0, 71, 127, 50, 47, 5, 51, 215, 80, 53, 19, 188, 213, 0, 10, 217, 22, 21, 196, 47, 26,
            81, 114, 20, 158, 103, 163, 164, 51, 1, 254, 200, 236, 248, 149, 106, 83, 191, 150,
            168, 96, 137, 34, 6, 156, 72, 235, 178, 118, 238, 22, 106, 64, 204, 170, 241, 142, 124,
            183, 232, 195, 186, 173, 18, 237,
        ];
        let memos = r##"
        [[0,183,200,6,104,98,113,157,225,77,43,234,88,21,179,87,168,218,41,245,13,79,123,245,163,179,15,221,38,251,86,113,253,185,21,130,29,159,189,90,118,173,181,180,57,65,2,243,91,11,39,35,75,235,69,49,1,245,107,108,48,230,130,202,90,255,84,211,52,249,113,84,87,25,75,91,77,110,112,64,254,58,184,57,5,137,204,90,120,146,188,211,41,178,240,137,113,29,74,253,242,153,68,118,147,23,243,126,57,51,133,86,3,214,37,73,16,161,215,62],
        [221,193,78,238,106,110,140,39,32,167,77,250,157,73,138,137,70,151,188,155,244,232,254,168,222,30,240,34,63,52,210,172,63,162,241,36,240,174,176,22,138,132,215,99,144,76,196,229,199,84,194,129,34,93,101,59,105,190,229,147,78,117,80,223,114,23,101,140,89,112,59,245,43,115,105,113,162,125,45,114,180,51,182,12,214,204,67,123,231,216,22,202,226,72,191,1,232,124,231,21,41,102,69,136,97,98,17,222,15,15,166,46,97,229,134,154,3,245,177,225],
        [223,167,100,169,245,107,90,56,50,49,98,192,222,170,34,72,106,10,159,237,152,196,92,85,3,135,203,8,140,73,6,180,248,56,116,128,137,20,158,233,176,34,245,40,74,48,136,42,6,76,114,63,250,105,158,56,251,248,251,198,16,222,205,79,4,42,194,254,92,216,65,17,84,255,211,133,251,50,96,183,3,102,103,160,41,54,235,230,68,165,218,248,71,255,211,19,86,202,99,17,163,111,252,50,31,78,91,143,41,223,239,205,14,13,75,111,54,201,103,189],
        [83,17,108,24,5,221,224,250,177,98,71,40,66,121,11,254,173,160,171,61,115,177,1,200,188,168,54,163,195,180,236,113,55,107,10,242,29,139,40,99,108,176,254,41,151,249,253,71,99,72,1,252,131,7,236,35,41,14,240,156,193,180,111,226,231,93,149,12,8,23,46,166,170,121,23,107,243,68,141,29,212,18,231,97,167,227,216,73,100,207,114,65,84,9,123,232,240,127,110,64,213,49,235,34,151,71,231,79,253,139,189,113,70,232,166,205,153,25,213,151],
        [211,26,231,213,10,61,127,242,143,173,201,15,9,241,106,113,193,123,252,131,241,201,246,114,58,187,63,184,83,145,191,157,178,153,92,1,229,223,106,106,140,219,52,186,187,44,212,225,209,7,134,56,70,83,202,80,191,66,128,69,246,207,241,73,81,217,100,168,202,52,26,138,232,107,143,41,207,198,192,210,133,219,43,3,254,248,215,202,104,20,212,239,136,39,8,183,59,205,2,61,250,98,1,31,125,156,79,97,34,100,135,210,9,167,46,143,157,76,168,160],
        [28,81,81,85,3,38,190,57,84,92,48,81,244,197,228,127,69,222,16,221,111,188,152,66,11,109,206,189,52,166,51,183,13,129,29,101,122,120,121,245,31,153,237,200,25,174,43,99,89,15,159,30,105,157,254,242,103,0,190,197,24,22,111,63,23,80,238,63,114,205,176,65,138,151,165,162,139,14,70,27,169,90,191,246,58,202,192,243,52,23,73,51,145,11,34,7,88,123,62,187,120,28,150,138,44,197,75,46,44,158,175,232,192,112,134,237,138,174,164,117],
        [31,127,115,145,240,225,78,100,19,138,25,226,55,52,179,66,241,207,12,105,192,33,126,236,195,252,27,231,119,105,121,86,173,97,96,231,117,165,225,26,93,100,43,198,187,7,184,205,221,136,190,19,93,108,130,190,53,239,78,77,204,215,203,76,110,145,152,128,98,214,105,217,214,34,114,11,55,10,7,194,196,134,154,103,239,25,124,16,41,68,106,136,222,143,156,45,37,27,247,240,193,231,252,71,61,16,97,81,219,177,33,185,218,241,32,8,101,254,141,118],
        [154,166,6,228,86,224,236,53,122,72,208,178,168,253,191,101,246,220,95,224,64,173,186,69,216,63,10,101,139,110,198,57,48,80,90,47,180,78,146,12,55,55,200,251,85,116,98,91,13,167,80,230,102,196,233,4,233,50,11,248,205,75,17,204,70,93,158,63,167,38,153,107,162,97,193,17,192,97,210,17,219,238,154,199,103,209,239,63,43,154,158,5,97,68,75,245,33,188,106,110,6,219,191,249,243,249,14,136,90,58,238,201,171,4,16,6,123,175,100,8]]
        "##;

        let abar: Vec<AnonAssetRecord> = serde_json::from_str(&abars).unwrap();
        let sender = KeyPair::noah_from_bytes(sender).unwrap();
        let memo: Vec<AxfrOwnerMemo> = serde_json::from_str(&memos).unwrap();
        let outputs = vec![(5, FEE_TYPE), (15, FEE_TYPE), (30, ASSET)];
        abar_to_abar(&abar, &sender, &memo, outputs);
    }

    #[test]
    fn abar_6in_6out_1asset_test2() {
        let note = r##"
{"body":{"inputs":["x_tSCz99BGX_pgG5G8_W3_vNHBhpRCepSdIZNKmQ4mQ=","jETvWgb6d-anM1PteOHb-_MKAp1O7Q88d4spuz88f2E=","PXRu70uIxjBUg7FopYt5_Q6KbxObLXGLbcVY1to3JCE=","a2VKMJ88IzBtfYokGsWDr3qgF_r56_AW1TEZ5X8DM2s=","YjC2VeLA-a53H7cZNBC8x2zjRvqgcil1t09NwUwsQlc=","Kx8MFBRGEFxZs2s4j3fTTo4D12fqoI41zscC_TUZ60o="],"outputs":[{"commitment":"uiCS913hFSLrtABtcGxKsU2ZQHEpGoU02KuX8rprP0A="},{"commitment":"PDqFguV3msNZpB6Ma7bT1hhdFXXyNjztvU9AS3my1hU="},{"commitment":"YZN8d_OH8Xiwf-FOw87_NtiCrWd_umIE2uSo-D_RHQI="},{"commitment":"FjPhzZW986i7EOCSeNbaNZU9r03dYa3eaNTvVuLuxxI="},{"commitment":"tCu1RTyg922VtH3DbhZRhv5sRoSStZ4BwHEcA3syEWs="},{"commitment":"lM6y1AjiWgC46cWW0zCuEdlzmIr-heWKfrEfpMkoFlc="}],"merkle_root":"5W-BVvKYCkVT7tyJvu4KlhGSYdMa30DY3PurlyKglR0=","merkle_root_version":1,"fee":23,"owner_memos":[[253,61,85,84,89,41,30,221,101,223,195,74,245,35,253,252,105,174,113,234,169,123,66,94,45,80,133,43,71,240,18,132,236,80,142,183,183,133,65,110,251,56,252,56,92,88,66,50,17,78,140,92,231,100,251,177,168,62,66,163,46,138,106,4,115,24,175,117,163,167,143,47,113,85,24,109,113,141,35,132,109,173,234,27,122,180,39,227,83,112,112,105,114,37,222,248,236,61,188,38,91,9,106,87,0,184,138,211,114,63,161,22,68,158,1,244,61,7,79,95],[30,4,233,10,30,13,229,221,42,83,90,216,192,105,203,174,147,9,217,243,106,16,232,187,94,9,238,90,97,17,182,25,29,133,171,85,22,213,79,141,51,196,29,226,177,161,211,26,59,174,248,138,226,239,218,15,111,90,171,51,71,172,93,88,216,22,198,139,229,103,44,176,182,255,20,251,224,39,178,254,6,253,241,55,76,29,125,104,110,192,187,8,220,97,227,115,132,97,69,155,41,153,80,169,137,147,223,193,167,76,103,234,75,139,71,233,0,59,252,208],[37,65,87,63,9,54,177,111,26,10,159,40,126,246,107,2,58,117,135,83,175,218,151,213,52,184,251,40,200,56,176,117,135,184,82,98,201,71,41,13,75,145,92,147,147,161,244,117,104,40,241,249,87,243,65,170,173,122,53,153,136,136,243,11,99,154,192,180,183,57,167,184,215,130,202,159,88,30,27,169,140,172,122,171,98,5,240,29,145,126,189,36,91,21,235,98,63,227,128,88,113,242,88,74,207,47,12,63,116,210,19,189,238,159,196,98,200,184,180,222],[251,249,79,168,148,126,20,28,210,210,86,166,82,60,112,116,112,79,192,227,157,90,44,153,57,121,39,58,129,84,98,130,137,121,122,160,161,25,151,239,129,232,204,32,57,247,222,135,160,120,67,29,17,23,235,50,48,113,147,68,10,76,149,42,144,143,24,108,244,105,166,168,30,154,120,140,8,202,9,109,154,105,5,21,144,217,49,17,216,102,116,219,115,63,96,151,6,223,4,198,45,248,17,254,15,59,37,235,156,93,242,80,125,166,29,92,209,61,73,111],[247,51,12,147,103,128,47,204,211,102,108,55,189,91,169,183,193,50,249,181,80,131,138,63,196,110,186,184,55,255,245,92,255,160,254,49,224,109,8,55,103,13,141,85,102,48,142,43,35,210,1,213,153,243,224,236,157,217,125,61,196,208,24,91,103,9,86,165,134,216,138,206,253,36,115,50,191,121,14,193,13,49,187,66,183,73,67,84,235,63,76,133,241,123,180,93,54,183,233,8,134,245,171,111,23,145,29,54,159,170,148,231,84,253,192,92,57,27,174,195],[145,107,13,95,227,225,189,216,10,125,109,148,198,117,225,134,102,231,140,164,137,20,80,198,62,45,213,79,0,190,248,214,0,179,70,117,243,103,129,68,185,117,46,123,79,228,23,232,169,86,103,185,2,207,41,219,90,185,61,219,255,176,183,105,174,126,232,231,219,87,53,40,70,252,244,144,231,113,212,163,193,149,73,23,88,129,43,238,205,45,84,164,34,202,98,138,11,74,12,22,189,187,110,19,78,192,40,170,141,120,201,218,69,195,59,120,249,255,235,84,216]]},"proof":{"cm_w_vec":["tAxVRNgHkAOzyw0sna2GHPdl5S5RCXgMbOiYdsoKTm-7Pl1z_ydcnWydtgc4fzel","if-7gh-eVKmSH5jBP5R8t0EJs0zeyiJcmcJRhOpCg5IiJRdssd8AgO_PQjdrKsPo","iDC5VsKbGUmfA6BlCdma1TjmUz-MpT0JnKgujjSeyQmwdy4OzdTxeNFjE5a-sCgr","sYaS9x2BvFhNrU6ALCmmNRq8wCfJSYfI1IN7HdAonZmD3PqVGuW7MMmy5Q-y2p4Y","tvC_i05PcoEXX50sItbz82zbmsP7B6RmUgxLWd7vLfTDw_KgH3chHspK1mXt-bkt"],"cm_t_vec":["pajRlynnWPUJjw-WQtyX4WTwK0_SGrOfdTgH_16-4TB7NBKL5Qk5FDHMGClOYg0v","tCqmnNvsPvmKLFNdIA9496UkVlwrszfrXu6UEWQiCBGXKUtwGlZDC7AQ6yAT_Ehn","k5ngXuvPUCdEjuFuTSQYjosqF65bdLeqeWGzfnBuRXAe8IYi6Z7e-lOMAN3AUvZx","uE3YalN4V9WhsVqe4kE-Pi7By2SdhiA6f37TnK0sDZfcPLmO2EDylknRExKRERdt","sxjgXx4byuhPGorGqSKdURdgYYRFS8pZ8zowM6ChUWgdfK8RdpUuZyfBEYvC6KPo"],"cm_z":"tblf46LRJsdV4ZFCAG_QloJ3DkrijLwaSA9E7n3ZjuUO7AjeUBiq97vW2Qk22A--","prk_3_poly_eval_zeta":"oa1--050HL_cjzTl6IAWVwWG6FSn0j6Dczhg09JLhiU=","prk_4_poly_eval_zeta":"GF8Ok_Ob2Ok6MwW6gwt3yaLH20QBgSmTt5PHH0oVZnI=","w_polys_eval_zeta":["WWPdgfG3JWjLoMcfTaFECmuZLzxe_t6_E4Zw7n6xLmY=","djDa2OvQNIAw1CEIpwERpBL1k9lyncNPzMKYCUI662U=","7uggIWlbyxoEzW3fJXk0bqNWIzk9Ny7z8gstRjtaID0=","8nMiFbsdiWoUUrPgB2j0JsNyQVUXTyj25voEWkH7Fjg=","McTUAPQJNVDsVpXlrSAAhQqNzHYKsmrvOV3Po0CVLnM="],"w_polys_eval_zeta_omega":["qI2Dpc2bxg9kYOxho_ad02P9C8DX4P-397QRPsyxlEE=","v5nief1xTmP_BEN_X8MNOZdCH-A-Qdq2ilE4Jtpf6Ao=","oIg8UHj5dmJwhrrHhw4A2J8BBMt3eH9hcHVrF_X_pig="],"z_eval_zeta_omega":"g1DeRwUKCf-XpRmqnUb4F97IRGpr8XPdHIFpyz-eBFs=","s_polys_eval_zeta":["KY8Wevxl_sprXkuZWXOoAkL5bsB78yUdfzGseigV5z4=","Y_HF3YxogScNe_kynUPdJ_rOinknFLSM_TdeHVmAfnM=","SYqyKJmONrqteN0-qvgd8ejsLH153A2JW7yPSBwNGR0=","KRQM3jN_Z2XTexizqU9k06SOsAfPOS5zHH3L1SkyKHM="],"opening_witness_zeta":"rxaon_9GwuNcDGHKw7iHD5zCWd7XYo_elUQTVzpyJFlJD044FIY5MjYCHUFrcKw2","opening_witness_zeta_omega":"lwOb_QZWfGLdrCKrx0LgQ3Qt-ucLolm14hWMFXLYZT5BP1d8OwrzJjNQmXYicFWb"},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"bYWuyQZghZq1ab0Nv3Al6njC9Try_wVZXQaA8P2CPAU=","randomizers":["xiomjSuXL1INbQM1g9bZS04pjjJwJxocTFl74EaIqDsA","1eUncNMV_u4k4obr7RPOGeTtznFYBsztWuIsz-P10hyA","9-QxSQ7FL35RxmL00pgObilAKTYZiYLs4ZYIEsvWexWA"],"response_scalars":[["z1tqxneAbCRsF7ZpYAs0A8ZYf_Lii8ypbVfy_cTcKwQ=","95gA-8UEqhaM3ePX_18-1L7ldqJXuhS-7WlRkvAV0FU="],["9zqdqdoFgScmtYj0nafc6rcl3DAER8-XbySzMCu_HQM=","Rhxg4wP-I5LL5s5u-uFX1TNoksPNghXlEDzokJ8NohA="],["MhZWdC6L7-lqdPFiKhOSZUXTrmvAOZXqxNLYz2X6en4=","wcaJWbE0HZ1b2gwM87l_AV5kgEdAoF6trdfytNVmZF0="]],"params_phantom":null},"scalar_mul_commitments":["IHOs88xhOVI5BOpINqKPnDBYTNRZ5vG9qybpStimJyMA","Nb3Zs9euyWO7SJGMtZOJuI8fy1vuNE6hwXe3UQ4M00sA","6-z-qiqOl-kmdG9rnoqQp1X2-DHtopu4VJtJdgHlEHIA"],"scalar_mul_proof":"Ek4MDUY0fr3mS4krFB6TibkXR8RV-SwSGQU_RM3uiRmAPvRBt4xqLs68pbh0F0YSuTMdbEv4Xe4CADkcV0dV4HqALeiObZN0kl_lZttlYIeISUl22M-uYGovdpP1qUhs11aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAfbmRAip8YMdY8_tDT8YEChSlLLH9jffownphoTIEcDMAHC5DUR0PjsRPZxAdyz9SnwxAo7uBdYB0q1AeGCYvN3CAfoYqnhvw2Tca-6-3CQ7b-5UxHYhgp03hdjE7Dl2R82AAdRpgt9FzQBc1NdsrGAAxP68yIXLjDEuyeeETUXFYgF6ANCRddLCr-VCcM9yHmcswlIaXydhEh9NMq5zOViKb8z0Ato6eO8DvvwFyijMk2F7_H2a-9RVUXWTJZd8uYWEU6QnfOZ4bcC2gyoicOs74klogAfNL7niFJh30tP48cWwWYW1oHeN4sCVAoft4OjPn_ZL4Q5W1oDUZdfAuRdbzUhpRCwAAAAAAAABQiUgBREMzwK9svahRrDV903TLRuC8vTSlpZ1mmnoSMQAmzAWM96b1twgpD1gn5_fExknkoshTirE9fDW7xAkUJgAEQr_VyzWY-lgQCbRKKUE_IqrYyyIJdXCB_W_Fg8pOKwDrzWyZ8Kq-NLvAWy6Cu7cFN3vNDtcW5Fv5p4Twu5KAMQAq9VHUGFPqe3u0npymqukK_r1YeB4g3Dfc8z0Y3t9yXICOYI-Yt_C3jaCCvcN5xOQkGDadabdR_9r8qCjQ_ljtPIBdjwpJv5XzZ8tpERocq4A0wrCjRX_1VUt3zrCoG_OxXYDcVULm8Pc-KxuLWDXIU-JJGEJ5dDvXa5kjpREpXTKoXIChGnDwxJ5we2Qldg4dhhHofJMgraGMuCKupub8BH5UbYDNvuyFnh_l1asAmt8wtgTF7E4KPc1aJ2qlczH3WdKVVAAtKAxLN7Ybtb2QIyl35RCbitHOrG6nq9DusvY2xWlhBAALAAAAAAAAADmo8ngjQjOPFuQ99yHwI-fIuiARPdDZmhY4PGyklKFGgGvXbjbVXX8vr-oLD2gnDBYB4Fa153GDif4-O9VwIC0AAA0MwrPKVYMbNrtl0ugqnxMrHoxLO4Z6TZDNgC1gvFMggOXA49Qoe6OvBhBdqAoQYJfbgJBZMVpe7nDEcO537W94ACr_X59QKoJsjQPCQDCGaLfeEYNPrALbN9doUtyY0YokgCUZ3B3_zXv1HBEefBLO_FKrEYPKyfmcqUCc7F4o1OZigMuHcWHNxijWwYVsUpLMSIj2HkSiSUoZKOYs03uYJuA7gDusp0Nq7mnN8QsAvI0EPkehV1VxlSgn6bjUZ_kTKT8vgDLKHH7HwEY_thHy3X8_O4JdzNZOXjUMNkO5UpWPTEdVABF7z8mehsHhXzyJEBxze4oHHlpciQaY10aMDcJ_h3F4AGqOA3zpkZDFjeD1ggVPkpH1RDQlpnAXONJM9ZJwZoUhgJ7iuxbtkQ0rOrFnOln6EhHsRwtyieD7D4SNu6CfRYkvZqw41sVP_58L9rQb0SldO5TJhxL6T_OMuYKKYtLctzw="}}}
        "##;

        let note: AXfrNote = serde_json::from_str(&note).unwrap();
        let verifier_params = VerifierParams::load_abar_to_abar(6, 6).unwrap();
        let hash = random_hasher([
            37, 41, 106, 44, 72, 19, 255, 171, 127, 181, 198, 56, 77, 3, 238, 59, 13, 22, 190, 62,
            57, 65, 217, 83, 111, 232, 23, 186, 18, 76, 154, 57,
        ]);
        assert!(verify_anon_xfr_note(
            &verifier_params,
            &note,
            &note.body.merkle_root,
            hash.clone()
        )
        .is_ok());
    }

    #[test]
    fn abar_8in_3out_2asset_test2() {
        let note = r##"
{"body":{"inputs":["0u_mlxThLmAZj-R01vrUEi7VMjvpTIF8DVKJOop5IWQ=","uCQHiHBBF5yg8WWvKotG9vuaNd-F3J_UEv-mwZIuEhE=","UgFd3tDwK6O2F9_E-BICh8YtQfLRVT5mbHHlBbp4ARU=","ECehuQWYB7QdAEHYcF3AmSrFoEZqwKoMCnDlTqkg9Tc=","kVOPKiwQuYcaezdzNvKS2Zj9dpj4TOajI6D9zV3Ri2g=","gBOocoPFaR3_5rf0TX70p1CaU2CicTPZ_k6X2U0umUQ=","Argx2I9STMUqhYLLIUBU10d5xOkN-Wvy3oe8vMBg-Wk=","IhoqiN8IEzS2tRgGXD9xg3HbsNmN7ezItVwmCOslSHA="],"outputs":[{"commitment":"zxr5ulwxL6umHrusVC2fmX9GGLLG2nG2CijyTTt9MjI="},{"commitment":"yixQuIj2OIsOWmGCQcIbGmFQjuqnzc0YBp67uSCaRUY="},{"commitment":"rAASMqj6rCo4mltAjVdHsbPErbPyQDGThnXaLywh0E4="}],"merkle_root":"wt_QYln859qs1fpKyOGkbiTKiCMyNAxGpDke5RbyQVc=","merkle_root_version":1,"fee":19,"owner_memos":[[55,240,25,162,102,90,231,254,198,200,154,12,186,250,162,104,110,161,159,245,240,16,107,244,133,142,105,127,146,59,34,40,113,199,213,35,177,111,220,189,32,244,194,252,104,177,36,164,151,189,110,77,167,96,53,173,52,244,185,244,34,77,34,231,91,219,177,173,40,94,201,18,21,168,167,107,65,135,56,238,70,22,106,58,227,126,68,23,193,171,182,75,68,226,3,203,59,178,191,238,57,61,34,151,92,237,212,62,114,42,26,169,145,161,177,53,252,79,42,228],[201,142,18,44,22,225,99,89,217,219,229,234,9,95,247,212,23,118,171,53,128,158,123,250,38,71,245,244,0,235,11,17,222,35,67,233,72,86,4,172,104,31,253,134,67,75,113,36,80,41,64,146,205,155,236,210,101,186,170,177,181,105,156,74,67,66,109,1,43,111,194,81,40,76,85,99,136,63,229,74,200,70,40,106,141,87,99,55,206,176,72,114,173,49,216,147,81,94,70,39,43,149,174,202,214,177,171,215,92,184,214,123,190,137,249,201,102,138,130,48],[225,176,5,26,43,131,70,100,6,253,7,204,86,47,44,18,95,20,221,221,143,236,58,54,79,5,191,152,154,1,149,219,0,208,114,23,112,111,67,4,5,21,36,78,42,90,127,179,60,200,98,150,237,49,106,218,135,72,83,212,47,173,166,134,19,211,152,32,101,116,149,198,97,106,74,57,47,196,26,185,66,195,219,214,105,166,231,132,152,94,161,105,51,107,176,14,86,86,34,5,204,230,251,194,243,146,44,34,252,157,64,18,80,152,38,65,27,109,3,118,165]]},"proof":{"cm_w_vec":["jooURKARYkysucYzQ-NFHieiivvatOBRQODe7oBIW3mjMfju1BYcmKg6vvs72JtE","uSNZA6eicChGNJi286mhpEmz8UfW7RYZi7DZDPdfxWWnippgg7WwrqosxMr4Rl8L","pk0-2QGEwkqwDoS3KCywKPouoW9-p78_mT9--MDfr4WsOK3dYPUyoQkX458rNgV-","jfJ7bD9Q4Ed8x9N1xIGdy_V_ATklLAF0hWhUDl1UXEOH3oCuJ3qNxJYjsKJmA46C","hKNkLQXZ8uFNvBLl0wALGUDiZgIdPMADSNiQrTE2wQkYPpmC3FjCJ0FX9KyRER7P"],"cm_t_vec":["l4qzaLSJQRIW-4OjdB8IXn2DrnqTV7C5EFoRnkc47CIJ64IyTaH4DmhTFwDXGgBt","lt4G-yrflDt29xCkn09dbeFUzEekD5RiP63ZTduUB5ufkkCd84TRB7lGu-yWqzIq","lh6NX-VXhXfLNkTC-IDgNu54oxKsFGh21tfVa2N8q3_5qVthfYmCnchzPYoaNZXv","q8DcteZb3_YEMeMw6Zr0fvlw2UUk-_au9Bxto570nA2Jc5EKRFC181iZb9QldrG_","tGgwqttQ6rqCcYQCBHdvsXJBm4a8zgi1OtDEISPz1CV7vYYb_xGOBZ8Fm7BYlQtz"],"cm_z":"rGs_YnQWKNBYWuokdpuq_yYMtQBiIR7wzROMzvI4qEU6gTaM0Lnyuqdd_bC5G2kr","prk_3_poly_eval_zeta":"xyePkxuUDWi488CADosyYY6hGNHK09NUbjk6niae9EU=","prk_4_poly_eval_zeta":"SXR2d5-wooDm4ZWFmJuCC3wQnp6dpr7uCtQ2zoaIH1o=","w_polys_eval_zeta":["-pvrTjB9w4S5LEz67tqq-9eIdtqxvhVfpQ1JAVmaDlo=","u0sHAzMLFOHytrMzMAupq9Od214rug5KIbb_v4ytwGs=","p0iyeLvltPSYVWZeBTNOl94k1guE_FHAjRhPyBbLqEs=","V_a87J_OKhJiRMCPtBGFAEr3RWDeWucuwN9uAINRbiA=","d0zKvxrent1TvceQ-UCM28DsRdwCUCJtYC7XU24mZzI="],"w_polys_eval_zeta_omega":["4AvNZLxkOVYAOkfytwv3UxsJaDt-2sd5_3eE5sl08D4=","B_PoJmjPjcPJIglCP4Ab1rE_gmwrzUEWCKAptPO6fQ4=","nzmRSaCXZ7RNAmbYwjnMCBQbc61gS69UHn4JvqM4K1E="],"z_eval_zeta_omega":"LpGABJnDG4UwLzTEBco0j2gcAzSHPqLogC3aVHQlXQA=","s_polys_eval_zeta":["UU_jErmdFCYI1AgUjg8F-mgtA_PTzkY3aeaNlJRReRc=","M7m6_1uF2QxmQv5cuEb9NaZ4NUvOBr4ftvp7yCCznlU=","lv51-Hlis0sbehbN03I2tr4hiJ36dguRtqS2BacBgU4=","eyLd2-7iBSbolB12R-KcQGFRVSvOnvYSbH-35ATAVW8="],"opening_witness_zeta":"iaI5JMla45uYI7RIBXt_jkHJwzeEPsYNTqpdJ8g9IWh4goiaXwZS31qUdUaoU3Xr","opening_witness_zeta_omega":"tdm_4V53yw0XuE42Nj1oekqdVOuDxLvMvq8_KULrbmZose3MY4d1Gy3MpBsFihcr"},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"V0X8e6ilTeVnbAj462vxC62FqojJHao3v207Vu1KKEg=","randomizers":["-FuOxdEF-KXymXmh148T1tweCBu7wBeci4nCOJ9OUkMA","QSqTyvCwXxHFesM-ElzODKlmN6hn9eqwDyr-bsxHanmA","3cD9pH3_2vxXNBHZtxfd-UsLEAqUa_3dih7a4DlZQCMA"],"response_scalars":[["I4lm5po4Rij2gHuXT9lN7Tza_3dbaagBaFDMURYUJT0=","v3eNXiAt9bTBPDrHBK7dugfsktWvPeKgGS0kXvHEcU8="],["Z0cK6zgPKJYlXCZLo1OFWrIkkgd2KFOiZrxm6yR1zRc=","tm4W4QXqRN3CwUaSRepyOSUVgXoFG3c0Vl-PaX1_D3M="],["_qEflRxh7EzlzqJoQhZgfoIL-9Q8C7WZ4_5ZKNmkzHM=","Oh5CY_xo2e2WpJmATnog_H5fQ4DpXpCPAS9f7bNALxQ="]],"params_phantom":null},"scalar_mul_commitments":["auO6Edhlrdrp2mAhlkvB_ywnx2ukqueSnzlQ4sXLSHGA","Yyk5eTX-qAGHDJIiPHrhkjAxVyGXw5sOvPLcMXlPn3MA","fnVqfSTW1BQkdQeBuCDgOvW_s7NZd7hHrgFH_i8oXz-A"],"scalar_mul_proof":"nldQmJ4UFQTgASSXC-711Z1V9ydDsmHEgDfuIvhnBzsAFwll_YnG5DWK1xpJHIzdBMocDXn8YVfJ_PP6KGfxMB8AnubYgAocTUDIK-ldxm8ifcodyB1DLoSQO49_J50y33sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAdtU-xm34-30Rru_-1iaZinklxZa2mxQ8TMwNtOHS9X0AShw3XcU-H1ykrm8ughFPMFNgkKAP3wca2_WZGz5SU1UApgIK6JBX0Ap6hZQlDpb9iUPIrk8hy6v7Xa2MMcz3bkmArea3ZpI8xfDtZa_j0B_aEPxvp_GBxnsRBinMIr0gfkEA8wCNAWo29V0tAvtvlUoOFW1XTX7zNe0J5VUVO7pRG0MAg5h73COTKGJGq5IHPEceIBquwCZjSdaG3NOcW5Tbq3uAC9z7LNxLtxYRnNHlLxaRD3CBhG8Cu1TMpZErC1pic5MGCzzMjswWd_jMzrMQRlChpCRJ7wVPNE_qxsLGCiJPCwAAAAAAAAA5ONUpWkP85oKnC1tkP4Q0ggMX_HGu1wTITNNDoGO7aQCxV-bIo4Y3waI9EuTVLWLzp3Wwi2fXVVfCxqaoTgJZZwAZwuDpfJmUBirUckmmZ6XHMhrotrO_jg9r5sHCja2iYAAhrvXHM6CmVGLeJlDx8l-KQZKugDo3m0iNmv66O4lLZYDL2Ejvg-SGfwnPeYySrXW5SGJAQC3Z3dzPlskkRs-xCQBS42EjFY_TkVxrN9dQJdtpa0K7fNI_TwIr32wXLVMmDgCKyUHOXX0PUaDcibiBuMiAr5OY5A9L4eX8F_afwwgjHoC9f1YOmpZ7hrq2ZXFY9emwfI5aB--zsPu2bXBOa32Yf4Bzize_3EPqa5zSZuapZgqzMfXp0qcLrYN5ZcNV7-mpNgDkaULl4aQjI17M92Nds4rfaqVheGZ_BB6BYsfzIDH1DIAXFQ-JqH3HiAIfmeDMx08GRYMRBlDi-0dPjT7Tn01jFoALAAAAAAAAAFy6pmYgr_CmcJqfin9Dqy0ahInfVr2V_KvBqL2QgE1EgGOkH8JWBqixDDyCCya4Oxg0hLcxpOlGPa6czDaHD6EKgA1jvKI5knPh6whe_7MlTRjFXuLFXk01AeHk8J5EC34agJfPsLLOvxZR8aTIl7nw5XHg3optEWi3VFNHJpHcZgoEgDG2w8GPv-QMlm4ZWMS2AuJNA6_kA3Vr45EWu61A0lxwgJKKPqtckAuIw6Fzxijx5XQgV79z1qWfj2l99SZJ-IV1gKDE19dhJPRW0uznflyBs8lu0rfw5kD2OI5s97Y67j5qAFUfX4ZWEwW7Q5_ZL_ywLtAgMr6-kE4bWT7JiZ07_mMWgH-QUbfrLaVzcAhl56zCGttkXjLk1xmLE0vMyudjGq5hgD87wc7GIvrR_Ruz8xYL94xA4Hy7X_JAJC7V0jKclOpFgN1y5KYlJAt9KzEfAVkDWvWL39iW8O3zmXcfgMEno3dTACN_GsLMHw27n1PAeOQrcv9HHs58tmvhGxRfEIcUK8JClMEPLPKJz1Yy_DF6zboRC8yxl1bjzle17s9kdbSVSwE="}}}
        "##;

        let note: AXfrNote = serde_json::from_str(&note).unwrap();
        let verifier_params = VerifierParams::load_abar_to_abar(8, 3).unwrap();
        let hash = random_hasher([
            252, 249, 49, 82, 187, 135, 100, 24, 119, 27, 185, 206, 245, 67, 28, 9, 129, 119, 6,
            21, 110, 193, 122, 238, 209, 126, 203, 149, 73, 135, 213, 177,
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
        let params = ProverParams::gen_abar_to_abar(abars.len(), outputs.len(), None).unwrap();
        let verifier_params =
            VerifierParams::load_abar_to_abar(abars.len(), outputs.len()).unwrap();

        let receivers: Vec<KeyPair> = (0..outputs.len())
            .map(|_| {
                if prng.gen() {
                    KeyPair::generate_secp256k1(&mut prng)
                } else {
                    KeyPair::generate_ed25519(&mut prng)
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
