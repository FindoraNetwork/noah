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
        let params = ProverParams::ar_to_abar_params().unwrap();
        let verify_params = VerifierParams::ar_to_abar_params().unwrap();
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
        {
            "body": {
                "input": {
                    "amount": {
                        "NonConfidential": "10"
                    },
                    "asset_type": {
                        "NonConfidential": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
                    },
                    "public_key": "AQN9V2PmvLeMLGw3idnmZzxb1cE3MwVLXIjBlTjQBmskWw=="
                },
                "output": {
                    "commitment": "pCV9tyOx2inpLntAJ_YZk0Kat-EeQQvoEI9eMfIShE0="
                },
                "proof": {
                    "cm_w_vec": ["tL0rtCP7XZodtJdIPHSO7WOt50emNHBdHJECgWYIxyb_KfaX-hMgc7sNDik3unFx", "ueydMeoTWVl8itPQPC8mqxUFo-6fF5Qys2Moz08zTOlOGiQ71_BXOPbjbCRV38XQ", "lvju4DBZ9CJsvoXXaWaF9AHDX2mxByo-k1hn7QFP6x4Sy3SjDhuiv6qrtkw5N5J6", "sbPz_nHoFvpst3FaMP7q3biY01mcKAzWT2V4-jKQudeciLNrTfV_f5NRnBrm_DTn", "q7dBF3qwbz2m7HVUt9FPsiqsXpI_waB-djEH1y3yzpvm3Z0OBdeAbdunK-KAssNY"],
                    "cm_t_vec": ["qjQ-yXxjbw862K2DOeDem5vurx76wGyuUhPq2vBp92FRMeP-FgaZR8npQZMKhT1n", "oZgf-q1A9S7hNkDEtfjDg58anel8LS7gi93ROzuNVXD7MgkDDnR6rOaQDDGgrNjW", "kbogwjC27_aI7VXPiwL5s2qlqMBq_4_UyXMCHkcNyS5jGCo6o0uuhY-uFzBLW2-H", "lDaxg2SOb6G-GD06cm6u_LlE8Rfju_Peg5gUDscldfjualrESvllnI59rvR0cb1j", "p3UTK57bAIcs8x4mj4F2AQaQ5lbPc1vgw9T74Cdt38VdryiajLbMVBfNP0TbDAO1"],
                    "cm_z": "sBBPt4cHhYCvZxwgeaBuIcZDdNcIPEn5_CC6ByoX83GR2e62Q8xwsLLwr47LiSp1",
                    "prk_3_poly_eval_zeta": "y4z2RSADjrffE31Ul0--_I9hPyej8Sjh-TBUPNmwaEA=",
                    "prk_4_poly_eval_zeta": "9OmwbxMFgiKXfDJGI88RYVa0-ECEjcDkUIhwEbMRHS4=",
                    "w_polys_eval_zeta": ["3q3ksXX2gytGty1SAwfMSqmqWa2X5qCv3Otwwz5cuGk=", "KaohXMlEqeYTNpuZlQEABmKti6g6rZxOFScaEK7kaAM=", "d4kLgdXbCDuof0dmLl6J8C7eOw2Moweg-6Gm4TZ322A=", "UiXrDHhp87pKH7n5OFpIzT8wBxhk9jc9wSAa6E9CXiI=", "NjjIqfE14LSkLXeiBKU0D7ZORbXWLPqE0dkd4hVqjE4="],
                    "w_polys_eval_zeta_omega": ["7Lzq_Bi4wBSEg2sNsPYbmqOZAwSrSToGf3g3Ehl9exw=", "_7jsb3au2fh_4vvkKD-YiAQ35SmeYCgCBsbX8ZFOQEE=", "S9ao2vC7meAeecR0hpOCaOUyk9C9V4oHtihOd3buC2A="],
                    "z_eval_zeta_omega": "JBohoEBTyd2p7n0KSIq_UJNU7vFpOdM5D3YJbkVlRlM=",
                    "s_polys_eval_zeta": ["PFbH8iqhbA-oISjVK1KhCAnMeiVG2--6gWFwIYHaJwU=", "RPMhjxZTelv4gvA_vId79SCjHbZQDEnRZlpsKYnziBo=", "lK3xo_I99LU6nhk01LkkDNkSSlfYr5b7dZj9FkuivGg=", "jOC1ctEkKnMVUMf9TGmWfT28QGpY0bUu_rxJKZvJ6ww="],
                    "opening_witness_zeta": "pTSxg2vxrmGVQWL1cnU5zFlfLtmi8aOnV89qFXkdQyFOVrxV8Df4N7NX06WPe7JU",
                    "opening_witness_zeta_omega": "mIFFF7ab2erow9mVAPYkgdtNQ5uGu-QLu8lRbtQyZfPXKchZv2lOPxvYhBVUCnrF"
                },
                "memo": [227, 44, 143, 61, 115, 36, 20, 87, 162, 134, 235, 61, 0, 117, 26, 27, 143, 96, 107, 71, 230, 155, 153, 72, 113, 59, 4, 173, 255, 87, 210, 128, 0, 159, 201, 249, 2, 88, 38, 72, 153, 35, 25, 233, 19, 204, 248, 124, 129, 197, 191, 147, 128, 90, 159, 58, 91, 42, 221, 121, 66, 175, 234, 225, 211, 255, 70, 175, 29, 141, 253, 6, 54, 85, 230, 228, 58, 194, 59, 245, 45, 163, 9, 215, 188, 98, 249, 172, 255, 91, 12, 43, 14, 221, 73, 93, 56, 54, 250, 112, 95, 106, 43, 101, 82, 249, 85, 94, 199, 244, 224, 206, 87, 161, 77, 107, 149, 172, 36, 133, 26]
            },
            "signature": "AVW4_GUgVATa8XSwUj1rFBX-bYDSs2EQiKFcNhDyb3QGIdr62fUkROmW6XoJ0L2lKseVuE1DANyEdU826ne6wFMB"
        }
        "##;

        let note: ArToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::ar_to_abar_params().unwrap();
        assert!(verify_ar_to_abar_note(&verify_params, &note).is_ok());
    }

    #[test]
    fn ar_to_abar_ed25519_test2() {
        let note = r##"
        {
            "body": {
                "input": {
                    "amount": {
                        "NonConfidential": "10"
                    },
                    "asset_type": {
                        "NonConfidential": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
                    },
                    "public_key": "QsRwq_sBCtAk9kc-r5FJtvkZ7fSTy66e3CApt3kJFbU="
                },
                "output": {
                    "commitment": "b6whqYlm8OQRAvIm07P3eR_UCr69w_AxKfqhgytchDc="
                },
                "proof": {
                    "cm_w_vec": ["sPiKUveTNi4_BNyKZfzmC157d2KHr8aIb1FYjQnxr1FCteOz2VP5CDCIz50v7_an", "pG2UXEs5puAOL5f2fQyjqZCl11h--XL1Wu1F6KoSUysFZynyNg4QNu2hu9bYGueR", "rK6_9kzctg1jJEbo6X397VGoULwHLiEnOvrBPZdGDHMtqFABpjMcdexbB66zmTfO", "goyM82zy2uP6_bcDEIc0m8R73CDiUWrMYeWClWRZhEg5sv3CB1OoMpt8A5WLLqpN", "jH508ofb9-Vb5ql10nW2qIH8SPnrRPAHJ3d00Uv8cUbmK634FK_1k5AXza5lqTIO"],
                    "cm_t_vec": ["gAarpjx7xT_gePzIoO6iK9iXSOzW24aJ06p226RArmgtrlxx7DGd5fagdK6j0r2a", "iTHQSEGVUixkgwUQpKw_ibr6x7DESvT1GIPB-jruackR2jTuD8en48B729pqQYgF", "s7zwB7EIH4PSxxcpwlyQ6Q6NMuYiLDXXnCoOi_84yJPzDz_cTFKLBsbQIgtpujJW", "qkxhj-M3TzVm-n3nhTy7oQHLof4X_csvGac3M2lw9fLwFoAC2LT5qF6bk3XgEJQi", "jykQPigvEqIUsox8h8IiOmqjGe69sYCNq7GptNETSiMgVc-60bhkfo3UQ6svk_WL"],
                    "cm_z": "kx95Urs0Ezln6OUn09oMx9bHvIHpaYQiUhWpfrAytzXWPvcxBrD8CxLbICT_CsV0",
                    "prk_3_poly_eval_zeta": "RzXWegoa3YNIgGz4_cL0UMRUn5bYJBU7g07SjPjxaUo=",
                    "prk_4_poly_eval_zeta": "ut0Ky13S2iF6EURlDabj__4mh3Qz0xI8wqLzD5JeYRs=",
                    "w_polys_eval_zeta": ["iyW2Q9UrXD_dUJ4iEFqgM5CojXCGccwmwylThd2R9lg=", "z0XCuRczDeEJ3hruPTNQbFLooWX8TnxgR4PJf6MXFSY=", "ZsImDhSGipBvBqRBD_m-qzIEFXUipmYbff5lohPjB1U=", "gD08ILIdEddptK7depvxrj6Ws07eAS3E5YsUOKqs9xc=", "MuUcq7JdFKaDZP-JxC81eTxek8mG8377JbVmjFYC8mw="],
                    "w_polys_eval_zeta_omega": ["S2-YK92qWWhqpcb0_IT7N8Qk2yg6jgAvDv2tSiecEW8=", "eOk2O0HyOcLbXgl_7d81cA-c1bfBpdM9xtnC6s1HiWI=", "L9CCjfT2XUcBmXanhenlF5O6CAhFmfdExBZiLy8J4h4="],
                    "z_eval_zeta_omega": "C7cSnfazSk4FB9_YoBup_litViNvNF9cTtzlw8Mx7kA=",
                    "s_polys_eval_zeta": ["49KbArOYqVf_pFw6XgNHWEyPBKUiXp25SAqDzHD7xiE=", "ClQSVCCAs37Nk86DRdepVtxKlIU56cnRn_QAMVw_9TU=", "fARNNFoJiHc_KZQFasy1heLQ27yIG3c9auijTrPmklo=", "SdGHVCykqbVQpeF5wy2-YJlLZI4NFXZgKlm0FcZBYQc="],
                    "opening_witness_zeta": "gzzA0lWhwdpX513QL20UfHr8R_TLD8AOcviHCpPWMRAHcWKgIsr_4P1PlF5yVv7l",
                    "opening_witness_zeta_omega": "pKFHqWixylEiu--YPqj2qcGeUAxuUUwKhpKOu9a0xu3i5S2z5cpypDUY-kbVokAt"
                },
                "memo": [159, 51, 44, 163, 125, 159, 178, 73, 97, 146, 26, 246, 14, 158, 79, 18, 100, 53, 174, 176, 200, 252, 204, 102, 175, 239, 165, 114, 36, 118, 72, 94, 17, 211, 55, 198, 193, 60, 98, 21, 141, 91, 218, 129, 237, 129, 250, 72, 50, 135, 97, 150, 148, 166, 81, 137, 54, 108, 210, 220, 7, 18, 131, 50, 84, 211, 185, 68, 83, 103, 103, 126, 8, 229, 205, 64, 105, 67, 104, 46, 191, 152, 98, 71, 157, 221, 43, 229, 247, 133, 50, 191, 95, 205, 5, 175, 152, 179, 166, 188, 79, 179, 129, 8]
            },
            "signature": "AGDcMxd0-o_oR1haRO4s6xPtIwdaK_35gwRwpI5AyyTrklQ8SPRRMZSFSb2FL_x3ccWC5pPtnhUYfxHzJO9-3w8A"
        }
        "##;

        let note: ArToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::ar_to_abar_params().unwrap();
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
        let params = ProverParams::bar_to_abar_params().unwrap();
        let verify_params = VerifierParams::bar_to_abar_params().unwrap();
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
        {
            "body": {
                "input": {
                    "amount": {
                        "Confidential": ["fECrLd-9AfHPKang-pd6FWZJO1UpnvpOSUFIkekYgXk=", "VowNN_RmkJ4BYtpg4_xPJF6Nl90x7qTHlwqLUTfHdyk="]
                    },
                    "asset_type": {
                        "Confidential": "4DbkRfiRpRje5u_kJ7oaEJK7ifWSi27Apuy5Rf1kxTw="
                    },
                    "public_key": "AQLvMkrgHO_gl13Tq9XAc1PTVEoypGX879GbhKXuA2gfWQ=="
                },
                "output": {
                    "commitment": "AbKebBKgro6tfvImEPMZQ2qvBLnbyYzSNRqs17YLExc="
                },
                "proof": [{
                    "inspection_comm": "MB4IyloD_Um94QB1kA3iSN6owFxBXCAoDVwtsE10hg0=",
                    "randomizers": ["_lBai872uC_TX5IPFP3H9J04kVg1cvyrgewKjD5triw=", "AB461CGuUlyIgJytxUSNgfuNbJ0-jw9oz1SAP4h-QCo="],
                    "response_scalars": [
                        ["nYROf7zTunBKF5tFugISFMHsL4aCnJuUvtNDiHyeMwE=", "mg3rd3HiGlR2d9DEOqTPtn7bQnUBR4WXI6t_cBDvfgg="],
                        ["3VrSCUNIRC0MV2rgGCfD_yEUD1Xtn5bwa8yYAWsKIQE=", "rUfNx0HqVkt_66y3R0J6bl_v3dEH5Yt7vrkn1gJxOwQ="]
                    ],
                    "params_phantom": null
                }, {
                    "cm_w_vec": ["tWjO1_icRkOMh88BWHEx3awPlf-DvkekNgb1ENnbkFPxJYRjuv9WqVsK7dlK_Y_G", "j4-P5t4r4tU0-fk3legvPqXTCYnGMHFCDhrImeJqvguGMLpqGWjXlXGGoXi1Beu2", "ivVBGTNIwWayIoRj1kiX3ycduGX87Nvzm_XJlpdMVSG8ENTI6Rnp1nJbYdDMKYg3", "l-qQIwrgAURmaWhOxlcKqRZ8Ja7kRk1SK34GRkQ_CeqOl60613Ugrrl20vgkZl8L", "r1Yb4YKskUG8dmG9rVF65tNmjmykDCCoIgV9EAJ4fvL7Ws6bAQm2WgEzJ6wT3RqS"],
                    "cm_t_vec": ["rBxJqK7SX3vvuhUJEpxKmsLEJ72-U96vXdQUIsvK0y1UGzRZCqQs12sLT4aYgQAI", "g0vj-UOuJiuYm_wc9eGx6y6M9SCGwjzv7ftDsPPNjBdmnT59801bp-e-SrKr1-ZP", "rH6-zNqq1rnlJl39LyHBO_CRljWGmOzhXTBYTDKUyHBx5GJ3OXVRNxo3pLlcNBr2", "mD46FrzaiF0ROvkLaP3FaKF4i0-Ersz2Qd4tFhb85PtQsD-N3XBcV1TFwcIgQGWA", "i7gvu4V-fa7becK7tCMBpVD6TYEIdUoUfp_kN7SwYM15Cn2Kk9gShc0tW1eZ_5ou"],
                    "cm_z": "s6AqobAjpsPqQRyF6-C63X0a1CRW9IBzeZGGU5UbokRkVGPs3kQT889GVyQmClp3",
                    "prk_3_poly_eval_zeta": "w1dBg8G-XAak_XsIiWDf-2F2pwBgCRYFnxQRxKiiSBg=",
                    "prk_4_poly_eval_zeta": "Jtw8gf9xc3VmANr0teMkvGwe1xSezvfLSSe0AcSunTc=",
                    "w_polys_eval_zeta": ["3ImfXVX_eVgO9AVH5NTysmvp9Z1uoo7isUyjMkPlw14=", "klRz_jURPWhVJPezJq3xDy8kWmUoGU0ihoIPISiPOkc=", "UqPtwITeMEtdiHXe2rDR7G66UVJS1RDCWUj2jGLnvHI=", "BJgiBCq5cqS59ilfDG_xy6FFKfSNyPBT75GOGKcvwVI=", "lmhd9G-hQ0VgkxXAdy3pi2XPZmAYkQdgD-DNS44VJlM="],
                    "w_polys_eval_zeta_omega": ["gTGzMRgMCnyvECEEE9L0KIrOKVYBcsv9Fs0c61aQ6wc=", "O3U6x_K8SA7OjeUFE2SdGRYkDrHuYmK11M9dYuZtSh8=", "d4so9X69s4F6VZIyVhUH5HJiWLwnWa9gc4Q9xp3ix24="],
                    "z_eval_zeta_omega": "mASn_jmd24n3qwmjIVRNzQS6VHkKNRqAuQcAjhqAOmI=",
                    "s_polys_eval_zeta": ["HuatHzA0qRDCJNqqiEPiIT6FJiJqAzCew2sSVoiTnhY=", "PvUyEpcQg7IbW1v3mUAkrYA7y0k8LHD9lBvKk_yZYiQ=", "IDz55mvmhYfy0QuQ9ZVZ05FrTCO8aMpqyq0bpslsKio=", "B18KCw1zKd7qBV2eoFMz9b8DwZX19d8wUJuBtkwOWVk="],
                    "opening_witness_zeta": "t3xkAbgJvvBP4zF4AJOEO2dGK32Z7FcWK89KPQTBeePeyeCk6Y3vpl25UiLhpN2s",
                    "opening_witness_zeta_omega": "lY-yJgC-IIeFC1QWSK9nB7GLE3O4CnOoMritU-WZpSfp-_TJF1PhW5959UX90FwM"
                }],
                "memo": [216, 36, 233, 67, 56, 64, 109, 143, 94, 38, 210, 251, 180, 133, 54, 75, 41, 94, 117, 238, 35, 111, 124, 16, 45, 166, 89, 184, 18, 148, 24, 2, 128, 242, 105, 56, 9, 85, 7, 144, 147, 133, 183, 85, 27, 63, 69, 17, 248, 241, 222, 255, 116, 91, 110, 142, 33, 215, 186, 117, 113, 98, 227, 21, 91, 223, 7, 232, 126, 131, 85, 168, 82, 143, 209, 34, 244, 201, 172, 212, 184, 253, 170, 103, 179, 192, 0, 221, 200, 226, 55, 128, 228, 224, 193, 144, 202, 210, 86, 26, 225, 240, 14, 192, 51, 56, 38, 247, 188, 199, 88, 143, 114, 15, 153, 163, 34, 61, 101, 80, 215]
            },
            "signature": "AZ7-TPPyV450L75r-zfsQkuAOs81gGPeuOC4VP7HtdwODwQhe5Qm-bSn3JEJjgS7suskuL1tjkZfFvn2wTzMDZYB"
        }
        "##;

        let note: BarToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::bar_to_abar_params().unwrap();
        assert!(
            verify_bar_to_abar_note(&verify_params, &note, &note.body.input.public_key).is_ok()
        );
    }

    #[test]
    fn bar_to_abar_ed25519_test2() {
        let note = r##"
        {
            "body": {
                "input": {
                    "amount": {
                        "Confidential": ["lGQ8LrInJYJNIyH1ddb2BoiJs9jWCUi-2oiiVgdILBk=", "aiM-RZEuN2QCpxoCii-6YFJY2ek2AEPXkusa5u36iXE="]
                    },
                    "asset_type": {
                        "Confidential": "ygpNDsHZIE5CsYhjPunmDOuV4TROu4EGaKAQdeTX_2g="
                    },
                    "public_key": "PtvmtDOjVOEYZxdpOlVUZtIo-1WYWqXaOw7RKffBujs="
                },
                "output": {
                    "commitment": "cBfKAZPRl81NfXbndBOG0KefT9a38kmBUV7ppk_Ox1k="
                },
                "proof": [{
                    "inspection_comm": "5EPyQ_3TCjh7OLGjD97OUfuUDfvcs4jw1yTPGzOLclg=",
                    "randomizers": ["VBUbAIx2cFerehuTgXQI2SbUh5dG82pZtrrm5T5sxlo=", "IInqPwvdtQlqetSj5qkvk4U4KVw_rw_SqZQ8k90e2hg="],
                    "response_scalars": [
                        ["jN-LeJ2yhJYr64FXTJVdK310HwE56U2n9e8LKOc5kws=", "5Ajg5S4YgFcEwHdzMnWOqF5ZpeNcYBQZRxiV8eTVdAo="],
                        ["rfBxHgA5luPJT-_XE2XNNkjpxXNjpEogJkiS-NVjvwQ=", "JSsxBtjbhs299k6wB5ANFF-77ZijCUUaYLZbYt4SxgY="]
                    ],
                    "params_phantom": null
                }, {
                    "cm_w_vec": ["lEWUpPCNCGxX-liyw3oGOpav9oh9Wvh3Qp4A9mLs1ZgguMEIasjFWiVu9nto0hnJ", "hsH-Ank9nVb96jYR9jzUYjrQAbTewhyMRZLfkq_Myn1XLW7FLRN18ymlYP3L0RZ8", "gbxWrx3hzsacONY-PVF0liuZv8ycV15uX05Ul0MUy47QjZTbaWSmtyB4MjxaHahx", "i-MeuojuVZ6qbR_JUKEmmDFRgEl3N5VKmtdX4edqF_fKZuc-4sZGMBLw7bYWkiCA", "kkpontCoTcgMqkqMwNYFggnv-bIi2Snn9uwQDPFASdn-JL0PR3T7txo4NjqmvIUC"],
                    "cm_t_vec": ["hCK9dGPh_b04qZnDlUSVJ4DZvTAc-sK4PaYqm5vih1ja8eExMRsYZLEJ0k8VnD86", "kWZ2Ycz83HYMeIKKK3hjYmdIFZiIIs-X6lkqkhWC5PU8X9BMN1eq5KwpripDJvyi", "hM79fyO6otCC-vIYS4yKQyAz9QuXUOvN5vckzn57oIVsSqvibMOl5GkxtbvN9nt9", "t_14nQ5BSSDN6rufW9lvSqnTF7e1W5DbYAadxN-PnMv5dC0ghkm0nVDXVr1yqLkB", "rXnpCyax23BrCWE2JIUh9s9wgsbPKmsZMtVerx2dsFUJ9cumz7fcv4Bmj1uQ-Ilg"],
                    "cm_z": "ppdc7z1HX1JzLBOQUvp2JVFdqdCrpbNj2JZdAf0Dlz2fbrzjU288b4Vo-lMMLUuL",
                    "prk_3_poly_eval_zeta": "qT8a5-sSzNkhuZ5QRWfF1FPIJXvxkrKRSjaMFU6SUWY=",
                    "prk_4_poly_eval_zeta": "5iMm-laDrEQaOvk2FJidFFAtkKKLJK2pmHHCBNKPWyI=",
                    "w_polys_eval_zeta": ["POZ2xRwKW_hAN7MbJIu8MXeFkvM1MXauatF25RsNmCY=", "3pST1fZWf62Qehc0kiHLxiYZRrGqhbb0AWUGs9deJ1Y=", "J7_tFpIGeM1kw4m0cWpa2IaYWtsqeaCFLDDysELQfE0=", "KvupzNKcUgPCNzACiBUDfN5WBtxVpsKy95KIV5Z_1Rg=", "m_am2qDtJdnjwRY0YVUxB6D2DKmwHXuCe4s15gkSGWE="],
                    "w_polys_eval_zeta_omega": ["e1jHZe7M9JDwOMpmMdzCzgHOUS98tLOSOVzZwI-ckms=", "q1GUE8y2elyqHUOs-hBxQdi9in6p3CyQxoHpAq5hFUA=", "dqs7wCSRj4QbAXyUZ-PYXaj9_Kmr-8U5wTMjKD9p-3E="],
                    "z_eval_zeta_omega": "EL8eiNGobtB4cJIUG9lu0GfUXgthM6yASn4Yj-xGD2Y=",
                    "s_polys_eval_zeta": ["B4EJcKCuRLat3jFU48X5rqXanoIBlyoVtHSfH9Ht6yA=", "juTl1uS8NGo8ni8KGjO7QvDPnsVpMpakiTFQ4AsKlBk=", "k-x0u44W5DWJirsU2JDiC2TjeM184kZb2BjRxIHsbl0=", "0M1UkNcXZBWVIG3n7ubW1Ww_G0dBdAZCsoz93XxfAyQ="],
                    "opening_witness_zeta": "pzf4ZKoznwETQ4fS1LTL65YfrThHJyGqki1HA7IipIOVoaNd_9fQZTvTn_K6deGF",
                    "opening_witness_zeta_omega": "t7b2Z4hNPyiIrqeQ2ANpg1tQI8MFU99CPQ2TYL8Lm7ur4oFkwpf7z7Sf6zhGbqUR"
                }],
                "memo": [213, 41, 12, 165, 75, 241, 153, 38, 158, 203, 250, 134, 206, 181, 126, 25, 178, 50, 24, 50, 169, 123, 2, 214, 19, 222, 105, 239, 238, 20, 214, 48, 104, 220, 233, 41, 109, 24, 118, 147, 7, 41, 69, 247, 114, 175, 216, 41, 126, 67, 148, 239, 22, 29, 192, 134, 152, 3, 223, 202, 16, 105, 171, 207, 236, 208, 28, 3, 6, 151, 28, 182, 150, 144, 201, 100, 193, 229, 7, 51, 169, 228, 23, 193, 22, 94, 51, 51, 186, 24, 224, 34, 88, 34, 168, 186, 148, 229, 138, 1, 94, 104, 74, 196]
            },
            "signature": "AJ9pYMw9gmvtvqGTVAY7721hTCZGOK6vLFok-VJRNGNHmdO0KNasDw-2U2aFo2BWBY4TsK3y24tBIGWqaJtoaQIA"
        }
        "##;

        let note: BarToAbarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::bar_to_abar_params().unwrap();
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
        let params = ProverParams::abar_to_ar_params(TREE_DEPTH).unwrap();
        let verify_params = VerifierParams::abar_to_ar_params().unwrap();
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
        {
            "body": {
                "input": "9gWkxGrARf9RfmV7Q194SdxE7mD1z9KAg3TezW2Z1Bo=",
                "output": {
                    "amount": {
                        "NonConfidential": "10"
                    },
                    "asset_type": {
                        "NonConfidential": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
                    },
                    "public_key": "AQNBYheIVxLYQPQ8WCbrQFklVNWAk8e0jrw3TZA4eksVnQ=="
                },
                "merkle_root": "byQPnbIe5_kUI_0CyComZYMBaom5U27yS79KLpwHJB8=",
                "merkle_root_version": 1,
                "memo": null
            },
            "proof": {
                "cm_w_vec": ["lw8wk_evy3SuMNsu7cSZrjRkprvX_Ra_V7tMa2oflXZi4bm-k8gqX17m4DTuJznR", "uKZ9z26MpH6lpjQLQnBBbktdlTfLmqHejvxypWSYGCqtcagZe-Kf6-85TtGXrspA", "hz6dOdiCamd9F_mMdWCTosyiUEb54fgdgj4wZmgyV3o7r_yNIHGQO6JEL-z2FkVN", "sRQK6uouckXbrnztG1tzONDt0IlePD9hO7-BEvQv75hFOsoPRqSwK-AMDGYuJ22S", "kW6cGH9SmUacKeKpw0DR94_R_dyVvGGmgbRkOgiEPbvghY7CKW2Hs1_5bDbbcWVq"],
                "cm_t_vec": ["kkl4UES-Dt5ASkr-MMNEPuK0adDBcU3CKGA60bcyp9oIVb5qGpu9L4aHpmc8s7zR", "oo-_tWjwghoJwbTwPBqU3hUe5ryiCYMvqFSzJQ0ndApq1hVReJtFGPLBCVaXSAw1", "kSllnS3LgiNytIC4FrYjLrKOjphgtzVwYSEz5N9HmMMN5hpBZRUeJl_i6yiLJesU", "hTTg2uKWaXqZz5qC0NrLhrWjG_hOgHimOFfDtdHsii0rYiZFtmYGCA6fdQWyEVEf", "oRWbrYHyEADje0DV45PuPHRZuFrxN8RfmOK_l_Ip2-_yfSu4c3TMg0EgxiwGiwvt"],
                "cm_z": "q7NlkhHFij8l8bRBejaDRAIbLxn9MOd-gWpYIgQy3NYXtNHnG_Ttr2tUQogeupSU",
                "prk_3_poly_eval_zeta": "BjQW8Bcv9IdCOCtxdLahzOznU4wPni2OjBHkRZkWnAE=",
                "prk_4_poly_eval_zeta": "L-ltqj56amlp-jDm7wM2PiPov4drObn4qPtKi52Sbhc=",
                "w_polys_eval_zeta": ["v9VyKq3eACCW2hxhXCB_jg-F0elUeiNIjmiobSWpR24=", "BBlrv1pZA4PR-nqN4UIgY1s_uHPKg25ZQatKuZIySSI=", "k1SkJiq0sBo8eZnRT_ifJiMhyDiMqVtfGZDkIHBBFCE=", "ucbKwOr5SmlxVMnexIWLk5yxifSYoLQWdcazaLjPIVg=", "PlfYpuSk7MkGwvnK1E-aG0sklQppLzxL30nUNzuaNTU="],
                "w_polys_eval_zeta_omega": ["Zpbf2KKWUi6eyGTUoKzzmnbEaTbFX0MS8iOmRU-iuS0=", "laQIj7HgcFBRZdFoG8DhKFCVnmSMZSRainEgj71l0hg=", "jmKGXQrZ2KpLbIMzx2qwCxO-nGCOOkqX38hCvzhZAAA="],
                "z_eval_zeta_omega": "DSl69nKT-Um6xMY7vc3ysl4t-7piFN41xXosavZayRQ=",
                "s_polys_eval_zeta": ["VBAMWavbJxx-w9nzHUT7J_jhr2R6nAF-TuccjYxfyFo=", "KS4BjOBVg4TD-i7tp5-tyz-rfO4VsJ2ngoD1Rox-CWg=", "41saLm1fJFhcmc_6wWaLtb1ixmeBQGefYRt48w1CdDE=", "M6IEs7jeAXKbn4Y4o-I2IDM4_PgjPv3tb5HFO02zcC0="],
                "opening_witness_zeta": "saHCaOkdPGsgz65f4hZMlhSsR_LdfqR5_kkz9WNI_zmwuWzl5nqv2B99amIfr83I",
                "opening_witness_zeta_omega": "sQCfoFy0IST7bJREhafPU05FKtLeGWKqJ8u6cXme9EwFG1f1XolzdFi3an8oE8lM"
            },
            "folding_instance": {
                "Secp256k1": {
                    "delegated_schnorr_proof": {
                        "inspection_comm": "nELP0hAO8Ndr_aqUKldDQXo5_sF6r6EPEkAtzRQdCE8=",
                        "randomizers": ["Pz-3wo_r-rfR1cDPGTh2tjMpeBM-Y4JuPaJhJeo83hcA", "KLF_-G8rgrA3H92W6-FXtwbLjvaproCGK7gfrgiBSy4A", "lqgc411FaUYgsgAXCbAXSD8CWvmzFDIgtEJSS9gVk8iA"],
                        "response_scalars": [
                            ["Iroi8jrctbUa6Ues86DdKfi6OJNiNGNJpfBHccI2Gf0=", "H9MaLN3BZDE5LJ1H7rM9nOa_YyTyX9fHdN-W7mx9bfE="],
                            ["ZFFFZd7Pa8q4bslSdeqx9Kq5L4sDbWe7JK5FaljEi20=", "suOTPZiPYSieGdVxAiFV-Agk8AuIg6kKqUJMFHJ40oc="],
                            ["h61jBL4iII1kBS7CbbLFE7YLPviAJaRR1GbzS-5p-K4=", "GF33fyDjmF7ji1GqjLY8W0C19Wu_OqOYJOIk47JViYE="]
                        ],
                        "params_phantom": null
                    },
                    "scalar_mul_commitments": ["O2JpWQILXuMyvlJXbQmxfnu0jBGNMthu6V03ZW7p_OOA", "5lQQtWesRb0vCST1lRxVwehnthUFc8tndXMGnZd5T3uA", "y-MvWQRHyOqKTlkcYFMPZjMRTJ-oeOby-xTTMfLGf8SA"],
                    "scalar_mul_proof": "jJE5vB0tmIXSa5fEpyYWpzVGJ4CeOiBLwWwaNPYidBWA0CQ35mk796BWFDSl3ucoiRk3qH0qJ2ATQ4Qycm8m26KAUoEkVVEPldlTJLtZBUCMErcwOquxmjkj-BvS8Bv5Rn0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAEMtA4vGOEecof-N1oI2rRjm7_210D1tLmyA2Rqf2Ui2AzyCmbvYqDqPeVgzCaG-zCecoyNDyo0N8y6VK3c3C6pSA3R4_g-_brXlLfSGtC3z8EIR_dJ0Iv33BZjhOuaR2l18Ad94SRu1XK-d5N4A4QO6wlAAvMjR5IDvY_dyKABcgTnGAHkIgk2iLUy8CGI-R3_3T0pvINVo-zb0hP-SmdLGm9SwAtMjFmSIZ1fdjpSGMo5QZWGcGwRtRHxcgRcx76_lXfeGSqcja37hq1NlPteZ7CHN6KI3vR_8A1WjVWR4uARCC39gZvNOr47jM981_d-EFb0yX8x32K0h9lqHpZUf-KEPlCwAAAAAAAABDDeivyPVA-Xpim6hcuxt_iiLV0V6uJd0i-w5oHuEXjwB1dmB6GEQV6hTghe6pt0Tai1XuFGCyO_nsIUYTSI0WjoDZMov3hG4EUMHTfzv2NvipJXOVnpv-Mxnv-eDysTItPoCYTT5wJR_0kQVHeaLV9yUWG9mRDOV6m8UntnVnQWTEawBHDlfZx-yglO5Fkz0gbAJIOV5w9iZMkGZzR9lNcTXL9gD50TLXdTaVe3VbcfmPOxNrf5gjqomUy6O3o5PBrLPNNIBG5jmPaKS-8k3uIQ5P98X35eNYu8tMZdZWE7XjaN2oqAD3nXvbFeeOgUA0CPcwywu09gYWWGPZa21jkMK-7Kt9zgAhEIvITn-dzeTMLgRo8UUX5s0sdvhfrQLjpXUN-G_cZAAhrgv-ftA1m8etDKORqP4pWpWg8GE9Xk7Alqg9T6gAOYBaHxKo1zyYGLbJoMWx9z3CqRlooOaJJGPb2vONeYL-uYALAAAAAAAAALNY6tQcfjeRJTCZq-WM29lBDCChOAsnkL5DUDBDSuNEAKYjoD8_gtVfSkfY7yb9UR65qg5uiuwCRBjPh7UCAfIXgMLq7iKaB1wix-EWDtZ3y-h00TqqVPb7ev9Dskvt_AukAHMO0H-YO_sTs5Uo1CNhsV_BguNqzKVu0Blblq2U1U2rAA0x266iAdOhTBOWadaxR9V8J_Oi4Wfi49bS6YLUlHd2gHX-TViTHkdp_KH6CU9jTh8NfQ8Pdom7-4DIX9HDKQ3wADZcW2BjgAY9_EM2YzqZK73tqexJK7juD47hprJhtX1qgDHWS1Ny6fv-7x6L4Yc2llMEEWoAiyrZUqNCFNPf4hyFABwfO-lZIqTh1o4PpNO2T_O5YpU-Ofd9InhtB92jIWZkgPtVj0cUVkD7OkgUXgvRC-tBbHQWXWBD4KbFnMHL8BfpgK7Y8Q3VufNQdtRIZlESLP1ubCkZZdHyJXrFY3n7UQogALatiMVFAHz6CkPeJDmhGFUetj1zydLtDayB0kunQ5PMX_MRpo6yJt2-79ue1yiAeqlUU6j6d1_RfHkRbrlIUtI="
                }
            }
        }
        "##;

        let note: AbarToArNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::abar_to_ar_params().unwrap();
        let hash = random_hasher([
            83, 145, 117, 214, 223, 191, 238, 68, 87, 177, 98, 92, 116, 103, 29, 135, 3, 22, 21,
            119, 221, 188, 128, 225, 176, 4, 23, 168, 118, 129, 226, 55,
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
        {
            "body": {
                "input": "MWTpn-t2o8Xbbw7_SGfJNTyADZRJPLMGgWPop-MT4Dw=",
                "output": {
                    "amount": {
                        "NonConfidential": "10"
                    },
                    "asset_type": {
                        "NonConfidential": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
                    },
                    "public_key": "XwRoWJWrkOU3lax1DHljI2yhK_eFDCCchvH0JEfIt2o="
                },
                "merkle_root": "Y4PWP6yHRuljdGnl2HCVnBh9nu6MV_ir2FaJtCvax04=",
                "merkle_root_version": 1,
                "memo": null
            },
            "proof": {
                "cm_w_vec": ["r_RMpcCiNcw-ule9xn-YO6-EwvNrkNNNrlQbO00nm0N_IlU987JpJ_4orsAnaZbQ", "lajC9D5VVOm_7wjEyNRT4wwWsxNdZeZhl0f7wEH2gus_9mojbDmqbxeTfcWRxDhU", "haOpvpC0UaIMZIAqeQgX1gK-_PpvZUQitilUeNcOwjq3sxfMxcFObLbNb579P_r0", "oT8ftEe7-z3ZhnWP_4z8kqQqWNsX3YwLwq4M6xLzU2BfxdxhTz9hA6GDcVPNcx6a", "iIU8wsWkN5_1ze1Ln4aqDAdWx6oVR_M9tRxKfpYWb4vEqNeRj8h0KJvYr2o5zzbo"],
                "cm_t_vec": ["jSfsvqasNzXgA4WtlLfvBR2EIDBfCk6vgxfc3dX-WkBHydUY0Fw5aHo4QLP8CMr1", "oAXy0sUK5Jkd53_bLLAGSgURoDmUtgmOXv3ksczY0rX3un4T8A3azs8K9G7kaNSQ", "gNDTw3cWHLtxnl6t7jyobcaHQtnPusDlUjHSes_cwlccjmT__tQ9p333ncyoeCZw", "sxahzeYCT7iFR5mG8TF_lETAHal-OuBV1FblCVHiTl_3YmM0dyAC7nkVH8l9SpFY", "h8qeFS3AphG9Rp-b8UJtSrCKFVCkWU7VrNvm8mnW8c2K6R_JW_25Y-7Erqdp-rFZ"],
                "cm_z": "uYOnVJxe_Dmluko6sVfSgHc0_iI7WD7VzV9GJT6bK87ahb8yt3OA7CwP_Yff_SeU",
                "prk_3_poly_eval_zeta": "4ohKV8BEm-16IkQ2De24KnBYcqYfttDj7URDFRMk-G8=",
                "prk_4_poly_eval_zeta": "pSuhX9EECfOL41vST3mddprCwz-b5zGTYII1NfMmEDg=",
                "w_polys_eval_zeta": ["VNg3meBxFre0Pi6B_hLuiEvexd8SB6is8EEfZlkR_ks=", "ctI0lL6Em0NgbgTTgr7FMIG2l0RTzFIKKQzJEgAXF1o=", "WOC1-QOLqrQKhnTbY2UfXMhFm4hCFavMWTkxTO15GkQ=", "CIK1lKmdN-ZZV-Wdc3UmWUAcdvSpJOeYWMN0XyDmehU=", "2lKEL5UCJrEliGIVDgZnLAr-9aRCKTYfwQv06T4QLjM="],
                "w_polys_eval_zeta_omega": ["0-twGcw5upcdv9BaSgE2RdmBXQYuHUjnP4hfpIoNM18=", "R0gyANJsJ6IENdUi8RDxwvtE3tuKMx9bNe85A08tGEE=", "5l96BrevTghakUJK2d6ijyzIiidPwxugPGUs2Cg3sCY="],
                "z_eval_zeta_omega": "cRH8tvKHyXPFzqVk9prbzAB6LD2saCKRpQNYY1bPvQw=",
                "s_polys_eval_zeta": ["o4o2TfM6tXZw6cojRuF7rPgk4yQZql7opCGqMlVdg00=", "nnWpz5weodXKgZzcaHfGym8_c_yzRwh7vmPxjA_e0wk=", "8KIpRncrp9sZAK0Mmd42L9euxHQuqx34k3VEPMbZcmA=", "uK6o2kpAzM1Zb_-W_MOfmcmK98lsVHXJz33QEh7pGGI="],
                "opening_witness_zeta": "kLf-96Il_tV2VYMijnBLmcccEZUM7ea5zwS9KwCE39naoKnTeBtRMg2Knd6Fb6Ej",
                "opening_witness_zeta_omega": "sJ_aTh60UsRrcEUMXNd1cGhlm0XL339-1z-NIfpRUdNwNZrKwiC58V4JC-tTl06P"
            },
            "folding_instance": {
                "Ed25519": {
                    "delegated_schnorr_proof": {
                        "inspection_comm": "8BAtvH-sqfq5-0ekNZASP1isIvZAFvlFthgPxBZMSFE=",
                        "randomizers": ["nuLB2KDpJVV1eTDWwQMcgb55NT3XitnAEhpcl7g8LnMA", "WImKM3P1VLgh0oc2lCOPeL0XzpUMRFgH7ghyT88fF0AA", "T2C1qopR55FLLoI3gXyQG6b1CWqsPVnqogWCmodMkw2A"],
                        "response_scalars": [
                            ["1NX80qNRb0kE3l83HeBJfg5dwE3UDGu416BSHDWpPWM=", "XYA482M_C5DZqERlr61HiQ5TGojFsv-9xVev6glx00k="],
                            ["Fax2M4e14bA9fJcjqzT6dQ6hhmD9Li5sF3n3154BkkY=", "cMIt95wmR5ko1jK6FC3hel9k5TuvV6YgbJA_m4d9fXM="],
                            ["ihmr9F0XvrzhI_XESxo2eu6dpdnJKMC3I9xLIucSAV8=", "ZZhAQajiy3jirSxdBmQxXReMHZZKUGLSfJqyhGyUmGA="]
                        ],
                        "params_phantom": null
                    },
                    "scalar_mul_commitments": ["RABsJBzf1wph5YXDU6SWr9YwiyUBXK_H4ITXUF20RR6A", "5mHWyxWyNjw6Z7LZ_BoGVK0nTbZ2zdHCa95_SlZLhxKA", "_xTXwrLi5vm5nhtfFQkJrRkg_Tnm-wnl5gglK2nBuysA"],
                    "scalar_mul_proof": "ZfC6dmRX165I9G5L9w5EOMPQMJnYhr3SqfMlCrmAwhOAguufz07Y6mJ_TTAB96dESjMA9xaRPI8kN2Fx2gMRix8ACuu6UJaZbbZMNn7YsF4OEZdAIb4ySlAQ4d1BEcBKxCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAXrsuLdFlL-D71CWcOtAj06u3RPnlnkahAiJCJxzZ9C0AWWWX5u-1Yy7vLequB4mh6OdwlBkTRpU4nxsmjc10dTYA4JyoG7Kt0cMc4roKhPi-s_n0b2t11_rSYnIowFlBwksAuH1HZkJYrOUwwQNbOfs0oG04agn9VvuTyBvgidFSuVKATgtaHcaADUhH4EmTF8XVUd2tcIAyrPZUUEaawnE4BBgAfm9ACE2mWln7H46MOCKQJDe_UF32yP3craSYCI6lmXIFmsRUsk9HporPH7UYW_3mELp4ONZ8VOlD_KlkPsc2STh4SDXwQOwgA-J5Ahh7MiQKAjzvqROkZC5OOqm6Xx4MCwAAAAAAAAC4H3pNiKB3WlemN0rYYFAoNDgoH0olmrk3VocaJgIadQCGCZIp1jUtezbPoOpIsHiBBZrQG-VMJF0j7d86frEueIA_G_JinhpCBYbR6uLbYaJFSvTvv1kYdax7cg1cKmJJNYBBKvTTgAIjDKnouNSaIQKv6wf0QI_O4DxvCYLkBg2wUAD8cPfwa8LVP71Z1GQZHlpN9br1M3Um0Jrwfugge1pfV4BXkI11ttQVRNPAeo_2aJllYpKlwMqJkkjY3vaDVWNPZgAnd2E6xOq_fScN2Ry8Bgst8CnOpIpizh_-GD8fqnUnboDnqze-se3_us7KjJDbRTJSrass_j-5ocL1XL44o7xEcAA4PzdmfxaDhR3F53xxkySYlKgrIj4sAjf0W0PGmnZoEwBvfasSaABMlI0FEMie6Dk54LidLrTUS_Ku1IfoLN75I4Bl2sN0M36U5yVOqHV5ewpZNWoZYz-LenllqIrC3PpvAQALAAAAAAAAAD6B9wluxmcgw4oO-lt3wDCUIV4_Tvuj0-cyHHQTQfhLAF8DeiRGwJ7f4aTzHHogVs_q6Uac01cn1N8kA5cQwSYfgBxSDiBCgFRy5k7gItFJb6DdiAvTLL8A4GQpqhqipPRIgORA9ryk8fItrSVbn2-coKhyaBjr06M2Nf5C02iVTJleANbH0Gn2x-02mQgzz9x9QWm5kVZ6oWroKZeW3WpG_YQqAGNQFWb07rGF_62PQKKyWqKv0yuabB1T9PZorEbSCcx9gO9NrD8XXEWsuxDDpCWAgkrnwTgfUmHXC8eYFaH2mlpJAEgkhnrxI_aE4OuLUANU48j412vbPN70cDuQFXjnxlxQAOs-G8O62ya1gMJRKdV6SGAVgOqXE82Lc4IbBKwJhAdDAM15HrMr3YHd2xMRWQYPZYnzLslcIPuhAu9fBlHXlpBMAK864FRPtSKheWDAp45I1mON1zEOM1814Dbo6XjQNw4pAL_HJjHnOVruPsG8583WD0yaPlFziL6rkJkrpi9r_6tO0jkB9QxzI2f5pi5Mfb2xddkoNknPekwWJhESG4_CmnY="
                }
            }
        }
        "##;

        let note: AbarToArNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::abar_to_ar_params().unwrap();
        let hash = random_hasher([
            191, 79, 63, 75, 108, 207, 113, 214, 12, 229, 29, 85, 139, 252, 147, 238, 92, 149, 89,
            73, 104, 239, 201, 253, 174, 96, 131, 174, 70, 41, 87, 163,
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
        let params = ProverParams::abar_to_bar_params(TREE_DEPTH).unwrap();
        let verify_params = VerifierParams::abar_to_bar_params().unwrap();
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
        {
            "body": {
                "input": "D8PF3NF1iRw-b-bGIL96lqT4uZxtOQO0nptkk7eunxY=",
                "output": {
                    "amount": {
                        "Confidential": ["HJSu1izGtAtKma7BGiFB2X1LSIm_JEezQZ9UG5P_Ohg=", "ZFHqg0sQAye1LRvBmEk5VoF4PxCYXscKb3uE_1b8Kls="]
                    },
                    "asset_type": {
                        "Confidential": "enze420duyk9wK5ORNEWMHBw-Zdo4OSLWlfNbusYLDI="
                    },
                    "public_key": "AQOcGh-SfpxOMBju_j0szWYqQNSsYr6QZyHMV4OWxtP9vw=="
                },
                "delegated_schnorr_proof": {
                    "inspection_comm": "q3a5dd9Q7Cg0OOawxs0EF0TYxF-Lm3wMs0P4BSd9VBc=",
                    "randomizers": ["rktfIsKMkOOILXi5hvEpU1hCbLzogrZSUDAVPIyW6iE=", "EgtsULfgh-bIcbH5Xn7MoNUhFI8wrRogCkCCIXJUDD4="],
                    "response_scalars": [
                        ["V8yslNHj1wf6jR-0p8SmCRQzp7QEvKrzrqBb34903Q8=", "fPm2srl-BrhFtKNWNKiVTiQ7VoVaXO9_VxvMw6HmNA4="],
                        ["kvy8XiWjPzJoLiaoxdfCsnJ6p7NgJy57i1c5tbjXQgU=", "BUIYL-FgK6_yEui6Y1FIupv77vRSpCtq-eB7JTD7XQw="]
                    ],
                    "params_phantom": null
                },
                "merkle_root": "52fHRmndRllB0-pecLpS0eN_1RFghrvKe3jhBxalTBQ=",
                "merkle_root_version": 1,
                "memo": {
                    "key_type": "Secp256k1",
                    "blind_share_bytes": [200, 114, 15, 137, 123, 231, 189, 27, 207, 198, 69, 221, 23, 173, 114, 13, 109, 99, 246, 0, 141, 143, 4, 148, 115, 64, 134, 153, 235, 135, 28, 119, 128],
                    "lock_bytes": [170, 170, 42, 240, 127, 165, 29, 169, 41, 72, 59, 54, 251, 155, 1, 25, 29, 215, 149, 223, 175, 205, 194, 152, 26, 115, 231, 205, 109, 194, 193, 7, 0, 162, 168, 156, 41, 134, 171, 124, 173, 238, 119, 86, 254, 151, 213, 137, 232, 82, 21, 198, 188, 229, 186, 239, 124, 5, 161, 206, 56, 45, 82, 237, 242, 99, 78, 29, 151, 139, 207, 218, 6, 5, 70, 176, 143, 125, 98, 149, 134, 84, 211, 217, 217, 14, 17, 200, 34]
                }
            },
            "proof": {
                "cm_w_vec": ["igGh2K7i33pC90BVbYav6SlreicCYiR05pocY1Eu9SW2-AiCh9o08FVMRoyS7lma", "tUykA2byXvm4RWRntgTuIm7x2ArluuBnzDBMaPbK5QfVp9cU-V4jlbTvSZ_31Rao", "kKGctFzagjmHDSYiQAxRHxzhE8LeYYyUbKilhGm20og8uYqWofUUVd2kGNeeTzsH", "tQVzKiLVw3W65MLDh_JYkpzDOLNHxD8ihN77xlNiIbZDJcYyYx3hNIBNo2MRAnOd", "ppRW_q1zq7Cmrr_v_JZ5-9KXyKbjWPkJVbAXUGXhk3ceGXjJKk8qFNnXAxD-kux4"],
                "cm_t_vec": ["rmX8Cd4YziN5p6i_aawlvHZQjzAKTQiOLw0dvj1KqG7BeZ7cUhmUKjgz6aFFT5ff", "tHx2aI3wMPx1GfsXBpCmLT-ogC8283s0J6EnM2VJw0O2oehK0PSXXQO9sO4u9h3s", "oce5E0xBhdmTLm-99N2ndA6WxpKsfEzXENGqH8iEVLER0BPNph27h7NYQd6y2USa", "la3SEXPJzyXs3XFy_fjJWqZtY4coYCagvEi-acwrX0hFc0xfzsCp1gpNbft0Mmyq", "tGzbCXyTdaMfDMR2WLN5808zyh-tpXOvU3XAxz2nOECjxNOIXdJhnFECOp66a5_k"],
                "cm_z": "hUA87dbgZPdEToB2CVenDccDyr2yQ-97EHD17xcnGS1F4lJZRFjQufCuU9ylm0_b",
                "prk_3_poly_eval_zeta": "ipM-3azDLGxBYOiKhtVb8JjqqIlBA3WSAjSeoxtMKic=",
                "prk_4_poly_eval_zeta": "aU8Wa-tnlUYLYJJ7RgIC5l88H3w1Cfy7-zBVe_o_tjo=",
                "w_polys_eval_zeta": ["Km1fEu3vnPIRN6Y66B9p4DBudgOJhhANdHoAybRn-B0=", "SfkOLVzHQpl532c4JX6iCgNyBv9diS4MQkYkgxEOxCw=", "n5izszAjguHIL-CeIE7l_xJ_r3Gvq5VJtPnNRiY2Umc=", "kqA65Bn8EXDyYD6EcZXlnxQaNZouE2rXzYIerEh5Gzo=", "V4940IYRvMNY9_YJmJiVGGlVqwBs9ZbdjPxHg5FzqHM="],
                "w_polys_eval_zeta_omega": ["JttNLFq79w_Njm1AERDeR2qoAtiCr8sxqSR4OXAipko=", "dhpQQmTblkOeM8dNfzlgINDQFqoSKbSAk-XL9gfiChQ=", "DJXAzIMn2yd5GsszMnvNr5GNBjqKTF-sW6atroz4ByA="],
                "z_eval_zeta_omega": "hxyQLYclWm7N-AS1OFwCCQ5f4v6Gmj7nX8qS05p0rCI=",
                "s_polys_eval_zeta": ["nN_xyvqvNwVGqL6VmJf-oj5ChYTP9USr4ZIErYtDjCw=", "J2WwHD1Z4FDtUDCDgey5M_Sgk4pxQq6al41qOSS06Rc=", "1T30uD45wXQDkF23U9O3upkrway3TgkoN5DnniCjOHA=", "AQljsUOjKQ97r9-ntW0nmtbEWDPkmXsx6TRVX0hXHRI="],
                "opening_witness_zeta": "kR0RpZpGS7WVKW5cO_U9NfKyeuIxvjMkquK8Ov_30ja8AHpe0KR7MqsEff8pGzFP",
                "opening_witness_zeta_omega": "osvbWu9j0ThimXLR16wz8QOUuRhGcH5m3S0DhxoMzXQSsQgEWsy93GsZc49JYuji"
            },
            "folding_instance": {
                "Secp256k1": {
                    "delegated_schnorr_proof": {
                        "inspection_comm": "IyVPpopIxFhgkzWMa0OEs9JVCfnLNF-Oc5snXPbR6Rs=",
                        "randomizers": ["MY8SS5yBAUz5I7o6o0Nfqyt7jRPoCe5E2odQsHjIOFWA", "lkBRrLxRTMsIY0Y61EdiPriES_C7c6d6iW4emeLr_fSA", "lwupMExfdT-vPgcR2d-S1jfMSo2Pd_9pWQIRSTmK59eA"],
                        "response_scalars": [
                            ["ylW5EmiBfu-hRwTgkZ2_dCFw8g7Q7da00ftU3jNfWc0=", "7ZL4sK6pTGiVPt8LPSyd381P7-72X71ehmRwAEf-ljM="],
                            ["79IzdR-QXKYpyKUCTKvxok9ErH3_zaARZSifGT5F-Tk=", "kInu2WUgwbTCVyXn3ZbTVBFIYoZAxPzTghtoTwEjCmM="],
                            ["J9hRaiia0sWC1JnZbXIliIsPhptZIBD2ANXGAtkzXlE=", "Zc_2r03T7RXDKN8WIVA-nLLQCEcIGDfZu9Nu746aYy8="]
                        ],
                        "params_phantom": null
                    },
                    "scalar_mul_commitments": ["fsqAFRyvSpmvxqPxbMQDD9VE00Q10mgqL_3udbm4CLyA", "uTmDHhXXMOHwb3cPp4pO6Q9SXGL2mt4QeLUQWibpBNaA", "YIEm5SDllu-GNzah4H-JrQQaUBwk8P_iH0INrk7LlnuA"],
                    "scalar_mul_proof": "Vn5xs6mPYHGqCB1ODE-h2qcGS2JyzuGgdCyHtnjQOH8AH3B5VG8LqWG6plsrijPr3IL1ekByqlWvhxsCzbtIQCiAiX2La3QHDxZ-ARZWy0UYsmOjRWbmio8_ZBtt2C9mk7mAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQAf8tNwJyqHkDkSinf5ASlFTIfavQfVMaQxJhtlCcPqAre4p8bxwxwXiAO90ATmQA8_XBajrRbSRWRIJLAs9oroAQqDk-osrQTix7r8cihx9MVuXxxNSGlkPpTNiwAd7jy0A1q76GPgGn-61cl_A_yzpjOjGJ9MB5jTi3rWTPwTXEiWAOjGRDBs0Ao-xUrsvLJoIZB9QEPuBBd8UGGdJk_43jq0AlLSRlWr15Tcm8Ax_cxRHsw0FerGTr-wmXSv9cVJGjhPxPjsk4Gs6pUMOssoObu6XoehPLQa_JpC3SsROLU7ZCpfVrLTR-oTwZM70VPp-u1JuV9NmzohE-kkGOFSJIuykCwAAAAAAAACFkw7Wu3tBeGOLxR7UUWvWk02G0s3F6-alUrSrUXJJCwA2LnM528_XrJnwUlHeVmbTfNpt01HoXAdDkKfFo5zqNgBxb2q5ltlRpzdPxDwxPUsNAHSBGYcemlI6DjWQ8h634QBf5YTA8hgPBBy9xbS3-wd6LqNMUV4sNSwO5qQrnhrb9wCrBRYki4h91tuQlByamDpQkKa_tHJf-6d7rko1rEb-kIBFtK6BEtdvliZ_2GUgQoNxk4hmvCZvBkFYNHtXEMqez4B6UQF0irUTcoJxjRYgbtRYqbVcA2VR2-xhDITDh6ELjABaeNkLIWGOMWO-zsekN5jHb4xC0xJBng9qk-I1Wv54RwBC1pyW3HlsldbL_4RXYfnFpKX7KvrdHckG3GgV1Ytn_IBEJZPMam74JjJGo5CPDQg9FOCE6yQAVRS8CW_oY6USNAD6CgqNEFjiKcL1P8f0eLe6Fk36TFmGbVD01-u7BNHKB4ALAAAAAAAAAP0U0X_snBq27ZevHg6coSH9-hdps374MXjc1VoES33BAJyGCFNw7zc-1wCPuvfa2gr5qvOPffofnpNd-95_HXbeAGKqkPt1nZme3NEb2YSm-WDKBR1LgEc3U4BZDujeWiSxgO-TFta0Zb3Y2U7yE8Vx2WzsRx2VfwRBv65w8UJixEkMgHHJfWufbBafGHJ1WQggfC6PiyEOIoM8pIVuaPwHqpj_gOZbCJfepmZ7XXWwe_z1WwuZ_W-SNa1V8reYZQ7wBI_4gLfUy71koY-U7MLVQ85UYi9r3bFYTQZXPR7UghbLMPlrAHY7C4p4oRvXPRkhMM-sWU8nNPEKufxNm7fCE4ezqFpEAJv_LwlOaFjuxSFHmhVqKusWjKtAwpokqGVQ9dJ2mGpEgD-nQ3HycSjcvb9zFWqYhoIaSy_Pp-A0TQ7o9Jk3J850gDFLmH5nVi-RZ3QVelNGXtZtB6UTvY2yhi_0X83AeuVMgC1LKjeZ9d7N97EOlA2lslzDjh0tFekBa3FBt4n2dxUNL6tQY64dZAG2cNdVfWIBO9BWIY6OdPQSHpcDB-toHYU="
                }
            }
        }
        "##;

        let note: AbarToBarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::abar_to_bar_params().unwrap();
        let hash = random_hasher([
            120, 93, 26, 196, 209, 56, 171, 178, 116, 224, 253, 30, 40, 124, 100, 97, 205, 168, 67,
            203, 49, 93, 190, 253, 222, 96, 236, 212, 170, 48, 198, 108,
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
        {
            "body": {
                "input": "7s1kLIytigZNMXMOG6lG5ElJ86jkSzjs9y-slrIV6DU=",
                "output": {
                    "amount": {
                        "Confidential": ["7FWlxfxnOOQASdk2d2Ke-TRfCBOZgG7sqxV7pCoAP1E=", "QrNRsaAoiF_2R9CTU8BXTk6m4Ol-IkT6rLY7nWi_uh0="]
                    },
                    "asset_type": {
                        "Confidential": "zKCxIeV03CIDGFoHP5s0zGqwTkwfImMv9GhKnfHOPHg="
                    },
                    "public_key": "H4OFLgDQAM_i_vSmNIe19pDpfzdsyPw1e1MfoaPGcSU="
                },
                "delegated_schnorr_proof": {
                    "inspection_comm": "q_TZDoKWPOj4LZeKXpmqQz6k02UIuuhqBFCpIR2txQg=",
                    "randomizers": ["GFrT1aDpSDvQgGXInZpXG9mFnLV5-2Ff3TBbjR4R1k4=", "8omGnplDGTeLyoIJgbKU0gAnrwwtuT0e6x92Y6aaARA="],
                    "response_scalars": [
                        ["FQTwffkWVTPExO2r9Yiz4r9ot8wgEiQ7xgWY0ccOzQA=", "MPsRrjLa7A5RcvWHgJV5m5ShseJG-v9dhBwEuaAJXAY="],
                        ["_3BSJFDgQGVM14DM9mSf1JisGDQtj5x3woFS-XraeQQ=", "k4iDs7HDWxX_ivTnx_uAYXKDrmsgd8SmcuqFt92iMwg="]
                    ],
                    "params_phantom": null
                },
                "merkle_root": "I6T-Zs2Gwa2PipvJaXjiCUmwCUGoutz1p6Xo73yNsG0=",
                "merkle_root_version": 1,
                "memo": {
                    "key_type": "Ed25519",
                    "blind_share_bytes": [138, 196, 146, 154, 91, 116, 10, 145, 160, 106, 99, 101, 138, 215, 76, 141, 83, 86, 252, 241, 172, 124, 36, 102, 202, 133, 174, 134, 227, 46, 33, 8],
                    "lock_bytes": [90, 19, 211, 225, 75, 18, 92, 20, 129, 177, 195, 100, 243, 140, 14, 26, 159, 236, 104, 152, 37, 194, 136, 56, 79, 30, 127, 90, 229, 199, 94, 26, 216, 141, 128, 228, 187, 170, 114, 230, 239, 184, 84, 246, 189, 242, 149, 238, 37, 127, 98, 193, 115, 102, 29, 183, 57, 76, 227, 141, 4, 207, 86, 81, 57, 80, 180, 71, 143, 23, 93, 8]
                }
            },
            "proof": {
                "cm_w_vec": ["juqCh-Z4mQD_-wPwYfhLx2cqRWpE4oV2pJNU-bkFbhA__YtFITexHbKovPiUYzip", "ixsQ2lXXnCfh4LzXv8DSCBITg4_HoQvDpvQ6KTq8Hm34fV7REPXLjKYz_frGwt6N", "pTmVinEcff1flslo-J1pGI9OxQGOGHfCkQibJlxoxORMOHY07IPBXZkVrgmmsk4j", "sjbHhBn7m1OUQweVfgcL2pNrg2I9vCOlIbRyh2KKGqh5kIchEj_WSp4MxVTC_iQ8", "h9AphfnDNYennVkdoRM77sQFJo6PIC35MrBlUFXuCWaeAL0wLVBmyMfFlt7j6ebe"],
                "cm_t_vec": ["ubJJUEXd2sIc9kLHVucsSqIATC29gV1ATRCeyHj5PTTnOhufsNHGSGy-69sJOFM3", "t8uGlOKQI2wrJ6oT_mYhbaW8cw2abjKtojCxsOFMPVDNB2vY7gzHqCD__AtyVdfH", "l-M2RXzJ5DBNI9dmpdbuW0eSk7FbKgndgk-qJtyCTRWSRg36tupwanaZKAJJL41M", "gtJyukPmV5-Nqh6qGsE2Rdwqt043NoicNXYs4waM3Szj8ctRhBXOuyaNV2ccYzQb", "rHBl9HTh1k5HAWDPh3C5JWuo_XnSdiy1JA8v-MY-WbzS97FbKDsRDNJKhGHC6XsS"],
                "cm_z": "hrLS4v_hOv5A4H8-LL5igIM3UCXAQAyuDuZtV4q3uwreNBEBbSnVJVERPpL3rUzA",
                "prk_3_poly_eval_zeta": "UyIKBHP5odsNyN58mKVLoDJo5-svyRjxizK8VmHRj0g=",
                "prk_4_poly_eval_zeta": "-ym6AmN17qCmrHVfpCvonkxjh1QlPVja19ENXdqKLjg=",
                "w_polys_eval_zeta": ["5yJij1KewAT6G4de6Pi-XCiUpQiIN1x9CBz0M_aevA8=", "DpTgsBwhqf51igSE3CWfJXTsjvElSn__A3HyWIupNmQ=", "t1d6-jcUwy-t2oln-C3u6-jSavFYX45zHqV4z3nF4EU=", "gQb40CwRuaRXljnouyfTC1sdhRMIcTa2UVdcbcnaY0c=", "_L2Sjw2Vzs1ta9opTCHJZf3PZkq458WoKpXcfIm2pSE="],
                "w_polys_eval_zeta_omega": ["kJiOB7re_z3j17_EkgR7mnCnA15yDtXXtJcPgZVRBlc=", "BNgZBZgba9ON4yGoOaayzjhGO1sRvtGgOH8OgoKCGRs=", "c1-4ZaaiS_y9q55LHYfaFNLKixngi8JCJ7mh56YVp3E="],
                "z_eval_zeta_omega": "lkayqD--SLQSogB2sumXvAnX6dSKByafGc29AWxPwVo=",
                "s_polys_eval_zeta": ["-aHeAnKkiOxWTZUO8tPn2MnsWmgFLIB_3yD8y7OPHgA=", "QakBLkqCB3CIvf0KNEi787MygH-uDgYB5SP8dkE29k0=", "sdi3bGM2Zj5sxmVeooJM3Ng_xACgR86vKYzKV5w7CgA=", "MNRV4VvYDIbtLPVHefBmT8awvcJsdGTpquwM-VwwlUo="],
                "opening_witness_zeta": "mMewM7KX63_nIbutcDKVDV1Viy2NK0kc_RVJklG--fudTPfcMhrHsGsVaf-FNT3j",
                "opening_witness_zeta_omega": "l7PpDERd1kGSwsp1Jyr623ZmY1Dq-YoWXMhqWvKcuMgUBj4FGiz2XkeEXB1pVpvO"
            },
            "folding_instance": {
                "Ed25519": {
                    "delegated_schnorr_proof": {
                        "inspection_comm": "J_UoE31ZOe7RDvGSt-mYX9vswhzb0fILga-jg67zyCU=",
                        "randomizers": ["uXGBvVsfhpbCaatIQTqeKZ1SuDQBNcm-H3NfRWA6xEOA", "nxQmLBHDjLtfS5Bw4LuhcMtSJN5BqSX6H9FOPsh0-RqA", "_78buDkcmnU9ndJu2oXKiGaJNkHqf174A97FEawvTmUA"],
                        "response_scalars": [
                            ["VsKa0j6zCWIW5bDXySCTBuACA_gX7tInED5wvF7St1c=", "72uCp9Fv1tf9CAY0NVMTcxgMsMGKbHvi3Getu649VDU="],
                            ["pOkxxKY1Ho0bs_lmcouU3X7ZaCa-eWJLoLuCCwIHxUY=", "2yrWatkgzTNaQkq36nIQTfvByrY-DjsPgU1XCq9sV3Y="],
                            ["Lmg8h7DPmueohL3ejwZcBydG6Oju1ObThngCY9iUYnI=", "bjBHpY4lK0DCPDBCh1NW5wMsP0GCzVgLQQqu-xdHBRo="]
                        ],
                        "params_phantom": null
                    },
                    "scalar_mul_commitments": ["qew4WGqjDU5SDMIi7IGZLAhEgLpKox4XML2JfJwGXwwA", "TkVPZMIhO-hfWYKmZhP4o6pyyBMQN8r3n3yPJa2RPRwA", "q8xd8Z8aGwK_m_SGwgI5cLhOMCDQixQnzjbSHcCOGT0A"],
                    "scalar_mul_proof": "Vv9hujmWfAyCW6Mz5gkxRkD3-7xNXCWxXo6vkDVkgxuAtK4AkMsFGaXc6JnXI9CEG_6Jc3230G1apLlfw-rQfkOAxTLdeXk3x9qNMT-9xshYdV-M5_8EwkjeQ3W7OnDDWyKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA-sUWvmbDHcoDWsXmRAkXWwhGOZRaOTcdTI2M0X2UhDQAhZ6yoNKhhpXPnz9-DzwlqfYQQvE5o8CLzmdQ3GJ2yVgAo5JpUJrRP_hWW3k64tafoWPweP-mcZk0DxejT--esi4AxfJXOn3a7ncsGNxUXkhLVgcyHgCmD7C0caJQJy5syDYARTXBs0acAEy-AOiEr3ZsuWcj2YfoMPPwfM-bZ6SWBCmAPIcGuA8koXTYH0iNbd8s14QHzir4Cvu3lU_pmtNca28Bpk3ephc4cZ2DJr-3g7NRtjo_WgLQlqG1-mqsWSwbI_HPUo1He5IeOTpqWJZomLqbQs85EhnVXUp1snpig9hiCwAAAAAAAADoDlSbch4RZu3TMxw8G8LtdK-dV4zqIjFQN2RefYUiSQC0vf5vmgbIbvaqT5eSLyNVKxg2gF-AVxFYt3CfvUwyZQAFEHFfowlp-_n3HIH7iqgDV2LJ-V4LzMnofxWOihO2QIALIXLP-Hhk2yp_MYzvSQuLAr3KbtPEt7AE5p6CqMzBJoDk0ygm8y04lJzsn3_RLxdLQ6NuPVNPbg-hCGFGgikrfYDAFCM63_DwQ3n1eubTW7UOC7sIzrVSfE4xSogiOoOYSACjSDKSIfU81YyMEDIfBKlVfIPSf2eFk6mhNJLe2X6vXoCwg7QliCE63a2NA41vluwr8Mno7CVKWtgufnWbFKFUK4C64ZNNFSiKBqE3YPia1KOa3Wq-7L_vISftBCpQrJNseoD51hD6wJtzoitQ9F5KzE6VoOZwbY8Xkix4oSM_JlISOYB-TkXq16QouDiSZhAjdV8jvSZCuUBT495x6AaXut8uFgALAAAAAAAAAKMqZABHJx_-N8m8ctPXe66O9uFzoH6HDFeHla3NsRoKgMikWXB-OqMxE9ecEjXr3XfhhlU7pbRkozJD_wnzyn5kgL7aweF4f0BrQSSGaODTmszudce6Ix3sFifNnfgBA5kVgK84lJ47BvtsDnHyYf0lRGu4epj4gkCZOEa7lU7CXNIHgFUzLMUfr50yC9hngz1ZDMtMclEDQUDatjhYWhJRCvBLALAG5LXzfkcdI8ijWRK1HWi9j6J4d0cMsund796atYN0gBptR0vPD9G0NUuD9yJMcIyqjofwPgzu2X3jPYYyGC8tAOmqIE-LLRmxrqjmIdcr8GGCiSvO8Hzbgcw6q3CoXSMngB0qlF6zkv8XFCyM70GTj-X0ktTbJ2MWBnlFftUsdVVcAEj9HQjq9a0_TtxvAMcG-y_n1ByS9atwaDhsw5LwfYxfgP0-VcGMtwBAgBN2Pb_l0IvqoCMklYsgFfUxPXeUavcXAE4sOD3z4hSTmGvnpDkgxVt2TNE7Ks2g1mh0OAL8EkR9lB-kctyd1qoFiOvRc209zTcWTnB-fK5bc2G3Ki_aqjA="
                }
            }
        }
        "##;

        let note: AbarToBarNote = serde_json::from_str(&note).unwrap();
        let verify_params = VerifierParams::abar_to_bar_params().unwrap();
        let hash = random_hasher([
            240, 101, 227, 110, 28, 79, 138, 98, 68, 98, 82, 11, 22, 212, 168, 97, 90, 136, 134,
            118, 91, 133, 119, 249, 4, 97, 50, 50, 42, 112, 185, 40,
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
{"body":{"inputs":["BDbK3WlymWSje4-1h5BcgFVlKo1_Q3P0-kGZo_WhnGk=","ZsK4Z-IfDQREBsI51CMa8t3dgvRSJYsyAFr6wLPV1SA=","YhGVw6CcSjmRJfjWJztKbjSiK91oG0ED34CDOjGMDy8=","3GxLXpuNPErpEjQCKLctx-NN_BMCZedkqPCtWPnRa0M=","HmCIDjSgyeH5qTFxanvBXjhbBV-Ezrs16Vw5DBoPHAc=","EbwlNUwz5lKmAsBs7fET3TcJ15OHu5BGXAwnwEQcoQA="],"outputs":[{"commitment":"3s7xclPz0l_ZcnesMIFSUKRl2p9c3dNVQRAtrK2pHXE="},{"commitment":"blfYMnXXDfDbpFBj9MosqqGUlYyxulxETnOueSLGqGU="},{"commitment":"TmCHuDEZXAIrbnpzhZzDhJrHLrebN0C2ui1sH7bU3WA="},{"commitment":"KIwKS4rJoTg3-0l_PEwfg8GWWsHBmA_A2eg4jp4tfiY="},{"commitment":"L-tYoxv7WJMtqzh0I95W5eRWOIEMfQebDhuIsR0MJDU="},{"commitment":"-04FZn3vEYJpTpz6Jo_caRM3VqIjG9pT0hfjR9aJRAg="}],"merkle_root":"RPBcIPwoxIpyLeyG7Jz-GwOiGrpLPDxBc28IljNY8TU=","merkle_root_version":1,"fee":23,"owner_memos":[[148,180,216,54,190,177,241,227,1,103,139,64,141,158,233,221,52,162,24,25,32,134,77,126,121,102,216,123,167,26,120,69,170,248,231,54,4,237,30,238,173,238,224,69,39,215,229,111,180,90,112,142,188,224,128,209,49,144,214,225,89,192,218,236,127,124,24,163,51,254,76,237,209,135,190,143,29,249,85,239,121,18,134,52,187,230,106,54,174,219,163,26,34,100,113,40,130,208,135,148,226,126,77,50,100,205,235,253,54,11,248,218,104,196,242,122,28,110,37,203],[73,253,211,104,162,189,45,89,84,40,78,96,152,103,239,201,121,254,3,137,62,126,222,62,15,231,249,90,45,44,67,223,128,249,231,160,159,134,45,185,85,103,223,185,149,245,136,77,44,155,138,135,38,105,59,101,202,184,243,200,186,183,208,143,73,104,206,175,87,122,68,236,135,249,182,61,245,250,70,216,164,224,172,179,21,51,71,185,116,93,145,93,74,237,173,44,20,123,24,128,242,252,212,115,189,6,11,30,74,128,83,247,127,77,116,247,198,1,17,93,220],[101,175,92,69,126,119,172,133,149,26,108,55,188,28,73,216,118,9,69,254,233,167,127,137,209,175,113,34,28,122,219,248,128,98,166,225,251,203,93,183,155,32,18,234,208,243,229,119,56,249,57,99,46,175,254,116,202,22,156,160,207,231,55,182,219,64,106,229,164,63,142,231,150,238,102,159,174,87,17,155,43,12,91,61,58,180,99,74,164,244,237,92,29,243,63,183,96,117,233,229,45,25,55,242,117,137,196,221,176,208,44,17,36,55,158,114,205,103,238,62,177],[160,62,196,126,122,191,147,38,27,180,175,32,60,99,25,241,197,21,150,254,10,234,157,70,127,234,126,133,178,184,114,132,210,247,16,18,201,50,204,75,232,184,254,153,5,246,213,8,133,211,176,250,21,127,131,79,170,132,179,42,28,192,57,199,91,60,152,5,95,10,47,127,200,253,191,81,154,48,236,196,98,42,91,54,112,81,101,231,46,192,214,219,6,47,143,185,114,187,255,115,18,150,54,215,57,31,172,63,178,179,24,172,134,178,33,106,143,104,197,61],[147,153,219,7,43,106,146,233,187,117,180,93,74,107,227,214,129,117,116,60,105,146,222,86,32,163,229,40,179,251,232,174,0,49,249,168,178,151,151,169,42,230,247,246,88,105,79,48,254,216,131,153,209,215,103,41,33,186,143,57,250,141,214,9,44,65,253,205,209,243,192,116,41,57,245,182,16,36,69,68,28,67,129,200,143,190,214,136,14,114,246,172,39,63,82,69,58,251,249,82,194,203,233,29,69,184,141,32,97,160,14,18,52,152,1,33,236,194,26,166,33],[103,235,98,206,25,89,19,168,57,160,238,104,218,240,21,68,232,238,5,142,163,134,143,72,148,107,191,195,56,75,99,70,0,137,75,2,131,161,45,131,10,118,103,69,92,179,203,190,132,224,244,52,214,200,53,242,117,161,233,241,215,84,250,66,168,56,150,157,155,225,156,33,128,249,88,39,210,120,160,0,134,116,121,194,117,34,255,240,72,19,169,178,229,89,10,28,91,231,174,52,172,245,230,45,66,168,222,242,186,255,62,0,229,219,140,37,102,236,93,194,208]]},"proof":{"cm_w_vec":["mdzLu6jymsH-1GdVlMOIWjkQyKKhx5v2iyrmG9IauqzCtS8PBN6VA8hU8GLfPMb7","ge8nWU-XuAa7jm6HvNAr9JBfgXQG8K7bNuVWVZmXVdIgMeuqekZD8CJ2OWTMDSt_","kOTv9Fas7NSf-Hi7_6MU1UTAOPNY0y13vjtSTcnEZUMoabKAzbZAiWw2H8lF1NWM","sQBSYwYoB47kMUCXSmbFLiREea-u9oxTDjeH0zKI5PoioqjSvvFZjs4rmLAKPE5n","kwMfhfmXm0t5tpk1JycqApd4Yxno18Yb4Q6jQL3ZzS7RJTUMCppJjwXE13govpKe"],"cm_t_vec":["sUJkuhQQ8jQMYxa91oLvd6i0glqexGCr7zO3QexwfKcleMa2-Vsau0RnUXnTvAAF","tmIBX9PbARQd6-da3mTehCwf21iu6DfOtjVjQ8E4xYyDEcT82OgI4f51JJ4P86yg","rUi-c5gYnawfOGvCoIC0rekZ9ijkBCldsRzsvZ3IAQqcpZ5_omo1KR5iFyIaboEv","pcH1d0nkL5BMp2S08l7a-3yvDTc5SemwfsiVvrUBSit7pfN0jZWEN8Y3qKIyK7tX","q98zMSqahidgEfPkqL2wzDtbXpuPUUbi3sNzdCXHlvQSXlXs5IT-_-5QzKN4FA6p"],"cm_z":"j6eYFnVnXHcx48A2VW2imKibCJ1FFeOODJQ-Tzhg261c1JACOiPUh-AFzfr4jpnb","prk_3_poly_eval_zeta":"TE6Lrz-5vc5gw6WLUIIaUzafjkAQlv0X3ccunkFoLFQ=","prk_4_poly_eval_zeta":"ZpuTirz2sOXk5Pxc05nVV0ueSljt46wMxG-mHcsh8ws=","w_polys_eval_zeta":["TIAeKr9toO_LCAaD2fMoqXtyp_bkx-BMbBCExZvzlRo=","LJq4WifZq5A6fB079kF-0wMf7wvIDxMjN51Avb7Qa00=","AIrScOStBA-gL5uNa9ai65j-pwdKliEVRFC9Z1XMRkg=","GBSZqnIt-o7M5rVIEIvAbpTx-Xfe9YqakL758mCAhBY=","Qj_fet-by1nZheWRlrK_eEpTjg-bJ-6iocu6GYU66Rw="],"w_polys_eval_zeta_omega":["UyuhYqV2Jh3quN1g6e895ox7qlvFV623omFCFWAlgGE=","MPG6GUjnUmJ7TQq6rdQYXNFkMlSKjr_0O1DLAwONDFU=","q30DrQww85iHA5fbnVan4xuUuV6dFzULHl3lwo1wB14="],"z_eval_zeta_omega":"ToObC4RD7p6UrlRAGFPX7o0CQ8LoNrp73I-FsOYWgF0=","s_polys_eval_zeta":["2Q7DYgbGXhw6wF6QYEo8GY_JULEPSWBZmSNQx9bjvWE=","PN4DFH458rZ64ycID5YJU9c78NSeqk-7kkg4u41jo0Q=","3zfrzbFO2ntpGfShMNsxQegEPCSPhY343rUJj-rofAg=","2IeQhgBCIa_15FH-imGaUho5acPZ75_UpgfrYAn8rHI="],"opening_witness_zeta":"t1xQCV2-BGOx-C4Z1u3cy7TD1a2Gm-jqQ6sp4H_SWAHu2SPTNqWPzY3OVynu-ejM","opening_witness_zeta_omega":"rxw02sr8LYVpFSTZa3qHBLoEhuIaEQYX9SF7BOb95kGDe6tTgtWuFcwyNjHqPO6s"},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"6ovOhYh-2lW03RQNbMmy8xSW5-EDNC8uSS6T-srcmjw=","randomizers":["SpVVY77JXgrb5j_dhaDiQ3dazkbiTrsP_K1XwQ1Wli6A","83imF0S9eWrwL-cf6VVoEf_FXgMM4mcNMzYx8Lz0I24A","aQJYfTHIsAefuLaiwLd9NMgD8hpbP1fepYPYL11RxkuA"],"response_scalars":[["XQs8leulUGbweKuQll4i3aZHXJ5jqjbbM6gwmOuSKV8=","97xFGkotyxqF2EMeLEKAREr3HpUxzdl2h2PVx7gAkwo="],["-HboGfJSVg9-zIJiwz42uv8yMxYaExQRBAilnPIdeV4=","j_uGKTOT6NUmZXST6yv7Rd8o_1Ohvq9f_dD8U8s8wj0="],["-rkvBJwIObc8D62RZU1teHfCkoIVTMtiZuOWZr0CdxM=","NxF6WCWU4SArXbEux1ScBMskpGBpcm_n8E8fGF87n08="]],"params_phantom":null},"scalar_mul_commitments":["iem5n4gyQMdwvqVecQ4z-hgo7_rn52_OKhsTg-x1REMA","_V3wh7vRyz6BCgn3c_HDTudzIWCswiC2tUsy0KldRj0A","1yLAwAW8w0Sue9BuWMIczrEuS5ehoLtqCl1xVJNxvAYA"],"scalar_mul_proof":"dgR_Vf8tJHsqvPJIrNl_Y90nlfvpxQIingra0ADgM2uAuZMxxKIz3aUJ7_ry1vg9YWxM2I8qJMkqNUpVAkwPJzUAgGNhgRV7UxSSJswpxpK2nbD0LeXyTM5pFTSUrrE3GTmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAYA9rl6GQzFZ4A00YJw_y3znqfsk0kFEZbyHgvbejxzyASrv-mdgUrCnF0o1egtXVR0-NA_pGL30Hn2Q2g1haUDEAikmPN0o25Ykke6ve-HBISWBw9ktnYiPZBepWYVNT8EKAJztHTJCVhzqWJCmkNbaDG0gZC8lfN0paizZPZSM4n32AyUX25anUVbWfD8N8IQQabdMXaUOB8NayWNcRjypLB1kAu7NlKT4d3tXM1RJFPYBSxvcWZNoSbbevUZ_yoeC-a3d5ClLMa4FUnuX894I8p5ATdE8EGnh6kx79R-YyHbFdf_xqt24bT6fpFZtaX9iqb7Nqm33wrIBx2eT8m8vE4ggPCwAAAAAAAAA14gBnMJxk5yp0tJKsgIWHUFAdXV343ZBo02Rdql-ffIBMmsn4CHRvY11rD5kNitflww-_3HXkYC1DIjdbfw2XMoAkntlg1LAsHJuCwA8kPEMxbzOdNqHYiuBDo9jrxBsJd4ChZr6JWmGP9s5xGf-UKjsSDje_r9qWBpM6fCYKIAqkTwDffiWyDCtKfZu3sTxy5FAlsCqGDgUIihMXfafH_houeoAK6QfQMSePHOULLtaKz9mHPd9C5eqNejQCmt-yjgwEe4ADisI3rZGUnSoG12sWXtWPnF3lAxcwcbkwlV-QGfZtewCOCluc9mqMfuZvFT-hB9xgUz_5lc07JoY7RftjfybsW4Ad7FKk0z9iPeb27QJIy9o2DknNKmxVsJvnJD9M7h_-LIAsDQcYW3jtDPqgdziFy7TLxiN2zYOtqAxw4OkDBM5FdADjponAWqv872jHkMu97pZGL5rvwIMbb9-x2gZMXP6SQgALAAAAAAAAAMO9LoHLolV-p7XLQbylj2PVddSrQ_XzYIOOCpcNIp1sgBvnQPgcJy5_rzvi5R01U5tVVQCKHlAPt_VCfGiRH_NYAKnbUvWymLrf_Pw_0a_1dNJcR_cLWHUo6RNF9rvqGzAWAG72QKpPUhLcMwK0_7WD21xUd3n3ic2oLzBLl-d7AfVDAKFd1XpNfkj_Xknpr9C-Go8_bWGRPrCzHYf39c4esp1vAESLWGjUvgpkEYdGX5k2lICtU2uDreqnjJOOZHSuF7Y3gPKq3s7ZGqJWrAvci3Y4Mly8dRgDause0lL4r9ZNfN5mgE9h35ZB3qigJ_Qgbjb5o2cjrGuZ2j-jr2mq0TEPF11IgDIbB5VGDR2xTBgSGK0b2sWVfkYaAL8iSxMU_wTfn2NmgPN8ZSFcW4MFydb8738nZB766l-JkeRgPUxjdGdjLfNwgCASg8aBmdigXT0Kmzt2OUL8bOeOUjrNy4QMlbNAG9p6gFMSfONwi9Szc-TJeOD5iUr2NNoaxptPAqUs5SOG5Owe0g-Z9adNkdfUlz6YY7Np5mVCHWWqr9ZQiKEgN8s5QiA="}}}
        "##;

        let note: AXfrNote = serde_json::from_str(&note).unwrap();
        let verifier_params = VerifierParams::load(6, 6).unwrap();
        let hash = random_hasher([
            138, 93, 172, 207, 171, 142, 70, 149, 66, 76, 30, 47, 29, 208, 38, 209, 33, 242, 143,
            148, 153, 191, 175, 159, 147, 178, 209, 183, 247, 103, 217, 23,
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
        {"body":{"inputs":["O5AJCeCIvagg3gbfubl9Qc8DA7ZfMC9jSvy-Oakf0GQ=","GEr8nh1DWdfOtLrvAvPc9KnMR21pbyt4DpiBxubAv0A=","PFMDPKPQUJLjDhdlV1SFL6mElpCu9sno_quBp4cJMGc=","vmAMQGhNR6EzN19Y60rOzyY3gcyKIwmDCe6eGj-lemo=","CYutoG4Ez3E8NHPzcvNohznEdHt8CaIxs9Pcc9dLo04=","BcA8CVvw6ZLtsht_2abrde0xwRUzpZcoTafKct0fTlE=","WTTIfcBwBnhGGb0nWLIHUUdumeiZj_1rI2y1Nelt3SU=","QI2rrbcgSkfMmAe26T_rab7a5wCUQLsNczz0jvnu8k0="],"outputs":[{"commitment":"xcKY_8NNUY2ixzeiA1695lYQ4j0X5khFqcBid0QasR0="},{"commitment":"jW3pYAlYKSalsl0UyR8cCaNwkrt266jPCeMZx8JJzFY="},{"commitment":"92waogNn6Dr7CtEGRKUMVhXi0-H2K4tjSLlKt7SOiEI="}],"merkle_root":"trGXl2K_iyeHi0SOg058ih6ltVRtE8e1I2jJVnjEggg=","merkle_root_version":1,"fee":19,"owner_memos":[[99,21,47,123,1,1,127,242,97,147,178,44,124,242,125,94,16,88,102,105,115,122,170,68,72,10,120,60,101,10,213,44,17,235,30,187,165,202,167,164,101,12,149,144,116,43,4,150,167,79,84,96,69,199,9,179,1,50,28,223,203,136,192,193,124,208,85,254,18,35,184,237,16,159,3,62,88,182,198,138,10,202,151,54,110,185,164,228,77,152,214,16,181,71,164,145,250,91,118,152,105,140,109,105,208,179,186,72,43,81,184,167,83,91,227,250,2,240,85,103],[56,115,254,146,243,70,217,100,106,16,57,223,162,40,182,194,113,34,64,186,162,33,193,210,24,234,165,61,206,143,8,37,0,83,203,95,187,173,244,89,153,20,85,195,192,82,242,171,145,64,206,234,28,149,12,148,213,83,254,24,217,223,138,71,210,98,228,250,86,218,214,155,113,53,154,230,237,40,11,45,107,163,46,254,76,42,99,183,207,151,108,168,126,89,58,251,24,38,162,77,214,88,137,89,216,76,9,243,166,126,27,115,213,99,1,30,82,138,200,74,182],[75,14,232,16,153,36,156,91,189,199,17,101,81,254,68,104,245,43,71,112,175,238,0,46,201,7,102,11,154,213,131,120,254,6,45,127,94,241,192,31,199,222,34,67,134,40,111,167,106,39,12,135,48,65,7,11,32,180,48,193,168,153,207,250,34,122,126,41,70,12,110,111,181,243,102,79,95,212,205,154,219,217,184,51,29,249,220,75,209,95,35,63,136,76,2,233,254,66,141,205,0,108,96,220,160,1,143,121,20,228,88,29,41,124,175,96,55,86,142,152]]},"proof":{"cm_w_vec":["p6LMIB0xOhxwWgcQEG0r7WwvHxhVeQjQZNBp-Bw3URXME_awGG2nB-H0UgGtn6K-","lq2Jtq6gMZW8u1pAPUWF5bmjMh_cg9v7Ois5LWYBCxxaJas7L7BZUdRUoXU3eAuf","kO4A_4rU2ij9JBi8-p94lmsvuhzmD1CST5rdeeTyNglITfse4-_yuE3TaLrKa357","ptRA60XvZMlQ4IX9eCJcKQEzXmMpRt4NpQ8sefoxYg8pA3TKcI1MAHu80mOVtDzI","pCwuLGpIxcV3EXIfb-HTfRWmEoPIeJJcpqH7zYFufoBbJPFbwUXJql-dlT1sUAt3"],"cm_t_vec":["iDhYkueNPuf4DR5B6avs4uMYznzXxKphwuBJPqyEPjPyO02FmYETxijHWZtIhLl5","twZUVoziibFnPGgkeITEkQ1kNX36ztaUfO8yBz_r0DnDu5k1bjaonXfJtV3bwdkB","t9KLy9DKobOwY9Lq-XhzNuMRhHhhWNRMRI49Z_7le-1hbmanDh8hjlgDrkznJZXX","ifHThjRvCy6QnQn4cVRG-prFIWXee0JnERK03Kj_FGcAAGbRQ8g59cLuRo3FFXK5","ovuglZeliPa6KfsM9qrHV3InMVeD5s6IRLB4TGJuNh694E1d7DmHZC_wQP62aEOw"],"cm_z":"tBA7WHWNX-W7AwQPjaBzPvc51JjJQpuej6IOCcQUoQFuQkhXPlkzEI7CFj93fNL5","prk_3_poly_eval_zeta":"McODTg813y42VQo1Iax34y5lUuVMJ17od6U28prLCDY=","prk_4_poly_eval_zeta":"R_o4jahx-lmMWZWeiNy2F0WmnAwnhd6oo3W_RgLXSjo=","w_polys_eval_zeta":["aHZv8txbLw_IOSzfFmlUrRQd11Xs3t3sTZRvb7K650Q=","oKLDkPK3gLdNzO5bpjKYGtG1_IuePUjhk3oHJfj1Vmo=","xMlkWinBE6JNpLNK3xheU1VshEXLclYFUVCapIS_tAw=","-Oelunnq2RmJQb2z6sRAf4HgVBk_SoXsilmppSAIbEo=","TPztU1LE7MyahZzfC2lymMRVd6I5rkarv8QZlG_4XS4="],"w_polys_eval_zeta_omega":["crpV_qhKnrFBMjyLYeo7c3xUhsRXl4b0Az10pvQKNVU=","6EEMTf6ZHmrWojBZ03XKZhex4UV6Juu7k42LR0C2tDY=","_gty7JTueSyDJ435mjhMpp-LFbKrPp0NxUdILr035VQ="],"z_eval_zeta_omega":"-Fmv0izPDQHLJCoMTsyhscAQWppRHTtKspdGt0qPUU8=","s_polys_eval_zeta":["Jpg1cXjR2j5--U16DzZ6CWo05yIOcl9KoLB8itOYfyo=","aO4T87Woo31zmE5FdFRT9RSLFjS6MgNoRV7316p1Jl8=","VLOatuzQGjv8IGxX5WnUZpccPp0jygEVuUhiKexlXCE=","_Zvoc7FT1LvWx2fIHqvx4sfvBv_-2hABCBRrNfgtehc="],"opening_witness_zeta":"iNY2bf3K5YpTfzRXLGTYSx8BpODInnX8TVabXZh59MNmh3n_-MKSxUKPdRhhmY0S","opening_witness_zeta_omega":"sjONndsLoY4-eLzq0F0DZegkcqnUU9vKUKaNSdha621BEKjyInZIu4TjU6pZiYum"},"folding_instance":{"Ed25519":{"delegated_schnorr_proof":{"inspection_comm":"ubXpMold9n_1McrZWUQ26qp0Zubsh3VodROgzfJRR1s=","randomizers":["9qsMVwEU2Y21ePH5-1I70hkDLrdLC7uFjUNV7qKkYm4A","8CktAPcVLJLI5hLbxcjUVmY1vb5dtBO0bQP55siVvxUA","28YoC6fVC54YIHc5RewYkfeUvfjRe2qLV93V4i9rMBaA"],"response_scalars":[["JjSRr33G8fhJWP2jsPfzMfV6E2IxCsSbXNm-JzxvHhU=","kToPMoByNOCg09WggIL5etwUl4eqIC6NlPigEP3--x8="],["XbTf1G_csGvtOimugg4-dNV8fRWHMSmxNS70nIxg9R8=","pYAWeDQX4XdsbruaKjaVRfVjlElT-fth22KNFCwIhnw="],["ixDN7KZnw3D3AEzlU39NKaE4PDand5APAy5q5v0o4SU=","2A_OmiwI6fYI1lUHDZnv49g3TlB3a7MaxwjtMpbYAR8="]],"params_phantom":null},"scalar_mul_commitments":["PLx-3E1A89jSv7feKe6J13d54GDHJmUSLM1pCj2ceBAA","oc10EOH5CgtCTAiV4fXN4Wg4su8gj4hQ_iVOr10Eb16A","X4UDe8L-rW9VjgvVBA51WK59naeOF3Cn6Lv1u-hvomEA"],"scalar_mul_proof":"mvfLmeTcY4eH0W4DkIuabMZGGvmoY1IZUnsyuuDEPSQAbKMU1VrBeE4BDkDm1T6xlJqHTsegxo7zcltpJm8a2muAZcFxR24OBMrUwQL7kN0FgmtBDMkKoT8pp4cIiHVami2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA6waA0sBcmLq-Z_Ku0TSan_biqXf-2DUmSlaqyaN7wy2AEqpMrer3HyT7yUanbwJkXXumA7etIb8s50Uyk-wQ6xaAAoooMer_evKHKrtJXF06J0Ii-AlUIqcuSxL497YI_TEAKSTWpLdprJ_DkydAmd67k2wNhvJsmeg1w3mkkqcY2gEAb7LrgskSQtnOQeRalbboDGi3oa_HKT1cvu4KsbkPA28AfJHOA76_kShzlCqSiY8msJHsIROFSd8gdnPoO3YjYGO99A2KF7KAm4gUyU8y6T68Y_dWfDpFMeLq835ZBebJfLuPrpZ-AzeLsWQzVXSnX1Uxqb1EffKTyhW4E7bpe8c2CwAAAAAAAADA8J6Qt1OkvLlgLBikp4o9T7T2xhqRzNsZOI0bUty5MYBr9bTy5wsmGQszg3acKU5MU7fqA8DStIm3dwiLyF5IM4ArYD15wSzgVIW9uUXhfZgwrHTHDldSl9vieHt6ZB1JQIBkfPrCDM94e5M7N0ILAVOLwSFyLlqofZP0aL1XWosfQQAiqdAtdWgfvKONrixDLczw_hRDnBtqYdrMBd1bgr1TJYBwBk_ipjQE8l7P6z258Z9n5Ia9Cfrp6NJQZYj_xYhYS4B2dZhJ3Z7jBNQGuZnG8vhG_1-xSi4SG0U1_WSbveQlU4D79xCuWWg3Sk_nks1_IKSD-cs_MSkaUq--L8tqOg2UDoBarsATaYyN_wuTw5NrkLQsO6DJKzVERyIqqtcx2e7cRgBPWXsofIFSwupoqVXTjeza6evn-Yeq9P_WoCxqpfFQH4BfNcz2yc9fYrRKXNHpZ1sSX8fSJAzHM9LzsSBDt8GzawALAAAAAAAAACjvhOhN9ICw6pdGiMEtnSnnxZ3KdwpFO5VtYzRlBoEggNfLeKO4Q1IIoHmA9FECfeXTtYDlDzNFpTRo5G5PBW1lAIGxPK4zycEFKHW0iiLuBYQcrWbfrR7gP2fl0p2rO25UAA2kLRK1oAOVY7PVy9Q3uJIPy-mnDa_hxieP2o6EeDAkgL8LXoNdOGgErhl6IAWNq0L7_zA9W1ogce6VHGALH5dVAOXHYd-a7jTiK47PJlAQ32eL8u7LqtP89Jne_b0IAdNYANW7ayf2kzAXAJlunrdjqVY6mxUL3L-KsouKqSZkafxpANMYltbgG5tqYlbbioWO0n2Yke3txKJhQ4SDUUc132o0gB6JHmidSyQMJVk-7SpVNnEng5Op6GDauFKoxyxA_HkbgH5MN1FdQZ2z2azU28HOna2yI4hnflKBtL-ezPPyRGAxgMOyRfem1UYslaV7XK21HOT0RTUav-ErlxcznWXByQFUgIZ47GgUCTbjr_lASi7GCyXthZbTLIaBiKJBvpXAkD57ATHW8F_pnrItolnngxeQ8rulXrZqiqi4ixb61jq34R0="}}}
        "##;

        let note: AXfrNote = serde_json::from_str(&note).unwrap();
        let verifier_params = VerifierParams::load(8, 3).unwrap();
        let hash = random_hasher([
            216, 56, 2, 214, 211, 43, 31, 66, 234, 54, 186, 194, 147, 42, 173, 164, 20, 93, 127,
            152, 132, 182, 77, 80, 104, 234, 133, 223, 114, 247, 96, 245,
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
        let params = ProverParams::new(abars.len(), outputs.len(), None).unwrap();
        let verifier_params = VerifierParams::load(abars.len(), outputs.len()).unwrap();

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
