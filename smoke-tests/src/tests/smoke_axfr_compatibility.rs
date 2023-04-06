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
        {
            "commitment": "jLyF1QvHZxG8UiQUodRld0lWYZCPdaadlSGy89ftDhE="
        }
        "##;

        let sender = &[
            0, 18, 115, 1, 38, 225, 96, 96, 3, 28, 79, 118, 104, 200, 211, 56, 166, 152, 195, 188,
            224, 41, 96, 232, 88, 249, 187, 155, 237, 9, 155, 246, 148, 45, 69, 91, 183, 32, 196,
            218, 240, 145, 94, 185, 178, 214, 138, 124, 131, 204, 109, 86, 73, 196, 128, 126, 9,
            84, 233, 239, 0, 50, 75, 202, 207,
        ];

        let memo = r##"
        [10,235,37,47,222,22,33,206,91,84,214,234,67,44,61,17,29,215,151,86,180,49,81,243,91,66,254,99,220,72,69,111,44,102,25,250,180,27,93,170,49,204,40,123,131,248,169,4,188,2,110,169,39,119,11,79,154,189,113,144,23,253,184,49,225,118,140,181,5,203,44,175,126,163,219,127,108,246,150,229,54,124,251,1,241,174,209,81,170,108,159,117,116,20,53,43,52,140,18,175,100,99,250,158]
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
            "commitment": "qrn8W86QjG_jFvcA_h-705wB-s-IgoJKNG0487VbNyM="
        }
        "##;

        let sender = &[
            0, 1, 208, 23, 28, 178, 79, 99, 119, 41, 218, 186, 225, 203, 254, 34, 89, 67, 136, 129,
            46, 231, 217, 150, 88, 225, 255, 62, 30, 132, 214, 198, 156, 204, 251, 214, 73, 172,
            177, 250, 164, 152, 87, 95, 33, 93, 238, 111, 10, 132, 21, 55, 122, 15, 204, 77, 61,
            165, 52, 178, 10, 171, 217, 204, 130,
        ];

        let memo = r##"
        [252,252,118,224,164,114,86,198,62,220,213,172,231,195,171,153,99,146,174,68,112,164,195,228,86,244,184,151,4,92,3,74,39,24,57,139,132,141,217,16,16,187,100,15,207,244,177,232,6,141,77,91,107,229,249,96,153,185,53,122,65,156,83,252,190,35,42,212,131,114,26,23,239,1,68,203,56,134,64,129,102,240,4,192,24,124,250,96,170,165,23,109,81,41,231,191,17,230,147,110,226,84,197,115]
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
        [{
            "commitment": "JaUpJHdFrtBwXyqGgaJwIQrHqfHqif8DKaHqSVeQ1Us="
        }, {
            "commitment": "IvBDVdZs-Rxo12gB6qPKnJH8MrwmvbKVeVxU9ENNcz0="
        }, {
            "commitment": "YG3VPSUenKO3NJb19k6REo2kpQQq70dahOjKej6TdEI="
        }, {
            "commitment": "AYa9-D8aIwMwZhQfx-CxMWhODluDVNRSpXIIp2Lt9HI="
        }, {
            "commitment": "I6lfavuxXahzqDWrAbST-2-rxvHoqyQCQyFn0d9Vvhw="
        }, {
            "commitment": "ilJHGuGKXva7cFiYF8WByIHJaO6UGOUTkgUDLZUWdwQ="
        }]
        "##;

        let sender = &[
            0, 129, 0, 4, 230, 51, 70, 58, 2, 67, 89, 251, 116, 83, 10, 89, 111, 195, 43, 139, 44,
            30, 83, 143, 246, 233, 110, 3, 119, 248, 180, 164, 22, 239, 11, 163, 184, 156, 158, 9,
            32, 243, 246, 8, 75, 85, 32, 152, 219, 2, 159, 202, 5, 21, 219, 58, 228, 104, 160, 175,
            150, 198, 9, 30, 196,
        ];

        let memos = r##"
        [
            [192, 142, 108, 75, 246, 87, 227, 89, 3, 106, 165, 237, 8, 2, 151, 4, 217, 169, 3, 227, 142, 96, 216, 212, 30, 71, 123, 152, 13, 56, 122, 104, 159, 68, 122, 133, 164, 252, 141, 222, 159, 244, 85, 238, 4, 106, 50, 230, 182, 130, 154, 12, 206, 245, 194, 62, 61, 246, 50, 182, 61, 29, 22, 81, 187, 159, 123, 115, 214, 62, 205, 21, 109, 175, 143, 241, 111, 196, 34, 242, 30, 245, 83, 230, 238, 35, 207, 16, 35, 192, 253, 232, 172, 119, 43, 79, 91, 107, 250, 201, 64, 214, 102, 195],
            [10, 64, 41, 241, 154, 6, 227, 71, 117, 46, 190, 32, 126, 216, 53, 194, 3, 74, 238, 145, 59, 178, 241, 192, 139, 210, 19, 160, 246, 131, 57, 5, 246, 223, 181, 3, 79, 240, 207, 82, 208, 173, 82, 158, 174, 164, 183, 236, 76, 25, 2, 172, 109, 46, 155, 50, 13, 163, 62, 111, 177, 106, 108, 49, 209, 173, 126, 120, 180, 76, 211, 166, 46, 33, 251, 101, 217, 1, 137, 122, 27, 177, 187, 172, 118, 236, 198, 50, 163, 237, 96, 123, 97, 216, 120, 187, 173, 227, 40, 120, 219, 238, 177, 141],
            [29, 249, 226, 86, 75, 130, 30, 77, 250, 134, 165, 255, 247, 63, 218, 203, 40, 74, 78, 166, 6, 234, 230, 131, 115, 49, 67, 16, 37, 236, 16, 119, 236, 174, 151, 139, 226, 210, 238, 119, 112, 253, 52, 218, 172, 16, 56, 217, 2, 133, 58, 2, 95, 1, 191, 16, 86, 224, 35, 30, 49, 197, 111, 64, 63, 111, 146, 130, 38, 12, 207, 240, 12, 98, 59, 113, 85, 209, 52, 119, 170, 187, 11, 77, 110, 167, 203, 117, 249, 72, 123, 7, 156, 233, 26, 129, 111, 94, 27, 15, 192, 215, 120, 55],
            [218, 246, 221, 26, 2, 126, 54, 91, 100, 85, 203, 199, 174, 250, 184, 21, 133, 222, 153, 252, 180, 6, 10, 91, 99, 173, 60, 175, 216, 113, 125, 81, 233, 85, 110, 202, 191, 200, 149, 89, 97, 229, 171, 98, 149, 116, 55, 94, 40, 44, 95, 255, 19, 115, 41, 228, 38, 162, 138, 54, 139, 203, 169, 212, 195, 109, 162, 246, 10, 254, 159, 238, 60, 235, 213, 230, 215, 4, 81, 88, 19, 181, 157, 247, 125, 52, 247, 108, 7, 182, 207, 41, 180, 163, 85, 14, 149, 223, 0, 249, 188, 88, 149, 228],
            [1, 190, 203, 110, 11, 167, 105, 64, 224, 11, 226, 22, 223, 37, 123, 33, 93, 80, 194, 233, 152, 108, 5, 122, 33, 6, 232, 174, 48, 137, 98, 26, 173, 206, 93, 114, 38, 103, 221, 255, 215, 43, 250, 139, 49, 131, 234, 52, 95, 221, 238, 30, 161, 177, 216, 66, 226, 228, 201, 149, 254, 189, 99, 229, 35, 220, 138, 137, 60, 95, 160, 34, 92, 243, 143, 176, 39, 112, 224, 96, 186, 48, 106, 76, 156, 56, 196, 157, 145, 135, 199, 108, 27, 202, 11, 178, 227, 152, 18, 220, 198, 244, 62, 241],
            [115, 129, 165, 147, 113, 129, 70, 220, 245, 245, 182, 142, 17, 163, 25, 107, 92, 139, 126, 15, 51, 64, 158, 42, 178, 14, 165, 172, 87, 118, 32, 95, 24, 210, 194, 249, 132, 119, 23, 217, 159, 147, 26, 81, 100, 156, 75, 75, 150, 10, 80, 120, 47, 228, 130, 197, 203, 153, 56, 243, 129, 126, 240, 29, 6, 147, 52, 149, 98, 20, 119, 90, 163, 44, 60, 131, 101, 94, 183, 103, 236, 181, 30, 248, 161, 47, 103, 144, 0, 203, 117, 77, 200, 79, 16, 255, 57, 63, 161, 119, 191, 103, 197, 47]
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
    fn abar_8in_3out_2asset_test1() {
        let abars = r##"
        [{
            "commitment": "n3GigxJ3P7LyAiVfbYenw7PjfkDYnjspt6pXnFTCcnI="
        }, {
            "commitment": "CNUnvSeJLdeZv62Nan3CWKBs1n-iSBxFfBROCfWF-Cw="
        }, {
            "commitment": "BiTkYo0XukgfGR54Bp9_PhS1ECrkukyn-wFdt-OaD2E="
        }, {
            "commitment": "S6tE2sTFkesj4PaYFG1Tjrgt4mLlzI9pWxs1wXXhpU0="
        }, {
            "commitment": "HZ_-hbiQyvainVrqOjZeWioTnPvN7zM1c2ye8EBk_Sg="
        }, {
            "commitment": "vcyiONwFeneyjrVpWGEvIYw5nVy9kr3B8qt4SBPxjWc="
        }, {
            "commitment": "kLLdsFTHlGTLbMiEZA8w_jLsYn5Asx4QFFYfjph9x1k="
        }, {
            "commitment": "9eJGjAjkC-j8HeWJU8-2JW1IhyvGgLXu8DTtPJgkNxo="
        }]
        "##;

        let sender = &[
            0, 71, 127, 50, 47, 5, 51, 215, 80, 53, 19, 188, 213, 0, 10, 217, 22, 21, 196, 47, 26,
            81, 114, 20, 158, 103, 163, 164, 51, 1, 254, 200, 236, 248, 149, 106, 83, 191, 150,
            168, 96, 137, 34, 6, 156, 72, 235, 178, 118, 238, 22, 106, 64, 204, 170, 241, 142, 124,
            183, 232, 195, 186, 173, 18, 237,
        ];
        let memos = r##"
        [
            [59, 27, 163, 36, 97, 46, 138, 159, 81, 83, 65, 84, 179, 218, 109, 19, 142, 201, 217, 225, 52, 74, 184, 230, 35, 232, 27, 159, 12, 109, 207, 79, 240, 231, 29, 246, 241, 202, 17, 153, 170, 38, 160, 147, 192, 237, 235, 71, 209, 186, 46, 22, 157, 130, 100, 29, 147, 254, 242, 12, 232, 172, 97, 216, 230, 4, 23, 99, 54, 209, 242, 206, 196, 109, 181, 105, 216, 21, 145, 254, 128, 152, 135, 19, 51, 97, 131, 87, 37, 90, 67, 113, 85, 64, 90, 6, 242, 163, 78, 211, 27, 255, 208, 227],
            [93, 192, 161, 215, 69, 60, 75, 22, 112, 158, 160, 168, 225, 33, 5, 64, 244, 173, 131, 130, 4, 78, 128, 162, 52, 61, 51, 71, 181, 140, 120, 19, 115, 54, 172, 4, 156, 95, 10, 140, 6, 88, 0, 254, 251, 73, 33, 246, 55, 15, 115, 25, 76, 131, 106, 146, 153, 143, 203, 79, 251, 40, 182, 247, 248, 128, 182, 205, 8, 79, 40, 163, 224, 210, 64, 75, 72, 52, 52, 93, 218, 134, 227, 197, 178, 25, 241, 217, 214, 90, 215, 228, 184, 241, 223, 18, 13, 0, 251, 51, 50, 180, 135, 145],
            [244, 35, 103, 61, 121, 38, 127, 119, 21, 88, 34, 252, 81, 33, 43, 161, 164, 22, 208, 80, 35, 135, 0, 190, 158, 8, 198, 129, 133, 214, 51, 27, 29, 56, 20, 55, 226, 9, 167, 197, 104, 242, 130, 205, 125, 93, 117, 1, 78, 100, 56, 147, 153, 138, 76, 13, 178, 153, 218, 23, 81, 2, 19, 81, 29, 197, 229, 126, 38, 222, 118, 76, 37, 62, 223, 56, 191, 179, 197, 21, 21, 100, 129, 49, 84, 205, 98, 122, 0, 159, 198, 220, 140, 30, 125, 222, 186, 231, 91, 21, 91, 68, 54, 8],
            [28, 127, 151, 216, 222, 4, 148, 196, 161, 68, 50, 170, 227, 215, 81, 235, 168, 190, 251, 62, 70, 204, 42, 236, 52, 29, 166, 3, 60, 234, 30, 88, 46, 108, 10, 9, 252, 150, 120, 167, 21, 218, 43, 224, 126, 73, 137, 193, 21, 213, 191, 189, 236, 26, 180, 22, 105, 251, 183, 121, 69, 45, 184, 48, 154, 150, 39, 197, 0, 255, 70, 148, 120, 167, 121, 186, 157, 66, 98, 54, 255, 60, 175, 253, 218, 113, 72, 245, 168, 37, 127, 54, 254, 20, 133, 223, 95, 205, 26, 63, 213, 127, 210, 179],
            [35, 170, 168, 244, 109, 118, 215, 123, 173, 174, 16, 212, 176, 118, 48, 201, 134, 173, 231, 95, 16, 181, 54, 79, 219, 224, 168, 229, 140, 195, 169, 115, 52, 218, 100, 138, 87, 201, 53, 178, 21, 84, 2, 66, 129, 238, 16, 248, 28, 119, 178, 181, 176, 61, 183, 48, 96, 235, 222, 186, 30, 60, 79, 103, 36, 136, 147, 21, 189, 106, 73, 9, 242, 215, 189, 82, 112, 237, 14, 23, 78, 64, 152, 199, 97, 117, 20, 162, 118, 255, 208, 222, 16, 60, 33, 107, 104, 134, 181, 121, 207, 85, 208, 82],
            [0, 81, 5, 199, 44, 125, 243, 124, 203, 81, 219, 11, 147, 86, 3, 158, 133, 79, 161, 22, 206, 141, 210, 7, 6, 89, 160, 109, 209, 180, 61, 31, 117, 86, 172, 133, 219, 182, 142, 183, 80, 147, 140, 71, 136, 3, 169, 159, 42, 50, 159, 159, 83, 176, 72, 224, 92, 59, 26, 207, 214, 240, 82, 235, 60, 135, 137, 189, 127, 255, 136, 115, 201, 79, 46, 86, 124, 170, 178, 87, 208, 83, 157, 82, 219, 191, 197, 26, 159, 224, 71, 63, 16, 133, 153, 5, 226, 243, 137, 201, 118, 58, 114, 171],
            [4, 49, 139, 18, 6, 135, 156, 11, 37, 199, 94, 75, 181, 250, 57, 112, 233, 1, 190, 152, 252, 240, 117, 230, 69, 192, 192, 234, 122, 119, 72, 32, 83, 183, 251, 137, 96, 11, 172, 89, 52, 191, 213, 33, 180, 229, 54, 98, 120, 187, 180, 169, 123, 97, 15, 190, 255, 218, 238, 201, 114, 254, 209, 13, 118, 195, 18, 77, 115, 69, 161, 160, 145, 153, 241, 10, 0, 141, 218, 170, 205, 58, 103, 112, 117, 134, 8, 238, 47, 76, 160, 3, 67, 157, 77, 192, 228, 210, 177, 118, 172, 243, 62, 38],
            [68, 23, 206, 243, 28, 243, 95, 216, 113, 28, 104, 245, 176, 25, 97, 229, 83, 143, 7, 65, 163, 33, 213, 51, 45, 118, 38, 186, 156, 204, 212, 127, 25, 4, 58, 116, 10, 208, 221, 250, 124, 161, 220, 153, 64, 144, 150, 52, 5, 251, 94, 229, 182, 174, 78, 65, 50, 115, 135, 113, 217, 162, 164, 76, 217, 110, 104, 134, 195, 35, 237, 128, 30, 252, 184, 60, 157, 22, 79, 106, 41, 241, 30, 205, 137, 206, 157, 172, 100, 82, 133, 59, 38, 36, 177, 64, 46, 87, 220, 183, 162, 161, 10, 69]
        ]
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
        {
            "body": {
                "inputs": ["afg5qLWVwCe8nAZBSt4F4YXqF5LYniP1Sh__MWsFDh8=", "ou1rgU31W0fvi_Jzdp1H7QGSswYL5ju9C8tFB6uiTEc=", "9JvOdHCAY1uiQeJt3X5W5Xxh7lmJ5zk2WR2p3vqvh1E=", "9JA8uH3b-Jgg6kypFKRRYH-Vj2zNtzJPaj-MHXQ2qhM=", "nq-IN1hMMwdvC9rK8n8Uk0Ji-55HqRfkPAqputIgIwM=", "0tpogURh6D0JpOu6MiK3BZH0Rj150s2iDrHOxNt8jxc="],
                "outputs": [{
                    "commitment": "-mPwaU00AuDLBoxNh7RbQm-suNf8DuuNV4touha4jCc="
                }, {
                    "commitment": "EFp8SseXO5-AtR4FlyUG6I27n4Fi7-XPQHRO4I_1eBg="
                }, {
                    "commitment": "f-OYnqX92C9Uvn2hYJ3bv8v8miqulALwh6QookhJe18="
                }, {
                    "commitment": "mJ3JarK9AwPi1qLUZVtYP9zGCwVXRmgTDPMuMtN9pD8="
                }, {
                    "commitment": "Rw7ggdweOLE9I5iJUEbgUuix57e97e9jFAEI06pbAj0="
                }, {
                    "commitment": "ZdHTw7eguCtfxUg7w86idoww8wWhJmaXmGR2OzHcUCI="
                }],
                "merkle_root": "ZLh89NMTiAlqxU2e02IED7QbacQG7d4nM8tTHXXgEXM=",
                "merkle_root_version": 1,
                "fee": 23,
                "owner_memos": [
                    [240, 116, 197, 229, 221, 230, 249, 93, 73, 126, 71, 27, 38, 16, 226, 24, 57, 153, 122, 159, 43, 227, 193, 194, 161, 146, 233, 206, 58, 25, 192, 109, 69, 52, 60, 173, 73, 190, 91, 140, 73, 174, 51, 27, 48, 153, 243, 141, 228, 209, 136, 205, 225, 126, 42, 248, 179, 37, 208, 185, 195, 184, 209, 57, 86, 53, 167, 197, 74, 40, 25, 228, 238, 198, 44, 246, 166, 214, 246, 69, 225, 124, 44, 249, 150, 155, 176, 64, 228, 69, 177, 160, 161, 9, 250, 37, 239, 174, 174, 205, 179, 38, 31, 59],
                    [232, 18, 178, 40, 112, 99, 152, 39, 100, 158, 33, 103, 26, 134, 43, 100, 125, 165, 82, 242, 7, 105, 171, 242, 98, 85, 228, 44, 98, 182, 123, 54, 219, 83, 195, 135, 9, 174, 205, 203, 108, 73, 163, 236, 6, 238, 102, 93, 176, 81, 191, 105, 62, 70, 59, 243, 102, 230, 250, 152, 196, 69, 20, 163, 43, 194, 1, 83, 152, 226, 34, 113, 110, 110, 244, 32, 207, 32, 226, 174, 33, 176, 171, 28, 162, 49, 191, 134, 86, 14, 0, 67, 173, 14, 110, 23, 69, 223, 235, 197, 229, 171, 100, 188],
                    [172, 49, 214, 75, 198, 236, 152, 115, 43, 108, 120, 10, 204, 98, 101, 233, 183, 56, 184, 11, 150, 94, 218, 174, 223, 242, 9, 234, 191, 205, 70, 72, 216, 128, 144, 141, 239, 134, 128, 223, 167, 126, 93, 174, 106, 170, 135, 53, 191, 236, 223, 18, 230, 149, 128, 53, 87, 188, 114, 147, 59, 180, 102, 69, 52, 7, 153, 194, 1, 55, 52, 143, 171, 3, 226, 53, 38, 81, 154, 224, 167, 88, 113, 166, 110, 93, 153, 231, 240, 118, 90, 101, 199, 33, 228, 81, 228, 192, 22, 60, 72, 87, 213, 121],
                    [166, 170, 157, 107, 93, 72, 148, 55, 239, 147, 24, 122, 107, 230, 151, 205, 31, 146, 32, 63, 2, 62, 93, 255, 161, 23, 1, 125, 246, 93, 240, 97, 128, 189, 128, 207, 237, 52, 138, 224, 163, 132, 206, 108, 121, 36, 112, 148, 206, 152, 73, 14, 247, 94, 216, 194, 212, 150, 100, 188, 141, 127, 106, 68, 228, 23, 49, 192, 49, 186, 43, 203, 139, 183, 108, 200, 63, 80, 37, 213, 192, 169, 223, 103, 202, 161, 153, 52, 148, 103, 97, 188, 133, 184, 248, 171, 91, 253, 103, 91, 212, 119, 149, 104, 239, 72, 182, 180, 38, 153, 42, 66, 30, 136, 237, 151, 111, 247, 163, 231, 57],
                    [92, 140, 173, 55, 149, 144, 56, 133, 205, 246, 187, 208, 69, 18, 247, 102, 25, 96, 10, 59, 42, 98, 239, 209, 160, 147, 190, 106, 125, 83, 49, 4, 128, 82, 199, 91, 186, 175, 181, 79, 133, 120, 93, 200, 208, 100, 138, 91, 247, 209, 236, 131, 132, 136, 191, 198, 119, 8, 52, 238, 97, 128, 158, 87, 157, 43, 167, 219, 6, 215, 15, 166, 183, 122, 75, 69, 82, 216, 215, 55, 218, 187, 56, 77, 203, 164, 180, 30, 134, 131, 184, 69, 76, 241, 148, 117, 164, 56, 247, 236, 133, 227, 141, 84, 32, 89, 231, 13, 135, 234, 217, 180, 224, 105, 224, 26, 53, 226, 178, 3, 133],
                    [255, 7, 67, 118, 136, 7, 192, 5, 204, 33, 248, 19, 77, 55, 143, 161, 22, 230, 20, 0, 229, 130, 250, 171, 218, 74, 19, 125, 16, 168, 56, 26, 206, 205, 76, 95, 26, 101, 227, 198, 185, 31, 90, 120, 33, 150, 128, 7, 223, 55, 157, 226, 148, 22, 82, 182, 41, 213, 97, 158, 225, 197, 159, 98, 138, 250, 111, 99, 135, 114, 199, 167, 190, 115, 67, 145, 0, 116, 86, 89, 28, 132, 102, 163, 224, 246, 173, 198, 40, 47, 50, 57, 208, 156, 54, 89, 200, 219, 68, 249, 122, 211, 225, 153]
                ]
            },
            "proof": {
                "cm_w_vec": ["iX1TpWAtff31npCQxOqHyHZSdcT3cw9MWQIk3M4d7cH14fXLKPIi82Edx4okubCD", "qEJjrr_mgOhEyCh2EYYiOrh8ldWKBMvanChEIB3SMqswPwy1seSn82Kzo1WVzdO1", "sHB23rHLd7FiI6YYGcqKDEFb9Ao2b7oPEwCsuti5kCRsjLDWdZOT91IXqHnQNsYY", "uM9xtKAtTWQ3xGUzxGgjgP7V9ijD04BHxWVZI2TmwR8IH0Hwt810Phnx3i9XfIvW", "gRkinQvTTCkfUicwwWR-5HUJOuBXvYof4O4-XMDRQrmpomToo1fmOn-4jNl_01KU"],
                "cm_t_vec": ["sluH4sT-TJGq4HQcAbY-wRJslwu9tjn_gcLT99WtfL3duXSqenMEWyQMgefSrIPz", "rj-YsjXGURQDrT1EReP1v3s7f98eHchX-5YrK9UBcMJo6D5LHrEcb0qjPrUkaeHL", "rRUJNdJvZOpCMZmPbm_cz4qZt_hWwy-9603JuQaQO9_vTmXuyjdDwFISN_Cl84an", "qLlbNtfNRAzU9YzvJrFMgonQVHmljTec793QlLUAurib3aq1z1vtDDAW86YLM9Az", "mLA_uwMN5cIQJx6shMtFt6v4phoATFR8BL0s9frIdNgnyBQpr5zYHs_uri0xcOlA"],
                "cm_z": "qjvjKNL_tIsLTDHShEQRWJKXmifeiEdifS_WO25DAwkoCIY15zApR7S-h914jViH",
                "prk_3_poly_eval_zeta": "wRvUNteMcicoX60EAxPPTnif6fyNg0Wr-yjXqC9HHGU=",
                "prk_4_poly_eval_zeta": "iy2DLkAPYBRHpnqZ-f93dW2hUUUJehkRw4ioV68EZkM=",
                "w_polys_eval_zeta": ["PfiIB6nA1zw30eXFFJijXdPrVwzzvvpfoGBxQeap-RY=", "YkFY2voQXr6szHS249mRp6C_tdh9at2pVrnu9sC3i1E=", "voSfD4EC4ybWeLTCusvb3zJ4NQW3836PTnn3AyrJ7Cc=", "dVjcRAPgYTI2PJbt6VXglYP6lDS9FHWNN99UxCnv2go=", "hhL0PMSEqYw9pkkF_-UvP_8dxe2YBEgDci9dDjnMEik="],
                "w_polys_eval_zeta_omega": ["hgpzSYXhT4Z-FzUnd2khlSATVlUE079MPpcHBZJ2rG4=", "cfKTXQWhBag8oJSwt7MlRrW8Dy3sRXpZ0_6YmNKBAjY=", "NHGxCJFF7dqY6lQpyJYvyUhlnzpGsbop33BSXmLzBGY="],
                "z_eval_zeta_omega": "pVwY480t0ku7EDNlVvjTLd3ZKUq6fAul3oZakYsCKyA=",
                "s_polys_eval_zeta": ["YzchjrI3XceUGqyJNRVGcE5EDzM12pCAyp67dpVP0Ss=", "W6Rj2prrVv4ILbSdGdMPrQWJfq-Of0B9MHjV0rf9jSs=", "jZoeahNiQntfEpBlUhGXdrBZwDm1CtwSGlKUginT2DM=", "juf-oLaI9Gq_S9yJYfdh6itCVY9mhUkZRxAN6ULZ00o="],
                "opening_witness_zeta": "izg466cSZumz-UdcYyXXaOX6HXWz8uVeuF6UWuvd_-gpgI-pWFtCq7f3xvLh1i77",
                "opening_witness_zeta_omega": "gmaCb92zaI1A8cJ6jPlvGoOIGrmLULUv8EBplzhjjqiJCJN5R1PnAwMhvpQ0Fevp"
            },
            "folding_instance": {
                "Secp256k1": {
                    "delegated_schnorr_proof": {
                        "inspection_comm": "oVmjHZVsEeETcFroshlzpK0Eqce64we1mJRZ8O_q2h8=",
                        "randomizers": ["l8Mk7NHSfgBwK5inf9nZvRPkOOSvEUGM7Xa3bgF7JV4A", "TNxAZP-xHNauY1RVvTz0vZKWKCbQsaq1wGzy1EgANXkA", "5c-eDHbFGTXRJT0zv8p-fokTAt9OtbpK5R63PIewgciA"],
                        "response_scalars": [
                            ["L-L0DKn7dLO2BCoFyiJiQnbjSBeTfHtlqWmPqmsSI_M=", "IHF3WlBt-zzbf208dtnUoXkJImavuQTvpiTNglk_ndU="],
                            ["j6r5DAJuBp-hoBYCWJic1Z9CR-ifVjJYc2MfItM3Iuk=", "W4dI16hEtbEahhLw1kIe4RJDt3CstmPTECdqIhHF-lU="],
                            ["mT9mvI2ImGyakyR7gVbj073J6GyLyQwGE0da3bALiNg=", "kfBq1qXip95tKzqg83MMB7Zz_RhXSc1A-f8a1vRUekA="]
                        ],
                        "params_phantom": null
                    },
                    "scalar_mul_commitments": ["_Z0vqHiYBMVMM91-9AqY9ENS3quPVy3VTbcHxZA_ISwA", "RcDGZuhae8yh_7OVcSCYpg3engqRbupOeUPSVn4J2y6A", "2BOATOjAz3QKEw73EH6RCm9n-4iAXV2sU606zUFcWbqA"],
                    "scalar_mul_proof": "O9cvZRZAIoMlfjuD6o2SFTekO3Up3AEYdTL90OYn4JMABDsVPLNsZZy-Pla6CQxkQabEu0LNJGtgSwGFt-cpecaAfF52Tui07Z3zfauBVLTLSptZTRPQ1p1qn-CkAGaTme2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAZr_K3CxvMAJyC2DlxMINOW6I7RwNRZoWSgJkjmsZAlWAD_vr_mm1gPXbVoWcjbWzM38ilmLTvSu-nnt-6GdLVzCApYxdyBuKaAXPXbcbCw_6D7vAG7ANifHY6HLPdRB5_9oA-lVNi4QhJVJbB30BxXnLCwguWtBj1h5gqr3dcGDLvpOAaKbPN5qAtuk7GYoge2_U8pH73vPdXP3wB2mczIRm84mAF8b85-XkV0NaJu-YZuVBJ7Z-bwmEOy2097l2HJBS9zqLZNSro0AHLDMpzTMbHIrsJF7pTzRbDyGpJW28A_LQXwPD8eEtANJnJ5F0fOedb8gul1dUHKYNcIy4EMrgqhzVCwAAAAAAAADzt6igK08OqWOPlOp6mdW0eWETwXlKKJ35EzAfpuUC04CYrfV1x7TwVWgu-JrF02nmV_Q95W5i4VMEQg_BGUkJF4ANXP-mQqHltp8v6Cfj0jI2qyxEWlkfFuO1rL6hx36bswAl2eMLiSfFmDgXcKYFstm6axixrA5TYsxGEojqzDSOggC1YBZXqsbBi-lSuWj8YrRpPr7iNpYgG_NdK396LBg2DoC-gmxVBoj1RNWoUKT6rg9k3mk3zFtEFejP9v0J_Q50YACXYqEHpd18SUJ2ofgJVB7ra1pNKhrUPSHsD29p8R9SCYDVRX6qIpmo3hj0XwS6xrc4fKA2TbRXasyPs5dzI5RIJYDPVMr2P4kTxzlpxSbQsPhsUkYdZHSkxXFWAwlOFr3KJQDrdhaoOgYOUXzbTnweDXLzjupuu3Lzj3Z_YaqvIqB_WoCMr2f2FL_bOAtIXQCJKylovwr5gswRMdrZkn3ZOFulvIALAAAAAAAAAA1E1ZyOPsnLNvUplOv5QuPiHF3Nij5YkRvjUEprWS9pAI2V7lObvLewQqwYM-utwKjg6vgXMiZMtiByNJwbXihIADwznKlGUrwXj2DVjo0ar11d_Ayrp6Wjy45jzm1XJzxGAMq2bZPfL6SJCgeqPTo0V31j7Us1O_0X6Q8-GfmFnNDrABpElelpvfLd3eDl5g1PLpPWlvuQ8DRIer6qlToKDxCXAATNEOQPDcaPvQcba8hayVtqgzNtejJcila5xSC-1s1WAKsoPmb2JsqT5w7-L9vqyv2O4XVtElQREAk20gSKJVuzgIVMy6mli8iKKojrYcS-9WYAxyDqy6rIO2dpXJn-RBbNgInsAKDGyW8jYf9Icslc395AcH0lXFQWOuAnxnyHYQTmgOP4EakRbWUZv3jsPZad4e30yMXUgWasEnxoIDORF4VqAET2aHjHC1R0r8DNhPoL06p9Zu2eaDKz8nLXyOqvFXB_AHsiEHIXXAO0MTt-_-Utv5lWzGObaikXft-aUSd-LY_6JjkhO_Ur8OQjtGBzWHTtIzj4J3aXbuP0bURlAxbhkBg="
                }
            }
        }
        "##;

        let note: AXfrNote = serde_json::from_str(&note).unwrap();
        let verifier_params = VerifierParams::load(6, 6).unwrap();
        let hash = random_hasher([
            187, 87, 120, 106, 172, 167, 187, 211, 42, 63, 112, 204, 120, 87, 23, 3, 180, 152, 25,
            112, 73, 81, 228, 170, 62, 233, 220, 204, 248, 6, 126, 208,
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
        {
            "body": {
                "inputs": ["t0kky9S4f3M08FeGiort--rFLS2Z795NwMNtJz7_gzg=", "8DNz5f-VOps0pR6iv8VPawLMX1ZUo4rf_ofH7oEiYhc=", "NEAaww60johYIyTdze77gljhQ_qIVZvhUiFfVzPevTE=", "ckPMxBl5HvSGFEptvWLm_h-rm_Pl0cpT_6RL3Dnc6E4=", "NtgxnfIhmwuuIbFIyWN3CXoPz1m-gJg-mUH5ilYLJzQ=", "TKJMfuWk-JGAnzZu-7L-iiSyT3mSpvS-CBg42fc2ri4=", "wznD0mDHydRKfHY1Hpp38Fp0ZNckCwAVSryKyM4tZU8=", "gd0AjnNRY55RneAV2F7Qc8nObLbqCXd1u-uU5YJN0Bo="],
                "outputs": [{
                    "commitment": "0xb_Jv1zgEdMDrrB8kA87uvX8UyZiBTW72WUPrLz0Co="
                }, {
                    "commitment": "GI-RkBaAtH7LIVK5fU1sdOyAr01pWfFX-LNXw9sIDmI="
                }, {
                    "commitment": "C8zxe4H_bdoKmduJFEeWzDBd9CPSFir-DdRTR2nB4Cg="
                }],
                "merkle_root": "8ozF69cJZTmwXe-bCHsqiN0hfo-zBue6C81-wro55Dw=",
                "merkle_root_version": 1,
                "fee": 19,
                "owner_memos": [
                    [152, 59, 112, 178, 182, 15, 30, 178, 122, 221, 237, 4, 227, 101, 155, 132, 162, 169, 57, 58, 138, 16, 198, 5, 228, 119, 26, 103, 64, 51, 160, 100, 128, 49, 219, 120, 183, 249, 169, 58, 110, 96, 241, 241, 96, 54, 237, 213, 212, 15, 188, 155, 197, 125, 214, 48, 43, 215, 187, 111, 211, 35, 81, 133, 65, 180, 33, 184, 9, 131, 8, 67, 195, 32, 22, 45, 50, 85, 167, 179, 211, 60, 158, 161, 210, 210, 60, 51, 185, 23, 171, 129, 146, 178, 137, 127, 121, 9, 90, 255, 222, 13, 22, 37, 135, 86, 13, 52, 3, 77, 24, 165, 11, 179, 203, 236, 251, 99, 23, 194, 109],
                    [43, 200, 220, 42, 240, 204, 20, 92, 80, 119, 43, 199, 138, 22, 107, 245, 202, 235, 124, 143, 8, 90, 107, 154, 247, 180, 2, 149, 151, 45, 179, 35, 0, 159, 182, 91, 29, 44, 194, 103, 122, 231, 158, 192, 85, 73, 28, 114, 73, 105, 58, 121, 69, 115, 142, 37, 12, 35, 42, 30, 9, 235, 137, 191, 48, 235, 239, 61, 126, 243, 247, 32, 21, 85, 43, 50, 159, 10, 247, 132, 57, 200, 233, 215, 23, 170, 44, 115, 161, 130, 177, 236, 21, 20, 203, 176, 154, 81, 44, 88, 96, 221, 171, 71, 243, 58, 200, 84, 156, 230, 228, 145, 197, 189, 215, 203, 12, 119, 183, 194, 96],
                    [66, 243, 252, 143, 250, 15, 162, 233, 137, 8, 4, 112, 1, 171, 179, 209, 249, 255, 3, 55, 38, 142, 76, 225, 233, 33, 151, 62, 35, 186, 47, 26, 128, 81, 145, 123, 89, 134, 179, 226, 193, 0, 177, 247, 24, 19, 143, 165, 51, 32, 238, 122, 224, 29, 218, 245, 93, 234, 113, 159, 142, 226, 39, 42, 91, 78, 230, 185, 38, 72, 69, 147, 178, 31, 153, 7, 244, 105, 117, 146, 3, 247, 57, 87, 186, 79, 110, 191, 112, 109, 255, 248, 151, 111, 197, 87, 173, 171, 85, 143, 63, 225, 194, 84, 43, 246, 76, 20, 152, 131, 81, 123, 134, 220, 193, 209, 49, 196, 114, 135, 23]
                ]
            },
            "proof": {
                "cm_w_vec": ["qyMPAiOCpJ6CgkkX9F-EcTtDByi4DPY4NVIubAeIv61X1EBxpElCoBAW4USioNXj", "kOV1D00wWijeT_vouYKTSlvZUuTyM2x6LFlyTtmQkyeL7YCUKO8Nyn0K8KXjqFJ8", "k1KHM6o5eNnnDKGWem1g-oDm7rS1ltRrsev4P6Xxn7NdrMSjTsdupT7Kn2gbeDsp", "tYysZBbvqpw1w6Cd8O24wIjuScgv5jOGb3zIUB2m_o5MT4sghEeXrCSgxzvITSu8", "iuH6nz_LFYzA6-DkAQz4pbuySNYA13fQpwIYC0qlo6xnXs5Wlh0k2LN3-VD8tegk"],
                "cm_t_vec": ["lplh21DoqDoLaZAUrdsOJp9vqWjzDQChQcWw-d-KYtOioMuE_Dipj6hCEJ3xVaGF", "iL3gAwT5aogHlQgKCrZ3YfmJZ5WSubz3d4L7y6XbzlLThun_l_Xxyy9xORahB_y6", "kSZhkA0tXlnMA2CsKxmPFP0HmG0DgFb0hkZ1d9-bDNq5KOudE_i2yyzNEupKAT90", "ros4o9hR1nGmpPMa5NfMjVnpQ2_RhQcY2_hv9OnLbMu9QHB9Erv9UD2IoruXfkIz", "tDa6aDt_TM3jrs2w-H9tDsCja0SgZk2u9KOlYwEmb2wLgs35Z34Q7PpjKrOqE1F6"],
                "cm_z": "rdY85CqNjkTa_Pt4DKbM-AMK-RWHUcept01rksETtxyBQcEn0s95naDlNct8T3sn",
                "prk_3_poly_eval_zeta": "wjnamdaH-6DN4hyksyUyp8wqOJ91C2-F_RodmpBy-nE=",
                "prk_4_poly_eval_zeta": "RuPsHdlPD6F6gAfhm7g2QOyEToILfrpoRNbbY6ObOjo=",
                "w_polys_eval_zeta": ["O_0cD9LqeuJ4v3AA9Z5nvHE3tTr5BdV9IyJDkg5SBXI=", "t0BTFmS71mKPAZdlGsq--b61LSEJ5Ytec8ff8M0Yt1s=", "3wxNI8EWnBTHZl4dfvleOmEV4E8B8-m3Qv4LaqrgBgw=", "pIqVJaNDf3OXTnswUQLcbomHqJ9VZftTw0Smbx74Zko=", "CI0Ehegm6nkU5V9XEaFvaa16pXHNNJm0_nDa8Q-c0kY="],
                "w_polys_eval_zeta_omega": ["7-2wWsldoxOsOr-9IHfIbTUWLHbctwOimwBrJYlowSs=", "IVkQlG4X_twG91jBmus2CEn0vPDU51i0qkgrMdvT5lY=", "CresW_laKwTdy7OihKHTU1rhuZg_LfLxePu8tyQWaxs="],
                "z_eval_zeta_omega": "0UrStzjn-B5Ce23umH6NulWFfPJyOAFrYQuoK1zNqWE=",
                "s_polys_eval_zeta": ["MbMTSYkEkOG1LZIgXn4JLL__hvaJ_t3oe6oSiiUi7UI=", "vc5R4ahOWXEL27JR-Nus1-uU9QyC3U30vhGH8I4HcVg=", "3T3p-GMjKvHexr1TBy1OlKgZpX1zxFB_A414oc8tVik=", "yPcWjoTNynSRcX9FvIw2uyx7GcEwzDoVFqyaDJN_OnM="],
                "opening_witness_zeta": "oOZUy2zlUKcd5YntDpnSvlaKcgFTTExkRdWU1IwgXraJSyXC4roJ9l8UOr3SSnSk",
                "opening_witness_zeta_omega": "kzXULVwoDq8CLZurshV1WFx3iEqkmtG7tAovJwymNg-h0wZGlfTPFlUr4G9RAUb8"
            },
            "folding_instance": {
                "Ed25519": {
                    "delegated_schnorr_proof": {
                        "inspection_comm": "K3HOSkZSfLZUmPgYLO9RZPh6dzUO7ZgHrZN7TUBTLhg=",
                        "randomizers": ["f8Mu-BkU7Z-vs4qAVd2xq38emIpmeSgLbr98ZPeTrAyA", "mSv1yJ6oudHRpQy2xOn2y1PYZ4X4ix4aNhR9AjlYXn2A", "sMbhImrfP24rTGPfgqtD2J4p6tfEY1_CVVNYjUOxfDCA"],
                        "response_scalars": [
                            ["qyZ3URvpScjjKUeJa0lZyypnVu1t-UB2DwwKjtXRswk=", "ixkQF4FVdsIQP0dfIYDDYf1YoMSsteFRSFI0Bv54PW8="],
                            ["122KVv_ZWMoViAZHk9fcZ76Mdz_02iPSD0rTACRhzTE=", "nXI4LhICaX_CYuiUGykuoddEIsfJ1aT0uWO6H8E2K34="],
                            ["8a5wg8a4tk1QIr6J743Z8ecZiHHPcGq3zkOQKTmCq1M=", "-VMCgpQg458JZGKIZ_gcG7atIKoKMSXf44UJymmT4z4="]
                        ],
                        "params_phantom": null
                    },
                    "scalar_mul_commitments": ["u0n5C7glH95KNak_hFE-jO-WE5bcxKw4PEu669OLagIA", "TOxBeljsHTsJHeYrqrQf89ALYeT9TGCoXJPZ9h6Z83kA", "Db41IZK_4CsTRNSGpNMc5SujNsjGN2m_ejZps_NLLxIA"],
                    "scalar_mul_proof": "Qyx9jcaiLaAuoVcDtl3296NpfD_5NPmZWa35fwkAC0aA2EK137MRRbmLgq8k_ZmKQca82j86bNnOgXEjx4SNjkkAFQFsGuGZ6-WwluBEdPRPJqgiw2ruqJiMQAAr2UUkgwkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA2_Xnb9L9l5sUaZ7qfd1xKxZvD4rhZYaePrczsbguTF2Asy8WYtBZYz2QTwTwzjINfVrvg3PdnK-XU0-FbEm8ElaA7pgZELfWlmmd0bKOkIbv4oxskabRO_Q7c-yJ9Ux9MHGAeug3Mr8872UBldO_JTZgjme6Qg1v66kCuz9hvZ-P4mCArw8xT7OI8GV_folC0M4W6IBTmFb6UY4yF4mbTuFtDCQAFeb_BWn3yEZ0aKr_qfBADfZEmclMMBL2Bli9zHcz1WN4LwYU7erkjp0oJetamH5pLKUMLgYXVy4BXgF7n8t4RyyA_p02IlZZlcbzXwBZz_pvSXzzfGd0tMymBAvfVnktCwAAAAAAAABQ4jrAcfWU2GWf9d8gClrpNOcwzUUbFBP_EiL-92N7JwDz6QL31n4zExTZvvrH98-xR4VHXNzURPbzISEtm_jMNAAXz3cT1N8LfThx97dvQqGOV6CJkxqnT1kRq8cT1TLdSoBL1l3xy1VXrNpnrL2mQ_eDMd2kf7rdbYeh-_2yMDczTwA6swTSCP9MpoMKjDd0fZIB5zIMCap7AFthhI-cwZhUEQBCQOyjza6VjmwdyF7ZQoBjSz8RMUrtFQLhR0j9AfCgSgAxhmRCpyE0HcvuzJpbnj6XY8AU29RUylzZA5KU5oaYOwC8TdcHur29-NAa9y6Z4SJT1lqOOXPZii2PFgRTPR0eJwBNBaiMwzliBiUzDVyoXPuyd0Z2BO9T1ukkgUTAE-KkfACh-Jk94psRg3fm0JeKQOSISh9V7vc9Pj2kCpjT6uO0GoA_-4cs5EZTur6fh95iDqouze0HX9wED-GXsVvgQQx7BgALAAAAAAAAAKIXkihrVT7KT5R1z-ahOUX9Mcyu6AlOKmngALQlYQccAHfRe0SDTw2CGtgz6YfjOVYhbuQPEoq7KSz78av40ndRgKx9ewuLXLf3UBJibv5djJ39q6ULIKEfZi7IJqfLvs0qAEQq9cd3_pHjCdsx6LCjYFKBKcizn0CfpVNvg2y4ItZzAC0OefyoUhidY0m7M0Nm8qJ11X5ugHD_TfZ8Z6rpfOwgALIthEWz7HBKUeZbD6OZD0DcMlytfi34I5mLXOsenLsYgCzAIgm6TK9HKfQbOIv0_KKT3oI5L0ijnZmLRq-_A6N5AHv-lI3UoQHF1bQMYHDRu5ZZVkH1dMBwArxjPBNSACEgABIXlatcaaFT6gVrG2hBFluMLkDdT4JLvPGDIDiiIL1kgPUD76XLx7j87fjbGJuLxNELl04Wc4kgV3oRUpmDa_9SgNRKlwUe5toIiXZCgi5oCc1oep3bH6jraezRnA5kV-cCgH3itLCZwuIICjiZu5MkWiURSrTdpt-L27jpcCWn2jUaOfdLZQwx6yNq4hZsscZYEIMth34SmH0_oxqAZk3iaDA="
                }
            }
        }
        "##;

        let note: AXfrNote = serde_json::from_str(&note).unwrap();
        let verifier_params = VerifierParams::load(8, 3).unwrap();
        let hash = random_hasher([
            15, 236, 87, 24, 18, 249, 150, 176, 188, 88, 119, 208, 123, 75, 250, 203, 42, 204, 226,
            147, 8, 236, 93, 195, 205, 75, 37, 83, 129, 244, 232, 160,
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
