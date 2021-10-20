
| algebra                                  | Test                                                                                               | Description |
|------------------------------------------|----------------------------------------------------------------------------------------------------|-------------|
| algebra/src/bls12_381.rs                 | test_scalar_ops                                                                                    |             |
|                                          | scalar_deser                                                                                       |             |
|                                          | scalar_from_to_bytes                                                                               |             |
|                                          | hard_coded_group_elements                                                                          |             |
|                                          | bilinear_properties                                                                                |             |
|                                          | curve_points_respresentation_of_g1                                                                 |             |
|                                          | curve_points_respresentation_of_g2                                                                 |             |
|                                          | test_serialization_of_points                                                                       |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| algebra/src/jubjub.rs                    | test_scalar_ops                                                                                    |             |
|                                          | scalar_deser                                                                                       |             |
|                                          | scalar_from_to_bytes                                                                               |             |
|                                          | schnorr_identification_protocol                                                                    |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| algebra/src/multi_exp.rs                 | test_multiexp_ristretto                                                                            |             |
|                                          | test_multiexp_blsg1                                                                                |             |
|                                          | test_multiexp_blsgt                                                                                |             |
|                                          | run_multiexp_test                                                                                  |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| algebra/src/ristretto.rs                 | scalar_ops                                                                                         |             |
|                                          | scalar_serialization                                                                               |             |
|                                          | scalar_to_radix                                                                                    |             |
|                                          |                                                                                                    |             |
| crypto                                   |                                                                                                    |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| poly_iops                                |                                                                                                    |             |
|                                          |                                                                                                    |             |
| zei_api                                  |                                                                                                    |             |
|                                          |                                                                                                    |             |
| Anon_xfr                                 |                                                                                                    |             |
| zei_api/src/anon_xfr/bar_to_from_abar.rs | test_bar_to_abar                                                                                   |             |
|                                          | test_bar_to_abar_xfr_note                                                                          |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| zei_api/src/anon_xfr/circuits.rs         | test_elgamal_hybrid_encrypt_cs                                                                     |             |
|                                          | test_asset_mixing                                                                                  |             |
|                                          | test_eq_committed_vals_cs                                                                          |             |
|                                          | test_commit                                                                                        |             |
|                                          | test_nullify                                                                                       |             |
|                                          | test_sort                                                                                          |             |
|                                          | test_merkle_root                                                                                   |             |
|                                          | test_add_merkle_path_variables                                                                     |             |
|                                          | test_build_multi_xfr_cs                                                                            |             |
|                                          | test_xfr_cs                                                                                        |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| zei_api/src/anon_xfr/key.rs              | test_axfr_pub_key_serialization                                                                    |             |
|                                          | test_axfr_key_pair_serialization                                                                   |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| zei_api/src/anon_xfr/merkle_tree.rs      | test_generate_path_keys                                                                            |             |
|                                          | test_tree                                                                                          |             |
|                                          | test_get_path                                                                                      |             |
|                                          | test_abar_proof                                                                                    |             |
|                                          | test_persistent_merkle_tree                                                                        |             |
|                                          | test_persistant_merkle_tree_proof_commitment                                                       |             |
|                                          | test_persistent_merkle_tree_recovery                                                               |             |
|                                          | test_init_tree                                                                                     |             |
|                                          | build_tree                                                                                         |             |
|                                          | build_and_save_dummy_tree                                                                          |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| zei_api/src/anon_xfr/proofs.rs           | test_anon_multi_xfr_proof_3in_6out_single_asset                                                    |             |
|                                          | test_anon_multi_xfr_proof_3in_3out_single_asset                                                    |             |
|                                          | test_anon_multi_xfr_proof_1in_2out_single_asset                                                    |             |
|                                          | test_anon_multi_xfr_proof_2in_1out_single_asset                                                    |             |
|                                          | test_anon_multi_xfr_proof_1in_1out_single_asset                                                    |             |
|                                          | test_anon_multi_xfr_proof_3in_6out_multi_asset                                                     |             |
|                                          | test_anon_multi_xfr_proof_3in_3out_multi_asset                                                     |             |
|                                          | test_anon_xfr_proof                                                                                |             |
|                                          | test_eq_committed_vals_proof                                                                       |             |
|                                          |                                                                                                    |             |
| api                                      |                                                                                                    |             |
| zei_api/src/api/solvency.rs              | test_solvency_correctness                                                                          |             |
|                                          | test_solvency_soundness                                                                            |             |
|                                          | test_solvency_ser_de                                                                               |             |
|                                          |                                                                                                    |             |
| xrf                                      |                                                                                                    |             |
| zei_api/src/xfr/asset_record.rs          | do_test_build_open_asset_record                                                                    |             |
|                                          | test_build_open_asset_record                                                                       |             |
|                                          | do_test_open_asset_record                                                                          |             |
|                                          | test_open_asset_record                                                                             |             |
|                                          | build_and_open_blind_record                                                                        |             |
|                                          | test_build_and_open_blind_record                                                                   |             |
|                                          | open_blind_asset_record_error                                                                      |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| zei_api/src/xfr/proofs.rs                | verify_identity_proofs_structure                                                                   |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| zei_api/src/xfr/tests.rs                 | test_transfer_not_confidential                                                                     |             |
|                                          | test_transfer_confidential_amount_plain_asset                                                      |             |
|                                          | test_transfer_confidential_asset_plain_amount                                                      |             |
|                                          | test_transfer_confidential                                                                         |             |
|                                          | test_transfer_input_some_amount_confidential_output_non_confidential                               |             |
|                                          | test_transfer_inputs_some_asset_confidential_output_non_confidential                               |             |
|                                          | test_transfer_input_some_confidential_amount_and_asset_type_output_non_confidential                |             |
|                                          | test_transfer_input_some_confidential_amount_other_confidential_asset_type_output_non_confidential |             |
|                                          | test_transfer_output_some_amount_confidential_input_non_confidential                               |             |
|                                          | test_transfer_output_some_asset_confidential_input_non_confidential                                |             |
|                                          | test_transfer_output_some_confidential_amount_and_asset_type_input_non_confidential                |             |
|                                          | test_transfer_output_some_confidential_amount_other_confidential_asset_type_input_non_confidential |             |
|                                          | do_multiasset_transfer_tests                                                                       |             |
|                                          | xfr_keys_error                                                                                     |             |
|                                          | test_identity_tracing_for_conf_assets                                                              |             |
|                                          | test_identity_tracing_for_non_conf_assets                                                          |             |
|                                          | asset_tracing_for_non_conf_assets_should_work                                                      |             |
|                                          | test_one_input_one_output_all_confidential                                                         |             |
|                                          | test_one_input_one_output_amount_confidential                                                      |             |
|                                          | test_one_input_one_output_asset_confidential                                                       |             |
|                                          | test_two_inputs_two_outputs_all_confidential_tracing_on_inputs                                     |             |
|                                          | test_two_inputs_two_outputs_all_confidential_tracing_on_inputs_and_outputs                         |             |
|                                          | test_single_asset_first_input_asset_tracing                                                        |             |
|                                          | test_single_asset_two_first_input_asset_tracing                                                    |             |
|                                          | test_complex_transaction                                                                           |             |
|                                          | test_integer_overflow                                                                              |             |
|                                          | test_asset_type_handling                                                                           |             |
|                                          | test_integer_overflow                                                                              |             |
|                                          | test_asset_type_handling                                                                           |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| zei_api/src/serialization.rs             | xfr_amount_u64_to_string_serde                                                                     |             |
|                                          | xfr_amount_u64_from_string_serde                                                                   |             |
|                                          | oar_amount_u64_to_string_serde                                                                     |             |
|                                          | anon_xfr_pub_key_serialization                                                                     |             |
|                                          | public_key_message_pack_serialization                                                              |             |
|                                          | x25519_public_key_message_pack_serialization                                                       |             |
|                                          | signature_message_pack_serialization                                                               |             |
|                                          | serialize_and_deserialize_as_json                                                                  |             |
|                                          | serialize_and_deserialize_elgamal                                                                  |             |
|                                          |                                                                                                    |             |
|                                          |                                                                                                    |             |
| zei_api/src/setup.rs                     | test_params_serialization                                                                          |             |
