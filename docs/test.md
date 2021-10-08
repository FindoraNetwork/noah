#List of test Zei library
##zei_api
###anon_xfr
####bar_to_from_abar.rs
- test_bar_to_abar.
- test_bar_to_abar_xfr_note.
####circuits.rs
- test_elgamal_hybrid_encrypt_cs
- test_asset_mixing
- test_eq_committed_vals_cs
- test_commit
- test_nullify
- test_sort
- test_merkle_root
- test_add_merkle_path_variables
- test_build_multi_xfr_cs
- test_xfr_cs
####keys.rs
- test_axfr_pub_key_serialization
- test_axfr_key_pair_serialization
####merkle_tree.rs
- test_generate_path_keys
- test_tree
- test_get_path
- test_abar_proof
- test_persistent_merkle_tree
- test_persistant_merkle_tree_proof_commitment
- test_persistent_merkle_tree_recovery
- test_init_tree
- build_tree
- build_and_save_dummy_tree
####proof.rs
- itest_anon_multi_xfr_proof_3in_6out_single_asset
- test_anon_multi_xfr_proof_3in_3out_single_asset
- test_anon_multi_xfr_proof_1in_2out_single_asset
- test_anon_multi_xfr_proof_2in_1out_single_asset
- test_anon_multi_xfr_proof_1in_1out_single_asset
- test_anon_multi_xfr_proof_3in_6out_multi_asset
- test_anon_multi_xfr_proof_3in_3out_multi_asset
- test_anon_xfr_proof
- test_eq_committed_vals_proof
##api
####solvency.rs
- test_solvency_correctness
- test_solvency_soundness
- test_solvency_ser_de
##xfr
####asset_record.rs
- do_test_build_open_asset_record
- test_build_open_asset_record
- do_test_open_asset_record
- test_open_asset_record
- build_and_open_blind_record
- test_build_and_open_blind_record
- open_blind_asset_record_error
- proofs.rs
- verify_identity_proofs_structure
####test.rs
- test_transfer_not_confidential
- test_transfer_confidential_amount_plain_asset
- test_transfer_confidential_asset_plain_amount
- test_transfer_confidential
- test_transfer_input_some_amount_confidential_output_non_confidential
- test_transfer_inputs_some_asset_confidential_output_non_confidential
- test_transfer_input_some_confidential_amount_and_asset_type_output_non_confidential
- test_transfer_input_some_confidential_amount_other_confidential_asset_type_output_non_confidential
- test_transfer_output_some_amount_confidential_input_non_confidential
- test_transfer_output_some_asset_confidential_input_non_confidential
- test_transfer_output_some_confidential_amount_and_asset_type_input_non_confidential
- test_transfer_output_some_confidential_amount_other_confidential_asset_type_input_non_confidential
- do_multiasset_transfer_tests
- xfr_keys_error
- test_identity_tracing_for_conf_assets
- test_identity_tracing_for_non_conf_assets
- asset_tracing_for_non_conf_assets_should_work
- test_one_input_one_output_all_confidential
- test_one_input_one_output_amount_confidential
- test_one_input_one_output_asset_confidential
- test_two_inputs_two_outputs_all_confidential_tracing_on_inputs
- test_two_inputs_two_outputs_all_confidential_tracing_on_inputs_and_outputs
- test_single_asset_first_input_asset_tracing
- test_single_asset_two_first_input_asset_tracing
- test_complex_transaction
- test_integer_overflow
- test_asset_type_handling
- test_integer_overflow
- test_asset_type_handling
####serialization.rs
- xfr_amount_u64_to_string_serde
- xfr_amount_u64_from_string_serde
- oar_amount_u64_to_string_serde
- anon_xfr_pub_key_serialization
- public_key_message_pack_serialization
- x25519_public_key_message_pack_serialization
- signature_message_pack_serialization
- serialize_and_deserialize_as_json
- serialize_and_deserialize_elgamal
###setup.rs
- test_params_serialization


##poly_iops


##algebra
###groups.rs
- Test_scalar_operations 

####Scalar operations
Performs test for the scalar operations "add", "mul" and "pow",
but we also need to test "add_assign", "mul_assign", "sub", "sub_assign", "inv" and "neg", 
all these methods are defined in group.rs, This is a generic test for a scalar field, so 
it works for test scalar operations in files bls12_381.rs, jubjub.rs and ristreto.rs.

###bls12_381.rs
- test_scalar_ops
- scalar_deser
- scalar_from_to_bytes
- hard_coded_group_elements
- bilinear_properties
- curve_points_respresentation_of_g1
- curve_points_respresentation_of_g2
- test_serialization_of_points


####Bilinear properties.
This file implements the operation over the curve BLS12-381 whose is a firendly pairing
elliptic curve. A pairing consists of three groups \mathbb{G}_1, \mathbb{G}_2 and \mathbb{G}_T 
and a bilinear map e: \mathbb{G}_1 X \mathbb{G}_2 \longrightarrow \mathbb{G_T}, such that for 
all P, P' \in \mathbb{G}_1 and for all Q, Q' \in \mathbb{G}_2.
e(P + P', Q) = e(P, Q) * e(P', Q)
e(P, Q + Q') = e(P, Q) * e(P, Q')
From which it follows that for scalars a,b
e([a]P, [b]Q) = e(P, [b]Q)^a = e([a],Q)^b =e(P,Q)^{ab} = e([b]P,[a]Q)

####Identity mapping
In a paring the following statement is true

$$e( I_{\mathbb{G}_1}, I_{\mathbb{G}_2} ) = I_{\mathbb{G}_T}$$

where $I_\mathbb{G}$ is the indentity element in the corresponding group $\mathbb{G}$.

####Generator mapping
Also it is hold that

$$e( \alpha_{\mathbb{G}1}, \alpha_{\mathbb{G}2} ) = \alpha_{\mathbb{G}_T}$$

where $\alpha_{\mathbb{G}}$ is the base o generator for \mathbb{G}, it is tested by 
"hard_coded_group_elements" test within bls12_381.rs.

####Curve point representation.

The representation of the pionts over the curve have two basic math representations, namely "Affine representation and Projective representation", both must be tested.

The prior assumption could be set as follows. Functions whose transform a point from one representation to another and visecersa must validate equivalent results over common operations. bls12_381-0.2.0 is the place where all the methods to deal with matter related to bls12-381 elliptic curve group, and all the nesessary to build the groups for pairing operations over this curve are coded.

For example the next function in g1.rs

```latex
pub fn add_mixed(&self, rhs: &G1Affine) -> G1Projective {  
```

sums a $\mathbb{G}_1$ element in affine representation to a $\mathbb{G}_1$ element in a projective representation and the outcome is returned in projective representaion. In a similar manner [g2.rs](http://g2.rs) implement the equivalent operation for  elements in $\mathbb{G}_2$ group.


###Byte curve point representation.

##### BLS12-381 serialization

- $\mathbb{F}_p$ elements are encoded in big-endian form. They occupy 48 bytes in this form.
- $\mathbb{F}_{p^2}$ *elements are encoded in big-endian form, meaning that
  the $\mathbb{F}_{p^2}$* element $c_0 + c_1 \cdot u$ is represented by the
  $\mathbb{F}_p$  element $c_1$ followed by the $\mathbb{F}_p$ element $c_0$*.
  This means $\mathbb{F}_{p^2}$* elements occupy 96 bytes in this form.
- The group  $\mathbb{G}_1$ uses $\mathbb{F}_p$ elements for coordinates. The
  group $\mathbb{G}_2$ *uses $\mathbb{F}_{p^2}$* elements for coordinates.
- $\mathbb{G}_1$ and $\mathbb{G}_2$ elements can be encoded in uncompressed
  form (the x-coordinate followed by the y-coordinate) or in compressed form
  (just the x-coordinate). $\mathbb{G}_1$ elements occupy 96 bytes in
  uncompressed form, and 48 bytes in compressed form. $\mathbb{G}_2$
  elements occupy 192 bytes in uncompressed form, and 96 bytes in compressed
  form.

The most-significant three bits of a $\mathbb{G}_1$ or $\mathbb{G}_2$
encoding should be masked away before the coordinate(s) are interpreted.
These bits are used to unambiguously represent the underlying element:

- The most significant bit, when set, indicates that the point is in
  compressed form. Otherwise, the point is in uncompressed form.
- The second-most significant bit indicates that the point is at infinity.
  If this bit is set, the remaining bits of the group element's encoding
  should be set to zero.
- The third-most significant bit is set if (and only if) this point is in
  compressed form *and* it is not the point at infinity *and* its
  y-coordinate is the lexicographically largest of the two associated with
  the encoded x-coordinate.

Some test vectors are present in bls12_381-0.2.0/src/tests/.

- g1_compressed_valid_test_vectors.dat
- g1_uncompressed_valid_test_vectors.dat
- g2_compressed_valid_test_vectors.dat
- g2_uncompressed_valid_test_vectors.dat

And also the file **mod.rs** in the same directory implement some test.


