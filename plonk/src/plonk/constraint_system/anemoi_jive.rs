use crate::plonk::constraint_system::{TurboCS, VarIndex};
use noah_algebra::bls12_381::BLSScalar;
use noah_algebra::ops::Neg;
use noah_algebra::{One, Zero};
use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381, AnemoiVLHTrace, JiveTrace};

impl TurboCS<BLSScalar> {
    /// Create constraints for the Anemoi permutation.
    fn anemoi_permutation_round(
        &mut self,
        input_var: &([VarIndex; 2], [VarIndex; 2]),
        output_var: &([Option<VarIndex>; 2], [Option<VarIndex>; 2]),
        intermediate_val: &([[BLSScalar; 2]; 12], [[BLSScalar; 2]; 12]),
        checksum: Option<BLSScalar>,
        salt: Option<BLSScalar>,
    ) -> Option<VarIndex> {
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        let zero_var = self.zero_var();

        // Allocate the intermediate values
        // (the last line of the intermediate values is the output of the last round
        // before the final linear layer)
        let mut intermediate_var = ([[zero_var; 2]; 12], [[zero_var; 2]; 12]);

        for r in 0..12 {
            intermediate_var.0[r][0] = self.new_variable(intermediate_val.0[r][0]);
            intermediate_var.0[r][1] = self.new_variable(intermediate_val.0[r][1]);
            intermediate_var.1[r][0] = self.new_variable(intermediate_val.1[r][0]);
            intermediate_var.1[r][1] = self.new_variable(intermediate_val.1[r][1]);
        }

        // Create the first gate --- which puts the initial value
        if salt.is_some() {
            self.push_add_selectors(zero, zero, zero, one);
            self.push_constant_selector(salt.unwrap().neg());
        } else {
            self.push_add_selectors(zero, zero, zero, zero);
            self.push_constant_selector(zero);
        }

        self.push_mul_selectors(zero, zero);
        self.push_ecc_selector(zero);
        self.push_out_selector(zero);

        self.wiring[0].push(input_var.0[0]); // a_0
        self.wiring[1].push(input_var.0[1]); // b_0
        self.wiring[2].push(input_var.1[0]); // c_0
        self.wiring[3].push(input_var.1[1]); // d_0
        self.wiring[4].push(intermediate_var.1[0][1]); // d_1
        self.finish_new_gate();

        self.attach_anemoi_jive_constraints_to_gate();

        // Create the remaining 11 gates
        for r in 1..12 {
            self.push_add_selectors(zero, zero, zero, zero);
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(zero);

            self.wiring[0].push(intermediate_var.0[r - 1][0]); // a_i
            self.wiring[1].push(intermediate_var.0[r - 1][1]); // b_i
            self.wiring[2].push(intermediate_var.1[r - 1][0]); // c_i
            self.wiring[3].push(intermediate_var.1[r - 1][1]); // d_i
            self.wiring[4].push(intermediate_var.1[r][1]); // d_{i+1}

            self.finish_new_gate();
        }

        if output_var.0[0].is_some() {
            let var = output_var.0[0].unwrap();

            self.push_add_selectors(
                AnemoiJive381::MDS_MATRIX[0][0],
                AnemoiJive381::MDS_MATRIX[0][1],
                zero,
                zero,
            );
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(one);

            self.wiring[0].push(intermediate_var.0[11][0]); // a_r
            self.wiring[1].push(intermediate_var.0[11][1]); // b_r
            self.wiring[2].push(intermediate_var.1[11][0]); // c_r
            self.wiring[3].push(intermediate_var.1[11][1]); // d_r
            self.wiring[4].push(var); // a_final

            self.finish_new_gate();
        }

        if output_var.0[1].is_some() {
            let var = output_var.0[1].unwrap();

            self.push_add_selectors(
                AnemoiJive381::MDS_MATRIX[1][0],
                AnemoiJive381::MDS_MATRIX[1][1],
                zero,
                zero,
            );
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(one);

            self.wiring[0].push(intermediate_var.0[11][0]); // a_r
            self.wiring[1].push(intermediate_var.0[11][1]); // b_r
            self.wiring[2].push(intermediate_var.1[11][0]); // c_r
            self.wiring[3].push(intermediate_var.1[11][1]); // d_r
            self.wiring[4].push(var); // b_final

            self.finish_new_gate();
        }

        if output_var.1[0].is_some() {
            let var = output_var.1[0].unwrap();

            self.push_add_selectors(
                zero,
                zero,
                AnemoiJive381::MDS_MATRIX[0][1],
                AnemoiJive381::MDS_MATRIX[0][0],
            );
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(one);

            self.wiring[0].push(intermediate_var.0[11][0]); // a_r
            self.wiring[1].push(intermediate_var.0[11][1]); // b_r
            self.wiring[2].push(intermediate_var.1[11][0]); // c_r
            self.wiring[3].push(intermediate_var.1[11][1]); // d_r
            self.wiring[4].push(var); // c_final

            self.finish_new_gate();
        }

        if output_var.1[1].is_some() {
            let var = output_var.1[1].unwrap();

            self.push_add_selectors(
                zero,
                zero,
                AnemoiJive381::MDS_MATRIX[1][1],
                AnemoiJive381::MDS_MATRIX[1][0],
            );
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(one);

            self.wiring[0].push(intermediate_var.0[11][0]); // a_r
            self.wiring[1].push(intermediate_var.0[11][1]); // b_r
            self.wiring[2].push(intermediate_var.1[11][0]); // c_r
            self.wiring[3].push(intermediate_var.1[11][1]); // d_r
            self.wiring[4].push(var); // d_final

            self.finish_new_gate();
        }

        if checksum.is_some() {
            let var = self.new_variable(checksum.unwrap());

            self.push_add_selectors(
                AnemoiJive381::MDS_MATRIX[0][0] + AnemoiJive381::MDS_MATRIX[1][0],
                AnemoiJive381::MDS_MATRIX[0][1] + AnemoiJive381::MDS_MATRIX[1][1],
                AnemoiJive381::MDS_MATRIX[0][1] + AnemoiJive381::MDS_MATRIX[1][1],
                AnemoiJive381::MDS_MATRIX[0][0] + AnemoiJive381::MDS_MATRIX[1][0],
            );
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(one);

            self.wiring[0].push(intermediate_var.0[11][0]); // a_r
            self.wiring[1].push(intermediate_var.0[11][1]); // b_r
            self.wiring[2].push(intermediate_var.1[11][0]); // c_r
            self.wiring[3].push(intermediate_var.1[11][1]); // d_r
            self.wiring[4].push(var); // sum

            self.finish_new_gate();

            Some(var)
        } else {
            None
        }
    }

    /// Create constraints for the Anemoi variable length hash function.
    pub fn anemoi_variable_length_hash(
        &mut self,
        trace: &AnemoiVLHTrace<BLSScalar, 2, 12>,
        input_var: &[VarIndex],
        output_var: VarIndex,
    ) {
        assert_eq!(input_var.len(), trace.input.len());

        let mut input_var = input_var.to_vec();
        let one_var = self.one_var();
        let zero_var = self.zero_var();

        if input_var.len() % (2 * 2 - 1) != 0 || input_var.is_empty() {
            input_var.push(one_var);
            if input_var.len() % (2 * 2 - 1) != 0 {
                input_var.extend_from_slice(
                    &[zero_var].repeat(2 * 2 - 1 - (input_var.len() % (2 * 2 - 1))),
                );
            }
        }

        assert_eq!(
            input_var.len(),
            trace.before_permutation.len() * (2 * 2 - 1)
        );

        // initialize the internal state.
        let chunks = input_var
            .chunks_exact(2 * 2 - 1)
            .map(|x| x.to_vec())
            .collect::<Vec<Vec<VarIndex>>>();
        let num_chunks = chunks.len();

        let mut x_var = [chunks[0][0], chunks[0][1]];
        let mut y_var = [chunks[0][2], zero_var];

        if num_chunks == 1 {
            self.anemoi_permutation_round(
                &(x_var, y_var),
                &([Some(output_var), None], [None, None]),
                &trace.intermediate_values_before_constant_additions[0],
                None,
                None,
            );
        } else {
            let mut new_x_var = [
                self.new_variable(trace.after_permutation[0].0[0]),
                self.new_variable(trace.after_permutation[0].0[1]),
            ];

            let mut new_y_var = [
                self.new_variable(trace.after_permutation[0].1[0]),
                self.new_variable(trace.after_permutation[0].1[1]),
            ];

            self.anemoi_permutation_round(
                &(x_var, y_var),
                &(
                    [Some(new_x_var[0]), Some(new_x_var[1])],
                    [Some(new_y_var[0]), Some(new_y_var[1])],
                ),
                &trace.intermediate_values_before_constant_additions[0],
                None,
                None,
            );

            for rr in 1..num_chunks - 1 {
                x_var = new_x_var;
                y_var = new_y_var;

                x_var[0] = self.add(x_var[0], chunks[rr][0]);
                x_var[1] = self.add(x_var[1], chunks[rr][1]);
                y_var[0] = self.add(y_var[0], chunks[rr][2]);

                new_x_var = [
                    self.new_variable(trace.after_permutation[rr].0[0]),
                    self.new_variable(trace.after_permutation[rr].0[1]),
                ];

                new_y_var = [
                    self.new_variable(trace.after_permutation[rr].1[0]),
                    self.new_variable(trace.after_permutation[rr].1[1]),
                ];

                self.anemoi_permutation_round(
                    &(x_var, y_var),
                    &(
                        [Some(new_x_var[0]), Some(new_x_var[1])],
                        [Some(new_y_var[0]), Some(new_y_var[1])],
                    ),
                    &trace.intermediate_values_before_constant_additions[rr],
                    None,
                    None,
                );
            }

            // last round
            {
                x_var = new_x_var;
                y_var = new_y_var;

                x_var[0] = self.add(x_var[0], chunks[num_chunks - 1][0]);
                x_var[1] = self.add(x_var[1], chunks[num_chunks - 1][1]);
                y_var[0] = self.add(y_var[0], chunks[num_chunks - 1][2]);

                self.anemoi_permutation_round(
                    &(x_var, y_var),
                    &([Some(output_var), None], [None, None]),
                    &trace.intermediate_values_before_constant_additions[num_chunks - 1],
                    None,
                    None,
                );
            }
        }
    }

    /// Create constraints for the Jive CRH.
    pub fn jive_crh(
        &mut self,
        trace: &JiveTrace<BLSScalar, 2, 12>,
        input_var: &[VarIndex; 3],
        salt: BLSScalar,
    ) -> VarIndex {
        let one = BLSScalar::one();
        let zero = BLSScalar::zero();

        let x_var = [input_var[0], input_var[1]];
        let y_var = [input_var[2], self.new_variable(salt)];

        let sum_output_val =
            trace.final_x[0] + trace.final_x[1] + trace.final_y[0] + trace.final_y[1];

        let sum_output_var = self
            .anemoi_permutation_round(
                &(x_var, y_var),
                &([None, None], [None, None]),
                &(
                    trace.intermediate_x_before_constant_additions,
                    trace.intermediate_y_before_constant_additions,
                ),
                Some(sum_output_val),
                Some(salt),
            )
            .unwrap();

        let wire_out = self.new_variable(
            sum_output_val
                + self.witness[input_var[0]]
                + self.witness[input_var[1]]
                + self.witness[input_var[2]]
                + salt,
        );

        self.push_add_selectors(one, one, one, one);
        self.push_mul_selectors(zero, zero);
        self.push_constant_selector(salt);
        self.push_ecc_selector(zero);
        self.push_out_selector(one);

        self.wiring[0].push(sum_output_var);
        self.wiring[1].push(input_var[0]);
        self.wiring[2].push(input_var[1]);
        self.wiring[3].push(input_var[2]);
        self.wiring[4].push(wire_out);
        self.finish_new_gate();

        wire_out
    }
}

#[cfg(test)]
mod test {
    use crate::plonk::constraint_system::TurboCS;
    use noah_algebra::bls12_381::BLSScalar;
    use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381, ANEMOI_JIVE_381_SALTS};

    #[test]
    fn test_jive_constraint_system() {
        let salt = ANEMOI_JIVE_381_SALTS[10];

        let trace = AnemoiJive381::eval_jive_with_trace(
            &[BLSScalar::from(1u64), BLSScalar::from(2u64)],
            &[BLSScalar::from(3u64), salt],
        );

        let mut cs = TurboCS::new();
        cs.load_anemoi_jive_parameters::<AnemoiJive381>();

        let one = cs.new_variable(BLSScalar::from(1u64));
        let two = cs.new_variable(BLSScalar::from(2u64));
        let three = cs.new_variable(BLSScalar::from(3u64));

        let _ = cs.jive_crh(&trace, &[one, two, three], salt);

        let witness = cs.get_and_clear_witness();
        cs.verify_witness(&witness, &[]).unwrap();
    }

    #[test]
    fn test_anemoi_variable_length_hash_constraint_system() {
        let trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[
            BLSScalar::from(1u64),
            BLSScalar::from(2u64),
            BLSScalar::from(3u64),
            BLSScalar::from(4u64),
        ]);

        let mut cs = TurboCS::new();
        cs.load_anemoi_jive_parameters::<AnemoiJive381>();

        let one = cs.new_variable(BLSScalar::from(1u64));
        let two = cs.new_variable(BLSScalar::from(2u64));
        let three = cs.new_variable(BLSScalar::from(3u64));
        let four = cs.new_variable(BLSScalar::from(4u64));

        let output_var = cs.new_variable(trace.output);

        let _ = cs.anemoi_variable_length_hash(&trace, &[one, two, three, four], output_var);

        let witness = cs.get_and_clear_witness();
        cs.verify_witness(&witness, &[]).unwrap();
    }
}

#[cfg(test)]
mod kzg_test {
    use crate::plonk::constraint_system::{ConstraintSystem, TurboCS};
    use crate::plonk::indexer::indexer;
    use crate::plonk::prover::prover;
    use crate::plonk::verifier::verifier;
    use crate::poly_commit::kzg_poly_com::KZGCommitmentScheme;
    use crate::poly_commit::pcs::PolyComScheme;
    use ark_std::test_rng;
    use merlin::Transcript;
    use noah_algebra::bls12_381::BLSScalar;
    use noah_algebra::prelude::*;
    use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381, ANEMOI_JIVE_381_SALTS};

    #[test]
    fn test_turbo_plonk_kzg_anemoi_jive() {
        let mut prng = test_rng();
        let pcs = KZGCommitmentScheme::new(260, &mut prng);
        test_turbo_plonk_anemoi_variable_length_hash(&pcs, &mut prng);
        test_turbo_plonk_jive_crh(&pcs, &mut prng);
    }

    fn test_turbo_plonk_anemoi_variable_length_hash<
        PCS: PolyComScheme<Field = BLSScalar>,
        R: CryptoRng + RngCore,
    >(
        pcs: &PCS,
        prng: &mut R,
    ) {
        let trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[
            BLSScalar::from(1u64),
            BLSScalar::from(2u64),
            BLSScalar::from(3u64),
            BLSScalar::from(4u64),
        ]);

        let mut cs = TurboCS::new();
        cs.load_anemoi_jive_parameters::<AnemoiJive381>();

        let one = cs.new_variable(BLSScalar::from(1u64));
        let two = cs.new_variable(BLSScalar::from(2u64));
        let three = cs.new_variable(BLSScalar::from(3u64));
        let four = cs.new_variable(BLSScalar::from(4u64));

        let output_var = cs.new_variable(trace.output);

        let _ = cs.anemoi_variable_length_hash(&trace, &[one, two, three, four], output_var);
        cs.pad();

        let witness = cs.get_and_clear_witness();
        cs.verify_witness(&witness, &[]).unwrap();
        check_turbo_plonk_proof(pcs, prng, &cs, &witness[..], &[]);
    }

    fn test_turbo_plonk_jive_crh<PCS: PolyComScheme<Field = BLSScalar>, R: CryptoRng + RngCore>(
        pcs: &PCS,
        prng: &mut R,
    ) {
        let salt = ANEMOI_JIVE_381_SALTS[10];

        let trace = AnemoiJive381::eval_jive_with_trace(
            &[BLSScalar::from(1u64), BLSScalar::from(2u64)],
            &[BLSScalar::from(3u64), salt],
        );

        let mut cs = TurboCS::new();
        cs.load_anemoi_jive_parameters::<AnemoiJive381>();

        let one = cs.new_variable(BLSScalar::from(1u64));
        let two = cs.new_variable(BLSScalar::from(2u64));
        let three = cs.new_variable(BLSScalar::from(3u64));

        let _ = cs.jive_crh(&trace, &[one, two, three], salt);
        cs.pad();

        let witness = cs.get_and_clear_witness();
        cs.verify_witness(&witness, &[]).unwrap();
        check_turbo_plonk_proof(pcs, prng, &cs, &witness[..], &[]);
    }

    fn check_turbo_plonk_proof<PCS: PolyComScheme, R: CryptoRng + RngCore>(
        pcs: &PCS,
        prng: &mut R,
        cs: &TurboCS<PCS::Field>,
        witness: &[PCS::Field],
        online_vars: &[PCS::Field],
    ) {
        let prover_params = indexer(cs, pcs).unwrap();
        let verifier_params_ref = &prover_params.verifier_params;

        let mut transcript = Transcript::new(b"TestTurboPlonk");
        let proof = prover(prng, &mut transcript, pcs, cs, &prover_params, witness).unwrap();

        let mut transcript = Transcript::new(b"TestTurboPlonk");
        assert!(verifier(
            &mut transcript,
            pcs,
            cs,
            verifier_params_ref,
            online_vars,
            &proof
        )
        .is_ok());

        let prover_cs = cs.shrink_to_verifier_only().unwrap();

        let mut transcript = Transcript::new(b"TestTurboPlonk");
        assert!(prover(
            prng,
            &mut transcript,
            pcs,
            &prover_cs,
            &prover_params,
            witness
        )
        .is_err());

        let mut transcript = Transcript::new(b"TestTurboPlonk");
        assert!(verifier(
            &mut transcript,
            pcs,
            &prover_cs,
            verifier_params_ref,
            online_vars,
            &proof
        )
        .is_ok());
    }
}
