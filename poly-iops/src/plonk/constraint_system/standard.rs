use algebra::traits::Scalar;
use ruc::*;

use crate::plonk::errors::PlonkError;

use super::ConstraintSystem;

pub struct StandardConstraintSystem<F> {
    pub selectors: Vec<Vec<F>>,
    pub wiring: [Vec<usize>; 3], // left, right, output, each of size `size`
    pub num_vars: usize,
    pub size: usize,
    pub public_vars_constraint_indices: Vec<usize>,
    pub public_vars_witness_indices: Vec<usize>,
    pub verifier_only: bool,
}

impl<F: Scalar> ConstraintSystem for StandardConstraintSystem<F> {
    type Field = F;

    fn size(&self) -> usize {
        self.size
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn wiring(&self) -> &[Vec<usize>] {
        &self.wiring[..]
    }

    fn quot_eval_dom_size(&self) -> usize {
        if self.size > 4 {
            self.size * 4
        } else {
            self.size * 8
        }
    }

    fn n_wires_per_gate() -> usize {
        3
    }

    fn num_selectors(&self) -> usize {
        assert_eq!(self.verifier_only, false);
        self.selectors.len()
    }

    fn public_vars_constraint_indices(&self) -> &[usize] {
        assert_eq!(self.verifier_only, false);
        &self.public_vars_constraint_indices
    }

    fn public_vars_witness_indices(&self) -> &[usize] {
        assert_eq!(self.verifier_only, false);
        &self.public_vars_witness_indices
    }

    fn selector(&self, index: usize) -> Result<&[F]> {
        if index >= self.selectors.len() {
            return Err(eg!(PlonkError::FuncParamsError));
        }
        Ok(&self.selectors[index])
    }

    /// The equation is wl * ql + wr * qr + wl * wr * qm - wo * qo + qc + PI  = 0.
    fn eval_gate_func(
        wire_vals: &[&Self::Field],
        sel_vals: &[&Self::Field],
        pub_input: &Self::Field,
    ) -> Result<Self::Field> {
        if wire_vals.len() < 3 || sel_vals.len() < 5 {
            return Err(eg!(PlonkError::FuncParamsError));
        }
        let left = sel_vals[0].mul(wire_vals[0]);
        let right = sel_vals[1].mul(wire_vals[1]);
        let mul = sel_vals[2].mul(&wire_vals[0].mul(wire_vals[1]));
        let out = sel_vals[3].mul(wire_vals[2]);
        let constant = sel_vals[4].add(pub_input);
        Ok(left.add(&right.add(&mul.add(&constant))).sub(&out))
    }

    /// The coefficients are (wl, wr, wl * wr, -wo, 1).
    fn eval_selector_multipliers(wire_vals: &[&Self::Field]) -> Result<Vec<Self::Field>> {
        if wire_vals.len() < 3 {
            return Err(eg!(PlonkError::FuncParamsError));
        }
        Ok(vec![
            *wire_vals[0],
            *wire_vals[1],
            wire_vals[0].mul(wire_vals[1]),
            wire_vals[2].neg(),
            F::one(),
        ])
    }

    fn is_verifier_only(&self) -> bool {
        self.verifier_only
    }

    fn shrink_to_verifier_only(&self) -> Result<Self> {
        Ok(StandardConstraintSystem {
            selectors: vec![],
            wiring: [vec![], vec![], vec![]], // 3-n_wires_per_gate
            num_vars: self.num_vars,
            size: self.size,
            public_vars_constraint_indices: vec![],
            public_vars_witness_indices: vec![],
            verifier_only: true,
        })
    }
}

impl<F: Scalar> StandardConstraintSystem<F> {
    pub fn new(num_vars: usize) -> StandardConstraintSystem<F> {
        StandardConstraintSystem {
            selectors: vec![vec![], vec![], vec![], vec![], vec![]], // q_L, q_R, q_M, q_O, q_C
            wiring: [vec![], vec![], vec![]],
            num_vars,
            size: 0,
            public_vars_constraint_indices: vec![],
            public_vars_witness_indices: vec![],
            verifier_only: false,
        }
    }

    pub fn insert_add_gate(
        &mut self,
        left_var_index: usize,
        right_var_index: usize,
        out_var_index: usize,
    ) {
        assert_eq!(self.verifier_only, false);
        self.insert_add_gate_with_inputs_multiplier(
            left_var_index,
            right_var_index,
            out_var_index,
            F::one(),
            F::one(),
        )
    }
    pub fn insert_add_gate_with_inputs_multiplier(
        &mut self,
        left_var_index: usize,
        right_var_index: usize,
        out_var_index: usize,
        left_var_multiplier: F,
        right_var_multiplier: F,
    ) {
        assert_eq!(self.verifier_only, false);
        assert!(
            left_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        assert!(
            right_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        assert!(
            out_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        self.selectors[0].push(left_var_multiplier);
        self.selectors[1].push(right_var_multiplier);
        self.selectors[2].push(F::zero());
        self.selectors[3].push(F::one());
        self.selectors[4].push(F::zero());
        self.wiring[0].push(left_var_index);
        self.wiring[1].push(right_var_index);
        self.wiring[2].push(out_var_index);
        self.size += 1;
    }

    pub fn insert_mul_gate(
        &mut self,
        left_var_index: usize,
        right_var_index: usize,
        out_var_index: usize,
    ) {
        assert_eq!(self.verifier_only, false);
        self.insert_mul_gate_with_input_multiplier(
            left_var_index,
            right_var_index,
            out_var_index,
            F::one(),
        )
    }

    pub fn insert_mul_gate_with_input_multiplier(
        &mut self,
        left_var_index: usize,
        right_var_index: usize,
        out_var_index: usize,
        in_vars_multiplier: F,
    ) {
        assert_eq!(self.verifier_only, false);
        assert!(
            left_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        assert!(
            right_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        assert!(
            out_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        self.selectors[0].push(F::zero());
        self.selectors[1].push(F::zero());
        self.selectors[2].push(in_vars_multiplier);
        self.selectors[3].push(F::one());
        self.selectors[4].push(F::zero());
        self.wiring[0].push(left_var_index);
        self.wiring[1].push(right_var_index);
        self.wiring[2].push(out_var_index);
        self.size += 1;
    }

    pub fn insert_boolean_gate(&mut self, var_index: usize) {
        assert_eq!(self.verifier_only, false);
        assert!(
            var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        self.selectors[0].push(F::zero());
        self.selectors[1].push(F::zero());
        self.selectors[2].push(F::one());
        self.selectors[3].push(F::one());
        self.selectors[4].push(F::zero());
        self.wiring[0].push(var_index);
        self.wiring[1].push(var_index);
        self.wiring[2].push(var_index);
        self.size += 1;
    }

    /// Insert a constant in the constraint system
    pub fn insert_constant(&mut self, var_index: usize, constant: F) {
        assert_eq!(self.verifier_only, false);
        assert!(
            var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        self.selectors[0].push(F::zero());
        self.selectors[1].push(F::zero());
        self.selectors[2].push(F::zero());
        self.selectors[3].push(F::one());
        self.selectors[4].push(constant);
        self.wiring[0].push(0);
        self.wiring[1].push(0);
        self.wiring[2].push(var_index);
        self.size += 1;
    }

    /// Insert constraint of a public IO value to be decided online
    pub fn prepare_io_variable(&mut self, var_index: usize) {
        assert_eq!(self.verifier_only, false);
        self.public_vars_constraint_indices.push(self.size);
        self.public_vars_witness_indices.push(var_index);
        self.insert_constant(var_index, F::zero());
    }

    /// Insert a dummy constraint in the constraint system
    pub fn insert_dummy(&mut self) {
        assert_eq!(self.verifier_only, false);
        self.selectors[0].push(F::zero());
        self.selectors[1].push(F::zero());
        self.selectors[2].push(F::zero());
        self.selectors[3].push(F::zero());
        self.selectors[4].push(F::zero());
        self.wiring[0].push(0);
        self.wiring[1].push(0);
        self.wiring[2].push(0);
        self.size += 1;
    }

    /// Pad the number of constraints to a power of two.
    pub fn pad(&mut self) {
        assert_eq!(self.verifier_only, false);
        let n = self.size.next_power_of_two();
        let diff = n - self.size();
        let zeroes_scalar = vec![F::zero(); diff];
        let zeroes = vec![0; diff];
        self.selectors[0].extend(zeroes_scalar.clone());
        self.selectors[1].extend(zeroes_scalar.clone());
        self.selectors[2].extend(zeroes_scalar.clone());
        self.selectors[3].extend(zeroes_scalar.clone());
        self.selectors[4].extend(zeroes_scalar);
        self.wiring[0].extend(zeroes.clone());
        self.wiring[1].extend(zeroes.clone());
        self.wiring[2].extend(zeroes);
        self.size += diff;
    }

    fn get_left_witness_index(&self, cs_index: usize) -> usize {
        assert_eq!(self.verifier_only, false);
        assert!(cs_index < self.size);
        self.wiring[0][cs_index] as usize
    }

    fn get_right_witness_index(&self, cs_index: usize) -> usize {
        assert_eq!(self.verifier_only, false);
        assert!(cs_index < self.size);
        self.wiring[1][cs_index] as usize
    }

    fn get_out_witness_index(&self, cs_index: usize) -> usize {
        assert_eq!(self.verifier_only, false);
        assert!(cs_index < self.size);
        self.wiring[2][cs_index] as usize
    }

    pub fn verify_witness(&self, witness: &[F], online_vars: &[F]) -> Result<()> {
        if witness.len() != self.num_vars {
            return Err(eg!());
        }
        if online_vars.len() != self.public_vars_witness_indices.len()
            || online_vars.len() != self.public_vars_constraint_indices.len()
        {
            return Err(eg!());
        }
        for cs_index in 0..self.size() {
            let mut public_online = F::zero();
            // check if constraint constrains a public variable
            // search constraint index in online vars
            for ((c_i, w_i), online_var) in self
                .public_vars_constraint_indices
                .iter()
                .zip(self.public_vars_witness_indices.iter())
                .zip(online_vars.iter())
            {
                if *c_i == cs_index {
                    // found
                    public_online = *online_var;
                    if witness[*w_i] != *online_var {
                        return Err(eg!());
                    }
                }
            }
            let left_wire_value = &witness[self.get_left_witness_index(cs_index)];
            let right_wire_value = &witness[self.get_right_witness_index(cs_index)];
            let out_wire_value = &witness[self.get_out_witness_index(cs_index)];
            let add = left_wire_value
                .mul(&self.selectors[0][cs_index])
                .add(&right_wire_value.mul(&self.selectors[1][cs_index]));
            let mul = right_wire_value
                .mul(left_wire_value)
                .mul(&self.selectors[2][cs_index]);
            let out = out_wire_value.mul(&self.selectors[3][cs_index]);
            let constant = &self.selectors[4][cs_index];
            let constant_add = constant.add(&public_online);
            if add.add(&mul.add(&constant_add)).sub(&out) != F::zero() {
                return Err(eg!());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use algebra::{
        bls12_381::{BLSScalar, BLSPairingEngine},
        traits::{One, ScalarArithmetic, Zero},
    };
    use merlin::Transcript;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::commitments::kzg_poly_com::KZGCommitmentScheme;
    use crate::plonk::{
        constraint_system::{standard::StandardConstraintSystem, ConstraintSystem},
        prover::prover,
        setup::{preprocess_prover, preprocess_verifier, PlonkPf},
        verifier::verifier,
    };

    type F = BLSScalar;

    #[test]
    fn test_standard_permutation() {
        let cs = StandardConstraintSystem::<F> {
            selectors: vec![vec![], vec![], vec![], vec![]],
            wiring: [vec![0, 1, 3], vec![3, 2, 2], vec![4, 3, 5]],
            num_vars: 6,
            size: 3,
            public_vars_constraint_indices: vec![],
            public_vars_witness_indices: vec![],
            verifier_only: false,
        };
        let perm = cs.compute_permutation();
        assert_eq!(perm, vec![0, 1, 3, 7, 5, 4, 6, 2, 8]);
    }

    #[test]
    fn test_standard_circuit_cs() {
        let mut cs = StandardConstraintSystem::<F>::new(3);
        let zero = F::zero();
        let one = F::one();
        // no constrains, every witness is valid
        assert!(cs.verify_witness(&[zero, zero, zero], &[]).is_ok());
        assert!(cs.verify_witness(&[zero, zero, one], &[]).is_ok());

        cs.insert_add_gate(0, 1, 2);
        assert!(cs.verify_witness(&[zero, zero, zero], &[]).is_ok());
        assert!(cs.verify_witness(&[zero, zero, one], &[]).is_err());
        assert!(cs.verify_witness(&[zero], &[]).is_err());

        cs.insert_mul_gate(2, 0, 1);
        assert!(cs.verify_witness(&[zero, zero, zero], &[]).is_ok());
        assert!(cs.verify_witness(&[zero, one, one], &[]).is_err());

        let mut cs = StandardConstraintSystem::<F>::new(4);
        // no constrains, every witness is valid
        assert!(cs.verify_witness(&[zero, zero, zero, zero], &[]).is_ok());
        // x + y = w
        // y * w = z
        cs.insert_add_gate(0, 1, 2);
        cs.insert_mul_gate(1, 2, 3);
        assert!(cs.verify_witness(&[zero, zero, zero, zero], &[]).is_ok());
        assert!(cs.verify_witness(&[zero, one, one, one], &[]).is_ok());
        let two = one.add(&one);
        assert!(cs.verify_witness(&[one, one, two, two], &[]).is_ok());
        let three = two.add(&one);
        assert!(cs.verify_witness(&[two, one, three, two], &[]).is_err());
        assert!(cs.verify_witness(&[two, one, three, three], &[]).is_ok());
    }

    #[test]
    fn test_standard_plonk_kzg() {
        let mut prng = ChaChaRng::from_seed([1u8; 32]);
        let pcs = KZGCommitmentScheme::new(30, &mut prng);

        // circuit (x_0 + x_1) * (x_2 + x_3) + x_0;
        let mut cs = StandardConstraintSystem::new(8);
        let one = F::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = two.add(&two);
        let seven = four.add(&three);
        let twenty_one = seven.mul(&three);
        let twenty_two = twenty_one.add(&one);
        // witness (1+2) * (3+4) + 1= 22
        let witness = [one, two, three, four, three, seven, twenty_one, twenty_two];

        cs.insert_add_gate(0, 1, 4);
        cs.insert_add_gate(2, 3, 5);
        cs.insert_mul_gate(4, 5, 6);
        cs.insert_add_gate(0, 6, 7);
        cs.pad();

        let common_seed = [0u8; 32];
        let proof = {
            assert!(cs.verify_witness(&witness, &[]).is_ok());
            let prover_params = preprocess_prover(&cs, &pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            prover(
                &mut prng,
                &mut transcript,
                &pcs,
                &cs,
                &prover_params,
                &witness,
            )
            .unwrap()
        };
        // test serialization
        let proof_json = serde_json::to_string(&proof).unwrap();
        let proof_de: PlonkPf<KZGCommitmentScheme<BLSPairingEngine>> =
            serde_json::from_str(&proof_json).unwrap();
        assert_eq!(proof, proof_de);
        {
            let verifier_params = preprocess_verifier(&cs, &pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            assert!(verifier(&mut transcript, &pcs, &cs, &verifier_params, &[], &proof).is_ok())
        }
    }

    #[test]
    fn test_standard_plonk_with_constants_wires() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pcs = KZGCommitmentScheme::new(64, &mut prng);
        type F = BLSScalar;

        let one = F::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = two.add(&two);
        let seven = four.add(&three);
        let twenty_one = seven.mul(&three);
        let twenty_five = twenty_one.add(&four);

        // circuit (x_0 + 2) * (x_2 + x_3) + x_0*4;
        let mut cs = StandardConstraintSystem::new(10);

        // witness (1+2) * (3+4) + 1*4= 25
        let witness = [
            one,
            two,
            three,
            four,
            three,
            seven,
            twenty_one,
            four,
            four,
            twenty_five,
        ];
        cs.insert_add_gate(0, 1, 4);
        cs.insert_add_gate(2, 3, 5);
        cs.insert_mul_gate(4, 5, 6);
        cs.insert_mul_gate(0, 7, 8);
        cs.insert_add_gate(6, 8, 9);
        cs.insert_constant(1, two);
        cs.insert_constant(7, four);
        cs.pad();

        let common_seed = [0u8; 32];
        let proof = {
            assert!(cs.verify_witness(&witness, &[]).is_ok());
            let prover_params = preprocess_prover(&cs, &pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            prover(
                &mut prng,
                &mut transcript,
                &pcs,
                &cs,
                &prover_params,
                &witness,
            )
            .unwrap()
        };

        {
            let verifier_params = preprocess_verifier(&cs, &pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            assert!(verifier(&mut transcript, &pcs, &cs, &verifier_params, &[], &proof).is_ok())
        }
    }

    #[test]
    fn test_standard_plonk_with_public_online_values() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pcs = KZGCommitmentScheme::new(64, &mut prng);
        type F = BLSScalar;
        let one = F::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = two.add(&two);
        let seven = four.add(&three);
        let twenty_one = seven.mul(&three);
        let twenty_five = twenty_one.add(&four);

        // circuit (x_0 + y0) * (x_2 + 4) + x_0*y1;
        let mut cs = StandardConstraintSystem::new(10);

        // witness (1+2) * (3+4) + 1*4= 25
        let witness = [
            one,
            two,
            three,
            four,
            three,
            seven,
            twenty_one,
            four,
            four,
            twenty_five,
        ];
        cs.insert_add_gate(0, 1, 4);
        cs.insert_add_gate(2, 3, 5);
        cs.insert_mul_gate(4, 5, 6);
        cs.insert_mul_gate(0, 7, 8);
        cs.insert_add_gate(6, 8, 9);
        cs.insert_constant(3, four);
        cs.prepare_io_variable(1);
        cs.prepare_io_variable(7);
        cs.pad();

        let online_vars = [two, four];

        let common_seed = [0u8; 32];
        let proof = {
            assert!(cs.verify_witness(&witness, &online_vars).is_ok());
            let prover_params = preprocess_prover(&cs, &pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            prover(
                &mut prng,
                &mut transcript,
                &pcs,
                &cs,
                &prover_params,
                &witness,
            )
            .unwrap()
        };
        {
            let verifier_params = preprocess_verifier(&cs, &pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            assert!(verifier(
                &mut transcript,
                &pcs,
                &cs,
                &verifier_params,
                &online_vars,
                &proof
            )
            .is_ok())
        }
    }
}
