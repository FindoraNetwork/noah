use crate::ioputils::u8_lsf_slice_to_u64_lsf_le_vec;
use crate::plonk::turbo_plonk_cs::{TurboPlonkConstraintSystem, VarIndex};
use algebra::bls12_381::BLSScalar;
use algebra::groups::{One, ScalarArithmetic, Zero};
use crypto::basics::hash::rescue::RescueInstance;

// state size
const WIDTH: usize = 4;
// # of rounds
const NR: usize = 12;
// alpha^{-1} mod (q-1) = 20974350070050476191779096203274386335076221000211055129041463479975432473805;
// least significant u8limb first
const ALPHA_INV: [u8; 32] = [
    0xCD, 0xCC, 0xCC, 0xCC, 0x32, 0x33, 0x33, 0x33, 0x99, 0xF1, 0x98, 0x99, 0x67, 0x0E,
    0x7F, 0x21, 0x02, 0xF0, 0x73, 0x9D, 0x69, 0x56, 0x4A, 0xE1, 0x1C, 0x32, 0x72, 0xDD,
    0xBA, 0x0F, 0x5F, 0x2E,
];

#[derive(Clone)]
pub struct StateVar(Vec<VarIndex>); // StateVar.0.len() == WIDTH
#[derive(Clone)]
pub struct State(Vec<BLSScalar>); // State.0.len() == WIDTH

impl From<&[BLSScalar; WIDTH]> for State {
    fn from(state: &[BLSScalar; WIDTH]) -> State {
        assert_eq!(state.len(), WIDTH);
        State(state.to_vec())
    }
}

impl From<&[BLSScalar]> for State {
    fn from(state: &[BLSScalar]) -> State {
        assert_eq!(state.len(), WIDTH);
        State(state.to_vec())
    }
}

impl State {
    pub fn new(array: [BLSScalar; WIDTH]) -> State {
        State(array.to_vec())
    }

    pub fn as_slice(&self) -> &[BLSScalar] {
        &self.0
    }
}

impl StateVar {
    pub fn new(array: [VarIndex; WIDTH]) -> StateVar {
        StateVar(array.to_vec())
    }

    pub fn as_slice(&self) -> &[VarIndex] {
        &self.0
    }
}

impl TurboPlonkConstraintSystem<BLSScalar> {
    /// Create a rescue state variable.
    pub fn new_rescue_state_variable(&mut self, state: State) -> StateVar {
        let vars: Vec<VarIndex> = state
            .0
            .into_iter()
            .map(|elem| self.new_variable(elem))
            .collect();
        StateVar(vars)
    }

    /// Create a rescue input variable and add a zero constraint for the last input elem.
    pub fn new_hash_input_variable(&mut self, input_state: State) -> StateVar {
        assert_eq!(input_state.0[WIDTH - 1], BLSScalar::zero());
        let input_var = self.new_rescue_state_variable(input_state);
        self.insert_constant_gate(input_var.0[WIDTH - 1], BLSScalar::zero());
        input_var
    }

    /// Returns the output of the rescue hash function on input variable `input_var`
    pub fn rescue_hash(&mut self, input_var: &StateVar) -> Vec<VarIndex> {
        let hash = RescueInstance::new();
        let zero = BLSScalar::zero();
        let zero_vec = vec![zero, zero, zero, zero];
        let keys = hash.key_scheduling(&zero_vec[..]);
        let keys_states: Vec<State> =
            keys.iter().map(|key| State::from(&key[..])).collect();
        let mds_states: Vec<State> =
            hash.MDS.iter().map(|mi| State::from(&mi[..])).collect();
        self.rescue_hash_with_keys(input_var, &mds_states, &keys_states)
    }

    /// Returns the output of the rescue hash function on input variable `input_var`, round keys `key`,
    /// and an MDS matrix.
    fn rescue_hash_with_keys(
        &mut self,
        input_var: &StateVar,
        mds: &[State],
        keys: &[State],
    ) -> Vec<VarIndex> {
        assert_eq!(keys.len(), 2 * NR + 1);
        assert_eq!(mds.len(), WIDTH);

        let mut state_var = self.add_constant_state(input_var, &keys[0]);
        for (r, key) in keys.iter().skip(1).enumerate() {
            if r % 2 == 0 {
                state_var = self.pow_5_inv(&state_var);
                state_var = self.linear_op(&state_var, mds, key);
            } else {
                state_var = self.non_linear_op(&state_var, mds, key);
            }
        }
        state_var.0
    }

    /// Rescue block cipher
    /// * `key_var` - the state variable representing the cipher key.
    /// * `input_var` - the state variable representing the block cipher input.
    /// * Returns the state variable representing the block cipher output.
    pub fn rescue_cipher(
        &mut self,
        key_var: &StateVar,
        input_var: &StateVar,
    ) -> StateVar {
        let cipher = RescueInstance::new();
        let mds_states: Vec<State> =
            cipher.MDS.iter().map(|mi| State::from(&mi[..])).collect();
        let keys_vars = self.key_scheduling(&cipher, &mds_states, key_var);
        self.rescue_cipher_with_keys(input_var, &keys_vars, &mds_states)
    }

    /// Returns the output of the rescue block cipher on input variable `input_var`, round keys `keys_vars`,
    /// and an MDS matrix `mds`.
    pub fn rescue_cipher_with_keys(
        &mut self,
        input_var: &StateVar,
        keys_vars: &[StateVar],
        mds: &[State],
    ) -> StateVar {
        assert_eq!(keys_vars.len(), 2 * NR + 1);
        assert_eq!(mds.len(), WIDTH);

        let zero_state = State::new([BLSScalar::zero(); WIDTH]);
        let mut state_var = self.add_state(input_var, &keys_vars[0]);
        for (r, key_var) in keys_vars.iter().skip(1).enumerate() {
            if r % 2 == 0 {
                state_var = self.pow_5_inv(&state_var);
                state_var = self.linear_op(&state_var, mds, &zero_state);
            } else {
                state_var = self.non_linear_op(&state_var, mds, &zero_state);
            }
            state_var = self.add_state(&state_var, key_var);
        }
        state_var
    }

    /// Return the round keys for Rescue block ciphers.
    /// * `cipher`: The Rescue instance.
    /// * `mds`: MDS matrix.
    /// * `key_var`: A state variable representing the input cipher key.
    pub fn key_scheduling(
        &mut self,
        cipher: &RescueInstance<BLSScalar>,
        mds: &[State],
        key_var: &StateVar,
    ) -> Vec<StateVar> {
        let mut key_injection = State::from(&cipher.IC[..]);
        let mut key_state_var = self.add_constant_state(key_var, &key_injection);
        let mut result = vec![key_state_var.clone()];
        for r in 0..2 * cipher.num_rounds() {
            RescueInstance::linear_op(&cipher.K, &mut key_injection.0, &cipher.C);
            if r % 2 == 0 {
                key_state_var = self.pow_5_inv(&key_state_var);
                key_state_var = self.linear_op(&key_state_var, mds, &key_injection);
            } else {
                key_state_var = self.non_linear_op(&key_state_var, mds, &key_injection);
            }
            result.push(key_state_var.clone());
        }
        result
    }

    /// Rescue counter mode encryption.
    /// The key should be a freshed one in each call, and the nonce is initialized to zero.
    /// * `key_vars` - the symmetric key variables
    /// * `data_vars` - the variables for the data to be encrypted
    /// * Returns the variables that map to the ciphertext
    pub fn rescue_ctr(
        &mut self,
        key_vars: Vec<VarIndex>,
        data_vars: &[VarIndex],
    ) -> Vec<VarIndex> {
        let cipher = RescueInstance::new();
        let mds_states: Vec<State> =
            cipher.MDS.iter().map(|m| State::from(&m[..])).collect();
        let round_keys_vars =
            self.key_scheduling(&cipher, &mds_states, &StateVar(key_vars));

        let zero_var = self.zero_var();
        let one = BLSScalar::one();
        let mut nonce_var = zero_var;
        let mut ctexts = vec![];
        for block in data_vars.chunks(WIDTH) {
            let mut input_vars = vec![nonce_var];
            input_vars.extend(vec![zero_var; WIDTH - 1]);
            nonce_var = self.add_constant(nonce_var, &one);
            let keystream = self
                .rescue_cipher_with_keys(
                    &StateVar(input_vars),
                    &round_keys_vars,
                    &mds_states,
                )
                .0;
            let len = block.len();
            for (&data, &mask) in block.iter().zip(keystream.iter()).take(len) {
                ctexts.push(self.add(data, mask));
            }
        }
        ctexts
    }

    fn add_state(
        &mut self,
        left_state_var: &StateVar,
        right_state_var: &StateVar,
    ) -> StateVar {
        let vars: Vec<VarIndex> = left_state_var
            .0
            .iter()
            .zip(right_state_var.0.iter())
            .map(|(&left_var, &right_var)| self.add(left_var, right_var))
            .collect();
        StateVar(vars)
    }

    fn add_constant_state(
        &mut self,
        state_var: &StateVar,
        constant: &State,
    ) -> StateVar {
        let vars: Vec<VarIndex> = state_var
            .0
            .iter()
            .zip(constant.0.iter())
            .map(|(&var, elem)| self.add_constant(var, elem))
            .collect();
        StateVar(vars)
    }

    fn linear_op(
        &mut self,
        state_var: &StateVar,
        mds: &[State],
        key: &State,
    ) -> StateVar {
        assert_eq!(mds.len(), WIDTH);
        // vars[i] = key[i] + \sum_{j=0..WIDTH-1} mds[i][j] * state_var[j]
        let vars: Vec<VarIndex> = (0..WIDTH)
            .map(|i| {
                self.add_linear_op_constraint(&state_var.0[..], &mds[i].0[..], &key.0[i])
            })
            .collect();
        StateVar(vars)
    }

    fn non_linear_op(
        &mut self,
        state_var: &StateVar,
        mds: &[State],
        key: &State,
    ) -> StateVar {
        assert_eq!(mds.len(), WIDTH);
        // vars[i] = key[i] + \sum_{j=0..WIDTH-1} mds[i][j] * state_var[j]^5
        let vars: Vec<VarIndex> = (0..WIDTH)
            .map(|i| {
                self.add_non_linear_op_constraint(
                    &state_var.0[..],
                    &mds[i].0[..],
                    &key.0[i],
                )
            })
            .collect();
        StateVar(vars)
    }

    fn pow_5_inv(&mut self, state_var: &StateVar) -> StateVar {
        let vars: Vec<VarIndex> = state_var
            .0
            .iter()
            .map(|&var| self.add_pow_5_inv_constraint(var))
            .collect();
        StateVar(vars)
    }

    /// Add a variable by a constant: wo = w1 + constant
    fn add_constant(&mut self, var: VarIndex, elem: &BLSScalar) -> VarIndex {
        let out_var = self.new_variable(self.witness[var].add(elem));
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        self.push_add_selectors(one, zero, zero, zero);
        self.push_mul_selectors(zero, zero);
        self.push_constant_selector(*elem);
        self.push_ecc_selector(zero);
        self.push_rescue_selectors(zero, zero, zero, zero);
        self.push_out_selector(one);
        self.wiring[0].push(var);
        self.wiring[1].push(0);
        self.wiring[2].push(0);
        self.wiring[3].push(0);
        self.wiring[4].push(out_var);
        self.size += 1;
        out_var
    }

    /// Add a linear constraint:
    /// witness[out_var] = sum_{i=1..4} coefs[i] * witness[vars[i]] + constant
    fn add_linear_op_constraint(
        &mut self,
        vars: &[VarIndex],
        coefs: &[BLSScalar],
        constant: &BLSScalar,
    ) -> VarIndex {
        assert_eq!(coefs.len(), WIDTH);
        assert_eq!(vars.len(), WIDTH);

        let out_val = (0..WIDTH).fold(*constant, |sum, i| {
            sum.add(&coefs[i].mul(&self.witness[vars[i]]))
        });
        let out_var = self.new_variable(out_val);
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        self.push_add_selectors(coefs[0], coefs[1], coefs[2], coefs[3]);
        self.push_mul_selectors(zero, zero);
        self.push_constant_selector(*constant);
        self.push_ecc_selector(zero);
        self.push_rescue_selectors(zero, zero, zero, zero);
        self.push_out_selector(one);
        for (i, var) in vars.iter().enumerate() {
            self.wiring[i].push(*var);
        }
        self.wiring[4].push(out_var);
        self.size += 1;

        out_var
    }

    /// Add a non-linear constraint:
    /// witness[out_var] = sum_{i=1..4} coefs[i] * witness[vars[i]]^5 + constant
    fn add_non_linear_op_constraint(
        &mut self,
        vars: &[VarIndex],
        coefs: &[BLSScalar],
        constant: &BLSScalar,
    ) -> VarIndex {
        assert_eq!(coefs.len(), WIDTH);
        assert_eq!(vars.len(), WIDTH);

        let out_val = (0..WIDTH).fold(*constant, |sum, i| {
            sum.add(&coefs[i].mul(&self.witness[vars[i]].pow(&[5u64])))
        });
        let out_var = self.new_variable(out_val);
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        self.push_add_selectors(zero, zero, zero, zero);
        self.push_mul_selectors(zero, zero);
        self.push_constant_selector(*constant);
        self.push_ecc_selector(zero);
        self.push_rescue_selectors(coefs[0], coefs[1], coefs[2], coefs[3]);
        self.push_out_selector(one);
        for (i, var) in vars.iter().enumerate() {
            self.wiring[i].push(*var);
        }
        self.wiring[4].push(out_var);
        self.size += 1;

        out_var
    }

    /// Add a 5th power inverse constraint:
    /// witness[out_var]^5 = witness[var]
    fn add_pow_5_inv_constraint(&mut self, var: VarIndex) -> VarIndex {
        let alpha_inv_u64_vec = u8_lsf_slice_to_u64_lsf_le_vec(&ALPHA_INV[..]);
        let out_val = self.witness[var].pow(&alpha_inv_u64_vec);
        let out_var = self.new_variable(out_val);
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        self.push_add_selectors(zero, zero, zero, zero);
        self.push_mul_selectors(zero, zero);
        self.push_constant_selector(zero);
        self.push_ecc_selector(zero);
        self.push_rescue_selectors(zero, zero, zero, one);
        self.push_out_selector(one);

        for i in 0..3 {
            self.wiring[i].push(0);
        }
        self.wiring[3].push(out_var);
        self.wiring[4].push(var);
        self.size += 1;
        out_var
    }
}

#[cfg(test)]
mod test {
    use crate::plonk::turbo_plonk_cs::rescue::State;
    use crate::plonk::turbo_plonk_cs::TurboPlonkConstraintSystem;
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{Scalar, Zero};
    use crypto::basics::hash::rescue::{RescueCtr, RescueInstance};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ruc::{err::*, *};

    type F = BLSScalar;

    #[test]
    fn test_rescue_hash() {
        let hash = RescueInstance::new();
        // use BLS12-381 field
        let mut cs = TurboPlonkConstraintSystem::<BLSScalar>::new();
        let input_vec = [
            BLSScalar::from_u32(11),
            BLSScalar::from_u32(171),
            BLSScalar::from_u32(273),
            BLSScalar::from_u32(0),
        ];
        let input_state = State::from(&input_vec[..]);
        let input_var = cs.new_hash_input_variable(input_state.clone());
        let out_var = cs.rescue_hash(&input_var)[0];

        // Check consistency between witness[input_var] and input_state
        let witness_input: Vec<F> =
            input_var.0.iter().map(|&var| cs.witness[var]).collect();
        assert_eq!(witness_input, input_state.0);

        // Check consistency between witness[out_var] and rescue_out_state[0]
        let rescue_out_state = State::from(&hash.rescue_hash(&input_vec)[..]);
        assert_eq!(cs.witness[out_var], rescue_out_state.0[0]);

        // Check good witness
        let mut witness = cs.get_and_clear_witness();
        pnk!(cs.verify_witness(&witness[..], &[]));

        // Check bad witness: witness[out_var] = zero()
        witness[out_var] = F::zero();
        assert!(cs.verify_witness(&witness[..], &[]).is_err());
    }

    #[test]
    fn test_rescue_cipher() {
        let cipher = RescueInstance::new();
        let mut cs = TurboPlonkConstraintSystem::new();
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let key_vec = vec![
            BLSScalar::random(&mut prng),
            BLSScalar::random(&mut prng),
            BLSScalar::random(&mut prng),
            BLSScalar::random(&mut prng),
        ];
        let input_vec = vec![
            BLSScalar::random(&mut prng),
            BLSScalar::random(&mut prng),
            BLSScalar::random(&mut prng),
            BLSScalar::random(&mut prng),
        ];
        let key_var = cs.new_rescue_state_variable(State::from(&key_vec[..]));
        let input_var = cs.new_rescue_state_variable(State::from(&input_vec[..]));
        let out_var = cs.rescue_cipher(&key_var, &input_var);

        // Check consistency between witness[input_var] and input_vec
        let witness_input: Vec<F> =
            input_var.0.iter().map(|&var| cs.witness[var]).collect();
        assert_eq!(witness_input, input_vec);

        // Check consistency between witness[key_var] and key_vec
        let witness_key: Vec<F> = key_var.0.iter().map(|&var| cs.witness[var]).collect();
        assert_eq!(witness_key, key_vec);

        // Check consistency between witness[out_var] and rescue cipher output
        let witness_output: Vec<F> =
            out_var.0.iter().map(|&var| cs.witness[var]).collect();
        assert_eq!(witness_output, cipher.rescue(&input_vec, &key_vec));

        // Check good witness
        let mut witness = cs.get_and_clear_witness();
        pnk!(cs.verify_witness(&witness[..], &[]));

        // Check bad witness
        witness[out_var.0[0]] = F::zero();
        assert!(cs.verify_witness(&witness[..], &[]).is_err());
    }

    #[test]
    fn test_rescue_ctr() {
        let mut cs = TurboPlonkConstraintSystem::new();
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let key_vec = vec![
            BLSScalar::random(&mut prng),
            BLSScalar::random(&mut prng),
            BLSScalar::random(&mut prng),
            BLSScalar::random(&mut prng),
        ];
        let key_var = cs.new_rescue_state_variable(State::from(&key_vec[..]));
        let mut data_vars = vec![];
        let mut data = vec![];
        for i in 0..10 {
            data.push(BLSScalar::from_u32(i as u32));
            data_vars.push(cs.new_variable(data[i]));
        }

        let mut ctr = RescueCtr::new(&key_vec, BLSScalar::zero());
        ctr.add_keystream(&mut data);
        let ctxts_vars = cs.rescue_ctr(key_var.0, &data_vars);

        let mut witness = cs.get_and_clear_witness();
        // check ciphertext consistency
        for (&ctxt, &ctxt_var) in data.iter().zip(ctxts_vars.iter()) {
            assert_eq!(ctxt, witness[ctxt_var]);
        }

        // check constraints
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        witness[ctxts_vars[0]] = BLSScalar::from_u32(1);
        assert!(cs.verify_witness(&witness, &[]).is_err());
    }
}
