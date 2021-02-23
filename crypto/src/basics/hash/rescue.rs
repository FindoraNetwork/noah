// This files implements the rescue block cipher and hash function
// It provides a generic algorithm for any parameters and also a specific instance
// for the BLS12_381 scalar field for a sponge construction parameters rate: 3 and capacity: 1.
// Instances parameters are obtained from https://github.com/KULeuven-COSIC/Marvellous
// instance = Rescue(s,q,m,alpha), where s is the security parameter (eg s = 128,
// q is the prime field size, m is the sponge state size = rate + capacity, and alpha is the *desired*
// S-box exponent for rescue construction.

// Rescue algorithm:
// 1. pad the input with `capacity` 0s
// 2. Set the state as padded input + instance.initial_constants + key.
// 3. Call key scheduling algorithm to derive rounds keys K_r' and K_r. This can be done on each round too.
// 4. Execute N rounds of the form
//   - state_r' = instance.M * S-box-inv(state_{r-1}) + K_r', first step of round r
//   - state_r = instance.M * S-box(state_r') + K_r, second step of round r
//   where S-box(x_1,...,x_m) = (x_1^\alpha, ..., x_m^\alpha) and
//        S-box-inv(x_1,...,x_m) = (x_1^{1/\alpha}, ..., x_m^{1/\alpha})
// 5. return state_N

// Key scheduling: The round keys are computed as:
// 1. Derive key injection keys:
// - set key_injection_0 = C
// 2. Use Rescue rounds to compute the round keys.
// - Set the key as input, and key_injection as the round keys.
// - do:
//   - key_injection_r' = instance.K * key_injection_{r-1} + instance.C, where K (m x m matrix) and C (m-size vector)
//   - K_r'= instance.M * S-box-inv(K_{r-1}) + key_injection_r'
//   - key_injection_r = instance.K * key_injection_r' + instance.C
//   - K_r = instance.M * S-box(K_r') + key_injection_r, used in second step of round r
use algebra::groups::Scalar;
use itertools::Itertools;

#[allow(non_snake_case)]
pub struct RescueInstance<S> {
    pub MDS: Vec<Vec<S>>, // m * m matrix, m = rate + capacity
    pub IC: Vec<S>,       // initial constant m vector
    pub C: Vec<S>,        // key scheduling constant m vector
    pub K: Vec<Vec<S>>,   // key scheduling constant m * m matrix
    pub rate: usize,
    pub capacity: usize,
    pub alpha: u64,
    pub alpha_inv: Vec<u64>,
    pub num_rounds: usize,
}

pub type RoundSubKey<S> = Vec<S>;
pub type RescueState<S> = Vec<S>;

impl<S: Scalar> RescueInstance<S> {
    pub fn num_rounds(&self) -> usize {
        self.num_rounds
    }

    pub fn state_size(&self) -> usize {
        self.rate + self.capacity
    }

    // Take input and produce an initial state by appending `capacity` zeros.
    fn pad_input_to_state_size(&self, input: &[S]) -> RescueState<S> {
        let mut r = input.to_vec();
        while r.len() != self.state_size() {
            r.push(Scalar::from_u32(0));
        }
        r
    }

    /// Produces RESCUE round keys from `key`
    pub fn key_scheduling(&self, key: &[S]) -> Vec<RoundSubKey<S>> {
        let mut key_injection = self.IC.clone();
        let mut prev_key: Vec<S> = key
            .iter()
            .zip(key_injection.iter())
            .map(|(a, b)| a.add(b))
            .collect();
        let mut keys = vec![prev_key.clone()];
        for i in 0..2 * self.num_rounds() {
            if i % 2 == 0 {
                Self::pow_vector(prev_key.as_mut_slice(), &self.alpha_inv);
            } else {
                Self::pow_vector(prev_key.as_mut_slice(), &[self.alpha]);
            }
            // 1. update key injection
            Self::linear_op(&self.K, key_injection.as_mut_slice(), &self.C);
            // 2. compute round key
            Self::linear_op(
                &self.MDS,
                prev_key.as_mut_slice(),
                key_injection.as_mut_slice(),
            );
            // 3. save key
            keys.push(prev_key.clone());
        }
        keys
    }

    /// Compute rescue permutation using preprocessed round keys
    pub fn rescue_with_round_keys(
        &self,
        input: &[S],
        round_keys: &[RoundSubKey<S>],
    ) -> RescueState<S> {
        assert_eq!(input.len(), self.state_size());
        let padded_input = self.pad_input_to_state_size(input);
        let mut state = padded_input
            .iter()
            .zip(round_keys[0].iter())
            .map(|(input, k0i)| input.add(k0i))
            .collect_vec();

        for (i, round_key) in round_keys.iter().skip(1).enumerate() {
            if i % 2 == 0 {
                Self::pow_vector(state.as_mut_slice(), &self.alpha_inv);
            } else {
                Self::pow_vector(state.as_mut_slice(), &[self.alpha]);
            }
            Self::linear_op(&self.MDS, state.as_mut_slice(), round_key);
        }
        state
    }

    /// Initiate Rescue hash function. Produces `keys` for each round.
    pub fn hash_init(&self) -> Vec<RoundSubKey<S>> {
        let key = vec![S::from_u32(0); self.state_size()];
        self.key_scheduling(&key)
    }

    /// Compute hash sampling the rounds' keys online
    pub fn rescue_hash(&self, input: &[S]) -> RescueState<S> {
        let key = vec![S::from_u32(0); self.state_size()];
        self.rescue(input, &key)
    }

    /// Compute RESCUE permutation sampling the rounds' keys online
    pub fn rescue(&self, input: &[S], key: &[S]) -> RescueState<S> {
        assert_eq!(input.len(), self.state_size());

        // key_state = key + initial constants
        let mut key_state: Vec<S> = self
            .IC
            .iter()
            .zip(key.iter())
            .map(|(ic, k)| ic.add(k))
            .collect();
        // key_injection = initial constants
        let mut key_injection = self.IC.clone();

        let padded_input = self.pad_input_to_state_size(input);
        // state = state + key_state
        let mut state = padded_input
            .iter()
            .zip(key_state.iter())
            .map(|(input, k0i)| input.add(k0i))
            .collect_vec();
        // N rounds divided in two parts forward S-box (even step) and backward S-box (forward step)
        for round in 0..2 * self.num_rounds {
            self.rescue_round(
                state.as_mut_slice(),
                key_state.as_mut_slice(),
                key_injection.as_mut_slice(),
                round,
            );
        }
        state
    }

    // Compute a rescue round, sampling the round keys online
    fn rescue_round(
        &self,
        state: &mut [S],
        key_state: &mut [S],
        key_injection: &mut [S],
        round: usize,
    ) {
        if round % 2 == 0 {
            Self::pow_vector(key_state, &self.alpha_inv);
            Self::pow_vector(state, &self.alpha_inv);
        } else {
            Self::pow_vector(key_state, &[self.alpha]);
            Self::pow_vector(state, &[self.alpha]);
        }

        Self::linear_op(&self.K, key_injection, &self.C);
        Self::linear_op(&self.MDS, key_state, key_injection);
        Self::linear_op(&self.MDS, state, key_state);
    }

    // helper function: compute r = M*r + c, where M is a square matrix and r and c are vectors. Result is stored in r.
    pub fn linear_op(matrix: &[Vec<S>], mul_assign_vector: &mut [S], add_vector: &[S]) {
        let mut aux_vec = add_vector.to_vec();
        // multiply matrix agains mul assign vector, result in aux_vec
        for (m_i, aux_i) in matrix.iter().zip(aux_vec.iter_mut()) {
            for (m_ij, v_j) in m_i.iter().zip(mul_assign_vector.iter()) {
                *aux_i = aux_i.add(&m_ij.mul(v_j));
            }
        }
        for (assign_i, aux_elem) in mul_assign_vector.iter_mut().zip(aux_vec) {
            *assign_i = aux_elem;
        }
    }

    fn pow_vector(vector: &mut [S], exponent: &[u64]) {
        for v in vector {
            *v = v.pow(exponent);
        }
    }
}

/// A counter mode encryption based on Rescue block ciphers.
/// * `round_keys`: the round keys determined by the input secret key.
/// * `nonce`: a counter.
/// * `cipher`: the Rescue block cipher instance.
pub struct RescueCtr<S> {
    pub(super) round_keys: Vec<RoundSubKey<S>>,
    pub(super) nonce: S,
    pub(super) cipher: RescueInstance<S>,
}

impl<S: Scalar> RescueCtr<S> {
    // Add keystream to the data.
    pub fn add_keystream(&mut self, data: &mut [S]) {
        self.apply_keystream(data, true);
    }

    // Subtract keystream to the data.
    pub fn sub_keystream(&mut self, data: &mut [S]) {
        self.apply_keystream(data, false);
    }

    fn apply_keystream(&mut self, data: &mut [S], is_add: bool) {
        let zero = S::zero();
        let one = S::one();
        for block in data.chunks_mut(self.cipher.state_size()) {
            let mut input_vec = vec![self.nonce];
            input_vec.extend(vec![zero; self.cipher.state_size() - 1]);
            let keystream = self
                .cipher
                .rescue_with_round_keys(&input_vec, &self.round_keys);
            let len = block.len();
            for (a, b) in block.iter_mut().zip(keystream.iter().take(len)) {
                if is_add {
                    a.add_assign(b);
                } else {
                    a.sub_assign(b);
                }
            }
            self.nonce.add_assign(&one);
        }
    }
}
