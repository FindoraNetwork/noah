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
const ALPHA_INV: [u8; 32] = [0xCD, 0xCC, 0xCC, 0xCC, 0x32, 0x33, 0x33, 0x33, 0x99, 0xF1, 0x98,
                             0x99, 0x67, 0x0E, 0x7F, 0x21, 0x02, 0xF0, 0x73, 0x9D, 0x69, 0x56,
                             0x4A, 0xE1, 0x1C, 0x32, 0x72, 0xDD, 0xBA, 0x0F, 0x5F, 0x2E];

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
    let vars: Vec<VarIndex> = state.0
                                   .into_iter()
                                   .map(|elem| self.new_variable(elem))
                                   .collect();
    StateVar(vars)
  }

  /// Create a rescue input variable and add a zero constraint for the last input elem.
  pub fn new_rescue_input_variable(&mut self, input_state: State) -> StateVar {
    assert_eq!(input_state.0[WIDTH - 1], BLSScalar::zero());
    let input_var = self.new_rescue_state_variable(input_state);
    self.insert_constant_gate(input_var.0[WIDTH - 1], BLSScalar::zero());
    input_var
  }

  /// Returns the output of the rescue hash function on input variable `input_var`
  pub fn rescue_hash(&mut self, input_var: &StateVar) -> VarIndex {
    let hash = RescueInstance::new();
    let zero = BLSScalar::zero();
    let zero_vec = vec![zero, zero, zero, zero];
    let keys = hash.key_scheduling(&zero_vec[..]);
    let keys_states: Vec<State> = keys.iter().map(|key| State::from(&key[..])).collect();
    let mds_states: Vec<State> = hash.MDS.iter().map(|mi| State::from(&mi[..])).collect();
    self.rescue_hash_with_keys(input_var, &mds_states, &keys_states)
  }

  /// Returns the output of the rescue hash function on input variable `input_var`, round keys `key`,
  /// and an MDS matrix.
  fn rescue_hash_with_keys(&mut self,
                           input_var: &StateVar,
                           mds: &[State],
                           keys: &[State])
                           -> VarIndex {
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
    state_var.0[0]
  }

  fn add_constant_state(&mut self, state_var: &StateVar, constant: &State) -> StateVar {
    let vars: Vec<VarIndex> = state_var.0
                                       .iter()
                                       .zip(constant.0.iter())
                                       .map(|(&var, elem)| self.add_constant(var, elem))
                                       .collect();
    StateVar(vars)
  }

  fn linear_op(&mut self, state_var: &StateVar, mds: &[State], key: &State) -> StateVar {
    assert_eq!(mds.len(), WIDTH);
    // vars[i] = key[i] + \sum_{j=0..WIDTH-1} mds[i][j] * state_var[j]
    let vars: Vec<VarIndex> =
      (0..WIDTH).map(|i| self.add_linear_op_constraint(&state_var.0[..], &mds[i].0[..], &key.0[i]))
                .collect();
    StateVar(vars)
  }

  fn non_linear_op(&mut self, state_var: &StateVar, mds: &[State], key: &State) -> StateVar {
    assert_eq!(mds.len(), WIDTH);
    // vars[i] = key[i] + \sum_{j=0..WIDTH-1} mds[i][j] * state_var[j]^5
    let vars: Vec<VarIndex> =
      (0..WIDTH).map(|i| {
                  self.add_non_linear_op_constraint(&state_var.0[..], &mds[i].0[..], &key.0[i])
                })
                .collect();
    StateVar(vars)
  }

  fn pow_5_inv(&mut self, state_var: &StateVar) -> StateVar {
    let vars: Vec<VarIndex> = state_var.0
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
  fn add_linear_op_constraint(&mut self,
                              vars: &[VarIndex],
                              coefs: &[BLSScalar],
                              constant: &BLSScalar)
                              -> VarIndex {
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
  fn add_non_linear_op_constraint(&mut self,
                                  vars: &[VarIndex],
                                  coefs: &[BLSScalar],
                                  constant: &BLSScalar)
                                  -> VarIndex {
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
  use crypto::basics::hash::rescue::RescueInstance;

  type F = BLSScalar;

  /*
  /// BLS12-381 scalar size:
  /// q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
  /// TODO: Move MODULUS to a pub(crate) constant.
  const MODULUS: [u8; 32] = [0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe,
                             0xff, 0x02, 0xa4, 0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8,
                             0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73];
   */
  #[test]
  fn test_rescue_hash() {
    let hash = RescueInstance::new();
    // use BLS12-381 field
    let mut cs = TurboPlonkConstraintSystem::<BLSScalar>::new();
    let input_vec = [BLSScalar::from_u32(11),
                     BLSScalar::from_u32(171),
                     BLSScalar::from_u32(273),
                     BLSScalar::from_u32(0)];
    let input_state = State::from(&input_vec[..]);
    let input_var = cs.new_rescue_input_variable(input_state.clone());
    let out_var = cs.rescue_hash(&input_var);

    // Check consistency between witness[input_var] and input_state
    let witness_input: Vec<F> = input_var.0
                                         .iter()
                                         .map(|&var| cs.witness[var].clone())
                                         .collect();
    assert_eq!(witness_input, input_state.0);

    // Check consistency between witness[out_var] and rescue_out_state[0]
    let rescue_out_state = State::from(&hash.rescue_hash(&input_vec)[..]);
    assert_eq!(cs.witness[out_var], rescue_out_state.0[0]);

    // Check good witness
    let mut witness = cs.get_and_clear_witness();
    let verify = cs.verify_witness(&witness[..], &[]);
    assert!(verify.is_ok(), verify.unwrap_err());

    // Check bad witness: witness[out_var] = zero()
    witness[out_var] = F::zero();
    assert!(cs.verify_witness(&witness[..], &[]).is_err());
  }
}
