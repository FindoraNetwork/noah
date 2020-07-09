use crate::algebra::groups::Scalar;
use itertools::Itertools;

#[allow(non_snake_case)]
pub struct RescueInstance<S> {
  M: Vec<Vec<S>>, // m * m matrix, m = rate + capacity
  K0: Vec<S>, //  m vector
  K: Vec<Vec<(S,S)>>, // (n rounds + 1) * m matritx
  pub rate: usize,
  pub capacity: usize,
  alpha: S,
  alpha_inv: S
}

impl<S: Scalar> RescueInstance<S>{

  pub fn num_rounds(&self) -> usize {
    self.K.len()
  }

  pub fn sponge_size(&self) -> usize {
    self.rate + self.capacity
  }

  fn pad_input(self, input: &[S]) -> Vec<S> {
    let mut r = input.to_vec();
    while r.len() != self.sponge_size() {
      r.push(Scalar::from_u32(0));
    }
    r
  }

  pub fn rescue_hash(self, input: &[S]) -> Vec<S> {
    assert_eq!(input.len(), self.sponge_size());
    let padded_input = self.pad_input(input);
    let mut state = padded_input
      .iter()
      .zip(self.K0.iter())
      .map(|(input, k0i)| {input.add(k0i)}).collect_vec();

    for round in self.n_rounds {
      rescue_round(instance, state.as_mut_slice(), round);
    }
    state[0..self.rate].to_vec()
  }

  fn rescue_round<S: Scalar> (self, state: &mut [S], round: usize) {
    let mut inter_state = vec![];
    for (M_i, (K_i_0, _)) in self.M.iter().zip(self.K[round].iter()) {
      let mut sum = S::from_u32(0);
      for (state_j, M_i_j) in M_i.iter().zip(state.iter()) {
        let s_box_1_value = state_j.pow(&self.alpha_inv);
        sum = sum.add(s_box_1_value.mul(M_i_j));
      }
      inter_state.push(K_i_0.add(sum))
    }
    for (state_i, (M_i, (_, K_i_1))) in state
      .iter_mut()
      .zip(self.M
        .iter()
        .zip(self.K[round].iter())) {
      let mut sum = S::from_u32(0);
      for (inter_state_j, M_i_j) in M_i.iter().zip(inter_state.iter()) {
        let s_box_0_value = inter_state_j.pow(&self.alpha);
        sum = sum.add(s_box_0_value.mul(M_i_j));
      }
      *state_i = K_i_1.add(sum);
    }
  }
}

pub mod bls12_381_2_1_rescue {
  use crate::crypto::rescue::RescueInstance;
  use crate::algebra::bls12_381::BLSScalar;
  use crate::algebra::groups::Scalar;

  const M00: &'static str = "19703017446530302026954081842172601421653728134317178448940156258115853425803";
  const M01: &'static str = "10251498144790729877114984073212046753223574188577263253763854582885300616634";
  const M02: &'static str = "23799697215770479455315980501436150478606639549341703710964277906023879274693";

  const M10: &'static str = "3007859742890615231402252990001597094047140204544326329227026628202747223471";
  const M11: &'static str = "28206680002640467010077105488518988050496606663258696654543362871739559141116";
  const M12: &'static str = "3001386190657217866716811031197002190094834176598601007437349105366277408753";

  const M20: &'static str = "3302832234223427084389235892793462946069958738751625733789554798277785616852";
  const M21: &'static str = "33828191304584863092326289783666465913001308709873493077072772336792329272781";
  const M22: &'static str = "39527082973012175895755035046102602497048600747962062191946750704586900696815";

  const K01:&'static str = "20508694040621567351648110034447675442497630601368754313856884903339587777311";
  const K02:&'static str = "21833126749675005420257511508741654628498211767962591705355382899857469438170";
  const K03:&'static str = "10094259962876866855921243786568400951965635335279511958062644189442373357290";

  impl RescueInstance<BLSScalar> {
    pub fn new() -> Self {
      Self{
        M: vec![vec![BLSScalar::], vec![], vec![]],
        K0: vec![],
        K: vec![vec![]],
        rate: 2,
        capacity: 1,
        alpha: BLSScalar::from_u32(3),
        alpha_inv: BLSScalar::from_u32(3).inv();
      }

    }
  }
}