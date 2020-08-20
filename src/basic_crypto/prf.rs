// This file implements a sponge-based PRF from a rescue permutation. The construction follows the
// Full-State Keyed Sponge (FKS) paradigm explained in https://eprint.iacr.org/2015/541.pdf
// Compared to HMAC, the scheme invokes fewer number of rescue hashes/permutations.

// PRF algorithm: Let p : Fp^w -> Fp^w be a public permutation.
// PRF^p(key, (m_0, ..., m_{n-1})) : Fp x Fp^{n} -> Fp is computed as follows:
// 1. Set the initial state s := (0^{w-1}||key) \in Fp^w
// 2. For i = 0..[(n-1)/w]+1:
//      2.1 Inject the messages into the state: s := s + (m_{i*w}||...||m_{i*w+w-1})
//      2.2 Permute the state: s := p(s)
// 3. Return s_0.
use crate::algebra::bls12_381::BLSScalar;
use crate::algebra::groups::Scalar;
use crate::basic_crypto::hash::rescue::RescueInstance;

pub struct PRF<S>(RescueInstance<S>);

impl<S: Scalar> PRF<S> {
  /// PRF evaluation without padding
  /// * `key` - PRF key
  /// * `msgs` - PRF inputs
  pub fn eval(&self, key: &S, msgs: &[S]) -> S {
    let width = self.0.state_size();
    let mut state = vec![S::from_u32(0); width];
    state[width - 1] = key.clone();
    // Each round can absorb `width` messages, so it takes \ceil{n/width} rounds to absorb all of
    // the n messages
    let n_rounds = (msgs.len() - 1) / width + 1;
    for i in 0..n_rounds {
      for (state_j, msg_j) in state.iter_mut()
                                   .zip(msgs.iter().skip(i * width).take(width))
      {
        *state_j = state_j.add(msg_j);
      }
      state = self.0.rescue_hash(&state);
    }
    state[0].clone()
  }
}

impl Default for PRF<BLSScalar> {
  fn default() -> Self {
    Self::new()
  }
}

impl PRF<BLSScalar> {
  pub fn new() -> Self {
    Self(RescueInstance::<BLSScalar>::new())
  }
}

#[cfg(test)]
mod test {
  use crate::algebra::bls12_381::BLSScalar;
  use crate::algebra::groups::Scalar;
  use crate::basic_crypto::hash::rescue::RescueInstance;
  use crate::basic_crypto::prf::PRF;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn test_prf_consistency() {
    let prf = PRF::<BLSScalar>::new();
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let key = BLSScalar::random_scalar(&mut prng);
    let mut input = vec![BLSScalar::from_u32(1),
                         BLSScalar::from_u32(2),
                         BLSScalar::from_u32(3),
                         BLSScalar::from_u32(4)];
    let output = prf.eval(&key, &input);

    let hash = RescueInstance::<BLSScalar>::new();
    // the first sponge round
    input[3] = input[3].add(&key);
    let expected_output = hash.rescue_hash(&input);
    // check output consistency
    assert_eq!(output, expected_output[0]);

    input = vec![BLSScalar::from_u32(1),
                 BLSScalar::from_u32(2),
                 BLSScalar::from_u32(3),
                 BLSScalar::from_u32(4),
                 BLSScalar::from_u32(5)];
    let output = prf.eval(&key, &input);

    // the first sponge round
    let mut state = vec![BLSScalar::from_u32(1),
                         BLSScalar::from_u32(2),
                         BLSScalar::from_u32(3),
                         BLSScalar::from_u32(4).add(&key)];
    state = hash.rescue_hash(&state);
    // the second sponge round
    state[0] = state[0].add(&input[4]);
    let expected_output = hash.rescue_hash(&state);
    // check output consistency
    assert_eq!(output, expected_output[0]);
  }
}
