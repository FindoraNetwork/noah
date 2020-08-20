// This file implements a commitment scheme based on rescue permutation.
// It provides a generic committing algorithm for any rescue hash instances and any scalar fields.

// Let r and c be the rate and the capacity of the rescue permutation.
// Let n < r be the number of messages.
// Committing algorithm: commit(m_1, ..., m_n)
// 1. Sample a random blinding factor rand.
// 2. Return rescue(rand, m_1, ..., m_n, 0^{r+c-n-1})[0].

// Opening verification: verify(m_1, ..., m_n, rand, commitment)
// 1. Check whether commitment == rescue(rand, m_1, ..., m_n, 0^{r+c-n-1})[0]
use crate::algebra::bls12_381::BLSScalar;
use crate::algebra::groups::Scalar;
use crate::basic_crypto::hash::rescue::RescueInstance;
use crate::errors::ZeiError;
use rand_core::{CryptoRng, RngCore};

pub struct Commitment<S> {
  hash: RescueInstance<S>,
  msg_len: usize, // number of messages to be committed
}

impl<S: Scalar> Commitment<S> {
  /// Returns the commitment and the opening to a message vector.
  /// It returns an error when the number of input messages is invalid.
  /// * `rng` - source of randomness
  /// * `msgs` - the messages to be committed
  pub fn commit<R: CryptoRng + RngCore>(&self,
                                        rng: &mut R,
                                        msgs: &[S])
                                        -> Result<(S, S), ZeiError> {
    if msgs.len() != self.msg_len {
      return Err(ZeiError::CommitmentInputError);
    }
    let blind_scalar = S::random_scalar(rng);
    let mut input_vec = vec![blind_scalar.clone()];
    input_vec.extend(msgs.to_vec());
    // Pad zeroes
    input_vec.extend(vec![S::from_u32(0); self.hash.rate + self.hash.capacity - msgs.len() - 1]);
    Ok((self.hash.rescue_hash(&input_vec)[0].clone(), blind_scalar))
  }

  /// Check the opening of a commitment.
  /// It returns an error when the check fails or the number of input messages is invalid.
  /// * `msgs` - the messages to be committed
  /// * `blind_scalar` - the blinding factor of the commitment
  /// * `commitment` - the commitment value
  pub fn verify(&self, msgs: &[S], blind_scalar: &S, commitment: &S) -> Result<(), ZeiError> {
    if msgs.len() != self.msg_len {
      return Err(ZeiError::CommitmentInputError);
    }
    let mut input_vec = vec![blind_scalar.clone()];
    input_vec.extend(msgs.to_vec());
    // Pad zeroes
    input_vec.extend(vec![S::from_u32(0); self.hash.rate + self.hash.capacity - msgs.len() - 1]);
    if &self.hash.rescue_hash(&input_vec)[0] != commitment {
      Err(ZeiError::CommitmentVerificationError)
    } else {
      Ok(())
    }
  }
}

impl Default for Commitment<BLSScalar> {
  fn default() -> Self {
    Self::new()
  }
}

impl Commitment<BLSScalar> {
  pub fn new() -> Self {
    let hash = RescueInstance::<BLSScalar>::new();
    let msg_len = hash.rate - 1;
    Self { hash, msg_len }
  }
}

#[cfg(test)]
mod test {
  use crate::algebra::bls12_381::BLSScalar;
  use crate::algebra::groups::Scalar;
  use crate::basic_crypto::commitment::Commitment;
  use crate::basic_crypto::hash::rescue::RescueInstance;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn test_hash_commitment() {
    let hash_comm = Commitment::<BLSScalar>::new();
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    // wrong number of input messages
    assert!(hash_comm.commit(&mut prng, &[BLSScalar::from_u32(0)])
                     .is_err());

    // the commitment is successful
    let mut msgs = [BLSScalar::from_u32(1), BLSScalar::from_u32(2)];
    let comm = hash_comm.commit(&mut prng, &msgs);
    assert!(comm.is_ok());
    let (commitment, blind_scalar) = comm.unwrap(); // safe unwrap

    // the commitment value is consistent with the hash output
    let hash = RescueInstance::<BLSScalar>::new();
    assert_eq!(commitment,
               hash.rescue_hash(&[blind_scalar.clone(),
                                  msgs[0].clone(),
                                  msgs[1].clone(),
                                  BLSScalar::from_u32(0)])[0]);

    // correct opening
    assert!(hash_comm.verify(&msgs, &blind_scalar, &commitment).is_ok());

    // wrong blinding randomness
    assert!(hash_comm.verify(&msgs, &BLSScalar::from_u32(0), &commitment)
                     .is_err());

    // wrong messages
    msgs[0] = BLSScalar::from_u32(0);
    assert!(hash_comm.verify(&msgs, &blind_scalar, &commitment).is_err());
  }
}
