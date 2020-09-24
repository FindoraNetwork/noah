// This file implements a commitment scheme based on rescue permutation.
// It provides a generic committing algorithm for any rescue hash instances and any scalar fields.

// Let r and c be the rate and the capacity of the rescue permutation.
// Let n < r be the number of messages.
// Committing algorithm: commit(rand; m_1, ..., m_n) (rand is a randomly sampled bliding factor)
// 1. Return rescue(rand, m_1, ..., m_n, 0^{r+c-n-1})[0].

// Opening verification: verify(m_1, ..., m_n, rand, commitment)
// 1. Check whether commitment == rescue(rand, m_1, ..., m_n, 0^{r+c-n-1})[0]
use crate::basics::hash::rescue::RescueInstance;
use algebra::bls12_381::BLSScalar;
use algebra::groups::Scalar;
use utils::errors::ZeiError;

pub struct HashCommitment<S> {
  hash: RescueInstance<S>,
  msg_len: usize, // number of messages to be committed
}

impl<S: Scalar> HashCommitment<S> {
  /// Returns the commitment to a message vector.
  /// It returns an error when the number of input messages is invalid.
  /// * `blind_scalar` - blinding randomness
  /// * `msgs` - the messages to be committed
  pub fn commit(&self, blind_scalar: &S, msgs: &[S]) -> Result<S, ZeiError> {
    if msgs.len() != self.msg_len {
      return Err(ZeiError::CommitmentInputError);
    }
    let mut input_vec = vec![*blind_scalar];
    input_vec.extend(msgs.to_vec());
    // Pad zeroes
    input_vec.extend(vec![S::from_u32(0); self.hash.rate + self.hash.capacity - msgs.len() - 1]);
    Ok(self.hash.rescue_hash(&input_vec)[0])
  }

  /// Check the opening of a commitment.
  /// It returns an error when the check fails or the number of input messages is invalid.
  /// * `msgs` - the messages to be committed
  /// * `blind_scalar` - the blinding factor of the commitment
  /// * `commitment` - the commitment value
  pub fn verify(&self, msgs: &[S], blind_scalar: &S, commitment: &S) -> Result<(), ZeiError> {
    let expected = self.commit(blind_scalar, msgs)?;
    if expected != *commitment {
      return Err(ZeiError::CommitmentVerificationError);
    }
    Ok(())
  }
}

impl Default for HashCommitment<BLSScalar> {
  fn default() -> Self {
    Self::new()
  }
}

impl HashCommitment<BLSScalar> {
  pub fn new() -> Self {
    let hash = RescueInstance::<BLSScalar>::new();
    let msg_len = hash.rate - 1;
    Self { hash, msg_len }
  }
}

#[cfg(test)]
mod test {
  use crate::basics::commitments::rescue::HashCommitment;
  use crate::basics::hash::rescue::RescueInstance;
  use algebra::bls12_381::BLSScalar;
  use algebra::groups::Scalar;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn test_hash_commitment() {
    let hash_comm = HashCommitment::<BLSScalar>::new();
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let blind_scalar = BLSScalar::random(&mut prng);
    // wrong number of input messages
    assert!(hash_comm.commit(&blind_scalar, &[BLSScalar::from_u32(0)])
                     .is_err());

    // the commitment is successful
    let mut msgs = [BLSScalar::from_u32(1), BLSScalar::from_u32(2)];
    let comm = hash_comm.commit(&blind_scalar, &msgs);
    assert!(comm.is_ok());
    let commitment = comm.unwrap(); // safe unwrap

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
