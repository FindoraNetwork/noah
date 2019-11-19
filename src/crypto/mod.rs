pub mod accumulators;
pub(crate) mod anon_creds;
pub mod bp_circuits;
pub mod chaum_pedersen;
pub(crate) mod conf_cred_reveal;
pub mod dlog;
pub mod pedersen_elgamal;
pub mod simple_group_signatures;
pub mod solvency;
pub mod whitelist;

use crate::algebra::groups::{Group, Scalar};
use crate::utils::u32_to_bigendian_u8array;
use sha2::Digest;

fn compute_challenge_ref<S: Scalar, G: Group<S>>(context: &[&G]) -> S {
  /*! I compute zk challenges for Dlog based proof. The challenge is a hash of the
  current context of the proof*/
  let mut hasher = sha2::Sha512::new();

  for point in context.iter() {
    hasher.input(point.to_compressed_bytes().as_slice());
  }

  S::from_hash(hasher)
}

fn compute_sub_challenge<S: Scalar>(challenge: &S, i: u32) -> S {
  /*! I compute zk sub challenges for multiple Dlog based proofs.
  The sub-challenge is a hash of the challenge and the position i of the sub-challenge*/
  let mut hasher = sha2::Sha512::new();

  hasher.input(S::to_bytes(&challenge).as_slice());
  hasher.input(u32_to_bigendian_u8array(i));

  S::from_hash(hasher)
}
