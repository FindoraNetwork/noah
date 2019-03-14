pub mod chaum_pedersen;
pub mod dlog;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use crate::utils::u32_to_bigendian_u8array;
use sha2::Digest;

fn compute_challenge(context: &[CompressedRistretto]) -> Scalar {
    /*! I compute zk challenges for Dlog based proof. The challenge is a hash of the
    current context of the proof*/
    let mut hasher = sha2::Sha512::new();

    for point in context.iter() {
        hasher.input(point.as_bytes());
    }

    Scalar::from_hash(hasher)
}

fn compute_sub_challenge(challenge: &Scalar, i: u32) -> Scalar {
    /*! I compute zk sub challenges for multiple Dlog based proofs.
    The sub-challenge is a hash of the challenge and the position i of the sub-challenge*/
    let mut hasher = sha2::Sha512::new();

    hasher.input(challenge.as_bytes());
    hasher.input(u32_to_bigendian_u8array(i));

    Scalar::from_hash(hasher)
}