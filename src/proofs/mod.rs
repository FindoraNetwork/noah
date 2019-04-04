pub mod chaum_pedersen;
pub mod dlog;
pub mod solvency;
pub mod pedersen_elgamal;
pub mod identity;

use crate::utils::u32_to_bigendian_u8array;
use sha2::Digest;
use crate::algebra::groups::{Group, Scalar};

fn compute_challenge_ref<G: Group>(context: &[&G]) -> G::ScalarType {
    /*! I compute zk challenges for Dlog based proof. The challenge is a hash of the
    current context of the proof*/
    let mut hasher = sha2::Sha512::new();

    for point in context.iter() {
        hasher.input(point.to_compressed_bytes().as_slice());
    }

    G::ScalarType::from_hash(hasher)
}

fn compute_sub_challenge<G: Group>(challenge: &G::ScalarType, i: u32) -> G::ScalarType {
    /*! I compute zk sub challenges for multiple Dlog based proofs.
    The sub-challenge is a hash of the challenge and the position i of the sub-challenge*/
    let mut hasher = sha2::Sha512::new();

    hasher.input(G::ScalarType::to_bytes(&challenge).as_slice());
    hasher.input(u32_to_bigendian_u8array(i));

    G::ScalarType::from_hash(hasher)
}