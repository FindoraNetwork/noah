use crate::prelude::*;
use crate::traits::PedersenCommitment;
use ark_secq256k1::Affine;

mod fr;
pub use fr::*;

mod fq;
pub use fq::*;

mod g1;
pub use g1::*;

/// The wrapped struct for
/// `ark_bulletproofs::r1cs::R1CSProof<ark_secq256k1::Affine>`
pub type SECQ256K1Proof = ark_bulletproofs::r1cs::R1CSProof<Affine>;

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// The Pedersen commitment implementation for the secq256k1 group.
pub struct PedersenCommitmentSecq256k1 {
    /// The generator for the value part.
    pub B: SECQ256K1G1,
    /// The generator for the blinding part.
    pub B_blinding: SECQ256K1G1,
}

impl Default for PedersenCommitmentSecq256k1 {
    fn default() -> Self {
        let pc_gens = ark_bulletproofs::PedersenGens::default();
        Self {
            B: SECQ256K1G1::from_raw(pc_gens.B),
            B_blinding: SECQ256K1G1::from_raw(pc_gens.B_blinding),
        }
    }
}

impl PedersenCommitment<SECQ256K1G1> for PedersenCommitmentSecq256k1 {
    fn generator(&self) -> SECQ256K1G1 {
        self.B
    }

    fn blinding_generator(&self) -> SECQ256K1G1 {
        self.B_blinding
    }

    fn commit(&self, value: SECQ256K1Scalar, blinding: SECQ256K1Scalar) -> SECQ256K1G1 {
        self.B.mul(&value).add(&self.B_blinding.mul(&blinding))
    }
}

impl From<&PedersenCommitmentSecq256k1> for ark_bulletproofs::PedersenGens<Affine> {
    fn from(rp: &PedersenCommitmentSecq256k1) -> Self {
        ark_bulletproofs::PedersenGens {
            B: rp.B.get_raw(),
            B_blinding: rp.B_blinding.get_raw(),
        }
    }
}

/// The wrapper struct for the Bulletproof generators.
pub type Secq256k1BulletproofGens = ark_bulletproofs::BulletproofGens<Affine>;

/// The number of bytes for a scalar value over the secq256k1 curve
pub const SECQ256K1_SCALAR_LEN: usize = 32;

#[cfg(test)]
mod secq256k1_groups_test {
    use crate::{
        prelude::*,
        secq256k1::{SECQ256K1Scalar, SECQ256K1G1},
        traits::group_tests::{test_scalar_operations, test_scalar_serialization},
    };
    use ark_ec::CurveGroup;
    use ark_secq256k1::Affine;

    #[test]
    fn test_scalar_ops() {
        test_scalar_operations::<SECQ256K1Scalar>();
    }

    #[test]
    fn scalar_deser() {
        test_scalar_serialization::<SECQ256K1Scalar>();
    }

    #[test]
    fn scalar_from_to_bytes() {
        let small_value = SECQ256K1Scalar::from(165747u32);
        let small_value_bytes = small_value.to_bytes();
        let expected_small_value_bytes: [u8; 32] = [
            115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(small_value_bytes, expected_small_value_bytes);

        let small_value_from_bytes = SECQ256K1Scalar::from_bytes(&small_value_bytes).unwrap();
        assert_eq!(small_value_from_bytes, small_value);
    }

    #[test]
    fn curve_points_respresentation_of_g1() {
        let mut prng = test_rng();

        let g1 = SECQ256K1G1::get_base();
        let s1 = SECQ256K1Scalar::from(50 + prng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = SECQ256K1G1::random(&mut prng);

        // This is the projective representation of g1
        let g1_projective = g1.0;
        let g1_prime_projective = g1_prime.0;

        // This is the affine representation of g1_prime
        let g1_prime_affine = Affine::from(g1_prime_projective);

        let g1_pr_plus_g1_prime_pr = g1_projective.add(&g1_prime_projective);

        // These two operations correspond to summation of points,
        // one in projective form and the other in affine form
        let g1_pr_plus_g1_prime_af = g1_projective.add(&g1_prime_affine);
        assert_eq!(g1_pr_plus_g1_prime_pr, g1_pr_plus_g1_prime_af);

        let g1_pr_plus_g1_prime_af = g1_projective.add(&g1_prime_projective.into_affine());
        assert_eq!(g1_pr_plus_g1_prime_pr, g1_pr_plus_g1_prime_af);
    }

    #[test]
    fn test_serialization_of_points() {
        let mut prng = test_rng();

        let g1 = SECQ256K1G1::random(&mut prng);
        let g1_bytes = g1.to_compressed_bytes();
        let g1_recovered = SECQ256K1G1::from_compressed_bytes(&g1_bytes).unwrap();
        assert_eq!(g1, g1_recovered);
    }
}
