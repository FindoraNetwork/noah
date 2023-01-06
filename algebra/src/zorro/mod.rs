use crate::prelude::*;
use crate::traits::PedersenCommitment;
use ark_bulletproofs::curve::zorro::G1Affine;

/// The number of bytes for a scalar value over Zorro
pub const ZORRO_SCALAR_LEN: usize = 32;

mod fr;
pub use fr::*;

mod fq;
pub use fq::*;

mod g1;
pub use g1::*;

/// The wrapped struct for
/// `ark_bulletproofs::r1cs::R1CSProof<ark_bulletproofs::curve::zorro::G1Affine>`
pub type ZorroProof = ark_bulletproofs::r1cs::R1CSProof<G1Affine>;

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// The Pedersen commitment implementation for the secq256k1 group.
pub struct PedersenCommitmentZorro {
    /// The generator for the value part.
    pub B: ZorroG1,
    /// The generator for the blinding part.
    pub B_blinding: ZorroG1,
}

impl Default for PedersenCommitmentZorro {
    fn default() -> Self {
        let pc_gens = ark_bulletproofs::PedersenGens::default();
        Self {
            B: ZorroG1::from_raw(pc_gens.B),
            B_blinding: ZorroG1::from_raw(pc_gens.B_blinding),
        }
    }
}

impl PedersenCommitment<ZorroG1> for PedersenCommitmentZorro {
    fn generator(&self) -> ZorroG1 {
        self.B
    }

    fn blinding_generator(&self) -> ZorroG1 {
        self.B_blinding
    }

    fn commit(&self, value: ZorroScalar, blinding: ZorroScalar) -> ZorroG1 {
        self.B.mul(&value).add(&self.B_blinding.mul(&blinding))
    }
}

impl From<&PedersenCommitmentZorro> for ark_bulletproofs::PedersenGens<G1Affine> {
    fn from(rp: &PedersenCommitmentZorro) -> Self {
        ark_bulletproofs::PedersenGens {
            B: rp.B.get_raw(),
            B_blinding: rp.B_blinding.get_raw(),
        }
    }
}

/// The wrapper struct for the Bulletproof generators.
pub type ZorroBulletproofGens = ark_bulletproofs::BulletproofGens<G1Affine>;

#[cfg(test)]
mod zorro_groups_test {
    use crate::{
        prelude::*,
        traits::group_tests::{test_scalar_operations, test_scalar_serialization},
        zorro::{ZorroFq, ZorroG1, ZorroScalar},
    };
    use ark_bulletproofs::curve::zorro::G1Affine;
    use ark_ec::CurveGroup;

    #[test]
    fn test_scalar_ops() {
        test_scalar_operations::<ZorroScalar>();
        test_scalar_operations::<ZorroFq>();
    }

    #[test]
    fn scalar_deser() {
        test_scalar_serialization::<ZorroScalar>();
        test_scalar_serialization::<ZorroFq>();
    }

    #[test]
    fn scalar_from_to_bytes() {
        let small_value = ZorroScalar::from(165747u32);
        let small_value_bytes = small_value.to_bytes();
        let expected_small_value_bytes: [u8; 32] = [
            115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(small_value_bytes, expected_small_value_bytes);

        let small_value_from_bytes = ZorroScalar::from_bytes(&small_value_bytes).unwrap();
        assert_eq!(small_value_from_bytes, small_value);
    }

    #[test]
    fn curve_points_respresentation_of_g1() {
        let mut prng = test_rng();

        let g1 = ZorroG1::get_base();
        let s1 = ZorroScalar::from(50 + prng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = ZorroG1::random(&mut prng);

        // This is the projective representation of g1
        let g1_projective = g1.0;
        let g1_prime_projective = g1_prime.0;

        // This is the affine representation of g1_prime
        let g1_prime_affine = G1Affine::from(g1_prime_projective);

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

        let g1 = ZorroG1::random(&mut prng);
        let g1_bytes = g1.to_compressed_bytes();
        let g1_recovered = ZorroG1::from_compressed_bytes(&g1_bytes).unwrap();
        assert_eq!(g1, g1_recovered);
    }
}
