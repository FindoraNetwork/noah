/// The number of bytes for a scalar value over secp256k1
pub const SECP256K1_SCALAR_LEN: usize = 32;

mod fr;
pub use fr::*;

mod fq;
pub use fq::*;

mod g1;
pub use g1::*;

/// A convenient macro to initialize a field element over the SECP256K1 curve.
#[macro_export]
macro_rules! new_secp256k1_fq {
    ($c0:expr) => {{
        let (is_positive, limbs) = ark_ff::ark_ff_macros::to_sign_and_limbs!($c0);
        SECP256K1Fq::new(is_positive, &limbs)
    }};
}

#[cfg(test)]
mod secp256k1_groups_test {
    use crate::{
        prelude::*,
        secp256k1::{SECP256K1Scalar, SECP256K1G1},
        traits::group_tests::{test_scalar_operations, test_scalar_serialization},
    };
    use ark_ec::CurveGroup;
    use ark_secp256k1::Affine;

    #[test]
    fn test_scalar_ops() {
        test_scalar_operations::<SECP256K1Scalar>();
    }

    #[test]
    fn scalar_deser() {
        test_scalar_serialization::<SECP256K1Scalar>();
    }

    #[test]
    fn scalar_from_to_bytes() {
        let small_value = SECP256K1Scalar::from(165747u32);
        let small_value_bytes = small_value.to_bytes();
        let expected_small_value_bytes: [u8; 32] = [
            115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(small_value_bytes, expected_small_value_bytes);

        let small_value_from_bytes = SECP256K1Scalar::from_bytes(&small_value_bytes).unwrap();
        assert_eq!(small_value_from_bytes, small_value);
    }

    #[test]
    fn curve_points_respresentation_of_g1() {
        let mut prng = test_rng();

        let g1 = SECP256K1G1::get_base();
        let s1 = SECP256K1Scalar::from(50 + prng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = SECP256K1G1::random(&mut prng);

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

        let g1 = SECP256K1G1::random(&mut prng);
        let g1_bytes = g1.to_compressed_bytes();
        let g1_recovered = SECP256K1G1::from_compressed_bytes(&g1_bytes).unwrap();
        assert_eq!(g1, g1_recovered);
    }
}
