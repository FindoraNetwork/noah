/// The number of bytes for a scalar value over BN254.
pub const BN254_SCALAR_LEN: usize = 32;

mod fr;
pub use fr::*;

mod fq;
pub use fq::*;

mod g1;
pub use g1::*;

mod g2;
pub use g2::*;

mod gt;
pub use gt::*;

mod pairing;
pub use pairing::*;

/// A convenient macro to initialize a field element over the BN254 curve.
#[macro_export]
macro_rules! new_bn254_fr {
    ($c0:expr) => {{
        let (is_positive, limbs) = ark_ff::ark_ff_macros::to_sign_and_limbs!($c0);
        BN254Scalar::new(is_positive, &limbs)
    }};
}

#[cfg(test)]
mod bn254_groups_test {
    use crate::traits::Group;
    use crate::{
        bn254::{BN254Fq, BN254Gt, BN254PairingEngine, BN254Scalar, BN254G1, BN254G2},
        prelude::*,
        traits::{
            group_tests::{test_scalar_operations, test_scalar_serialization},
            Pairing,
        },
    };
    use ark_bn254::{G1Affine, G2Affine};
    use ark_ec::CurveGroup;

    #[test]
    fn test_scalar_ops() {
        test_scalar_operations::<BN254Scalar>();
        test_scalar_operations::<BN254Fq>();
    }

    #[test]
    fn scalar_deser() {
        test_scalar_serialization::<BN254Scalar>();
        test_scalar_serialization::<BN254Fq>();
    }

    #[test]
    fn scalar_from_to_bytes() {
        let small_value = BN254Scalar::from(165747u32);
        let small_value_bytes = small_value.to_bytes();
        let expected_small_value_bytes: [u8; 32] = [
            115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(small_value_bytes, expected_small_value_bytes);

        let small_value_from_bytes = BN254Scalar::from_bytes(&small_value_bytes).unwrap();
        assert_eq!(small_value_from_bytes, small_value);
    }

    #[test]
    fn hard_coded_group_elements() {
        let base_gt = BN254Gt::get_base();
        let expected_base = BN254PairingEngine::pairing(&BN254G1::get_base(), &BN254G2::get_base());
        assert_eq!(base_gt, expected_base);
    }

    #[test]
    fn bilinear_properties() {
        let identity_g1 = BN254G1::get_identity();
        let identity_g2 = BN254G2::get_identity();
        let identity_gt_computed = BN254PairingEngine::pairing(&identity_g1, &identity_g2);
        let identity_gt = BN254Gt::get_identity();
        assert_eq!(identity_gt, identity_gt_computed);

        let mut prng = test_rng();

        let s1 = BN254Scalar::from(50 + prng.next_u32() % 50);
        let s2 = BN254Scalar::from(50 + prng.next_u32() % 50);

        let base_g1 = BN254G1::get_base();
        let base_g2 = BN254G2::get_base();

        let s1_base_g1 = base_g1.mul(&s1);
        let s2_base_g2 = base_g2.mul(&s2);

        let gt_mapped_element = BN254PairingEngine::pairing(&s1_base_g1, &s2_base_g2);

        let gt_base_computed = BN254PairingEngine::pairing(&base_g1, &base_g2);
        let base_gt = BN254Gt::get_base();
        assert_eq!(base_gt, gt_base_computed);

        assert_eq!(
            gt_mapped_element,
            BN254PairingEngine::pairing(&base_g1, &s2_base_g2).mul(&s1)
        );
        assert_eq!(
            gt_mapped_element,
            BN254PairingEngine::pairing(&s1_base_g1, &base_g2).mul(&s2)
        );

        assert_eq!(gt_mapped_element, gt_base_computed.mul(&s1).mul(&s2));
        assert_eq!(gt_mapped_element, gt_base_computed.mul(&s2).mul(&s1));
    }

    #[test]
    fn curve_points_respresentation_of_g1() {
        let mut prng = test_rng();

        let g1 = BN254G1::get_base();
        let s1 = BN254Scalar::from(50 + prng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = BN254G1::random(&mut prng);

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
    fn curve_points_respresentation_of_g2() {
        let mut prng = test_rng();

        let g1 = BN254G2::get_base();
        let s1 = BN254Scalar::from(50 + prng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = BN254G2::random(&mut prng);

        // This is the projective representation of g1
        let g1_projective = g1.0;
        let g1_prime_projective = g1_prime.0;

        // This is the affine representation of g1_prime
        let g1_prime_affine = G2Affine::from(g1_prime_projective);

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

        let g1 = BN254G1::random(&mut prng);
        let g1_bytes = g1.to_compressed_bytes();
        let g1_recovered = BN254G1::from_compressed_bytes(&g1_bytes).unwrap();
        assert_eq!(g1, g1_recovered);

        let g2 = BN254G2::random(&mut prng);
        let g2_bytes = g2.to_compressed_bytes();
        let g2_recovered = BN254G2::from_compressed_bytes(&g2_bytes).unwrap();
        assert_eq!(g2, g2_recovered);

        let gt = BN254Gt::random(&mut prng);
        let gt_bytes = gt.to_compressed_bytes();
        let gt_recovered = BN254Gt::from_compressed_bytes(&gt_bytes).unwrap();
        assert_eq!(gt, gt_recovered);
    }
}
