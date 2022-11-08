/// The number of bytes for a scalar value over Jubjub
pub const JUBJUB_SCALAR_LEN: usize = 32;

mod fr;
pub use fr::*;

mod fq;
pub use fq::*;

mod g1;
pub use g1::*;

#[cfg(test)]
mod jubjub_groups_test {
    use crate::{
        jubjub::{JubjubPoint, JubjubScalar},
        prelude::*,
        traits::group_tests::{test_scalar_operations, test_scalar_serialization},
    };
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_scalar_ops() {
        test_scalar_operations::<JubjubScalar>();
    }

    #[test]
    fn scalar_deser() {
        test_scalar_serialization::<JubjubScalar>();
    }

    #[test]
    fn scalar_from_to_bytes() {
        let small_value = JubjubScalar::from(165747u32);
        let small_value_bytes = small_value.to_bytes();
        let expected_small_value_bytes: [u8; 32] = [
            115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(small_value_bytes, expected_small_value_bytes);

        let small_value_from_bytes = JubjubScalar::from_bytes(&small_value_bytes).unwrap();
        assert_eq!(small_value_from_bytes, small_value);
    }

    #[test]
    fn schnorr_identification_protocol() {
        let mut rng = ChaCha20Rng::from_entropy();

        // Private key
        let alpha = JubjubScalar::random(&mut rng);

        // Public key
        let base = JubjubPoint::get_base();
        let u = base.mul(&alpha);

        // Verifier challenge
        let c = JubjubScalar::random(&mut rng);

        // Prover commitment
        let alpha_t = JubjubScalar::random(&mut rng);
        let u_t = base.mul(&alpha_t);

        // Prover response
        let alpha_z = alpha_t.add(&c.mul(&alpha));

        // Proof verification
        let left = base.mul(&alpha_z);
        let right = u_t.add(&u.mul(&c));

        assert_eq!(left, right);
    }
}
