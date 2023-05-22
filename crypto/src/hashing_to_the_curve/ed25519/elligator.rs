use crate::hashing_to_the_curve::models::elligator::ElligatorParameters;
use noah_algebra::ed25519::Ed25519Point;
use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq};

/// Elligator map for Ed25519
pub struct Ed25519ElligatorParameters;

impl ElligatorParameters<Ed25519Point> for Ed25519ElligatorParameters {
    const A: Ed25519Fq = new_ed25519_fq!("486662");
    const B: Ed25519Fq = new_ed25519_fq!("1");
    const QNR: Ed25519Fq = new_ed25519_fq!("2");
}

#[cfg(test)]
mod tests {
    use crate::hashing_to_the_curve::ed25519::elligator::Ed25519ElligatorParameters;
    use crate::hashing_to_the_curve::models::elligator::Elligator;
    use crate::hashing_to_the_curve::traits::HashingToCurve;
    use noah_algebra::ed25519::{Ed25519Fq, Ed25519Point};
    use noah_algebra::prelude::{test_rng, Scalar};

    type M = Elligator<Ed25519Point, Ed25519ElligatorParameters>;

    #[test]
    fn test_random_t() {
        for _ in 0..100 {
            let mut rng = test_rng();
            let t = Ed25519Fq::random(&mut rng);
            assert!(M::get_cofactor_uncleared_x(&t).is_ok());
        }
    }
}
