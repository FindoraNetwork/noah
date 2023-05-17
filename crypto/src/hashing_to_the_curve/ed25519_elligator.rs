use crate::hashing_to_the_curve::traits::ElligatorParameters;
use noah_algebra::ed25519::Ed25519Point;
use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq, prelude::*};

/// Elligator map for Ed25519
pub struct Ed25519Elligator;

impl ElligatorParameters<Ed25519Point> for Ed25519Elligator {
    const A: Ed25519Fq = new_ed25519_fq!("486662");
    const QNR: Ed25519Fq = new_ed25519_fq!("2");

    /// check if x lies on the curve
    #[allow(unused)]
    fn is_x_on_curve(x: &Ed25519Fq) -> bool {
        let temp = x.pow(&[2u64]).mul(Self::A);
        let y_squared = x.pow(&[3u64]).add(x).add(temp);

        if y_squared.legendre() == LegendreSymbol::QuadraticNonResidue {
            false
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hashing_to_the_curve::ed25519_elligator::Ed25519Elligator;
    use crate::hashing_to_the_curve::traits::ElligatorParameters;
    use noah_algebra::ed25519::Ed25519Fq;
    use noah_algebra::prelude::{test_rng, Scalar};

    #[test]
    fn test_random_t() {
        for _ in 0..100 {
            let mut rng = test_rng();
            let t = Ed25519Fq::random(&mut rng);
            assert!(Ed25519Elligator::get_x_coordinate_without_cofactor_clearing(&t).is_ok());
        }
    }
}
