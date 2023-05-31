use crate::hashing_to_the_curve::models::elligator::ElligatorParameters;
use noah_algebra::ed25519::Ed25519Point;
use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq};
use crate::errors::Result;

/// Elligator map for Ed25519
pub struct Ed25519ElligatorParameters;

const Y_SCALE_FACTOR: Ed25519Fq =
    new_ed25519_fq!("51042569399160536130206135233146329284152202253034631822681833788666877215207");

impl ElligatorParameters<Ed25519Point> for Ed25519ElligatorParameters {
    const A: Ed25519Fq = new_ed25519_fq!("486662");
    const B: Ed25519Fq = new_ed25519_fq!("1");
    const QNR: Ed25519Fq = new_ed25519_fq!("2");

    fn convert_to_group(x: &G::BaseType, y: &G::BaseType) -> Result<G> {
        // from the Montgomery curve: y^2 = x^3 + 486662 x^2 + x
        // to the twisted Edwards curve: -x^2 + y^2 = 1 - (121665/121666) * x^2 * y^2

        let y_inv = y.inv()?;

        let new_x = x * y_inv * P::Y_SCALE_FACTOR;

        let x_plus_one = G::BaseType::one() - x;
        let x_minus_one = G::BaseType::one() + x;

        let x_minus_one_inv = x_minus_one.inv()?;

        let new_y = x_plus_one * x_minus_one_inv;

        Ok(G::new(new_x, new_y))
    }

    fn convert_from_group(p: &G) -> Result<(G::BaseType, G::BaseType)> {
        let x = p.get_x();
        let y = p.get_y();

        let y_plus_1 = y + G::BaseType::one();
        let y_sub_1 = G::BaseType::one() - &y;
        let y_sub_1_inv = y_sub_1.inv()?;
        let x_inv = x.inv()?;

        let new_x = y_plus_1 * y_sub_1_inv;
        let new_y = P::Y_SCALE_FACTOR * new_x * x_inv;

        Ok((new_x, new_y))
    }
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

            let final_x = M::get_cofactor_uncleared_x(&t).unwrap();
            let (final_x2, trace) = M::get_cofactor_uncleared_x_and_trace(&t).unwrap();

            assert_eq!(final_x, final_x2);
            assert!(M::verify_trace(&t, &final_x, &trace));
            assert!(M::is_x_on_curve(&final_x));
        }
    }
}
