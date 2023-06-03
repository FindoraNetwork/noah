use crate::errors::Result;
use crate::hashing_to_the_curve::ed25519::Y_SCALE_FACTOR;
use crate::hashing_to_the_curve::models::elligator::ElligatorParameters;
use noah_algebra::ed25519::Ed25519Point;
use noah_algebra::prelude::*;
use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq};

/// Elligator map for Ed25519
pub struct Ed25519ElligatorParameters;

impl ElligatorParameters<Ed25519Point> for Ed25519ElligatorParameters {
    const A: Ed25519Fq = new_ed25519_fq!("486662");
    const B: Ed25519Fq = new_ed25519_fq!("1");
    const QNR: Ed25519Fq = new_ed25519_fq!("2");

    fn convert_to_group(x: &Ed25519Fq, y: &Ed25519Fq) -> Result<Ed25519Point> {
        // from the Montgomery curve: y^2 = x^3 + 486662 x^2 + x
        // to the twisted Edwards curve: -x^2 + y^2 = 1 - (121665/121666) * x^2 * y^2

        let y_inv = y.inv()?;

        let new_x = Y_SCALE_FACTOR * x * y_inv;

        let x_minus_one = (*x) - &Ed25519Fq::one();
        let x_plus_one = Ed25519Fq::one() + x;

        let x_plus_one_inv = x_plus_one.inv()?;

        let new_y = x_minus_one * x_plus_one_inv;

        Ok(Ed25519Point::new(&new_x, &new_y))
    }

    fn convert_from_group(p: &Ed25519Point) -> Result<(Ed25519Fq, Ed25519Fq)> {
        let x = p.get_x();
        let y = p.get_y();

        let y_plus_1 = y + Ed25519Fq::one();
        let y_sub_1 = Ed25519Fq::one() - &y;
        let y_sub_1_inv = y_sub_1.inv()?;
        let x_inv = x.inv()?;

        let new_x = y_plus_1 * y_sub_1_inv;
        let new_y = Y_SCALE_FACTOR * new_x * x_inv;

        Ok((new_x, new_y))
    }
}

#[cfg(test)]
mod tests {
    use crate::hashing_to_the_curve::ed25519::elligator::Ed25519ElligatorParameters;
    use crate::hashing_to_the_curve::models::elligator::Elligator;
    use crate::hashing_to_the_curve::traits::HashingToCurve;
    use noah_algebra::ed25519::{Ed25519Fq, Ed25519Point};
    use noah_algebra::prelude::*;

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

    #[test]
    fn test_group_conversion() {
        for _ in 0..100 {
            let mut rng = test_rng();
            let p = Ed25519Point::random(&mut rng);

            let p_conv = M::convert_from_group(&p).unwrap();
            let p_rec = M::convert_to_group(&p_conv.0, &p_conv.1).unwrap();
            assert_eq!(p, p_rec);
        }
    }
}
