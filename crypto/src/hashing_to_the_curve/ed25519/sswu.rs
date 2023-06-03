use crate::hashing_to_the_curve::ed25519::Y_SCALE_FACTOR;
use crate::hashing_to_the_curve::models::sswu::SSWUParameters;
use noah_algebra::ed25519::Ed25519Point;
use noah_algebra::prelude::*;
use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq};

const SW_X_RESCALE: Ed25519Fq =
    new_ed25519_fq!("3588469012313698530330944230071891185932753502600616350412800610627019690467");
const SW_Y_RESCALE: Ed25519Fq = new_ed25519_fq!(
    "19664379987077386454535042711455997342735372489368666653119195093328899270820"
);

const SW_X_RESCALE_INV: Ed25519Fq = new_ed25519_fq!(
    "21963914854679844700726282993359278263729888963355376752140162891402579336876"
);
const SW_Y_RESCALE_INV: Ed25519Fq = new_ed25519_fq!(
    "41914391159623114879653526778217233303395870266520846601365575963904391892926"
);

const SW_TO_MONT_X_ADJ: Ed25519Fq = new_ed25519_fq!(
    "38597363079105398474523661669562635951089994888546854679819194669304376384412"
);

/// The simplified SWU map for ed25519.
pub struct Ed25519SSWUParameters;

impl SSWUParameters<Ed25519Point> for Ed25519SSWUParameters {
    const C1: Ed25519Fq = new_ed25519_fq!(
        "23090418627330554870558147835411017348134811420561311724956192453459391843510"
    );
    const A: Ed25519Fq = new_ed25519_fq!("6");
    const B: Ed25519Fq = new_ed25519_fq!(
        "35145622091990963912007590500565757691096108475092975709449221291113343398787"
    );
    const A_ORG: Ed25519Fq = new_ed25519_fq!("6");
    const B_ORG: Ed25519Fq = new_ed25519_fq!(
        "35145622091990963912007590500565757691096108475092975709449221291113343398787"
    );
    const QNR: Ed25519Fq = new_ed25519_fq!("2");

    const ISOGENY_DEGREE: u32 = 0;

    fn get_isogeny_numerator_term<'a>(_: usize) -> &'a Ed25519Fq {
        unimplemented!()
    }

    fn get_isogeny_denominator_term<'a>(_: usize) -> &'a Ed25519Fq {
        unimplemented!()
    }

    fn convert_to_group(x: &Ed25519Fq, y: &Ed25519Fq) -> crate::errors::Result<Ed25519Point> {
        // from a special short Weierstrass curve: y^2 = x^3 + 6 x^2 + B
        // to the twisted Edwards curve: -x^2 + y^2 = 1 - (121665/121666) * x^2 * y^2

        // first, rescale x and y to the right short Weierstrass curve
        let x = SW_X_RESCALE * x;
        let y = SW_Y_RESCALE * y;

        // move it to the Montgomery curve
        let x = x + SW_TO_MONT_X_ADJ;

        // convert it to the twisted Edwards curve
        let y_inv = y.inv()?;
        let new_x = Y_SCALE_FACTOR * x * y_inv;

        let x_minus_one = x - &Ed25519Fq::one();
        let x_plus_one = Ed25519Fq::one() + x;

        let x_plus_one_inv = x_plus_one.inv()?;
        let new_y = x_minus_one * x_plus_one_inv;

        Ok(Ed25519Point::new(&new_x, &new_y))
    }

    fn convert_from_group(p: &Ed25519Point) -> crate::errors::Result<(Ed25519Fq, Ed25519Fq)> {
        // from the twisted Edwards curve: -x^2 + y^2 = 1 - (121665/121666) * x^2 * y^2
        // to the special short Weierstrass curve: y^2 = x^3 + 6 x^2 + B

        // first, convert it to the Montgomery curve y^2 = x^3 + 486662 x^2 + x

        let x = p.get_x();
        let y = p.get_y();

        let y_plus_1 = y + Ed25519Fq::one();
        let y_sub_1 = Ed25519Fq::one() - &y;
        let y_sub_1_inv = y_sub_1.inv()?;
        let x_inv = x.inv()?;

        let x = y_plus_1 * y_sub_1_inv;
        let y = Y_SCALE_FACTOR * x * x_inv;

        // move it to the right short Weierstrass curve
        let x = x - &SW_TO_MONT_X_ADJ;

        // first, rescale x and y from the right short Weierstrass curve
        let x = SW_X_RESCALE_INV * x;
        let y = SW_Y_RESCALE_INV * y;

        Ok((x, y))
    }
}

#[cfg(test)]
mod tests {
    use crate::hashing_to_the_curve::ed25519::sswu::Ed25519SSWUParameters;
    use crate::hashing_to_the_curve::models::sswu::SSWUMap;
    use crate::hashing_to_the_curve::traits::HashingToCurve;
    use noah_algebra::ed25519::{Ed25519Fq, Ed25519Point};
    use noah_algebra::new_ed25519_fq;
    use noah_algebra::prelude::*;

    type M = SSWUMap<Ed25519Point, Ed25519SSWUParameters>;

    #[test]
    fn test_x_derivation() {
        let mut t: Ed25519Fq = new_ed25519_fq!("7836");

        let x1 = M::isogeny_x1(&t).unwrap();
        let x2 = M::isogeny_x2(&t, &x1).unwrap();

        assert_eq!(
            x1,
            new_ed25519_fq!(
                "7457287917660312610502022429244984294187063250777089098680404356212894903224"
            )
        );
        assert_eq!(
            x2,
            new_ed25519_fq!(
                "20419531772605805968014286708006493082455024474557275692874981839751918710082"
            )
        );

        t = new_ed25519_fq!(
            "26261490946361586592261280563100114235157954222781295781974865328952772526824"
        );

        let x1 = M::isogeny_x1(&t).unwrap();
        let x2 = M::isogeny_x2(&t, &x1).unwrap();

        assert_eq!(
            x1,
            new_ed25519_fq!(
                "18242114560107859291669116711737021445542340546877785663857283795718913401958"
            )
        );
        assert_eq!(
            x2,
            new_ed25519_fq!(
                "8810771453702010396430590702953341512697278170129472741126134566236416256139"
            )
        );
    }

    #[test]
    fn test_random_t() {
        for _ in 0..100 {
            let mut rng = test_rng();
            let t = Ed25519Fq::random(&mut rng);

            let final_x = M::get_cofactor_uncleared_x(&t).unwrap();
            let (final_x2, trace) = M::get_cofactor_uncleared_x_and_trace(&t).unwrap();

            assert_eq!(final_x, final_x2);
            assert!(M::verify_trace(&t, &final_x, &trace));
            assert!(M::is_x_on_isogeny_curve(&final_x));
            assert!(M::is_x_on_original_curve(&final_x));
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
