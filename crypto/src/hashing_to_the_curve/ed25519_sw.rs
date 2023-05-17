use crate::hashing_to_the_curve::traits::SWParameters;
use noah_algebra::ed25519::Ed25519Point;
use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq, prelude::*};

/// The SW map for ed25519.
pub struct Ed25519SW;

impl SWParameters<Ed25519Point> for Ed25519SW {
    const Z0: Ed25519Fq = new_ed25519_fq!(
        "7351004470711496783299639200077825248508346112056564349554070979984169706335"
    );
    const C1: Ed25519Fq = new_ed25519_fq!(
        "7351004470711496783299639200077825248508346112056564349554070979984169463003"
    );
    const C2: Ed25519Fq = new_ed25519_fq!(
        "14702008941422993566599278400155650497016692224113128699108141959968339412670"
    );
    const C3: Ed25519Fq = new_ed25519_fq!("1946658");
    const C4: Ed25519Fq = new_ed25519_fq!(
        "50545040147946600928485853304266128678126646220763717670174721023972394870282"
    );
    const C5: Ed25519Fq = new_ed25519_fq!("2");
    const C6: Ed25519Fq = new_ed25519_fq!(
        "22595885493139578480537169384951274962349491958774703396425382945106958635058"
    );

    fn is_x_on_curve(x: &Ed25519Fq) -> bool {
        let first_term = x.pow(&[3u64]);
        let second_term = x.pow(&[2u64]).mul(Ed25519Fq::from(486662u64));
        let y_squared = first_term.add(second_term).add(x);

        if y_squared.legendre() == LegendreSymbol::QuadraticNonResidue {
            false
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hashing_to_the_curve::ed25519_sw::Ed25519SW;
    use crate::hashing_to_the_curve::traits::SWParameters;
    use noah_algebra::ed25519::Ed25519Fq;
    use noah_algebra::new_ed25519_fq;
    use noah_algebra::prelude::{test_rng, Scalar};

    #[test]
    fn test_x_derivation() {
        let mut t: Ed25519Fq = new_ed25519_fq!("7836");

        let x1 = Ed25519SW::x1(&t).unwrap();
        let x2 = Ed25519SW::x2(&t).unwrap();
        let x3 = Ed25519SW::x3(&t).unwrap();

        assert_eq!(
            x1,
            new_ed25519_fq!(
                "35052544075417610700660092540301712605483067939443826766625142601993311385282"
            )
        );
        assert_eq!(
            x2,
            new_ed25519_fq!(
                "22843500543240487011125399964042241321151924393376455253103649401963252948003"
            )
        );
        assert_eq!(
            x3,
            new_ed25519_fq!(
                "55628280783676121122135371125950213811806717931300590918014233701929027895981"
            )
        );

        t = new_ed25519_fq!(
            "26261490946361586592261280563100114235157954222781295781974865328952772526824"
        );

        let x1 = Ed25519SW::x1(&t).unwrap();
        let x2 = Ed25519SW::x2(&t).unwrap();
        let x3 = Ed25519SW::x3(&t).unwrap();

        assert_eq!(
            x1,
            new_ed25519_fq!(
                "55662970774143248676152068296021054624113686786963469155330127785619018187083"
            )
        );
        assert_eq!(
            x2,
            new_ed25519_fq!(
                "2233073844514849035633424208322899302521305545856812864398664218337546146202"
            )
        );
        assert_eq!(
            x3,
            new_ed25519_fq!(
                "53840827294954389625880150540438237547370106120164461777668468238174198448700"
            )
        );
    }

    #[test]
    fn test_random_t() {
        for _ in 0..100 {
            let mut rng = test_rng();
            let t = Ed25519Fq::random(&mut rng);
            assert!(Ed25519SW::get_x_coordinate_without_cofactor_clearing(&t).is_ok());
        }
    }
}
