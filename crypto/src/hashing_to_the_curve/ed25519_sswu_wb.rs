use crate::errors::Result;
use crate::hashing_to_the_curve::traits::SimplifiedSWUParameters;
use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq};

/// The simplified SWU map for ed25519.
pub struct Ed25519SSWU;

impl SimplifiedSWUParameters<Ed25519Fq> for Ed25519SSWU {
    const C1: Ed25519Fq = new_ed25519_fq!(
        "23090418627330554870558147835411017348134811420561311724956192453459391843510"
    );
    const A: Ed25519Fq = new_ed25519_fq!("6");
    const B: Ed25519Fq = new_ed25519_fq!(
        "35145622091990963912007590500565757691096108475092975709449221291113343398787"
    );
    const QNR: Ed25519Fq = new_ed25519_fq!("2");

    fn isogeny_map_x(&self, x: &Ed25519Fq) -> Result<Ed25519Fq> {
        Ok(*x)
    }
}

#[cfg(test)]
mod tests {
    use crate::hashing_to_the_curve::ed25519_sswu_wb::Ed25519SSWU;
    use crate::hashing_to_the_curve::ed25519_sw::Ed25519SW;
    use crate::hashing_to_the_curve::traits::SimplifiedSWUParameters;
    use noah_algebra::ed25519::Ed25519Fq;
    use noah_algebra::new_ed25519_fq;
    use noah_algebra::prelude::{test_rng, Scalar};

    #[test]
    fn test_x_derivation() {
        let mut t: Ed25519Fq = new_ed25519_fq!("7836");

        let sswu = Ed25519SSWU;
        let x1 = sswu.isogeny_x1(&t).unwrap();
        let x2 = sswu.isogeny_x2(&t, &x1).unwrap();

        assert_eq!(
            x1,
            new_ed25519_fq!(
                "33821190375296719008508280622781480091993943653389170324589199485103136885022"
            )
        );
        assert_eq!(
            x2,
            new_ed25519_fq!(
                "30025209482082666434513164466705496093028098632716614425685296620510493126106"
            )
        );

        t = new_ed25519_fq!(
            "26261490946361586592261280563100114235157954222781295781974865328952772526824"
        );

        let x1 = sswu.isogeny_x1(&t).unwrap();
        let x2 = sswu.isogeny_x2(&t, &x1).unwrap();

        assert_eq!(
            x1,
            new_ed25519_fq!(
                "34982774390495799875250315523171766522468818892991829848824023076855122861807"
            )
        );
        assert_eq!(
            x2,
            new_ed25519_fq!(
                "8860628524403289011878347206615908715790477551639145320170475832347442378824"
            )
        );
    }

    // #[test]
    // fn test_random_t() {
    //     let sswu = Ed25519SSWU;
    //     let _sw = Ed25519SW;
    //     for i in 0..10000 {
    //         println!("{i}");
    //         let mut rng = test_rng();
    //         let t = Ed25519Fq::random(&mut rng);
    //
    //         let x1 = sswu.isogeny_x1(&t).unwrap();
    //         if sswu.is_x_on_isogeny_curve(&x1) {
    //
    //             // let d1 = sswu.isogeny_map_x(&x1).unwrap();
    //             // assert!(sw.is_x_on_curve(&d1));
    //         } else {
    //             let x2 = sswu.isogeny_x2(&t, &x1).unwrap();
    //             assert!(sswu.is_x_on_isogeny_curve(&x2));
    //
    //             // let d2 = sswu.isogeny_map_x(&x2).unwrap();
    //             // assert!(sw.is_x_on_curve(&d2));
    //         }
    //     }
    // }
}
