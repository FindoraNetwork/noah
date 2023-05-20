use crate::errors::Result;
use crate::hashing_to_the_curve::models::sswu::SimplifiedSWUParameters;
use noah_algebra::ed25519::Ed25519Point;
use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq};

/// The simplified SWU map for ed25519.
pub struct Ed25519SSWUParameters;

impl SimplifiedSWUParameters<Ed25519Point> for Ed25519SSWUParameters {
    const C1: Ed25519Fq = new_ed25519_fq!(
        "23090418627330554870558147835411017348134811420561311724956192453459391843510"
    );
    const A: Ed25519Fq = new_ed25519_fq!("6");
    const B: Ed25519Fq = new_ed25519_fq!(
        "35145622091990963912007590500565757691096108475092975709449221291113343398787"
    );
    const QNR: Ed25519Fq = new_ed25519_fq!("2");

    fn isogeny_map_x(x: &Ed25519Fq) -> Result<Ed25519Fq> {
        Ok(*x)
    }
}

#[cfg(test)]
mod tests {
    use crate::hashing_to_the_curve::ed25519::sswu::Ed25519SSWUParameters;
    use crate::hashing_to_the_curve::models::sswu::SimplifiedSWUMap;
    use crate::hashing_to_the_curve::traits::HashingToCurve;
    use noah_algebra::ed25519::{Ed25519Fq, Ed25519Point};
    use noah_algebra::new_ed25519_fq;
    use noah_algebra::prelude::{test_rng, Scalar};

    type M = SimplifiedSWUMap<Ed25519Point, Ed25519SSWUParameters>;

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
            assert!(M::get_x_coordinate_without_cofactor_clearing(&t).is_ok());
        }
    }
}
