use crate::hashing_to_the_curve::models::sswu::SSWUParameters;
use noah_algebra::secp256k1::SECP256K1G1;
use noah_algebra::{new_secp256k1_fq, secp256k1::SECP256K1Fq};

/// The simplified SWU map for secp256k1.
pub struct Secp256k1SSWUParameters;

const K10: SECP256K1Fq = new_secp256k1_fq!(
    "64328938465175664124206102782604393251816658147578091133031991115504908150983"
);
const K11: SECP256K1Fq = new_secp256k1_fq!(
    "3540463234204664767867377763959255381561641196938647754971861192896365225345"
);
const K12: SECP256K1Fq = new_secp256k1_fq!(
    "37676595701789655284650173187508961899444205326770530105295841645151729341026"
);
const K13: SECP256K1Fq = new_secp256k1_fq!(
    "64328938465175664124206102782604393251816658147578091133031991115504908150924"
);
const K20: SECP256K1Fq = new_secp256k1_fq!(
    "95592507323525948732419199626899895302164312317343489384240252208201861084315"
);
const K21: SECP256K1Fq = new_secp256k1_fq!(
    "107505182841474506714709588670204841388457878609653642868747406790547894725908"
);
const K22: SECP256K1Fq = new_secp256k1_fq!("1");

impl SSWUParameters<SECP256K1G1> for Secp256k1SSWUParameters {
    const C1: SECP256K1Fq = new_secp256k1_fq!(
        "5324262023205125242632636178842408935272934169651804884418803605709653231043"
    );
    const A: SECP256K1Fq = new_secp256k1_fq!(
        "28734576633528757162648956269730739219262246272443394170905244663053633733939"
    );
    const B: SECP256K1Fq = new_secp256k1_fq!("1771");
    const QNR: SECP256K1Fq = new_secp256k1_fq!("-1");

    const ISOGENY_DEGREE: u32 = 3;

    fn get_isogeny_numerator_term<'a>(i: usize) -> &'a SECP256K1Fq {
        match i {
            0 => &K10,
            1 => &K11,
            2 => &K12,
            3 => &K13,
            _ => unimplemented!(),
        }
    }

    fn get_isogeny_denominator_term<'a>(i: usize) -> &'a SECP256K1Fq {
        match i {
            0 => &K20,
            1 => &K21,
            2 => &K22,
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hashing_to_the_curve::models::sswu::SSWUMap;
    use crate::hashing_to_the_curve::secp256k1::sswu::Secp256k1SSWUParameters;
    use crate::hashing_to_the_curve::traits::HashingToCurve;
    use noah_algebra::new_secp256k1_fq;
    use noah_algebra::prelude::{test_rng, Scalar};
    use noah_algebra::secp256k1::{SECP256K1Fq, SECP256K1G1};

    type M = SSWUMap<SECP256K1G1, Secp256k1SSWUParameters>;

    #[test]
    fn test_x_derivation() {
        let mut t: SECP256K1Fq = new_secp256k1_fq!("7836");

        let x1 = M::isogeny_x1(&t).unwrap();
        let x2 = M::isogeny_x2(&t, &x1).unwrap();

        assert_eq!(
            x1,
            new_secp256k1_fq!(
                "5059133040005307975438481414558956461437749113940297443224564873449406058043"
            )
        );
        assert_eq!(
            x2,
            new_secp256k1_fq!(
                "91803102038907996103462406316775760503033811617762340431858158677398502472253"
            )
        );

        t = new_secp256k1_fq!(
            "26261490946361586592261280563100114235157954222781295781974865328952772526824"
        );

        let x1 = M::isogeny_x1(&t).unwrap();
        let x2 = M::isogeny_x2(&t, &x1).unwrap();

        assert_eq!(
            x1,
            new_secp256k1_fq!(
                "14271252946971651109053873822424845507662995056426487553711544270115966265738"
            )
        );
        assert_eq!(
            x2,
            new_secp256k1_fq!(
                "8113571707777645763641624972377886627550199494987092202971773425971145497983"
            )
        );

        let x1_mapped = M::isogeny_map_x(&x1).unwrap();
        let x2_mapped = M::isogeny_map_x(&x2).unwrap();
        assert_eq!(
            x1_mapped,
            new_secp256k1_fq!(
                "4616312591568409694240531723779240970923173089337361658730513933746206717500"
            )
        );
        assert_eq!(
            x2_mapped,
            new_secp256k1_fq!(
                "15918002750200560155055460282218026071902505692630707383867291353189907320206"
            )
        );
    }

    #[test]
    fn test_random_t() {
        for _ in 0..100 {
            let mut rng = test_rng();
            let t = SECP256K1Fq::random(&mut rng);

            let final_x = M::get_cofactor_uncleared_x(&t).unwrap();
            let (final_x2, trace) = M::get_cofactor_uncleared_x_and_trace(&t).unwrap();

            assert_eq!(final_x, final_x2);
            assert!(M::verify_trace(&t, &final_x, &trace));
        }
    }
}
