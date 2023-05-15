use crate::hashing_to_the_curve::traits::SWParameters;
use noah_algebra::{new_secp256k1_fq, prelude::*, secp256k1::SECP256K1Fq};

/// The SW map for secp256k1.
pub struct Secp256k1SW;

impl SWParameters<SECP256K1Fq> for Secp256k1SW {
    const Z0: SECP256K1Fq = new_secp256k1_fq!(
        "2301468970328204842700089520541121182249040118132057797950280022211810753577"
    );
    const C1: SECP256K1Fq = new_secp256k1_fq!(
        "60197513588986302554485582024885075108884032450952339817679072026166228089409"
    );
    const C2: SECP256K1Fq = new_secp256k1_fq!(
        "4602937940656409685400179041082242364498080236264115595900560044423621507154"
    );
    const C3: SECP256K1Fq = new_secp256k1_fq!("6");
    const C4: SECP256K1Fq = new_secp256k1_fq!(
        "55594575648329892869085402983802832744385952214688224221778511981742606582255"
    );
    const C5: SECP256K1Fq = new_secp256k1_fq!(
        "115792089237316195423570985008687907853269984665640564039457584007908834671662"
    );
    const C6: SECP256K1Fq = new_secp256k1_fq!(
        "38597363079105398474523661669562635951089994888546854679819194669302944890554"
    );

    fn is_x_on_curve(&self, x: &SECP256K1Fq) -> bool {
        let y_squared = x.pow(&[3u64]).add(SECP256K1Fq::from(7u64));

        if y_squared.legendre() == LegendreSymbol::QuadraticNonResidue {
            false
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use noah_algebra::new_secp256k1_fq;
    use noah_algebra::prelude::{Scalar, test_rng};
    use noah_algebra::secp256k1::SECP256K1Fq;
    use crate::hashing_to_the_curve::secp256k1_sw::Secp256k1SW;
    use crate::hashing_to_the_curve::traits::SWParameters;

    #[test]
    fn test_x_derivation() {
        let mut t: SECP256K1Fq = new_secp256k1_fq!("7836");

        let sw = Secp256k1SW;
        let x1 = sw.x1(&t).unwrap();
        let x2 = sw.x2(&t).unwrap();
        let x3 = sw.x3(&t).unwrap();

        assert_eq!(x1, new_secp256k1_fq!("12173361532131623274578764961252033537537011288282760545929785782471408876466"));
        assert_eq!(x2, new_secp256k1_fq!("103618727705184572148992220047435874315732973377357803493527798225437425795198"));
        assert_eq!(x3, new_secp256k1_fq!("74087608966983262623115840088572810691661208660740673962981321521047702830003"));

        t = new_secp256k1_fq!("26261490946361586592261280563100114235157954222781295781974865328952772526824");

        let x1 = sw.x1(&t).unwrap();
        let x2 = sw.x2(&t).unwrap();
        let x3 = sw.x3(&t).unwrap();

        assert_eq!(x1, new_secp256k1_fq!("26139849459076662048090509060200323109571459447699535307492857403137446071407"));
        assert_eq!(x2, new_secp256k1_fq!("89652239778239533375480475948487584743698525217941028731964726604771388600257"));
        assert_eq!(x3, new_secp256k1_fq!("57498912498287391356729542970652380787836579419942546263322241630256315967730"));
    }

    #[test]
    fn test_random_t() {

        let sw = Secp256k1SW;
        for _i in 0..10000 {
            let mut rng = test_rng();
            let t = SECP256K1Fq::random(&mut rng);

            let x1 = sw.x1(&t).unwrap();
            if sw.is_x_on_curve(&x1) {
                continue
            }

            let x2 = sw.x2(&t).unwrap();
            if sw.is_x_on_curve(&x2) {
                continue
            }

            let x3 = sw.x3(&t).unwrap();
            assert!(sw.is_x_on_curve(&x3))

        }
    }
}