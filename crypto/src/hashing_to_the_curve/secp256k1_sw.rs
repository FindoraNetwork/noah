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
