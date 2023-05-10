use std::ops::{Add, Mul};
use ark_ff::LegendreSymbol;
use crate::hashing_to_the_curve::traits::SW;
use noah_algebra::{
    ed25519::Ed25519Fq, new_ed25519_fq, prelude::*
};

///
pub type Ed25519SW = Ed25519Fq;

impl SW<Ed25519Fq> for Ed25519SW {
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

    fn is_x_on_curve(&self, x: &Ed25519Fq) -> bool {
        let first_term = x.pow(&[3u64]);
        let second_term = x.pow(&[2u64]).mul(Ed25519Fq::from(486662u64));
        let y_squared = first_term.add(second_term).add(x);

        if y_squared.legendre() == LegendreSymbol::QuadraticNonResidue {
            false
        } else { true }
    }
}
