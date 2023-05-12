use crate::errors::Result;
use crate::hashing_to_the_curve::traits::SimplifiedSWU;
use ark_ff::LegendreSymbol;
use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq, prelude::*};

/// The simplified SWU map for ed25519.
pub struct Ed25519SSWU;

const B: Ed25519Fq = new_ed25519_fq!(
    "35145622091990963912007590500565757691096108475092975709449221291113343398787"
);

impl SimplifiedSWU<Ed25519Fq> for Ed25519SSWU {
    fn isogeny_x1(&self, t: &Ed25519Fq) -> Result<Ed25519Fq> {
        let t2 = t.square();
        let t4 = t2.square();

        let temp = t4.sub(&t2).inv()?.add(Ed25519Fq::one());
        let b_inv = B.inv()?;

        Ok(b_inv.mul(Ed25519Fq::from(6u32)).mul(temp).neg())
    }

    fn isogeny_x2(&self, t: &Ed25519Fq, x1: &Ed25519Fq) -> Result<Ed25519Fq> {
        let t2 = t.square();

        Ok(x1.mul(t2).mul(Ed25519Fq::from(2u32)))
    }

    fn is_x_on_isogeny_curve(&self, x: &Ed25519Fq) -> bool {
        let first_term = x.pow(&[3u64]);
        let second_term = x.mul(Ed25519Fq::from(6u64));
        let y_squared = first_term.add(second_term).add(B);

        if y_squared.legendre() == LegendreSymbol::QuadraticNonResidue {
            false
        } else {
            true
        }
    }

    fn isogeny_map_x(&self, x: &Ed25519Fq) -> Result<Ed25519Fq> {
        Ok(*x)
    }
}
