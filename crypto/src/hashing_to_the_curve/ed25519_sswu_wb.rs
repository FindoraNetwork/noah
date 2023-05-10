use crate::hashing_to_the_curve::traits::SSWU;
use noah_algebra::ed25519::Ed25519Fq;
use noah_algebra::new_ed25519_fq;
use noah_algebra::prelude::Scalar;
use num_traits::One;
use ruc::*;
use std::ops::{Add, Mul, Neg, Sub};

///
pub type Ed25519SSWU = Ed25519Fq;

const B: Ed25519Fq = new_ed25519_fq!(
    "35145622091990963912007590500565757691096108475092975709449221291113343398787"
);

impl SSWU<Ed25519Fq> for Ed25519SSWU {
    fn x1(&self, t: &Ed25519Fq) -> Result<Ed25519Fq> {
        let t2 = t.square();
        let t4 = t2.square();

        let temp = t4.sub(&t2).inv()?.add(Ed25519Fq::one());

        let b_inv = B.inv()?;

        Ok(b_inv.mul(Ed25519Fq::from(6u32)).mul(temp).neg())
    }

    fn x2(&self, t: &Ed25519Fq, x1: &Ed25519Fq) -> Result<Ed25519Fq> {
        let t2 = t.square();

        Ok(x1.mul(t2).mul(Ed25519Fq::from(2u32)))
    }
}
