use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq, prelude::*};

/// Elligator map for Ed25519
pub struct Ed25519Elligator(Ed25519Fq);

const C: Ed25519Fq = new_ed25519_fq!("486662");

impl Ed25519Elligator {
    /// first candidate for x
    pub fn x1(t: &Ed25519Fq) -> Result<Ed25519Fq> {
        let t_sq = t.square();
        let temp = t_sq
            .mul(Ed25519Fq::from(2u32))
            .add(Ed25519Fq::one())
            .inv()?;

        Ok(temp.mul(C).neg())
    }

    /// second candidate for x
    pub fn x2(x1: &Ed25519Fq) -> Result<Ed25519Fq> {
        Ok(C.add(x1).neg())
    }
}
