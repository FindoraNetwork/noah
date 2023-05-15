use crate::errors::Result;
use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq, prelude::*};

/// Elligator map for Ed25519
pub struct Ed25519Elligator;

const C: Ed25519Fq = new_ed25519_fq!("486662");

impl Ed25519Elligator {
    /// first candidate for x
    pub fn x1(&self, t: &Ed25519Fq) -> Result<Ed25519Fq> {
        let t_sq = t.square();
        let temp = t_sq
            .mul(Ed25519Fq::from(2u32))
            .add(Ed25519Fq::one())
            .inv()?;

        Ok(temp.mul(C).neg())
    }

    /// second candidate for x
    pub fn x2(&self, x1: &Ed25519Fq) -> Result<Ed25519Fq> {
        Ok(C.add(x1).neg())
    }

    ///
    fn is_x_on_curve(&self, x: &Ed25519Fq) -> bool {

        let temp = x.pow(&[2u64]).mul(Ed25519Fq::from(486662u32));
        let y_squared = x.pow(&[3u64]).add(x).add(temp);

        if y_squared.legendre() == LegendreSymbol::QuadraticNonResidue {
            false
        } else {
            true
        }
    }
}


#[cfg(test)]
mod tests {
    use noah_algebra::ed25519::Ed25519Fq;
    use noah_algebra::prelude::{Scalar, test_rng};
    use crate::hashing_to_the_curve::ed25519_elligator::Ed25519Elligator;

    #[test]
    fn test_random_t() {

        let eg = Ed25519Elligator;
        for _i in 0..10000 {
            let mut rng = test_rng();
            let t = Ed25519Fq::random(&mut rng);

            let x1 = eg.x1(&t).unwrap();
            if eg.is_x_on_curve(&x1) {
                continue
            }

            let x2 = eg.x2(&x1).unwrap();
            assert!(eg.is_x_on_curve(&x2))

        }
    }
}