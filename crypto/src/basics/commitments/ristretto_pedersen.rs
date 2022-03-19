use bulletproofs::PedersenGens;
use curve25519_dalek::traits::MultiscalarMul;
use zei_algebra::ristretto::{RistrettoPoint, RistrettoScalar};

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RistrettoPedersenGens {
    pub B: RistrettoPoint,
    pub B_blinding: RistrettoPoint,
}

impl Default for RistrettoPedersenGens {
    fn default() -> RistrettoPedersenGens {
        let pc_gens = PedersenGens::default();
        RistrettoPedersenGens {
            B: RistrettoPoint(pc_gens.B),
            B_blinding: RistrettoPoint(pc_gens.B_blinding),
        }
    }
}
impl RistrettoPedersenGens {
    pub fn commit(&self, value: RistrettoScalar, blinding: RistrettoScalar) -> RistrettoPoint {
        RistrettoPoint(
            curve25519_dalek::ristretto::RistrettoPoint::multiscalar_mul(
                &[value.0, blinding.0],
                &[self.B.0, self.B_blinding.0],
            ),
        )
    }
}

impl From<PedersenGens> for RistrettoPedersenGens {
    fn from(gens: PedersenGens) -> Self {
        RistrettoPedersenGens {
            B: RistrettoPoint(gens.B),
            B_blinding: RistrettoPoint(gens.B_blinding),
        }
    }
}

impl From<&RistrettoPedersenGens> for PedersenGens {
    fn from(rp: &RistrettoPedersenGens) -> Self {
        PedersenGens {
            B: rp.B.0,
            B_blinding: rp.B_blinding.0,
        }
    }
}
