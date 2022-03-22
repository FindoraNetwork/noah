use bulletproofs::PedersenGens;
use curve25519_dalek::traits::MultiscalarMul;
use zei_algebra::ristretto::{RistrettoPoint, RistrettoScalar};

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RistrettoPedersenCommitment {
    pub B: RistrettoPoint,
    pub B_blinding: RistrettoPoint,
}

impl Default for RistrettoPedersenCommitment {
    fn default() -> RistrettoPedersenCommitment {
        let pc_gens = PedersenGens::default();
        RistrettoPedersenCommitment {
            B: RistrettoPoint(pc_gens.B),
            B_blinding: RistrettoPoint(pc_gens.B_blinding),
        }
    }
}
impl RistrettoPedersenCommitment {
    pub fn commit(&self, value: RistrettoScalar, blinding: RistrettoScalar) -> RistrettoPoint {
        RistrettoPoint(
            curve25519_dalek::ristretto::RistrettoPoint::multiscalar_mul(
                &[value.0, blinding.0],
                &[self.B.0, self.B_blinding.0],
            ),
        )
    }
}

impl From<&RistrettoPedersenCommitment> for PedersenGens {
    fn from(rp: &RistrettoPedersenCommitment) -> Self {
        PedersenGens {
            B: rp.B.0,
            B_blinding: rp.B_blinding.0,
        }
    }
}
