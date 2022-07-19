use bulletproofs::PedersenGens;
use curve25519_dalek::traits::MultiscalarMul;
use zei_algebra::ristretto::{RistrettoPoint, RistrettoScalar};
use zei_algebra::traits::Group;

/// Trait for Pedersen commitment.
pub trait PedersenCommitment<G: Group>: Default {
    /// Return the generator for the value part.
    fn generator(&self) -> G;
    /// Return the generator for the blinding part.
    fn blinding_generator(&self) -> G;
    /// Compute the Pedersen commitment over the Ristretto group.
    fn commit(&self, value: G::ScalarType, blinding: G::ScalarType) -> G;
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// The Pedersen commitment implementation for the Ristretto group.
pub struct PedersenCommitmentRistretto {
    /// The generator for the value part.
    pub B: RistrettoPoint,
    /// The generator for the blinding part.
    pub B_blinding: RistrettoPoint,
}

impl Default for PedersenCommitmentRistretto {
    fn default() -> Self {
        let pc_gens = PedersenGens::default();
        Self {
            B: RistrettoPoint(pc_gens.B),
            B_blinding: RistrettoPoint(pc_gens.B_blinding),
        }
    }
}
impl PedersenCommitment<RistrettoPoint> for PedersenCommitmentRistretto {
    fn generator(&self) -> RistrettoPoint {
        self.B
    }

    fn blinding_generator(&self) -> RistrettoPoint {
        self.B_blinding
    }

    fn commit(&self, value: RistrettoScalar, blinding: RistrettoScalar) -> RistrettoPoint {
        RistrettoPoint(
            curve25519_dalek::ristretto::RistrettoPoint::multiscalar_mul(
                &[value.0, blinding.0],
                &[self.B.0, self.B_blinding.0],
            ),
        )
    }
}

impl From<&PedersenCommitmentRistretto> for PedersenGens {
    fn from(rp: &PedersenCommitmentRistretto) -> Self {
        PedersenGens {
            B: rp.B.0,
            B_blinding: rp.B_blinding.0,
        }
    }
}
