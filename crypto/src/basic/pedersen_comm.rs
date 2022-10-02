use curve25519_dalek::traits::MultiscalarMul;
use noah_algebra::ops::{Add, Mul};
use noah_algebra::ristretto::{RistrettoPoint, RistrettoScalar};
use noah_algebra::secq256k1::{SECQ256K1Scalar, SECQ256K1G1};
use noah_algebra::traits::Group;

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
        let pc_gens = bulletproofs::PedersenGens::default();
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

impl From<&PedersenCommitmentRistretto> for bulletproofs::PedersenGens {
    fn from(rp: &PedersenCommitmentRistretto) -> Self {
        bulletproofs::PedersenGens {
            B: rp.B.0,
            B_blinding: rp.B_blinding.0,
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// The Pedersen commitment implementation for the secq256k1 group.
pub struct PedersenCommitmentSecq256k1 {
    /// The generator for the value part.
    pub B: SECQ256K1G1,
    /// The generator for the blinding part.
    pub B_blinding: SECQ256K1G1,
}

impl Default for PedersenCommitmentSecq256k1 {
    fn default() -> Self {
        let pc_gens = ark_bulletproofs_secq256k1::PedersenGens::default();
        Self {
            B: SECQ256K1G1::from_raw(pc_gens.B),
            B_blinding: SECQ256K1G1::from_raw(pc_gens.B_blinding),
        }
    }
}

impl PedersenCommitment<SECQ256K1G1> for PedersenCommitmentSecq256k1 {
    fn generator(&self) -> SECQ256K1G1 {
        self.B
    }

    fn blinding_generator(&self) -> SECQ256K1G1 {
        self.B_blinding
    }

    fn commit(&self, value: SECQ256K1Scalar, blinding: SECQ256K1Scalar) -> SECQ256K1G1 {
        self.B.mul(&value).add(&self.B_blinding.mul(&blinding))
    }
}

impl From<&PedersenCommitmentSecq256k1> for ark_bulletproofs_secq256k1::PedersenGens {
    fn from(rp: &PedersenCommitmentSecq256k1) -> Self {
        ark_bulletproofs_secq256k1::PedersenGens {
            B: rp.B.get_raw(),
            B_blinding: rp.B_blinding.get_raw(),
        }
    }
}
