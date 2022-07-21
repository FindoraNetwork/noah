use curve25519_dalek::traits::MultiscalarMul;
use digest::Digest;
use rand_chacha::ChaChaRng;
use sha3::Sha3_512;
use zei_algebra::bs257::{BS257Scalar, BS257G1};
use zei_algebra::ristretto::{RistrettoPoint, RistrettoScalar};
use zei_algebra::traits::Group;
use zei_algebra::{
    ops::{Add, Mul},
    rand::SeedableRng,
};

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
/// The Pedersen commitment implementation for the BS257 group.
pub struct PedersenCommitmentBS257 {
    /// The generator for the value part.
    pub B: BS257G1,
    /// The generator for the blinding part.
    pub B_blinding: BS257G1,
}

impl Default for PedersenCommitmentBS257 {
    fn default() -> Self {
        let base = BS257G1::get_base();

        let mut hash = Sha3_512::new();
        Digest::update(&mut hash, base.to_compressed_bytes());
        let h = hash.finalize();

        let mut res = [0u8; 32];
        res.copy_from_slice(&h[..32]);

        let mut prng = ChaChaRng::from_seed(res);
        let blinding = BS257G1::random(&mut prng);

        Self {
            B: base,
            B_blinding: blinding,
        }
    }
}

impl PedersenCommitment<BS257G1> for PedersenCommitmentBS257 {
    fn generator(&self) -> BS257G1 {
        self.B
    }

    fn blinding_generator(&self) -> BS257G1 {
        self.B_blinding
    }

    fn commit(&self, value: BS257Scalar, blinding: BS257Scalar) -> BS257G1 {
        self.B.mul(&value).add(&self.B_blinding.mul(&blinding))
    }
}

impl From<&PedersenCommitmentBS257> for bulletproofs_bs257::PedersenGens {
    fn from(rp: &PedersenCommitmentBS257) -> Self {
        bulletproofs_bs257::PedersenGens {
            B: rp.B.get_raw(),
            B_blinding: rp.B_blinding.get_raw(),
        }
    }
}
