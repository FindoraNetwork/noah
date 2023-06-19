use crate::errors::Result;
use crate::hashing_to_the_curve::traits::HashingToCurve;
use merlin::Transcript;
use noah_algebra::prelude::*;

/// The implementation for the hoisting version of the GDH undeniable signature.
pub mod hoisting;
/// The implementation for the standard version of the GDH undeniable signature.
pub mod standard;

/// A trait for gap Diffie-Hellman undeniable signature.
pub trait GapDHSignature<G: CurveGroup, H: HashingToCurve<G>> {
    /// The struct of the proof.
    type Proof: Default + Clone;

    /// Generate the keys.
    fn keygen<R: CryptoRng + RngCore>(prng: &mut R) -> (G::ScalarType, G) {
        let sk = G::ScalarType::random(prng);
        let pk = G::get_base().mul(&sk);

        (sk, pk)
    }

    /// Map the message into a point.
    fn map(m: &G::BaseType) -> Result<G> {
        let (x, y) = H::get_cofactor_uncleared_point(m)?;
        let p = H::convert_to_group(&x, &y)?;

        Ok(p.multiply_by_cofactor())
    }

    /// Create the undeniable signature.
    fn sign(sk: &G::ScalarType, m: &G) -> G;

    /// Compute the proof that confirms the undeniable signature.
    fn confirm<R: CryptoRng + RngCore>(
        prng: &mut R,
        transcript: &mut Transcript,
        sk: &G::ScalarType,
        m: &G,
        sigma: &G,
    ) -> Self::Proof;

    /// Verify a undeniable signature with the proof.
    fn verify(
        transcript: &mut Transcript,
        pk: &G,
        m: &G,
        sigma: &G,
        proof: &Self::Proof,
    ) -> Result<()>;
}
