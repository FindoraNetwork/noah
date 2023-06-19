use crate::errors::Result;
use crate::hashing_to_the_curve::traits::HashingToCurve;
use merlin::Transcript;
use noah_algebra::prelude::*;

/// The implementation for the hoisting version of the GDH undeniable signature.
pub mod hoisting;
/// The implementation for the standard version of the GDH undeniable signature.
pub mod standard;

pub trait GapDHSignature<G: CurveGroup, H: HashingToCurve<G>> {
    type Proof: Default + Clone;

    fn keygen<R: CryptoRng + RngCore>(prng: &mut R) -> (G::ScalarType, G) {
        let sk = G::ScalarType::random(prng);
        let pk = G::get_base().mul(&sk);

        (sk, pk)
    }

    fn map(m: &G::BaseType) -> Result<G> {
        let (x, y) = H::get_cofactor_uncleared_point(m)?;
        let p = H::convert_to_group(&x, &y)?;

        Ok(p.multiply_by_cofactor())
    }

    fn sign(sk: &G::ScalarType, m: &G) -> G;
    fn confirm<R: CryptoRng + RngCore>(
        prng: &mut R,
        transcript: &mut Transcript,
        sk: &G::ScalarType,
        m: &G,
        sigma: &G,
    ) -> Self::Proof;
    fn verify(
        transcript: &mut Transcript,
        pk: &G,
        m: &G,
        sigma: &G,
        proof: &Self::Proof,
    ) -> Result<()>;
}
