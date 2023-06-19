use crate::errors::{CryptoError, Result};
use crate::gapdh::GapDHSignature;
use crate::hashing_to_the_curve::traits::HashingToCurve;
use crate::matrix_sigma::SigmaTranscript;
use merlin::Transcript;
use noah_algebra::marker::PhantomData;
use noah_algebra::prelude::*;
use rand_chacha::ChaChaRng;

/// The standard implementation of GDH undeniable signature.
pub struct StandardGDH<G: CurveGroup, H: HashingToCurve<G>> {
    g_phantom: PhantomData<G>,
    h_phantom: PhantomData<H>,
}

/// The struct for a proof in the standard implementation.
#[derive(Default, Clone)]
pub struct StandardGDHProof<G: CurveGroup> {
    /// Point R1.
    pub point_r_1: G,
    /// Point R2.
    pub point_r_2: G,
    /// Response.
    pub response: G::ScalarType,
}

impl<G: CurveGroup, H: HashingToCurve<G>> GapDHSignature<G, H> for StandardGDH<G, H> {
    type Proof = StandardGDHProof<G>;

    fn sign(sk: &G::ScalarType, m: &G) -> G {
        m.mul(sk)
    }

    fn confirm<R: CryptoRng + RngCore>(
        prng: &mut R,
        transcript: &mut Transcript,
        sk: &G::ScalarType,
        m: &G,
        sigma: &G,
    ) -> Self::Proof {
        let r = G::ScalarType::random(prng);
        let pk = G::get_base().mul(&sk);

        let point_r_1 = m.mul(&r);
        let point_r_2 = G::get_base().mul(&r);

        transcript.append_group_element(b"message", m);
        transcript.append_group_element(b"signature", sigma);
        transcript.append_group_element(b"public key", &pk);
        transcript.append_group_element(b"R1", &point_r_1);
        transcript.append_group_element(b"R2", &point_r_2);

        let mut bytes = [0u8; 32];
        transcript.challenge_bytes(b"challenge", &mut bytes);

        let beta = {
            let mut rng = ChaChaRng::from_seed(bytes);
            G::ScalarType::random(&mut rng)
        };

        let response = r * &beta + sk;

        let proof = StandardGDHProof {
            point_r_1,
            point_r_2,
            response,
        };

        proof
    }

    fn verify(
        transcript: &mut Transcript,
        pk: &G,
        m: &G,
        sigma: &G,
        proof: &Self::Proof,
    ) -> Result<()> {
        transcript.append_group_element(b"message", m);
        transcript.append_group_element(b"signature", sigma);
        transcript.append_group_element(b"public key", pk);
        transcript.append_group_element(b"R1", &proof.point_r_1);
        transcript.append_group_element(b"R2", &proof.point_r_2);

        let mut bytes = [0u8; 32];
        transcript.challenge_bytes(b"challenge", &mut bytes);

        let beta = {
            let mut rng = ChaChaRng::from_seed(bytes);
            G::ScalarType::random(&mut rng)
        };

        let lhs = proof.point_r_1.mul(&beta) + sigma;
        let rhs = m.mul(&proof.response);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        let lhs = proof.point_r_2.mul(&beta) + pk;
        let rhs = G::get_base().mul(&proof.response);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::gapdh::standard::StandardGDH;
    use crate::gapdh::GapDHSignature;
    use crate::hashing_to_the_curve::models::sw::SWMap;
    use crate::hashing_to_the_curve::secp256k1::sw::Secp256k1SWParameters;
    use merlin::Transcript;
    use noah_algebra::prelude::*;
    use noah_algebra::secp256k1::{SECP256K1Fq, SECP256K1G1};

    type T = StandardGDH<SECP256K1G1, SWMap<SECP256K1G1, Secp256k1SWParameters>>;

    #[test]
    fn test_standard_correctness() {
        let mut prng = test_rng();

        let (sk, pk) = T::keygen(&mut prng);
        let m = T::map(&SECP256K1Fq::random(&mut prng)).unwrap();

        let sigma = T::sign(&sk, &m);

        let mut prover_transcript = Transcript::new(b"Test");
        let proof = T::confirm(&mut prng, &mut prover_transcript, &sk, &m, &sigma);

        let mut verifier_transcript = Transcript::new(b"Test");
        T::verify(&mut verifier_transcript, &pk, &m, &sigma, &proof).unwrap();
    }
}
