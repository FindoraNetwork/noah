use crate::errors::{CryptoError, Result};
use crate::gapdh::GapDHSignature;
use crate::hashing_to_the_curve::traits::HashingToCurve;
use crate::matrix_sigma::SigmaTranscript;
use merlin::Transcript;
use noah_algebra::marker::PhantomData;
use noah_algebra::prelude::*;
use rand_chacha::ChaChaRng;

/// The hoisting implementation of GDH undeniable signature.
pub struct HoistingGDH<G: CurveGroup, H: HashingToCurve<G>> {
    g_phantom: PhantomData<G>,
    h_phantom: PhantomData<H>,
}

/// The struct for a proof in the hoisting implementation.
#[derive(Default, Clone)]
pub struct HoistingGDHProof<G: CurveGroup> {
    /// Point P.
    pub point_p: G,
    /// Point R_{pk}.
    pub point_r_pk: G,
    /// Point R_{P1}.
    pub point_r_p1: G,
    /// Point R_{P2}.
    pub point_r_p2: G,
    /// Point R_\sigma.
    pub point_r_sigma: G,
    /// The first response.
    pub response_1: G::ScalarType,
    /// The second response.
    pub response_2: G::ScalarType,
    /// The third response.
    pub response_3: G::ScalarType,
}

impl<G: CurveGroup, H: HashingToCurve<G>> GapDHSignature<G, H> for HoistingGDH<G, H> {
    type Proof = HoistingGDHProof<G>;

    fn sign(sk: &G::ScalarType, m: &G) -> G {
        m.mul(&sk.square())
    }

    fn confirm<R: CryptoRng + RngCore>(
        prng: &mut R,
        transcript: &mut Transcript,
        sk: &G::ScalarType,
        m: &G,
        sigma: &G,
    ) -> Self::Proof {
        let pk = G::get_base().mul(&sk);

        let r1 = G::ScalarType::random(prng);
        let r2 = G::ScalarType::random(prng);
        let r3 = G::ScalarType::random(prng);
        let r4 = G::ScalarType::random(prng);

        let h = {
            let mut rng = ChaChaRng::from_seed([0u8; 32]);
            G::random(&mut rng)
        };

        let point_p = pk.mul(sk) + &h.mul(&r1);
        let point_r_pk = G::get_base().mul(&r2);

        let h_r3 = h.mul(&r3);
        let point_r_p1 = pk.mul(&r2) + &h_r3;
        let point_r_p2 = G::get_base().mul(&r4) + &h_r3;
        let point_r_sigma = m.mul(&r4);

        transcript.append_group_element(b"message", m);
        transcript.append_group_element(b"public key", &pk);
        transcript.append_group_element(b"point P", &point_p);
        transcript.append_group_element(b"signature", sigma);
        transcript.append_group_element(b"R_pk", &point_r_pk);
        transcript.append_group_element(b"R_p1", &point_r_p1);
        transcript.append_group_element(b"R_p2", &point_r_p2);
        transcript.append_group_element(b"R_sigma", &point_r_sigma);

        let mut bytes = [0u8; 32];
        transcript.challenge_bytes(b"challenge", &mut bytes);

        let beta = {
            let mut rng = ChaChaRng::from_seed(bytes);
            G::ScalarType::random(&mut rng)
        };

        let response_1 = r2 * &beta + sk;
        let response_2 = r3 * &beta + r1;
        let response_3 = r4 * &beta + sk.square();

        let proof = HoistingGDHProof {
            point_p,
            point_r_pk,
            point_r_p1,
            point_r_p2,
            point_r_sigma,
            response_1,
            response_2,
            response_3,
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
        transcript.append_group_element(b"public key", pk);
        transcript.append_group_element(b"point P", &proof.point_p);
        transcript.append_group_element(b"signature", sigma);
        transcript.append_group_element(b"R_pk", &proof.point_r_pk);
        transcript.append_group_element(b"R_p1", &proof.point_r_p1);
        transcript.append_group_element(b"R_p2", &proof.point_r_p2);
        transcript.append_group_element(b"R_sigma", &proof.point_r_sigma);

        let mut bytes = [0u8; 32];
        transcript.challenge_bytes(b"challenge", &mut bytes);

        let beta = {
            let mut rng = ChaChaRng::from_seed(bytes);
            G::ScalarType::random(&mut rng)
        };

        let h = {
            let mut rng = ChaChaRng::from_seed([0u8; 32]);
            G::random(&mut rng)
        };

        let lhs = proof.point_r_pk.mul(&beta) + pk;
        let rhs = G::get_base().mul(&proof.response_1);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        let h_s2 = h.mul(&proof.response_2);

        let lhs = proof.point_r_p1.mul(&beta) + &proof.point_p;
        let rhs = pk.mul(&proof.response_1) + &h_s2;

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        let lhs = proof.point_r_p2.mul(&beta) + &proof.point_p;
        let rhs = G::get_base().mul(&proof.response_3) + &h_s2;

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        let lhs = proof.point_r_sigma.mul(&beta) + sigma;
        let rhs = m.mul(&proof.response_3);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::gapdh::hoisting::HoistingGDH;
    use crate::gapdh::GapDHSignature;
    use crate::hashing_to_the_curve::models::sw::SWMap;
    use crate::hashing_to_the_curve::secp256k1::sw::Secp256k1SWParameters;
    use merlin::Transcript;
    use noah_algebra::prelude::*;
    use noah_algebra::secp256k1::{SECP256K1Fq, SECP256K1G1};

    type T = HoistingGDH<SECP256K1G1, SWMap<SECP256K1G1, Secp256k1SWParameters>>;

    #[test]
    fn test_hoisting_correctness() {
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
