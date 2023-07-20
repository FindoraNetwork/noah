use crate::errors::CryptoError;
use crate::matrix_sigma::SigmaTranscript;
use crate::schnorr_gadgets::SchnorrGadget;
use merlin::Transcript;
use noah_algebra::prelude::*;
use rand_chacha::ChaChaRng;

/// The struct for the proof of Gadget 1.
#[derive(Clone, Default)]
pub struct Gadget1Proof<G: CurveGroup> {
    /// The randomizer R_P.
    pub point_r_p: G,
    /// The randomizer R_Q.
    pub point_r_q: G,
    /// The first response.
    pub response_1: G::ScalarType,
    /// The second response.
    pub response_2: G::ScalarType,
    /// The third response.
    pub response_3: G::ScalarType,
}

/// The struct for the instance of Gadget 1.
pub struct Gadget1Instance<G: CurveGroup> {
    /// The point P with (a, b).
    pub point_p: G,
    /// The point Q with (a^2, c).
    pub point_q: G,
    /// The first independent generator.
    pub g1: G,
    /// The second independent generator.
    pub g2: G,
}

/// The struct for the witness of Gadget 1.
pub struct Gadget1Witness<G: CurveGroup> {
    /// The scalar a, in point P.
    pub a: G::ScalarType,
    /// The scalar b, in point P.
    pub b: G::ScalarType,
    /// The scalar c, in point Q.
    pub c: G::ScalarType,
}

/// The Gadget 1, which moves (a, b) to (a^2, c) for any a, b, c.
pub struct Gadget1<G: CurveGroup> {
    gadget_phantom: PhantomData<G>,
}

impl<G: CurveGroup> SchnorrGadget<G> for Gadget1<G> {
    type Proof = Gadget1Proof<G>;
    type Instance = Gadget1Instance<G>;
    type Witness = Gadget1Witness<G>;

    fn prove<R: CryptoRng + RngCore>(
        prng: &mut R,
        transcript: &mut Transcript,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> Self::Proof {
        let r1 = G::ScalarType::random(prng);
        let r2 = G::ScalarType::random(prng);
        let r3 = G::ScalarType::random(prng);

        let point_r_p = instance.g1.mul(&r1) + &instance.g2.mul(&r2);
        let point_r_q = instance.point_p.mul(&r1) + &instance.g2.mul(&r3);

        transcript.append_group_element(b"P", &instance.point_p);
        transcript.append_group_element(b"Q", &instance.point_q);
        transcript.append_group_element(b"G1", &instance.g1);
        transcript.append_group_element(b"G2", &instance.g2);

        transcript.append_group_element(b"R_P", &point_r_p);
        transcript.append_group_element(b"R_Q", &point_r_q);

        let mut bytes = [0u8; 32];
        transcript.challenge_bytes(b"challenge", &mut bytes);

        let beta = {
            let mut rng = ChaChaRng::from_seed(bytes);
            G::ScalarType::random(&mut rng)
        };

        let response_1 = r1 * &beta + witness.a;
        let response_2 = r2 * &beta + witness.b;
        let response_3 = r3 * &beta + witness.c - &witness.a.mul(witness.b);

        

        Gadget1Proof {
            point_r_p,
            point_r_q,
            response_1,
            response_2,
            response_3,
        }
    }

    fn verify(
        transcript: &mut Transcript,
        instance: &Self::Instance,
        proof: &Self::Proof,
    ) -> crate::errors::Result<()> {
        transcript.append_group_element(b"P", &instance.point_p);
        transcript.append_group_element(b"Q", &instance.point_q);
        transcript.append_group_element(b"G1", &instance.g1);
        transcript.append_group_element(b"G2", &instance.g2);

        transcript.append_group_element(b"R_P", &proof.point_r_p);
        transcript.append_group_element(b"R_Q", &proof.point_r_q);

        let mut bytes = [1u8; 32];
        transcript.challenge_bytes(b"challenge", &mut bytes);

        let beta = {
            let mut rng = ChaChaRng::from_seed(bytes);
            G::ScalarType::random(&mut rng)
        };

        let lhs = instance.point_p + &proof.point_r_p.mul(&beta);
        let rhs = instance.g1.mul(&proof.response_1) + &instance.g2.mul(&proof.response_2);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        let lhs = instance.point_q + &proof.point_r_q.mul(&beta);
        let rhs = instance.point_p.mul(&proof.response_1) + &instance.g2.mul(&proof.response_3);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::schnorr_gadgets::gadget1_square::{Gadget1, Gadget1Instance, Gadget1Witness};
    use crate::schnorr_gadgets::SchnorrGadget;
    use merlin::Transcript;
    use noah_algebra::prelude::*;
    use noah_algebra::secp256k1::SECP256K1Scalar;
    use noah_algebra::secp256k1::SECP256K1G1;

    type G = Gadget1<SECP256K1G1>;

    #[test]
    fn check_gadget_correctness() {
        let mut prng = test_rng();

        let a = SECP256K1Scalar::random(&mut prng);
        let b = SECP256K1Scalar::random(&mut prng);
        let c = SECP256K1Scalar::random(&mut prng);

        // For the purpose of this test, we sample generators directly.
        let g1 = SECP256K1G1::random(&mut prng);
        let g2 = SECP256K1G1::random(&mut prng);

        let point_p = g1.mul(&a) + &g2.mul(&b);
        let point_q = g1.mul(&a.square()) + &g2.mul(&c);

        let instance = Gadget1Instance::<SECP256K1G1> {
            point_p,
            point_q,
            g1,
            g2,
        };

        let witness = Gadget1Witness::<SECP256K1G1> { a, b, c };

        let mut prover_transcript = Transcript::new(b"Test");
        let proof = G::prove(&mut prng, &mut prover_transcript, &instance, &witness);

        let mut verifier_transcript = Transcript::new(b"Test");
        G::verify(&mut verifier_transcript, &instance, &proof).unwrap();
    }
}
