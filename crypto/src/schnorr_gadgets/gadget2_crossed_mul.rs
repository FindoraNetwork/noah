use crate::errors::CryptoError;
use crate::matrix_sigma::SigmaTranscript;
use crate::schnorr_gadgets::SchnorrGadget;
use merlin::Transcript;
use noah_algebra::prelude::*;
use rand_chacha::ChaChaRng;

/// The struct for the proof of Gadget 2.
#[derive(Clone, Default)]
pub struct Gadget2Proof<G: CurveGroup> {
    /// The randomizer R_P.
    pub point_r_p: G,
    /// The randomizer R_R.
    pub point_r_r: G,
    /// The first response.
    pub response_1: G::ScalarType,
    /// The second response.
    pub response_2: G::ScalarType,
    /// The third response.
    pub response_3: G::ScalarType,
}

/// The struct for the instance of Gadget 2.
pub struct Gadget2Instance<G: CurveGroup> {
    /// The point Q with (a^2, c).
    pub point_q: G,
    /// The point P with (a, b).
    pub point_p: G,
    /// The point R with (a^2 * b, d).
    pub point_r: G,
    /// The first independent generator.
    pub g1: G,
    /// The second independent generator.
    pub g2: G,
}

/// The struct for the witness of Gadget 2.
pub struct Gadget2Witness<G: CurveGroup> {
    /// The scalar a, in point P.
    pub a: G::ScalarType,
    /// The scalar b, in point P.
    pub b: G::ScalarType,
    /// The scalar c, in point Q.
    pub c: G::ScalarType,
    /// The scalar d, in point R.
    pub d: G::ScalarType,
}

/// The Gadget 2, which moves (a^2, c) and (a, b) to (a^2 b, d) for any a, b, c, d.
pub struct Gadget2<G: CurveGroup> {
    gadget_phantom: PhantomData<G>,
}

impl<G: CurveGroup> SchnorrGadget<G> for Gadget2<G> {
    type Proof = Gadget2Proof<G>;
    type Instance = Gadget2Instance<G>;
    type Witness = Gadget2Witness<G>;

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
        let point_r_r = instance.point_q.mul(&r2) + &instance.g2.mul(&r3);

        transcript.append_group_element(b"Q", &instance.point_q);
        transcript.append_group_element(b"P", &instance.point_p);
        transcript.append_group_element(b"R", &instance.point_r);
        transcript.append_group_element(b"G1", &instance.g1);
        transcript.append_group_element(b"G2", &instance.g2);

        transcript.append_group_element(b"R_P", &point_r_p);
        transcript.append_group_element(b"R_R", &point_r_r);

        let mut bytes = [0u8; 32];
        transcript.challenge_bytes(b"challenge", &mut bytes);

        let beta = {
            let mut rng = ChaChaRng::from_seed(bytes);
            G::ScalarType::random(&mut rng)
        };

        let response_1 = r1 * beta + witness.a;
        let response_2 = r2 * beta + witness.b;
        let response_3 = r3 * beta + witness.d - &witness.b.mul(&witness.c);

        Gadget2Proof {
            point_r_p,
            point_r_r,
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
        transcript.append_group_element(b"Q", &instance.point_q);
        transcript.append_group_element(b"P", &instance.point_p);
        transcript.append_group_element(b"R", &instance.point_r);
        transcript.append_group_element(b"G1", &instance.g1);
        transcript.append_group_element(b"G2", &instance.g2);

        transcript.append_group_element(b"R_P", &proof.point_r_p);
        transcript.append_group_element(b"R_R", &proof.point_r_r);

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

        let lhs = instance.point_r + &proof.point_r_r.mul(&beta);
        let rhs = instance.point_q.mul(&proof.response_2) + &instance.g2.mul(&proof.response_3);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::schnorr_gadgets::gadget2_crossed_mul::{Gadget2, Gadget2Instance, Gadget2Witness};
    use crate::schnorr_gadgets::SchnorrGadget;
    use merlin::Transcript;
    use noah_algebra::prelude::*;
    use noah_algebra::secp256k1::SECP256K1Scalar;
    use noah_algebra::secp256k1::SECP256K1G1;

    type G = Gadget2<SECP256K1G1>;

    #[test]
    fn check_gadget_correctness() {
        let mut prng = test_rng();

        let a = SECP256K1Scalar::random(&mut prng);
        let b = SECP256K1Scalar::random(&mut prng);
        let c = SECP256K1Scalar::random(&mut prng);
        let d = SECP256K1Scalar::random(&mut prng);

        // For the purpose of this test, we sample generators directly.
        let g1 = SECP256K1G1::random(&mut prng);
        let g2 = SECP256K1G1::random(&mut prng);

        let point_p = g1.mul(&a) + &g2.mul(&b);
        let point_q = g1.mul(&a.square()) + &g2.mul(&c);
        let point_r = g1.mul(&a.square().mul(&b)) + &g2.mul(&d);

        let instance = Gadget2Instance::<SECP256K1G1> {
            point_p,
            point_q,
            point_r,
            g1,
            g2,
        };

        let witness = Gadget2Witness::<SECP256K1G1> { a, b, c, d };

        let mut prover_transcript = Transcript::new(b"Test");
        let proof = G::prove(&mut prng, &mut prover_transcript, &instance, &witness);

        let mut verifier_transcript = Transcript::new(b"Test");
        G::verify(&mut verifier_transcript, &instance, &proof).unwrap();
    }
}
