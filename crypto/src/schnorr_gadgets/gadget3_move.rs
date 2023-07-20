use crate::errors::CryptoError;
use crate::matrix_sigma::SigmaTranscript;
use crate::schnorr_gadgets::SchnorrGadget;
use merlin::Transcript;
use noah_algebra::prelude::*;
use rand_chacha::ChaChaRng;

/// The struct for the proof of Gadget 3.
#[derive(Clone, Default)]
pub struct Gadget3Proof<G: CurveGroup> {
    /// The randomizer R_Q.
    pub point_r_q: G,
    /// The randomizer R_R.
    pub point_r_r: G,
    /// The randomizer R_S.
    pub point_r_s: G,
    /// The first response.
    pub response_1: G::ScalarType,
    /// The second response.
    pub response_2: G::ScalarType,
    /// The third response.
    pub response_3: G::ScalarType,
    /// The fourth response.
    pub response_4: G::ScalarType,
}

/// The struct for the instance of Gadget 3.
pub struct Gadget3Instance<G: CurveGroup> {
    /// The point Q with (a^2, c).
    pub point_q: G,
    /// The point R with (a^2 * b, d).
    pub point_r: G,
    /// The point S with (a^2, a^2 * b).
    pub point_s: G,
    /// The first independent generator for Q and R.
    pub g1: G,
    /// The second independent generator for Q and R.
    pub g2: G,
    /// The first independent generator for S.
    pub h1: G,
    /// The second independent generator for S.
    pub h2: G,
}

/// The struct for the witness of Gadget 3.
pub struct Gadget3Witness<G: CurveGroup> {
    /// The scalar a^2, in point P.
    pub a_square: G::ScalarType,
    /// The scalar b, in point P.
    pub b: G::ScalarType,
    /// The scalar c, in point Q.
    pub c: G::ScalarType,
    /// The scalar d, in point R.
    pub d: G::ScalarType,
}

/// The Gadget 3, which moves (a^2, c) and (a^2 * b, d) to (a^2, a^2 * b) for any a, b, c, d.
pub struct Gadget3<G: CurveGroup> {
    gadget_phantom: PhantomData<G>,
}

impl<G: CurveGroup> SchnorrGadget<G> for Gadget3<G> {
    type Proof = Gadget3Proof<G>;
    type Instance = Gadget3Instance<G>;
    type Witness = Gadget3Witness<G>;

    fn prove<R: CryptoRng + RngCore>(
        prng: &mut R,
        transcript: &mut Transcript,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> Self::Proof {
        let r1 = G::ScalarType::random(prng);
        let r2 = G::ScalarType::random(prng);
        let r3 = G::ScalarType::random(prng);
        let r4 = G::ScalarType::random(prng);

        let point_r_q = instance.g1.mul(&r1) + &instance.g2.mul(&r2);
        let point_r_r = instance.g1.mul(&r3) + &instance.g2.mul(&r4);
        let point_r_s = instance.h1.mul(&r1) + &instance.h2.mul(&r3);

        transcript.append_group_element(b"Q", &instance.point_q);
        transcript.append_group_element(b"R", &instance.point_r);
        transcript.append_group_element(b"S", &instance.point_s);
        transcript.append_group_element(b"G1", &instance.g1);
        transcript.append_group_element(b"G2", &instance.g2);
        transcript.append_group_element(b"H1", &instance.h1);
        transcript.append_group_element(b"H2", &instance.h2);

        transcript.append_group_element(b"R_Q", &point_r_q);
        transcript.append_group_element(b"R_R", &point_r_r);
        transcript.append_group_element(b"R_S", &point_r_s);

        let mut bytes = [0u8; 32];
        transcript.challenge_bytes(b"challenge", &mut bytes);

        let beta = {
            let mut rng = ChaChaRng::from_seed(bytes);
            G::ScalarType::random(&mut rng)
        };

        let response_1 = r1 * beta + witness.a_square;
        let response_2 = r2 * beta + witness.c;
        let response_3 = r3 * beta + witness.a_square * witness.b;
        let response_4 = r4 * beta + witness.d;

        Gadget3Proof {
            point_r_q,
            point_r_r,
            point_r_s,
            response_1,
            response_2,
            response_3,
            response_4,
        }
    }

    fn verify(
        transcript: &mut Transcript,
        instance: &Self::Instance,
        proof: &Self::Proof,
    ) -> crate::errors::Result<()> {
        transcript.append_group_element(b"Q", &instance.point_q);
        transcript.append_group_element(b"R", &instance.point_r);
        transcript.append_group_element(b"S", &instance.point_s);
        transcript.append_group_element(b"G1", &instance.g1);
        transcript.append_group_element(b"G2", &instance.g2);
        transcript.append_group_element(b"H1", &instance.h1);
        transcript.append_group_element(b"H2", &instance.h2);

        transcript.append_group_element(b"R_Q", &proof.point_r_q);
        transcript.append_group_element(b"R_R", &proof.point_r_r);
        transcript.append_group_element(b"R_S", &proof.point_r_s);

        let mut bytes = [1u8; 32];
        transcript.challenge_bytes(b"challenge", &mut bytes);

        let beta = {
            let mut rng = ChaChaRng::from_seed(bytes);
            G::ScalarType::random(&mut rng)
        };

        let lhs = instance.point_q + &proof.point_r_q.mul(&beta);
        let rhs = instance.g1.mul(&proof.response_1) + &instance.g2.mul(&proof.response_2);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        let lhs = instance.point_r + &proof.point_r_r.mul(&beta);
        let rhs = instance.g1.mul(&proof.response_3) + &instance.g2.mul(&proof.response_4);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        let lhs = instance.point_s + &proof.point_r_s.mul(&beta);
        let rhs = instance.h1.mul(&proof.response_1) + &instance.h2.mul(&proof.response_3);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::schnorr_gadgets::gadget3_move::{Gadget3, Gadget3Instance, Gadget3Witness};
    use crate::schnorr_gadgets::SchnorrGadget;
    use merlin::Transcript;
    use noah_algebra::prelude::*;
    use noah_algebra::secp256k1::SECP256K1Scalar;
    use noah_algebra::secp256k1::SECP256K1G1;

    type G = Gadget3<SECP256K1G1>;

    #[test]
    fn check_gadget_correctness() {
        let mut prng = test_rng();

        let a = SECP256K1Scalar::random(&mut prng);
        let b = SECP256K1Scalar::random(&mut prng);
        let c = SECP256K1Scalar::random(&mut prng);
        let d = SECP256K1Scalar::random(&mut prng);

        let a_square = a.square();

        // For the purpose of this test, we sample generators directly.
        let g1 = SECP256K1G1::random(&mut prng);
        let g2 = SECP256K1G1::random(&mut prng);

        let h1 = SECP256K1G1::random(&mut prng);
        let h2 = SECP256K1G1::random(&mut prng);

        let point_q = g1.mul(&a_square) + &g2.mul(&c);
        let point_r = g1.mul(&a_square.mul(&b)) + &g2.mul(&d);
        let point_s = h1.mul(&a_square) + &h2.mul(&a_square.mul(&b));

        let instance = Gadget3Instance::<SECP256K1G1> {
            point_q,
            point_r,
            point_s,
            g1,
            g2,
            h1,
            h2,
        };

        let witness = Gadget3Witness::<SECP256K1G1> { a_square, b, c, d };

        let mut prover_transcript = Transcript::new(b"Test");
        let proof = G::prove(&mut prng, &mut prover_transcript, &instance, &witness);

        let mut verifier_transcript = Transcript::new(b"Test");
        G::verify(&mut verifier_transcript, &instance, &proof).unwrap();
    }
}
