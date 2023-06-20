use crate::errors::CryptoError;
use crate::matrix_sigma::SigmaTranscript;
use crate::schnorr_gadgets::SchnorrGadget;
use merlin::Transcript;
use noah_algebra::prelude::*;
use rand_chacha::ChaChaRng;

/// The struct for the proof of Gadget 4.
#[derive(Clone, Default)]
pub struct Gadget4Proof<G: CurveGroup> {
    /// The randomizer Q.
    pub point_q: G,
    /// The randomizer R.
    pub point_r: G,
    /// The randomizer R_P.
    pub point_r_p: G,
    /// The randomizer R_Q1.
    pub point_r_q1: G,
    /// The randomizer R_Q2.
    pub point_r_q2: G,
    /// The randomizer R_R1.
    pub point_r_r1: G,
    /// The randomizer R_R2.
    pub point_r_r2: G,
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
    /// The fifth response.
    pub response_5: G::ScalarType,
    /// The sixth response.
    pub response_6: G::ScalarType,
    /// The seventh response.
    pub response_7: G::ScalarType,
    /// The eighth response.
    pub response_8: G::ScalarType,
}

/// The struct for the instance of Gadget 4.
pub struct Gadget4Instance<G: CurveGroup> {
    /// The point P with (a, b).
    pub point_p: G,
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

/// The struct for the witness of Gadget 4.
pub struct Gadget4Witness<G: CurveGroup> {
    /// The scalar a, in point P.
    pub a: G::ScalarType,
    /// The scalar b, in point P.
    pub b: G::ScalarType,
}

/// The Gadget 4, which moves (a, b) to (a^2, a^2 * b) for any a, b.
pub struct Gadget4<G: CurveGroup> {
    gadget_phantom: PhantomData<G>,
}

impl<G: CurveGroup> SchnorrGadget<G> for Gadget4<G> {
    type Proof = Gadget4Proof<G>;
    type Instance = Gadget4Instance<G>;
    type Witness = Gadget4Witness<G>;

    fn prove<R: CryptoRng + RngCore>(
        prng: &mut R,
        transcript: &mut Transcript,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> Self::Proof {
        let c = G::ScalarType::random(prng);
        let d = G::ScalarType::random(prng);
        let a_square = witness.a.square();

        let point_q = instance.g1.mul(&a_square) + &instance.g2.mul(&c);
        let point_r = instance.g1.mul(&a_square.mul(&witness.b)) + &instance.g2.mul(&d);

        let r1 = G::ScalarType::random(prng);
        let r2 = G::ScalarType::random(prng);
        let r3 = G::ScalarType::random(prng);
        let r4 = G::ScalarType::random(prng);
        let r5 = G::ScalarType::random(prng);
        let r6 = G::ScalarType::random(prng);
        let r7 = G::ScalarType::random(prng);
        let r8 = G::ScalarType::random(prng);

        let point_r_p = instance.g1.mul(&r1) + &instance.g2.mul(&r2);
        let point_r_q1 = instance.point_p.mul(&r1) + &instance.g2.mul(&r3);
        let point_r_q2 = instance.g1.mul(&r4) + &instance.g2.mul(&r5);
        let point_r_r1 = point_q.mul(&r2) + &instance.g2.mul(&r6);
        let point_r_r2 = instance.g1.mul(&r7) + &instance.g2.mul(&r8);
        let point_r_s = instance.h1.mul(&r4) + &instance.h2.mul(&r7);

        transcript.append_group_element(b"P", &instance.point_p);
        transcript.append_group_element(b"Q", &point_q);
        transcript.append_group_element(b"R", &point_r);
        transcript.append_group_element(b"S", &instance.point_s);
        transcript.append_group_element(b"G1", &instance.g1);
        transcript.append_group_element(b"G2", &instance.g2);
        transcript.append_group_element(b"H1", &instance.h1);
        transcript.append_group_element(b"H2", &instance.h2);

        transcript.append_group_element(b"R_P", &point_r_p);
        transcript.append_group_element(b"R_Q1", &point_r_q1);
        transcript.append_group_element(b"R_Q2", &point_r_q2);
        transcript.append_group_element(b"R_R1", &point_r_r1);
        transcript.append_group_element(b"R_R2", &point_r_r2);
        transcript.append_group_element(b"R_S", &point_r_s);

        let mut bytes = [0u8; 32];
        transcript.challenge_bytes(b"challenge", &mut bytes);

        let beta = {
            let mut rng = ChaChaRng::from_seed(bytes);
            G::ScalarType::random(&mut rng)
        };

        let response_1 = r1 * &beta + witness.a;
        let response_2 = r2 * &beta + witness.b;
        let response_3 = r3 * &beta + c - &(witness.a * &witness.b);
        let response_4 = r4 * &beta + a_square;
        let response_5 = r5 * &beta + c;
        let response_6 = r6 * &beta + d - &(witness.b * c);
        let response_7 = r7 * &beta + a_square.mul(&witness.b);
        let response_8 = r8 * &beta + d;

        let proof = Gadget4Proof {
            point_q,
            point_r,
            point_r_p,
            point_r_q1,
            point_r_q2,
            point_r_r1,
            point_r_r2,
            point_r_s,
            response_1,
            response_2,
            response_3,
            response_4,
            response_5,
            response_6,
            response_7,
            response_8,
        };

        proof
    }

    fn verify(
        transcript: &mut Transcript,
        instance: &Self::Instance,
        proof: &Self::Proof,
    ) -> crate::errors::Result<()> {
        transcript.append_group_element(b"P", &instance.point_p);
        transcript.append_group_element(b"Q", &proof.point_q);
        transcript.append_group_element(b"R", &proof.point_r);
        transcript.append_group_element(b"S", &instance.point_s);
        transcript.append_group_element(b"G1", &instance.g1);
        transcript.append_group_element(b"G2", &instance.g2);
        transcript.append_group_element(b"H1", &instance.h1);
        transcript.append_group_element(b"H2", &instance.h2);

        transcript.append_group_element(b"R_P", &proof.point_r_p);
        transcript.append_group_element(b"R_Q1", &proof.point_r_q1);
        transcript.append_group_element(b"R_Q2", &proof.point_r_q2);
        transcript.append_group_element(b"R_R1", &proof.point_r_r1);
        transcript.append_group_element(b"R_R2", &proof.point_r_r2);
        transcript.append_group_element(b"R_S", &proof.point_r_s);

        let mut bytes = [0u8; 32];
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

        let lhs = proof.point_q + &proof.point_r_q1.mul(&beta);
        let rhs = instance.point_p.mul(&proof.response_1) + &instance.g2.mul(&proof.response_3);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        let lhs = proof.point_q + &proof.point_r_q2.mul(&beta);
        let rhs = instance.g1.mul(&proof.response_4) + &instance.g2.mul(&proof.response_5);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        let lhs = proof.point_r + &proof.point_r_r1.mul(&beta);
        let rhs = proof.point_q.mul(&proof.response_2) + &instance.g2.mul(&proof.response_6);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        let lhs = proof.point_r + &proof.point_r_r2.mul(&beta);
        let rhs = instance.g1.mul(&proof.response_7) + &instance.g2.mul(&proof.response_8);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        let lhs = instance.point_s + &proof.point_r_s.mul(&beta);
        let rhs = instance.h1.mul(&proof.response_4) + &instance.h2.mul(&proof.response_7);

        if lhs != rhs {
            return Err(CryptoError::SignatureError);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::schnorr_gadgets::gadget4_merged::{Gadget4, Gadget4Instance, Gadget4Witness};
    use crate::schnorr_gadgets::SchnorrGadget;
    use merlin::Transcript;
    use noah_algebra::prelude::*;
    use noah_algebra::secp256k1::SECP256K1Scalar;
    use noah_algebra::secp256k1::SECP256K1G1;

    type G = Gadget4<SECP256K1G1>;

    #[test]
    fn check_gadget_correctness() {
        let mut prng = test_rng();

        let a = SECP256K1Scalar::random(&mut prng);
        let b = SECP256K1Scalar::random(&mut prng);

        let a_square = a.square();

        // For the purpose of this test, we sample generators directly.
        let g1 = SECP256K1G1::random(&mut prng);
        let g2 = SECP256K1G1::random(&mut prng);

        let h1 = SECP256K1G1::random(&mut prng);
        let h2 = SECP256K1G1::random(&mut prng);

        let point_p = g1.mul(&a) + &g2.mul(&b);
        let point_s = h1.mul(&a_square) + &h2.mul(&a_square.mul(&b));

        let instance = Gadget4Instance::<SECP256K1G1> {
            point_p,
            point_s,
            g1,
            g2,
            h1,
            h2,
        };

        let witness = Gadget4Witness::<SECP256K1G1> { a, b };

        let mut prover_transcript = Transcript::new(b"Test");
        let proof = G::prove(&mut prng, &mut prover_transcript, &instance, &witness);

        let mut verifier_transcript = Transcript::new(b"Test");
        G::verify(&mut verifier_transcript, &instance, &proof).unwrap();
    }
}
