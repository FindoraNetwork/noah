use crate::basic::pedersen_comm::PedersenCommitment;
use crate::basic::rescue::RescueInstance;
use crate::field_simulation::{SimFr, SimFrParams};
use merlin::Transcript;
use num_bigint::BigUint;
use rand_chacha::ChaChaRng;
use serde::Deserialize;
use std::marker::PhantomData;
use zei_algebra::{bls12_381::BLSScalar, prelude::*};

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Clone, Default)]
/// The non-interactive proof provided to the verifier.
pub struct DelegatedChaumPedersenProof<S, G, P> {
    /// The commitment of the non-ZK verifier's state.
    pub inspection_comm: BLSScalar,
    /// The first randomizer point.
    pub point_r: G,
    /// The second randomizer point.
    pub point_s: G,
    /// The response scalar `s_1`.
    pub s_1: S,
    /// The response scalar `s_2`.
    pub s_2: S,
    /// The response scalar `s_3`.
    pub s_3: S,
    /// The response scalar `s_4`.
    pub s_4: S,
    /// PhantomData for the parameters.
    pub params_phantom: PhantomData<P>,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Clone, Default)]
/// The state of the inspector.
pub struct DelegatedChaumPedersenInspection<S, G, P> {
    /// The committed value of the first Pedersen commitment.
    pub x: S,
    /// The committed value of the second Pedersen commitment.
    pub y: S,
    /// The committed value of the randomizer for the first Pedersen commitment.
    pub a: S,
    /// The committed value of the randomizer for the second Pedersen commitment.
    pub b: S,
    /// The randomizer used to make the Rescue hash function a commitment scheme.
    pub r: BLSScalar,
    /// PhantomData for the parameters.
    pub params_phantom: PhantomData<P>,
    /// PhantomData for the group.
    pub group_phantom: PhantomData<G>,
}

impl<S: Scalar, G: Group<ScalarType = S>, P: SimFrParams> DelegatedChaumPedersenProof<S, G, P> {
    /// Represent the information needed by zk-SNARKs in its format.
    pub fn to_verifier_input(&self) -> Vec<BLSScalar> {
        let s_1_biguint = BigUint::from_bytes_le(&self.s_1.to_bytes());
        let s_2_biguint = BigUint::from_bytes_le(&self.s_2.to_bytes());

        let s_1_sim_fr = SimFr::<P>::from(&s_1_biguint);
        let s_2_sim_fr = SimFr::<P>::from(&s_2_biguint);

        let mut res = Vec::with_capacity(1 + P::NUM_OF_LIMBS * 2);
        res[0] = self.inspection_comm;
        for i in 0..P::NUM_OF_LIMBS {
            res[i + 1] = s_1_sim_fr.limbs[i];
            res[i + P::NUM_OF_LIMBS + 1] = s_2_sim_fr.limbs[i];
        }

        res
    }
}

/// Generate a proof in the delegated Chaum-Pedersen protocol.
pub fn prove_delegated_chaum_pedersen<
    R: CryptoRng + RngCore,
    S: Scalar,
    G: Group<ScalarType = S>,
    P: SimFrParams,
    PC: PedersenCommitment<G>,
>(
    rng: &mut R,
    x: &S,
    gamma: &S,
    y: &S,
    delta: &S,
    pc_gens: &PC,
    point_p: &G,
    point_q: &G,
    aux_info: &BLSScalar,
) -> Result<(
    DelegatedChaumPedersenProof<S, G, P>,
    DelegatedChaumPedersenInspection<S, G, P>,
    S,
    S,
)> {
    let mut proof = DelegatedChaumPedersenProof::default();
    let mut inspection = DelegatedChaumPedersenInspection::default();
    let mut transcript = Transcript::new(b"Pedersen Eq Rescure Split Verifier -- ZK Verifier Part");

    // 1. sample a, b, c, d
    let a = S::random(rng);
    let b = S::random(rng);
    let c = S::random(rng);
    let d = S::random(rng);
    let r = BLSScalar::random(rng);

    // 2. generate x, y, a, b; these are the non-ZK verifier's state
    let x_biguint = BigUint::from_bytes_le(&x.to_bytes());
    let y_biguint = BigUint::from_bytes_le(&y.to_bytes());
    let a_biguint = BigUint::from_bytes_le(&a.to_bytes());
    let b_biguint = BigUint::from_bytes_le(&b.to_bytes());

    let x_sim_fr = SimFr::<P>::from(&x_biguint);
    let y_sim_fr = SimFr::<P>::from(&y_biguint);
    let a_sim_fr = SimFr::<P>::from(&a_biguint);
    let b_sim_fr = SimFr::<P>::from(&b_biguint);

    // 3. merge limbs of x, y, a, b
    let mut all_limbs = Vec::with_capacity(4 * P::NUM_OF_LIMBS);
    all_limbs.extend_from_slice(&x_sim_fr.limbs);
    all_limbs.extend_from_slice(&y_sim_fr.limbs);
    all_limbs.extend_from_slice(&a_sim_fr.limbs);
    all_limbs.extend_from_slice(&b_sim_fr.limbs);

    let num_limbs_compressed = BLSScalar::capacity() / P::BIT_PER_LIMB;

    let mut compressed_limbs = Vec::with_capacity(num_limbs_compressed);
    for limbs in all_limbs.chunks(num_limbs_compressed) {
        let mut sum = BigUint::zero();
        for (i, limb) in limbs.iter().enumerate() {
            sum.add_assign(
                <&BLSScalar as Into<BigUint>>::into(limb)
                    .mul(&BigUint::from(1u32).shl(P::BIT_PER_LIMB * i)),
            );
        }
        compressed_limbs.push(BLSScalar::from(&sum));
    }

    // 4. compute comm, which is the commitment of the non-ZK verifier's state
    let comm_instance = RescueInstance::<BLSScalar>::new();
    let comm = {
        let mut input = compressed_limbs.clone();
        input.push(r);
        input.resize((input.len() - 1 + 2) / 3 * 3 + 1, BLSScalar::zero());

        let mut h = comm_instance.rescue(&[
            compressed_limbs[0],
            compressed_limbs[1],
            compressed_limbs[2],
            compressed_limbs[3],
        ])[0];

        let input = input[4..].to_vec();

        for chunk in input.chunks(3) {
            h = comm_instance.rescue(&[h, chunk[0], chunk[1], chunk[2]])[0];
        }

        h
    };
    proof.inspection_comm = comm;

    // 5. compute the two blinding points
    let point_r = pc_gens.commit(a, c);
    let point_s = pc_gens.commit(b, d);

    proof.point_r = point_r;
    proof.point_s = point_s;

    // 6. Fiat-Shamir transform
    transcript.append_message(b"PC base", &pc_gens.generator().to_compressed_bytes());
    transcript.append_message(
        b"PC base blinding",
        &pc_gens.blinding_generator().to_compressed_bytes(),
    );
    transcript.append_message(b"Point P", &point_p.to_compressed_bytes());
    transcript.append_message(b"Point Q", &point_q.to_compressed_bytes());
    transcript.append_message(
        b"Auxiliary information (Rescue commitment z, or a nullifier)",
        &aux_info.to_bytes(),
    );
    transcript.append_message(b"Inspector state commitment comm", &comm.to_bytes());
    transcript.append_message(b"Point R", &point_r.to_compressed_bytes());
    transcript.append_message(b"Point S", &point_s.to_compressed_bytes());

    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    let mut rng = ChaChaRng::from_seed(bytes);

    let mut rand_bytes = [0u8; 16];
    rng.fill_bytes(&mut rand_bytes);
    let beta = S::from_bytes(&rand_bytes).unwrap();

    // 7. compute the responses
    let s_1 = beta.mul(x).add(&a);
    let s_2 = beta.mul(y).add(&b);
    let s_3 = beta.mul(gamma).add(&c);
    let s_4 = beta.mul(delta).add(&d);

    transcript.append_message(b"Response s1", &s_1.to_bytes());
    transcript.append_message(b"Response s2", &s_2.to_bytes());
    transcript.append_message(b"Response s3", &s_3.to_bytes());
    transcript.append_message(b"Response s4", &s_4.to_bytes());

    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    let mut rng = ChaChaRng::from_seed(bytes);

    let mut rand_bytes = [0u8; 16];
    rng.fill_bytes(&mut rand_bytes);
    let lambda = S::from_bytes(&rand_bytes).unwrap();

    proof.s_1 = s_1;
    proof.s_2 = s_2;
    proof.s_3 = s_3;
    proof.s_4 = s_4;

    inspection.x = *x;
    inspection.y = *y;
    inspection.a = a;
    inspection.b = b;
    inspection.r = r;

    Ok((proof, inspection, beta, lambda))
}

/// Verify a proof in the delegated Chaum-Pedersen protocol.
pub fn verify_delegated_chaum_pedersen<
    S: Scalar,
    G: Group<ScalarType = S>,
    P: SimFrParams,
    PC: PedersenCommitment<G>,
>(
    pc_gens: &PC,
    point_p: &G,
    point_q: &G,
    aux_info: &BLSScalar,
    proof: &DelegatedChaumPedersenProof<S, G, P>,
) -> Result<(S, S)> {
    // 1. Fiat-Shamir transform
    let mut transcript = Transcript::new(b"Pedersen Eq Rescure Split Verifier -- ZK Verifier Part");

    transcript.append_message(b"PC base", &pc_gens.generator().to_compressed_bytes());
    transcript.append_message(
        b"PC base blinding",
        &pc_gens.blinding_generator().to_compressed_bytes(),
    );
    transcript.append_message(b"Point P", &point_p.to_compressed_bytes());
    transcript.append_message(b"Point Q", &point_q.to_compressed_bytes());
    transcript.append_message(
        b"Auxiliary information (Rescue commitment z, or a nullifier)",
        &aux_info.to_bytes(),
    );
    transcript.append_message(
        b"Inspector state commitment comm",
        &proof.inspection_comm.to_bytes(),
    );
    transcript.append_message(b"Point R", &proof.point_r.to_compressed_bytes());
    transcript.append_message(b"Point S", &proof.point_s.to_compressed_bytes());

    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    let mut rng = ChaChaRng::from_seed(bytes);

    let mut rand_bytes = [0u8; 16];
    rng.fill_bytes(&mut rand_bytes);
    let beta = S::from_bytes(&rand_bytes).unwrap();

    transcript.append_message(b"Response s1", &proof.s_1.to_bytes());
    transcript.append_message(b"Response s2", &proof.s_2.to_bytes());
    transcript.append_message(b"Response s3", &proof.s_3.to_bytes());
    transcript.append_message(b"Response s4", &proof.s_4.to_bytes());

    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    let mut rng = ChaChaRng::from_seed(bytes);

    let mut rand_bytes = [0u8; 16];
    rng.fill_bytes(&mut rand_bytes);
    let lambda = S::from_bytes(&rand_bytes).unwrap();

    // 2. check the group relationships
    let first_eqn_left = pc_gens.commit(proof.s_1, proof.s_3);
    let first_eqn_right = point_p.mul(&beta).add(&proof.point_r);

    if first_eqn_left.ne(&first_eqn_right) {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    let second_eqn_left = pc_gens.commit(proof.s_2, proof.s_4);
    let second_eqn_right = point_q.mul(&beta).add(&proof.point_s);

    if second_eqn_left.ne(&second_eqn_right) {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    Ok((beta, lambda))
}

#[cfg(test)]
mod test {
    use crate::basic::pedersen_comm::{PedersenCommitment, PedersenCommitmentRistretto};
    use crate::basic::rescue::RescueInstance;
    use crate::delegated_chaum_pedersen::{
        prove_delegated_chaum_pedersen, verify_delegated_chaum_pedersen,
    };
    use crate::field_simulation::SimFrParamsRistretto;
    use num_bigint::BigUint;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use zei_algebra::ristretto::RistrettoScalar;
    use zei_algebra::{bls12_381::BLSScalar, traits::Scalar, Zero};

    #[test]
    fn test_correctness() {
        let mut rng = ChaChaRng::from_entropy();

        for _ in 0..10 {
            let x = RistrettoScalar::random(&mut rng);
            let gamma = RistrettoScalar::random(&mut rng);
            let y = RistrettoScalar::random(&mut rng);
            let delta = RistrettoScalar::random(&mut rng);

            let pc_gens = PedersenCommitmentRistretto::default();

            let point_p = pc_gens.commit(x, gamma);
            let point_q = pc_gens.commit(y, delta);

            let z_randomizer = BLSScalar::random(&mut rng);
            let z_instance = RescueInstance::<BLSScalar>::new();

            let x_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&x.to_bytes()));
            let y_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&y.to_bytes()));

            let z = z_instance.rescue(&[
                z_randomizer,
                x_in_bls12_381,
                y_in_bls12_381,
                BLSScalar::zero(),
            ])[0];

            let (proof, _, _, _) =
                prove_delegated_chaum_pedersen::<_, _, _, SimFrParamsRistretto, _>(
                    &mut rng, &x, &gamma, &y, &delta, &pc_gens, &point_p, &point_q, &z,
                )
                .unwrap();

            let _ =
                verify_delegated_chaum_pedersen(&pc_gens, &point_p, &point_q, &z, &proof).unwrap();
        }
    }
}
