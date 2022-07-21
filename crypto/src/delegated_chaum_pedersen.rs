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
    /// The randomizer points
    pub randomizers: Vec<G>,
    /// The response scalars (two per pair)
    pub response_scalars: Vec<(S, S)>,
    /// PhantomData for the parameters.
    pub params_phantom: PhantomData<P>,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Clone, Default)]
/// The state of the inspector.
pub struct DelegatedChaumPedersenInspection<S, G, P> {
    /// The committed value and their corresponding randomizer
    pub committed_data_and_randomizer: Vec<(S, S)>,
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
        let response_scalars_sim_fr_limbs = self
            .response_scalars
            .iter()
            .flat_map(|(first, second)| {
                let first_biguint: BigUint = first.clone().into();
                let second_biguint: BigUint = second.clone().into();

                let first_sim_fr = SimFr::<P>::from(&first_biguint);
                let second_sim_fr = SimFr::<P>::from(&second_biguint);

                let mut v = first_sim_fr.limbs;
                v.extend_from_slice(&second_sim_fr.limbs);
                v
            })
            .collect::<Vec<BLSScalar>>();

        let mut res = Vec::with_capacity(1 + P::NUM_OF_LIMBS * response_scalars_sim_fr_limbs.len());
        res.push(self.inspection_comm);
        res.extend_from_slice(&response_scalars_sim_fr_limbs);
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
    committed_data: &Vec<(S, S)>,
    pc_gens: &PC,
    commitments: &Vec<G>,
    aux_info: &BLSScalar,
) -> Result<(
    DelegatedChaumPedersenProof<S, G, P>,
    DelegatedChaumPedersenInspection<S, G, P>,
    S,
    S,
)> {
    assert_eq!(committed_data.len(), commitments.len());
    let len = committed_data.len();

    let mut proof = DelegatedChaumPedersenProof::default();
    let mut inspection = DelegatedChaumPedersenInspection::default();
    let mut transcript = Transcript::new(b"Pedersen Eq Rescure Split Verifier -- ZK Verifier Part");

    // 1. sample the scalars for the randomizers.
    let mut randomizer_scalars = Vec::<(S, S)>::with_capacity(len);
    for _ in 0..len {
        randomizer_scalars.push((S::random(rng), S::random(rng)));
    }
    let r = BLSScalar::random(rng);

    // 2. convert the first part of each entry in the committed data into biguint and sim_fr; these are in the inspector's state.
    let committed_data_biguint = committed_data
        .iter()
        .map(|(v, _)| <S as Into<BigUint>>::into(v.clone()))
        .collect::<Vec<BigUint>>();
    let committed_data_sim_fr = committed_data_biguint
        .iter()
        .map(|v| SimFr::<P>::from(v))
        .collect::<Vec<SimFr<P>>>();

    // 3. convert the first part of each pair of randomizer scalars; these are in the inspector's state.
    let randomizer_biguint = randomizer_scalars
        .iter()
        .map(|(v, _)| <S as Into<BigUint>>::into(v.clone()))
        .collect::<Vec<BigUint>>();
    let randomizer_sim_fr = randomizer_biguint
        .iter()
        .map(|v| SimFr::<P>::from(v))
        .collect::<Vec<SimFr<P>>>();

    // 3. merge limbs of the committed data as well as the randomizer scalars
    let mut all_limbs = Vec::with_capacity(2 * len * P::NUM_OF_LIMBS);
    committed_data_sim_fr
        .iter()
        .for_each(|v| all_limbs.extend_from_slice(&v.limbs));
    randomizer_sim_fr
        .iter()
        .for_each(|v| all_limbs.extend_from_slice(&v.limbs));

    // 4. compress these limbs for public input.
    let num_limbs_compressed = BLSScalar::capacity() / P::BIT_PER_LIMB;
    let mut compressed_limbs = Vec::new();
    for limbs in all_limbs.chunks(num_limbs_compressed) {
        let mut sum = BigUint::zero();
        for (i, limb) in limbs.iter().enumerate() {
            sum.add_assign(
                <BLSScalar as Into<BigUint>>::into(limb.clone())
                    .mul(&BigUint::from(1u32).shl(P::BIT_PER_LIMB * i)),
            );
        }
        compressed_limbs.push(BLSScalar::from(&sum));
    }

    // 5. compute comm, which is the commitment of the non-ZK verifier's state
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

    // 6. compute the randomizer points.
    let randomizers = randomizer_scalars
        .iter()
        .map(|(v, r)| pc_gens.commit(v.clone(), r.clone()))
        .collect::<Vec<G>>();

    proof.randomizers = randomizers.clone();

    // 7. Fiat-Shamir transform.
    transcript.append_message(b"PC base", &pc_gens.generator().to_compressed_bytes());
    transcript.append_message(
        b"PC base blinding",
        &pc_gens.blinding_generator().to_compressed_bytes(),
    );
    transcript.append_message(b"Number of points", &len.to_le_bytes());
    commitments.iter().for_each(|p| {
        transcript.append_message(b"Commitment", &p.to_compressed_bytes());
    });
    transcript.append_message(
        b"Auxiliary information (Rescue commitment z, or a nullifier)",
        &aux_info.to_bytes(),
    );
    transcript.append_message(b"Inspector state commitment comm", &comm.to_bytes());
    randomizers
        .iter()
        .for_each(|p| transcript.append_message(b"Randomizer", &p.to_compressed_bytes()));

    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    let mut rng = ChaChaRng::from_seed(bytes);

    let mut rand_bytes = [0u8; 16];
    rng.fill_bytes(&mut rand_bytes);
    let beta = S::from_bytes(&rand_bytes).unwrap();

    // 8. compute the responses.
    let response_scalars = committed_data
        .iter()
        .zip(randomizer_scalars.iter())
        .map(|((ll, lr), (rl, rr))| {
            let s_first = beta.mul(ll).add(rl);
            let s_second = beta.mul(lr).add(rr);
            (s_first, s_second)
        })
        .collect::<Vec<(S, S)>>();

    response_scalars.iter().for_each(|(l, r)| {
        transcript.append_message(b"Response", &l.to_bytes());
        transcript.append_message(b"Response", &r.to_bytes());
    });

    proof.response_scalars = response_scalars;

    // 9. assemble the inspector's state.
    inspection.committed_data_and_randomizer = committed_data
        .iter()
        .zip(randomizer_scalars.iter())
        .map(|((ll, _), (rl, _))| (ll.clone(), rl.clone()))
        .collect::<Vec<(S, S)>>();
    inspection.r = r;

    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    let mut rng = ChaChaRng::from_seed(bytes);

    let mut rand_bytes = [0u8; 16];
    rng.fill_bytes(&mut rand_bytes);
    let lambda = S::from_bytes(&rand_bytes).unwrap();

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
    commitments: &Vec<G>,
    aux_info: &BLSScalar,
    proof: &DelegatedChaumPedersenProof<S, G, P>,
) -> Result<(S, S)> {
    assert_eq!(commitments.len(), proof.randomizers.len());
    assert_eq!(commitments.len(), proof.response_scalars.len());

    let len = commitments.len();

    // 1. Fiat-Shamir transform
    let mut transcript = Transcript::new(b"Pedersen Eq Rescure Split Verifier -- ZK Verifier Part");

    transcript.append_message(b"PC base", &pc_gens.generator().to_compressed_bytes());
    transcript.append_message(
        b"PC base blinding",
        &pc_gens.blinding_generator().to_compressed_bytes(),
    );
    transcript.append_message(b"Number of points", &len.to_le_bytes());
    commitments.iter().for_each(|p| {
        transcript.append_message(b"Commitment", &p.to_compressed_bytes());
    });
    transcript.append_message(
        b"Auxiliary information (Rescue commitment z, or a nullifier)",
        &aux_info.to_bytes(),
    );
    transcript.append_message(
        b"Inspector state commitment comm",
        &proof.inspection_comm.to_bytes(),
    );
    proof
        .randomizers
        .iter()
        .for_each(|p| transcript.append_message(b"Randomizer", &p.to_compressed_bytes()));

    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    let mut rng = ChaChaRng::from_seed(bytes);

    let mut rand_bytes = [0u8; 16];
    rng.fill_bytes(&mut rand_bytes);
    let beta = S::from_bytes(&rand_bytes).unwrap();

    proof.response_scalars.iter().for_each(|(l, r)| {
        transcript.append_message(b"Response", &l.to_bytes());
        transcript.append_message(b"Response", &r.to_bytes());
    });

    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    let mut rng = ChaChaRng::from_seed(bytes);

    let mut rand_bytes = [0u8; 16];
    rng.fill_bytes(&mut rand_bytes);
    let lambda = S::from_bytes(&rand_bytes).unwrap();

    // 2. check the group relationships
    for ((scalars, committed_data), randomizer) in proof
        .response_scalars
        .iter()
        .zip(commitments.iter())
        .zip(proof.randomizers.iter())
    {
        let eqn_left = pc_gens.commit(scalars.0, scalars.1);
        let eqn_right = committed_data.mul(&beta).add(&randomizer);

        if eqn_left.ne(&eqn_right) {
            return Err(eg!(ZeiError::ZKProofVerificationError));
        }
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
                    &mut rng,
                    &vec![(x, gamma), (y, delta)],
                    &pc_gens,
                    &vec![point_p, point_q],
                    &z,
                )
                .unwrap();

            let _ = verify_delegated_chaum_pedersen(&pc_gens, &vec![point_p, point_q], &z, &proof)
                .unwrap();
        }
    }
}
