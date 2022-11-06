use crate::basic::anemoi_jive::{AnemoiJive, AnemoiJive381};
use crate::basic::pedersen_comm::PedersenCommitment;
use crate::field_simulation::{SimFr, SimFrParams};
use merlin::Transcript;
use noah_algebra::{bls12_381::BLSFr, prelude::*};
use num_bigint::BigUint;
use rand_chacha::ChaChaRng;
use serde::Deserialize;
use std::marker::PhantomData;

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Clone)]
/// The non-interactive proof provided to the verifier.
pub struct DelegatedSchnorrProof<S, G, P> {
    /// The commitment of the non-ZK verifier's state.
    pub inspection_comm: BLSFr,
    /// The randomizer points
    pub randomizers: Vec<G>,
    /// The response scalars (two per pair)
    pub response_scalars: Vec<(S, S)>,
    /// PhantomData for the parameters.
    pub params_phantom: PhantomData<P>,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Clone)]
/// The state of the inspector.
pub struct DelegatedSchnorrInspection<S, G, P> {
    /// The committed value and their corresponding randomizer
    pub committed_data_and_randomizer: Vec<(S, S)>,
    /// The randomizer used to make the hash function a commitment scheme.
    pub r: BLSFr,
    /// PhantomData for the parameters.
    pub params_phantom: PhantomData<P>,
    /// PhantomData for the group.
    pub group_phantom: PhantomData<G>,
}

impl<S: Scalar, G: Group<ScalarType = S>, P: SimFrParams> DelegatedSchnorrInspection<S, G, P> {
    /// Create a dummy new one.
    pub fn new() -> Self {
        Self {
            committed_data_and_randomizer: vec![],
            params_phantom: PhantomData,
            r: BLSFr::default(),
            group_phantom: PhantomData,
        }
    }
}

impl<S: Scalar, G: Group<ScalarType = S>, P: SimFrParams> DelegatedSchnorrProof<S, G, P> {
    /// Create a dummy new one.
    pub fn new() -> Self {
        Self {
            inspection_comm: BLSFr::default(),
            randomizers: vec![],
            response_scalars: vec![],
            params_phantom: PhantomData,
        }
    }

    /// Represent the information needed by zk-SNARKs in its format.
    pub fn to_verifier_input(&self) -> Vec<BLSFr> {
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
            .collect::<Vec<BLSFr>>();

        let mut res = Vec::with_capacity(1 + P::NUM_OF_LIMBS * response_scalars_sim_fr_limbs.len());
        res.push(self.inspection_comm);
        res.extend_from_slice(&response_scalars_sim_fr_limbs);
        res
    }
}

/// Generate a proof in the delegated Schnorr protocol.
pub fn prove_delegated_schnorr<
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
    transcript: &mut Transcript,
) -> Result<(
    DelegatedSchnorrProof<S, G, P>,
    DelegatedSchnorrInspection<S, G, P>,
    S,
    S,
)> {
    assert_eq!(committed_data.len(), commitments.len());
    let len = committed_data.len();

    let mut proof = DelegatedSchnorrProof::new();
    let mut inspection = DelegatedSchnorrInspection::new();

    // 1. sample the scalars for the randomizers.
    let mut randomizer_scalars = Vec::<(S, S)>::with_capacity(len);
    for _ in 0..len {
        randomizer_scalars.push((S::random(rng), S::random(rng)));
    }
    let r = BLSFr::random(rng);

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
    let num_limbs_compressed = BLSFr::capacity() / P::BIT_PER_LIMB;
    let mut compressed_limbs = Vec::new();
    for limbs in all_limbs.chunks(num_limbs_compressed) {
        let mut sum = BigUint::zero();
        for (i, limb) in limbs.iter().enumerate() {
            sum.add_assign(
                <BLSFr as Into<BigUint>>::into(limb.clone())
                    .mul(&BigUint::from(1u32).shl(P::BIT_PER_LIMB * i)),
            );
        }
        compressed_limbs.push(BLSFr::from(&sum));
    }

    // 5. compute comm, which is the commitment of the non-ZK verifier's state
    let comm = {
        let mut input = compressed_limbs.clone();
        input.push(r);

        AnemoiJive381::eval_variable_length_hash(&input)
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
    transcript.append_message(b"Number of points", &(len as u64).to_le_bytes());
    commitments.iter().for_each(|p| {
        transcript.append_message(b"Commitment", &p.to_compressed_bytes());
    });
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

/// Verify a proof in the delegated Schnorr protocol.
pub fn verify_delegated_schnorr<
    S: Scalar,
    G: Group<ScalarType = S>,
    P: SimFrParams,
    PC: PedersenCommitment<G>,
>(
    pc_gens: &PC,
    commitments: &Vec<G>,
    proof: &DelegatedSchnorrProof<S, G, P>,
    transcript: &mut Transcript,
) -> Result<(S, S)> {
    assert_eq!(commitments.len(), proof.randomizers.len());
    assert_eq!(commitments.len(), proof.response_scalars.len());

    let len = commitments.len();

    // 1. Fiat-Shamir transform
    transcript.append_message(b"PC base", &pc_gens.generator().to_compressed_bytes());
    transcript.append_message(
        b"PC base blinding",
        &pc_gens.blinding_generator().to_compressed_bytes(),
    );
    transcript.append_message(b"Number of points", &(len as u64).to_le_bytes());
    commitments.iter().for_each(|p| {
        transcript.append_message(b"Commitment", &p.to_compressed_bytes());
    });
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
            return Err(eg!(NoahError::ZKProofVerificationError));
        }
    }

    Ok((beta, lambda))
}

#[cfg(test)]
mod test {
    use crate::basic::pedersen_comm::{PedersenCommitment, PedersenCommitmentRistretto};
    use crate::delegated_schnorr::{prove_delegated_schnorr, verify_delegated_schnorr};
    use crate::field_simulation::SimFrParamsRistretto;
    use merlin::Transcript;
    use noah_algebra::{prelude::*, ristretto::RistrettoScalar};

    #[test]
    fn test_correctness() {
        let mut prng = test_rng();

        for _ in 0..10 {
            let x = RistrettoScalar::random(&mut prng);
            let gamma = RistrettoScalar::random(&mut prng);
            let y = RistrettoScalar::random(&mut prng);
            let delta = RistrettoScalar::random(&mut prng);

            let pc_gens = PedersenCommitmentRistretto::default();

            let point_p = pc_gens.commit(x, gamma);
            let point_q = pc_gens.commit(y, delta);

            let mut transcript = Transcript::new(b"Test");

            let (proof, _, _, _) = prove_delegated_schnorr::<_, _, _, SimFrParamsRistretto, _>(
                &mut prng,
                &vec![(x, gamma), (y, delta)],
                &pc_gens,
                &vec![point_p, point_q],
                &mut transcript,
            )
            .unwrap();

            let mut transcript = Transcript::new(b"Test");

            let _ = verify_delegated_schnorr(
                &pc_gens,
                &vec![point_p, point_q],
                &proof,
                &mut transcript,
            )
            .unwrap();
        }
    }
}
