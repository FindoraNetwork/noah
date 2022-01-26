use crate::basics::commitments::pedersen::PedersenGens;
use crate::basics::hash::rescue::RescueInstance;
use crate::field_simulation::{SimFr, BIT_PER_LIMB, NUM_OF_LIMBS};
use algebra::bls12_381::BLSScalar;
use algebra::groups::{
    Group, GroupArithmetic, Scalar, ScalarArithmetic, Zero as ArkZero,
};
use algebra::ristretto::{RistrettoPoint, RistrettoScalar};
use merlin::Transcript;
use num_bigint::BigUint;
use num_traits::Zero;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use ruc::*;
use std::ops::{AddAssign, Mul, Shl};
use utils::errors::ZeiError;

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Clone, Default)]
pub struct ZKPartProof {
    pub non_zk_part_state_commitment: BLSScalar,
    pub point_r: RistrettoPoint,
    pub point_s: RistrettoPoint,
    pub s_1: RistrettoScalar,
    pub s_2: RistrettoScalar,
    pub s_3: RistrettoScalar,
    pub s_4: RistrettoScalar,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Clone, Default)]
pub struct NonZKState {
    pub x: RistrettoScalar,
    pub y: RistrettoScalar,
    pub a: RistrettoScalar,
    pub b: RistrettoScalar,
    pub r: BLSScalar,
}

impl ZKPartProof {
    pub fn to_verifier_input(&self) -> Vec<BLSScalar> {
        let s_1_biguint = BigUint::from_bytes_le(&self.s_1.to_bytes());
        let s_2_biguint = BigUint::from_bytes_le(&self.s_2.to_bytes());

        let s_1_sim_fr = SimFr::from(&s_1_biguint);
        let s_2_sim_fr = SimFr::from(&s_2_biguint);

        let mut res = Vec::with_capacity(1 + NUM_OF_LIMBS * 2);
        res[0] = self.non_zk_part_state_commitment;
        for i in 0..NUM_OF_LIMBS {
            res[i + 1] = s_1_sim_fr.limbs[i];
            res[i + NUM_OF_LIMBS + 1] = s_2_sim_fr.limbs[i];
        }

        res
    }
}

#[allow(unused)]
pub fn prove_pc_eq_rescue_split_verifier_zk_part<R: CryptoRng + RngCore>(
    rng: &mut R,
    x: &RistrettoScalar,
    gamma: &RistrettoScalar,
    y: &RistrettoScalar,
    delta: &RistrettoScalar,
    pc_gens: &PedersenGens<RistrettoPoint>,
    point_p: &RistrettoPoint,
    point_q: &RistrettoPoint,
    z: &BLSScalar,
) -> Result<(ZKPartProof, NonZKState, RistrettoScalar)> {
    assert_eq!(NUM_OF_LIMBS, 6);
    assert_eq!(BIT_PER_LIMB, 43);

    let mut proof = ZKPartProof::default();
    let mut non_zk_state = NonZKState::default();
    let mut transcript =
        Transcript::new(b"Pedersen Eq Rescure Split Verifier -- ZK Verifier Part");

    // 1. sample a, b, c, d
    let a = RistrettoScalar::random(rng);
    let b = RistrettoScalar::random(rng);
    let c = RistrettoScalar::random(rng);
    let d = RistrettoScalar::random(rng);
    let r = BLSScalar::random(rng);

    // 2. generate x, y, a, b; these are the non-ZK verifier's state
    let x_biguint = BigUint::from_bytes_le(&x.to_bytes());
    let y_biguint = BigUint::from_bytes_le(&y.to_bytes());
    let a_biguint = BigUint::from_bytes_le(&a.to_bytes());
    let b_biguint = BigUint::from_bytes_le(&b.to_bytes());

    let x_sim_fr = SimFr::from(&x_biguint);
    let y_sim_fr = SimFr::from(&y_biguint);
    let a_sim_fr = SimFr::from(&a_biguint);
    let b_sim_fr = SimFr::from(&b_biguint);

    // 3. merge limbs of x, y, a, b
    let mut all_limbs = Vec::with_capacity(4 * NUM_OF_LIMBS);
    all_limbs.extend_from_slice(&x_sim_fr.limbs);
    all_limbs.extend_from_slice(&y_sim_fr.limbs);
    all_limbs.extend_from_slice(&a_sim_fr.limbs);
    all_limbs.extend_from_slice(&b_sim_fr.limbs);

    let mut compressed_limbs = Vec::with_capacity(5);
    for limbs in all_limbs.chunks(5) {
        let mut sum = BigUint::zero();
        for (i, limb) in limbs.iter().enumerate() {
            sum.add_assign(
                <&BLSScalar as Into<BigUint>>::into(limb)
                    .mul(&BigUint::from(1u32).shl(BIT_PER_LIMB * i)),
            );
        }
        compressed_limbs.push(BLSScalar::from(&sum));
    }

    // 4. compute comm, which is the commitment of the non-ZK verifier's state
    let comm_instance = RescueInstance::<BLSScalar>::new();
    let comm = {
        let h1 = comm_instance.rescue_hash(&[
            compressed_limbs[0],
            compressed_limbs[1],
            compressed_limbs[2],
            compressed_limbs[3],
        ])[0];
        comm_instance.rescue_hash(&[h1, compressed_limbs[4], r, BLSScalar::zero()])[0]
    };
    proof.non_zk_part_state_commitment = comm;

    // 5. compute the two blinding points
    let point_r = pc_gens.commit(&[a], &c).c(d!())?;
    let point_s = pc_gens.commit(&[b], &d).c(d!())?;

    proof.point_r = point_r;
    proof.point_s = point_s;

    // 6. Fiat-Shamir transform
    transcript.append_message(
        b"PC base",
        &pc_gens.get_base(0).unwrap().to_compressed_bytes(),
    );
    transcript.append_message(
        b"PC base blinding",
        &pc_gens.get_blinding_base().to_compressed_bytes(),
    );
    transcript.append_message(b"Point P", &point_p.to_compressed_bytes());
    transcript.append_message(b"Point Q", &point_q.to_compressed_bytes());
    transcript.append_message(b"Rescue commitment z", &z.to_bytes());
    transcript
        .append_message(b"Non-ZK verifier state commitment comm", &comm.to_bytes());
    transcript.append_message(b"Point R", &point_r.to_compressed_bytes());
    transcript.append_message(b"Point S", &point_s.to_compressed_bytes());

    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    let mut rng = ChaChaRng::from_seed(bytes);
    let beta = RistrettoScalar::random(&mut rng);

    // 7. compute the responses
    let s_1 = beta.mul(x).add(&a);
    let s_2 = beta.mul(y).add(&b);
    let s_3 = beta.mul(gamma).add(&c);
    let s_4 = beta.mul(delta).add(&d);

    proof.s_1 = s_1;
    proof.s_2 = s_2;
    proof.s_3 = s_3;
    proof.s_4 = s_4;

    non_zk_state.x = *x;
    non_zk_state.y = *y;
    non_zk_state.a = a;
    non_zk_state.b = b;
    non_zk_state.r = r;

    Ok((proof, non_zk_state, beta))
}

#[allow(unused)]
pub fn verify_pc_eq_rescue_split_verifier_zk_part(
    pc_gens: &PedersenGens<RistrettoPoint>,
    point_p: &RistrettoPoint,
    point_q: &RistrettoPoint,
    z: &BLSScalar,
    zk_part_proof: &ZKPartProof,
) -> Result<RistrettoScalar> {
    // 1. Fiat-Shamir transform
    let mut transcript =
        Transcript::new(b"Pedersen Eq Rescure Split Verifier -- ZK Verifier Part");

    transcript.append_message(
        b"PC base",
        &pc_gens.get_base(0).unwrap().to_compressed_bytes(),
    );
    transcript.append_message(
        b"PC base blinding",
        &pc_gens.get_blinding_base().to_compressed_bytes(),
    );
    transcript.append_message(b"Point P", &point_p.to_compressed_bytes());
    transcript.append_message(b"Point Q", &point_q.to_compressed_bytes());
    transcript.append_message(b"Rescue commitment z", &z.to_bytes());
    transcript.append_message(
        b"Non-ZK verifier state commitment comm",
        &zk_part_proof.non_zk_part_state_commitment.to_bytes(),
    );
    transcript.append_message(b"Point R", &zk_part_proof.point_r.to_compressed_bytes());
    transcript.append_message(b"Point S", &zk_part_proof.point_s.to_compressed_bytes());

    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    let mut rng = ChaChaRng::from_seed(bytes);
    let beta = RistrettoScalar::random(&mut rng);

    // 2. check the group relationships
    let first_eqn_left = pc_gens
        .commit(&[zk_part_proof.s_1], &zk_part_proof.s_3)
        .c(d!(ZeiError::ZKProofVerificationError))?;
    let first_eqn_right = point_p.mul(&beta).add(&zk_part_proof.point_r);

    if first_eqn_left.ne(&first_eqn_right) {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    let second_eqn_left = pc_gens
        .commit(&[zk_part_proof.s_2], &zk_part_proof.s_4)
        .c(d!(ZeiError::ZKProofVerificationError))?;
    let second_eqn_right = point_q.mul(&beta).add(&zk_part_proof.point_s);

    if second_eqn_left.ne(&second_eqn_right) {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    Ok(beta)
}

#[cfg(test)]
mod test {
    use crate::basics::commitments::pedersen::PedersenGens;
    use crate::basics::hash::rescue::RescueInstance;
    use crate::pc_eq_rescue_split_verifier_zk_part::{
        prove_pc_eq_rescue_split_verifier_zk_part,
        verify_pc_eq_rescue_split_verifier_zk_part,
    };
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{Scalar, Zero};
    use algebra::ristretto::{RistrettoPoint, RistrettoScalar};
    use num_bigint::BigUint;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_correctness() {
        let mut rng = ChaChaRng::from_entropy();

        for _ in 0..10 {
            let x = RistrettoScalar::random(&mut rng);
            let gamma = RistrettoScalar::random(&mut rng);
            let y = RistrettoScalar::random(&mut rng);
            let delta = RistrettoScalar::random(&mut rng);

            let pc_gens = PedersenGens::<RistrettoPoint>::from(
                bulletproofs::PedersenGens::default(),
            );

            let point_p = pc_gens.commit(&[x], &gamma).unwrap();
            let point_q = pc_gens.commit(&[y], &delta).unwrap();

            let z_randomizer = BLSScalar::random(&mut rng);
            let z_instance = RescueInstance::<BLSScalar>::new();

            let x_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&x.to_bytes()));
            let y_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&y.to_bytes()));

            let z = z_instance.rescue_hash(&[
                z_randomizer,
                x_in_bls12_381,
                y_in_bls12_381,
                BLSScalar::zero(),
            ])[0];

            let (proof, _, _) = prove_pc_eq_rescue_split_verifier_zk_part(
                &mut rng, &x, &gamma, &y, &delta, &pc_gens, &point_p, &point_q, &z,
            )
            .unwrap();

            let _ = verify_pc_eq_rescue_split_verifier_zk_part(
                &pc_gens, &point_p, &point_q, &z, &proof,
            )
            .unwrap();
        }
    }
}
