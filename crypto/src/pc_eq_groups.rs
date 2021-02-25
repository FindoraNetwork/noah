use crate::basics::commitments::pedersen::PedersenGens;
use algebra::groups::{Group, Scalar};
use merlin::Transcript;
use num_bigint::{BigUint, RandBigInt};
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use ruc::{err::*, *};
use serde::ser::Serializer;
use utils::errors::ZeiError;
use utils::serialization::ZeiFromToBytes;

#[derive(Debug)]
struct BigNum(BigUint); //wrapper that enables to implement serialize and deserialize for BigUint

impl ZeiFromToBytes for BigNum {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes_le()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(BigNum(BigUint::from_bytes_le(bytes)))
    }
}

serialize_deserialize!(BigNum);

#[derive(Debug, Deserialize, Serialize)]
pub struct Proof<G1, G2> {
    com_v1: G1,
    com_v2: G1,
    com_v1_v2: G2,
    responses: [BigNum; 5],
}

fn trascript_init<G1: Group, G2: Group>(
    transcript: &mut Transcript,
    pc_gens_g1: &PedersenGens<G1>,
    pc_gens_g2: &PedersenGens<G2>,
    c1: &G1,
    c2: &G1,
    c3: &G2,
) {
    transcript.append_message(
        b"Domain Separation",
        b"PedersenEq pair to vector in different groups",
    );
    transcript.append_message(
        b"G1 base",
        &pc_gens_g1.get_base(0).unwrap().to_compressed_bytes(),
    );
    transcript.append_message(
        b"G1 base blinding",
        &pc_gens_g1.get_blinding_base().to_compressed_bytes(),
    );
    transcript.append_message(
        b"G2 base 0",
        &pc_gens_g2.get_base(0).unwrap().to_compressed_bytes(),
    );
    transcript.append_message(
        b"G2 base 1",
        &pc_gens_g2.get_base(1).unwrap().to_compressed_bytes(),
    );
    transcript.append_message(
        b"G2 base blinding",
        &pc_gens_g2.get_blinding_base().to_compressed_bytes(),
    );
    transcript
        .append_message(b"Commitment first value in g1", &c1.to_compressed_bytes());
    transcript
        .append_message(b"Commitment second value in g1", &c2.to_compressed_bytes());
    transcript.append_message(b"Commitment values in g2", &c3.to_compressed_bytes());
}

fn transcript_append_commitments_get_challenge<G1: Group, G2: Group>(
    transcript: &mut Transcript,
    com_v1: &G1,
    com_v2: &G1,
    com_v1_v2: &G2,
    n: &BigUint,
) -> BigUint {
    transcript.append_message(b"com1G1", &com_v1.to_compressed_bytes());
    transcript.append_message(b"com2G1", &com_v2.to_compressed_bytes());
    transcript.append_message(b"comgG2", &com_v1_v2.to_compressed_bytes());

    let mut bytes = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    let mut rng = ChaChaRng::from_seed(bytes);
    rng.gen_biguint_below(n)
}

/// Produce proof that `values` committed using `blinds_g1` in G1 pedersen commitments matches the vector
/// pedersen commitment over G1 using blinding `blind_g1`
pub fn prove_pair_to_vector_pc<R: CryptoRng + RngCore, G1: Group, G2: Group>(
    prng: &mut R,
    transcript: &mut Transcript,
    values: (&[u8], &[u8]),
    blinds_g1: (&G1::S, &G1::S),
    blind_g2: &G2::S,
    pc_gens1: &PedersenGens<G1>,
    pc_gens2: &PedersenGens<G2>,
) -> Result<Proof<G1, G2>> {
    // input commitments
    let value1_g1 =
        G1::S::from_le_bytes(values.0).c(d!(ZeiError::SerializationError))?;
    let value2_g1 =
        G1::S::from_le_bytes(values.1).c(d!(ZeiError::SerializationError))?;
    let c1 = pc_gens1.commit(&[value1_g1], &blinds_g1.0).c(d!())?;
    let c2 = pc_gens1.commit(&[value2_g1], &blinds_g1.1).c(d!())?;

    let value1_g2 =
        G2::S::from_le_bytes(values.0).c(d!(ZeiError::SerializationError))?;
    let value2_g2 =
        G2::S::from_le_bytes(values.1).c(d!(ZeiError::SerializationError))?;

    let c3 = pc_gens2
        .commit(&[value1_g2, value2_g2], &blind_g2)
        .c(d!())?;
    trascript_init(transcript, &pc_gens1, &pc_gens2, &c1, &c2, &c3);

    // 1. compute scalar group Z_{p * q}
    let g1_size_le_bytes = G1::S::get_field_size_lsf_bytes();
    let g2_size_le_bytes = G2::S::get_field_size_lsf_bytes();

    let g1_size = BigUint::from_bytes_le(&g1_size_le_bytes);
    let g2_size = BigUint::from_bytes_le(&g2_size_le_bytes);
    let n = &g1_size * &g2_size;

    // 2. Compute proof commitments
    // 2.1 Sample proof blindings in Z_n
    let v1 = prng.gen_biguint_below(&n);
    let v2 = prng.gen_biguint_below(&n);
    let b1 = prng.gen_biguint_below(&g1_size);
    let b2 = prng.gen_biguint_below(&g1_size);
    let b3 = prng.gen_biguint_below(&g2_size);

    let v1_mod_p = biguint_mod_scalar::<G1::S>(&v1);
    let b1_scalar = G1::S::from_le_bytes(&b1.to_bytes_le()).unwrap();
    let v2_mod_p = biguint_mod_scalar::<G1::S>(&v2);
    let b2_scalar = G1::S::from_le_bytes(&b2.to_bytes_le()).unwrap();
    let com_v1 = pc_gens1.commit(&[v1_mod_p], &b1_scalar).unwrap();
    let com_v2 = pc_gens1.commit(&[v2_mod_p], &b2_scalar).unwrap();

    let v1_mod_q = biguint_mod_scalar::<G2::S>(&v1);
    let v2_mod_q = biguint_mod_scalar::<G2::S>(&v2);
    let b3_scalar = G2::S::from_le_bytes(&b3.to_bytes_le()).unwrap();
    let com_v1_v2 = pc_gens2
        .commit(&[v1_mod_q, v2_mod_q], &b3_scalar)
        .c(d!(ZeiError::ParameterError))?;

    // 3. commit and get challenge
    let challenge = transcript_append_commitments_get_challenge(
        transcript, &com_v1, &com_v2, &com_v1_v2, &n,
    );

    // 4. Compute responses
    let value1_buint = BigUint::from_bytes_le(values.0);
    let value2_buint = BigUint::from_bytes_le(values.1);
    let blind1_buint = BigUint::from_bytes_le(&blinds_g1.0.to_bytes());
    let blind2_buint = BigUint::from_bytes_le(&blinds_g1.1.to_bytes());
    let blind3_buint = BigUint::from_bytes_le(&blind_g2.to_bytes());
    let responses = [
        BigNum(value1_buint * &challenge + v1),
        BigNum(value2_buint * &challenge + v2),
        BigNum(blind1_buint * &challenge + b1),
        BigNum(blind2_buint * &challenge + b2),
        BigNum(blind3_buint * challenge + b3),
    ];

    Ok(Proof {
        com_v1,
        com_v2,
        com_v1_v2,
        responses,
    })
}

/// Verify a proof of knowledge of v1, v2, b1, b2, b3 such that
/// C1 = pc_gens1.commit(v1, b1)
/// C2 = pc_gens1.commit(v2, b2)
/// C3 = pc_gens2.commit([v1, v2], b3)
pub fn verify_pair_to_vector_pc<G1: Group, G2: Group>(
    transcript: &mut Transcript,
    coms_g1: (&G1, &G1),
    com_g2: &G2,
    pc_gens1: &PedersenGens<G1>,
    pc_gens2: &PedersenGens<G2>,
    proof: &Proof<G1, G2>,
) -> Result<()> {
    // 1. init transcript
    trascript_init(transcript, pc_gens1, pc_gens2, coms_g1.0, coms_g1.1, com_g2);

    // 2. get challenge
    let g1_size_le_bytes = G1::S::get_field_size_lsf_bytes();
    let g2_size_le_bytes = G2::S::get_field_size_lsf_bytes();

    let g1_size = BigUint::from_bytes_le(&g1_size_le_bytes);
    let g2_size = BigUint::from_bytes_le(&g2_size_le_bytes);
    let n = &g1_size * &g2_size;

    let challenge = transcript_append_commitments_get_challenge(
        transcript,
        &proof.com_v1,
        &proof.com_v2,
        &proof.com_v1_v2,
        &n,
    );
    let challenge_mod_p = biguint_mod_scalar::<G1::S>(&challenge);

    let response_value1_mod_p = biguint_mod_scalar::<G1::S>(&proof.responses[0].0);
    let response_value2_mod_p = biguint_mod_scalar::<G1::S>(&proof.responses[1].0);
    let response_blind1_mod_p = biguint_mod_scalar::<G1::S>(&proof.responses[2].0);
    let response_blind2_mod_p = biguint_mod_scalar::<G1::S>(&proof.responses[3].0);

    let com_response_value1 = pc_gens1
        .commit(&[response_value1_mod_p], &response_blind1_mod_p)
        .c(d!(ZeiError::ZKProofVerificationError))?;
    if com_response_value1 != coms_g1.0.mul(&challenge_mod_p).add(&proof.com_v1) {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    let com_response_value2 = pc_gens1
        .commit(&[response_value2_mod_p], &response_blind2_mod_p)
        .c(d!(ZeiError::ZKProofVerificationError))?;
    if com_response_value2 != coms_g1.1.mul(&challenge_mod_p).add(&proof.com_v2) {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    let challenge_mod_q = biguint_mod_scalar::<G2::S>(&challenge);
    let response_value1_mod_q = biguint_mod_scalar::<G2::S>(&proof.responses[0].0);
    let response_value2_mod_q = biguint_mod_scalar::<G2::S>(&proof.responses[1].0);
    let response_blind3_mod_q = biguint_mod_scalar::<G2::S>(&proof.responses[4].0);

    let response_com_v1_v2 = pc_gens2
        .commit(
            &[response_value1_mod_q, response_value2_mod_q],
            &response_blind3_mod_q,
        )
        .c(d!(ZeiError::ZKProofVerificationError))?;
    if response_com_v1_v2 != com_g2.mul(&challenge_mod_q).add(&proof.com_v1_v2) {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    Ok(())
}

fn biguint_mod_scalar<S: Scalar>(bigint: &BigUint) -> S {
    let mut bytes = vec![0u8; S::bytes_len()];
    let scalar_size = BigUint::from_bytes_le(&S::get_field_size_lsf_bytes());
    let bigint_mod_p = bigint
        .modpow(&BigUint::from(1u64), &scalar_size)
        .to_bytes_le();
    let len = bigint_mod_p.len();
    bytes[0..len].copy_from_slice(&bigint_mod_p);
    S::from_le_bytes(&bytes).unwrap() //safe unwrap
}

#[cfg(test)]
mod test {
    use crate::basics::commitments::pedersen::PedersenGens;
    use crate::pc_eq_groups::BigNum;
    use algebra::groups::{Group, GroupArithmetic, Scalar};
    use algebra::jubjub::{JubjubPoint, JubjubScalar};
    use algebra::ristretto::{RistrettoPoint, RistrettoScalar};
    use merlin::Transcript;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use std::ops::{Add, Sub};

    #[test]
    pub fn test_pc_eq() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let value1 = RistrettoScalar::from_u64(10);
        let value2 = RistrettoScalar::from_u64(200);
        let blind1 = RistrettoScalar::random(&mut prng);
        let blind2 = RistrettoScalar::random(&mut prng);

        let pc_gens_rist =
            PedersenGens::<RistrettoPoint>::from(bulletproofs::PedersenGens::default());
        let com_value1 = pc_gens_rist.commit(&[value1], &blind1).unwrap();
        let com_value2 = pc_gens_rist.commit(&[value2], &blind2).unwrap();

        let value1_g2 = JubjubScalar::from_u64(10);
        let value2_g2 = JubjubScalar::from_u64(200);
        let blind3 = JubjubScalar::random(&mut prng);

        let pc_gens_jubjub = PedersenGens::<JubjubPoint>::new(2);
        let com_value1_value2 = pc_gens_jubjub
            .commit(&[value1_g2, value2_g2], &blind3)
            .unwrap();

        let mut prover_transcript = Transcript::new(b"test");
        let proof = super::prove_pair_to_vector_pc(
            &mut prng,
            &mut prover_transcript,
            (&value1_g2.to_bytes(), &value2_g2.to_bytes()),
            (&blind1, &blind2),
            &blind3,
            &pc_gens_rist,
            &pc_gens_jubjub,
        )
        .unwrap();

        let mut verifier_transcript = Transcript::new(b"test");
        assert!(
            super::verify_pair_to_vector_pc(
                &mut verifier_transcript,
                (&com_value1, &com_value2),
                &com_value1_value2,
                &pc_gens_rist,
                &pc_gens_jubjub,
                &proof
            )
            .is_ok()
        );

        let mut verifier_transcript = Transcript::new(b"test");
        assert!(
            super::verify_pair_to_vector_pc(
                &mut verifier_transcript,
                (&RistrettoPoint::get_base(), &com_value2),
                &com_value1_value2,
                &pc_gens_rist,
                &pc_gens_jubjub,
                &proof
            )
            .is_err()
        );

        let mut proof = proof;
        proof.responses[0] = BigNum(proof.responses[0].0.clone().add(1u8));
        let mut verifier_transcript = Transcript::new(b"test");
        assert!(
            super::verify_pair_to_vector_pc(
                &mut verifier_transcript,
                (&com_value1, &com_value2),
                &com_value1_value2,
                &pc_gens_rist,
                &pc_gens_jubjub,
                &proof
            )
            .is_err()
        );

        let mut proof = proof;
        proof.responses[0] = BigNum(proof.responses[0].0.clone().sub(1u8));
        proof.com_v1_v2 = proof.com_v1_v2.add(&JubjubPoint::get_base());
        let mut verifier_transcript = Transcript::new(b"test");
        assert!(
            super::verify_pair_to_vector_pc(
                &mut verifier_transcript,
                (&com_value1, &com_value2),
                &com_value1_value2,
                &pc_gens_rist,
                &pc_gens_jubjub,
                &proof
            )
            .is_err()
        )
    }
}
