use crate::basics::matrix_sigma::{
    sigma_prove, sigma_verify, sigma_verify_scalars, SigmaProof, SigmaTranscript,
};
use crate::basics::ristretto_pedersen_comm::RistrettoPedersenCommitment;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use merlin::Transcript;
use zei_algebra::prelude::*;
use zei_algebra::ristretto::RistrettoPoint;
use zei_algebra::ristretto::RistrettoScalar;

/// A Chaum-Pedersen proof of commitment equality
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct ChaumPedersenProof {
    pub(crate) c3: RistrettoPoint,
    pub(crate) c4: RistrettoPoint,
    pub(crate) z1: RistrettoScalar,
    pub(crate) z2: RistrettoScalar,
    pub(crate) z3: RistrettoScalar,
}

fn init_chaum_pedersen(
    transcript: &mut Transcript,
    c1: &RistrettoPoint,
    c2: &RistrettoPoint,
) -> (Vec<RistrettoPoint>, Vec<Vec<usize>>, Vec<usize>) {
    let identity = RistrettoPoint::get_identity();
    let pc_gens = RistrettoPedersenCommitment::default();
    transcript.append_message(b"new_domain", b"Chaum Pedersen");
    let elems = vec![identity, pc_gens.B, pc_gens.B_blinding, *c1, *c2];
    let lhs_matrix = vec![vec![1, 2, 0], vec![1, 0, 2]];
    let rhs_vec = vec![3, 4];
    (elems, lhs_matrix, rhs_vec)
}

/// Compute a Chaum-Pedersen proof of knowledge of openings of two commitments to the same value
pub fn chaum_pedersen_prove_eq<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    value: &RistrettoScalar,
    com1: (&RistrettoPoint, &RistrettoScalar), // commitment and blinding
    com2: (&RistrettoPoint, &RistrettoScalar), // commitment and blinding
) -> ChaumPedersenProof {
    let c1 = com1.0;
    let c2 = com2.0;
    let blinding_factor1 = com1.1;
    let blinding_factor2 = com2.1;
    let (elems, lhs_matrix, _) = init_chaum_pedersen(transcript, c1, c2);
    let secrets = [value, blinding_factor1, blinding_factor2];
    let proof = sigma_prove(
        transcript,
        prng,
        elems.as_slice(),
        lhs_matrix.as_slice(),
        &secrets[..],
    );

    ChaumPedersenProof {
        c3: proof.commitments[0],
        c4: proof.commitments[1],
        z1: proof.responses[0],
        z2: proof.responses[1],
        z3: proof.responses[2],
    }
}

/// Return verification scalars associated with a chaum pedersen proof of equality of two commitment.
/// The scalars can then be used in a single multi-exponentiation to verify a chaum pedersen proof.
/// The order of the returned scalars is
///  - 0: scalar associated with pc_gens.B
///  - 1: scalar associated with pc_gens.B_blinding
///  - 2: scalar associated with commitments\[0\]
///  - 3: scalar associated with commitments\[1\]
///  - 4: scalar associated with proof.c1_eq_c2.c3
///  - 5: scalar associated with proof.c1_eq_c2.c4
pub fn chaum_pedersen_verify_eq_scalars<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    c1: &RistrettoPoint,
    c2: &RistrettoPoint,
    proof: &ChaumPedersenProof,
) -> Vec<RistrettoScalar> {
    let (elems, lhs_matrix, rhs_vec) = init_chaum_pedersen(transcript, c1, c2);

    let sigma_proof = SigmaProof {
        commitments: vec![proof.c3, proof.c4],
        responses: vec![proof.z1, proof.z2, proof.z3],
    };
    let mut scalars = sigma_verify_scalars(
        transcript,
        prng,
        &elems,
        &lhs_matrix,
        &rhs_vec,
        &sigma_proof,
    );
    scalars.remove(0); // The first element is the identity element.
    scalars
}

/// Verify a Chaum-Pedersen equality proof. Return Ok() in case of success,
/// Err(ZeiError::ZKVerificationError) in case of verification failure, and
/// Err(Error::DecompressElementError) in case some CompressedRistretto can not be decompressed.
pub fn chaum_pedersen_verify_eq<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    c1: &RistrettoPoint,
    c2: &RistrettoPoint,
    proof: &ChaumPedersenProof,
) -> Result<()> {
    let (elems, lhs_matrix, rhs_vec) = init_chaum_pedersen(transcript, c1, c2);

    let sigma_proof = SigmaProof {
        commitments: vec![proof.c3, proof.c4],
        responses: vec![proof.z1, proof.z2, proof.z3],
    };

    sigma_verify::<_, RistrettoPoint>(
        transcript,
        prng,
        elems.as_slice(),
        lhs_matrix.as_slice(),
        rhs_vec.as_slice(),
        &sigma_proof,
    )
    .c(d!())
}

/// A Chaum-Pedersen proof of equality of multiple commitments
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct ChaumPedersenProofX {
    pub(crate) c1_eq_c2: ChaumPedersenProof,
    pub(crate) zero: Option<ChaumPedersenProof>,
}

fn init_chaum_pedersen_multiple(transcript: &mut Transcript, commitments: &[RistrettoPoint]) {
    let pc_gens = RistrettoPedersenCommitment::default();

    let b = pc_gens.B;
    let b_blinding = pc_gens.B_blinding;
    let mut public_elems = vec![b, b_blinding];
    for c in commitments.iter() {
        public_elems.push(*c);
    }
    transcript.init_sigma(b"ChaumPedersenMultiple", &[], public_elems.as_slice())
}

/// Creates a zero-knowledge proof of knowledge for equality of a set of commitments
pub fn chaum_pedersen_prove_multiple_eq<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    value: &RistrettoScalar,
    commitments: &[RistrettoPoint],
    blinding_factors: &[RistrettoScalar],
) -> Result<ChaumPedersenProofX> {
    let n = commitments.len();
    if n != blinding_factors.len() || n < 2 {
        return Err(eg!(ZeiError::ParameterError));
    }

    init_chaum_pedersen_multiple(transcript, commitments);
    let proof_c0_c1 = chaum_pedersen_prove_eq(
        transcript,
        prng,
        value,
        (&commitments[0], &blinding_factors[0]),
        (&commitments[1], &blinding_factors[1]),
    );

    if commitments.len() == 2 {
        return Ok(ChaumPedersenProofX {
            c1_eq_c2: proof_c0_c1,
            zero: None,
        });
    }
    let lc_scalars = get_lc_scalars(transcript, commitments.len() - 2);
    let mut d = RistrettoPoint::get_identity();
    let mut z = RistrettoScalar::zero();
    let c0 = &commitments[0];
    let r0 = &blinding_factors[0];
    for (ai, ri, ci) in izip!(
        lc_scalars.iter(),
        blinding_factors.iter().skip(2),
        commitments.iter().skip(2)
    ) {
        let di = c0.sub(ci).mul(ai);
        let zi = r0.sub(ri).mul(ai);
        d = d.add(&di);
        z = z.add(&zi);
    }

    // Note that a simpler way to prove that 'd' is a commitment to 0 consists in
    // proving knowledge of the discrete logarithm of 'z' given Z=g^z
    // However in this implementation it is convenient to have several Chaum-Pedersen proofs
    //  because these proofs can be batched.
    // See for example api/src/api/proofs.rs:batch_verify_confidential_asset
    let proof_zero = chaum_pedersen_prove_eq(
        transcript,
        prng,
        &RistrettoScalar::zero(),
        (&d, &z),
        (&get_zero_commitment(), &get_zero_commitment_blinding()),
    );
    Ok(ChaumPedersenProofX {
        c1_eq_c2: proof_c0_c1,
        zero: Some(proof_zero),
    })
}

/// Return verification scalars associated with a chaum pedersen proof of equality of multiple
/// pedersen commitments.
/// The scalars can then be used in a single multi-exponentiation to verify a chaum pedersen proof.
/// The order of the returned scalars is
///  - 0: scalar associated with pc_gens.B
///  - 1: scalar associated with pc_gens.B_blinding
///  - 2: scalar associated with commitments\[0\]
///  - 3: scalar associated with commitments\[1\]
///  - 4: scalar associated with proof.c1_eq_c2.c3
///  - 5: scalar associated with proof.c1_eq_c2.c4
/// If commitments.len() > 2, then proof returns scalars and an element D and scalars is complemented with
///  - 6: scalar associated with D
///  - 7: scalar associated with proof.zero.c3
///  - 8: scalar associated with proof.zero.c4
pub fn chaum_pedersen_verify_multiple_eq_scalars<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    commitments: &[RistrettoPoint],
    proof: &ChaumPedersenProofX,
) -> Result<(Vec<RistrettoScalar>, Option<RistrettoPoint>)> {
    init_chaum_pedersen_multiple(transcript, commitments);
    let c1_eq_c2_scalars = chaum_pedersen_verify_eq_scalars(
        transcript,
        prng,
        &commitments[0],
        &commitments[1],
        &proof.c1_eq_c2,
    );

    if commitments.len() == 2 {
        // check proof structure is consistent
        return match proof.zero {
            None => Ok((c1_eq_c2_scalars, None)),
            Some(_) => Err(eg!(ZeiError::ZKProofVerificationError)),
        };
    }
    if proof.zero.is_none() {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    let lc_scalars = get_lc_scalars(transcript, commitments.len() - 2);
    let mut d = RistrettoPoint::get_identity();
    let c0 = commitments[0];
    for (ai, ci) in lc_scalars.iter().zip(commitments.iter().skip(2)) {
        let di = c0.sub(ci).mul(ai);
        d = d.add(&di);
    }
    let ci_scalars = chaum_pedersen_verify_eq_scalars(
        transcript,
        prng,
        &d,
        &get_zero_commitment(),
        proof.zero.as_ref().unwrap(),
    ); // safe unwrap

    let alpha = RistrettoScalar::random(prng);

    let mut result = c1_eq_c2_scalars;
    result[0] = result[0].add(&alpha.mul(&ci_scalars[0])); // aggregate B scalars
    result[1] = result[1].add(&alpha.mul(&ci_scalars[1])); // aggregate B_blinding scalars
    result.push(alpha.mul(&ci_scalars[2])); // for commitment d
                                            // result.push(alpha * ci_scalars[3]); skip, because this one is for the zero commitment
    result.push(alpha.mul(&ci_scalars[4]));
    result.push(alpha.mul(&ci_scalars[5]));

    Ok((result, Some(d)))
}

/// Verify a proof that all commitments are to the same value.
///  * Return Ok() in case of success, Err(ZeiError:ZKVerificationError) in case of verification failure,
///  * and Err(Error::DecompressElementError) in case some CompressedRistretto can not be decompressed
pub fn chaum_pedersen_verify_multiple_eq<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    commitments: &[RistrettoPoint],
    proof: &ChaumPedersenProofX,
) -> Result<()> {
    if commitments.len() < 2 {
        return Err(eg!(ZeiError::ParameterError));
    }

    init_chaum_pedersen_multiple(transcript, commitments);
    chaum_pedersen_verify_eq(
        transcript,
        prng,
        &commitments[0],
        &commitments[1],
        &proof.c1_eq_c2,
    )
    .c(d!())?;

    if commitments.len() == 2 {
        return match proof.zero {
            // check proof structure is consistent
            None => Ok(()),
            Some(_) => Err(eg!(ZeiError::ZKProofVerificationError)),
        };
    }

    if proof.zero.is_none() {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    let lc_scalars = get_lc_scalars(transcript, commitments.len() - 2);
    let mut d = RistrettoPoint::get_identity();
    let c0 = commitments[0];
    for (ai, ci) in lc_scalars.iter().zip(commitments.iter().skip(2)) {
        let di = c0.sub(ci).mul(ai);
        d = d.add(&di);
    }

    chaum_pedersen_verify_eq(
        transcript,
        prng,
        &d,
        &get_zero_commitment(),
        proof.zero.as_ref().unwrap(),
    )
    .c(d!()) // safe unwrap
}

/// Batch verification of chaum pedersen equality of commitment proofs
/// This function aggregates all instances using a random linear combination
/// of each, grouping scalars and elements, and executing a single multiexponentiation.
/// Returns ZeiError::ZKProofBatchVerificationError if at least one instance has an incorrect proof.
pub fn chaum_pedersen_batch_verify_multiple_eq<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    instances: &[(Vec<RistrettoPoint>, &ChaumPedersenProofX)],
) -> Result<()> {
    let pc_gens = RistrettoPedersenCommitment::default();

    let multi_exp_len_bound = 2 + 7 * instances.len();
    let mut all_scalars = Vec::with_capacity(multi_exp_len_bound);
    let mut all_elems = Vec::with_capacity(multi_exp_len_bound);
    all_scalars.push(RistrettoScalar::zero());
    all_scalars.push(RistrettoScalar::zero());
    all_elems.push(pc_gens.B);
    all_elems.push(pc_gens.B_blinding);
    for (commitments, proof) in instances {
        let mut instance_transcript = transcript.clone();
        let (instance_scalars, elem) = chaum_pedersen_verify_multiple_eq_scalars(
            &mut instance_transcript,
            prng,
            commitments.as_slice(),
            proof,
        )
        .c(d!())?;

        let alpha = RistrettoScalar::random(prng); // scale instance verification equation by random scalar
        all_scalars[0] = all_scalars[0].add(&instance_scalars[0].mul(&alpha)); // aggregate B
        all_scalars[1] = all_scalars[1].add(&instance_scalars[1].mul(&alpha)); // aggregate B_blinding
        all_scalars.push(instance_scalars[2].mul(&alpha));
        all_scalars.push(instance_scalars[3].mul(&alpha));
        all_scalars.push(instance_scalars[4].mul(&alpha));
        all_scalars.push(instance_scalars[5].mul(&alpha));
        all_elems.push(commitments[0]);
        all_elems.push(commitments[1]);
        all_elems.push(proof.c1_eq_c2.c3);
        all_elems.push(proof.c1_eq_c2.c4);
        if let Some(commitments_combination) = elem {
            all_scalars.push(instance_scalars[6].mul(&alpha));
            all_scalars.push(instance_scalars[7].mul(&alpha));
            all_scalars.push(instance_scalars[8].mul(&alpha));
            all_elems.push(commitments_combination);
            all_elems.push(proof.zero.as_ref().unwrap().c3); // safe unwrap
            all_elems.push(proof.zero.as_ref().unwrap().c4); // safe unwrap
        }
    }

    let multiexp = curve25519_dalek::ristretto::RistrettoPoint::vartime_multiscalar_mul(
        all_scalars.iter().map(|x| x.0),
        all_elems.iter().map(|x| x.0),
    );
    if multiexp != curve25519_dalek::ristretto::RistrettoPoint::identity() {
        Err(eg!(ZeiError::ZKProofBatchVerificationError))
    } else {
        Ok(())
    }
}

// Helper functions for the proof of multiple commitments equality below

// Obtain a fake compressed commitment to zero, eg The identity
fn get_zero_commitment() -> RistrettoPoint {
    RistrettoPoint::get_identity()
}

// Obtain the blinding used in the get_fake_zero_commitment
fn get_zero_commitment_blinding() -> RistrettoScalar {
    RistrettoScalar::zero()
}

fn get_lc_scalars(transcript: &mut Transcript, n: usize) -> Vec<RistrettoScalar> {
    if n == 0 {
        return vec![];
    }
    let mut r = vec![RistrettoScalar::one()];
    for _ in 1..n {
        r.push(transcript.get_challenge::<RistrettoScalar>());
    }
    r
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::basics::ristretto_pedersen_comm::RistrettoPedersenCommitment;
    use rand_chacha::ChaChaRng;

    #[test]
    pub fn test_chaum_pedersen_equality_commitment() {
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = RistrettoPedersenCommitment::default();
        let value1 = RistrettoScalar::from(16u32);
        let value2 = RistrettoScalar::from(32u32);
        let bf1 = RistrettoScalar::from(10u32);
        let bf2 = RistrettoScalar::from(100u32);
        let c1 = pc_gens.commit(value1, bf1);
        let c2 = pc_gens.commit(value2, bf2);

        let mut prover_transcript = Transcript::new(b"test");

        let proof = chaum_pedersen_prove_eq(
            &mut prover_transcript,
            &mut csprng,
            &value1,
            (&c1, &bf1),
            (&c2, &bf2),
        );

        let mut verifier_transcript = Transcript::new(b"test");
        msg_eq!(
            ZeiError::ZKProofVerificationError,
            chaum_pedersen_verify_eq(&mut verifier_transcript, &mut csprng, &c1, &c2, &proof)
                .unwrap_err()
        );

        let mut prover_transcript = Transcript::new(b"test");
        let proof = chaum_pedersen_prove_eq(
            &mut prover_transcript,
            &mut csprng,
            &value2,
            (&c1, &bf2),
            (&c2, &bf2),
        );
        let mut verifier_transcript = Transcript::new(b"test");
        msg_eq!(
            ZeiError::ZKProofVerificationError,
            chaum_pedersen_verify_eq(&mut verifier_transcript, &mut csprng, &c1, &c2, &proof)
                .unwrap_err()
        );

        let mut prover_transcript = Transcript::new(b"test");
        let c3 = pc_gens.commit(value1, bf2);
        let proof = chaum_pedersen_prove_eq(
            &mut prover_transcript,
            &mut csprng,
            &value1,
            (&c1, &bf1),
            (&c3, &bf2),
        );
        let mut verifier_transcript = Transcript::new(b"test");
        assert!(
            chaum_pedersen_verify_eq(&mut verifier_transcript, &mut csprng, &c1, &c3, &proof)
                .is_ok()
        );
    }

    #[test]
    fn test_chaum_pedersen_multiple_eq_proof() {
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);
        let value1 = RistrettoScalar::from(16u32);
        let value2 = RistrettoScalar::from(32u32);
        let bf1 = RistrettoScalar::from(10u32);
        let bf2 = RistrettoScalar::from(100u32);
        let bf3 = RistrettoScalar::from(1000u32);

        let pc_gens = RistrettoPedersenCommitment::default();
        let c1 = pc_gens.commit(value1, bf1);
        let c2 = pc_gens.commit(value2, bf2);
        let c3 = pc_gens.commit(value1, bf3);

        let com_vec = &[c1, c2, c3];
        let blind_vec = vec![bf1, bf2, bf3];
        let mut prover_transcript = Transcript::new(b"Test");
        let proof = chaum_pedersen_prove_multiple_eq(
            &mut prover_transcript,
            &mut csprng,
            &value1,
            com_vec,
            &blind_vec,
        )
        .unwrap();

        let mut verifier_transcript = Transcript::new(b"Test");
        msg_eq!(
            ZeiError::ZKProofVerificationError,
            chaum_pedersen_verify_multiple_eq(
                &mut verifier_transcript,
                &mut csprng,
                com_vec,
                &proof
            )
            .unwrap_err()
        );

        let c1 = pc_gens.commit(value1, bf1);
        let c2 = pc_gens.commit(value1, bf2);
        let c3 = pc_gens.commit(value1, bf3);

        let com_vec = &[c1, c2, c3];
        let blind_vec = vec![bf1, bf2, bf3];

        let mut prover_transcript = Transcript::new(b"Test");
        let proof = chaum_pedersen_prove_multiple_eq(
            &mut prover_transcript,
            &mut csprng,
            &value1,
            com_vec,
            &blind_vec,
        )
        .unwrap();
        let mut verifier_transcript = Transcript::new(b"Test");
        assert!(chaum_pedersen_verify_multiple_eq(
            &mut verifier_transcript,
            &mut csprng,
            com_vec,
            &proof
        )
        .is_ok());
    }

    #[test]
    fn test_chaum_pedersen_multiple_eq_proof_using_two() {
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);
        let value1 = RistrettoScalar::from(16u32);
        let value2 = RistrettoScalar::from(32u32);
        let bf1 = RistrettoScalar::from(10u32);
        let bf2 = RistrettoScalar::from(100u32);
        let pc_gens = RistrettoPedersenCommitment::default();
        let c1 = pc_gens.commit(value1, bf1);
        let c2 = pc_gens.commit(value2, bf2);

        let com_vec = &[c1, c2];
        let blind_vec = vec![bf1, bf2];

        let mut prover_transcript = Transcript::new(b"Test");
        let proof = chaum_pedersen_prove_multiple_eq(
            &mut prover_transcript,
            &mut csprng,
            &value1,
            com_vec,
            &blind_vec,
        )
        .unwrap();

        let mut verifier_transcript = Transcript::new(b"Test");
        msg_eq!(
            ZeiError::ZKProofVerificationError,
            chaum_pedersen_verify_multiple_eq(
                &mut verifier_transcript,
                &mut csprng,
                com_vec,
                &proof
            )
            .unwrap_err(),
            "Values were different"
        );

        let c1 = pc_gens.commit(value1, bf1);
        let c2 = pc_gens.commit(value1, bf2);

        let com_vec = &[c1, c2];
        let blind_vec = vec![bf1, bf2];

        let mut prover_transcript = Transcript::new(b"Test");
        let proof = chaum_pedersen_prove_multiple_eq(
            &mut prover_transcript,
            &mut csprng,
            &value1,
            com_vec,
            &blind_vec,
        )
        .unwrap();
        let mut verifier_transcript = Transcript::new(b"Test");
        assert!(
            chaum_pedersen_verify_multiple_eq(
                &mut verifier_transcript,
                &mut csprng,
                com_vec,
                &proof
            )
            .is_ok(),
            "Values are the same"
        );
    }
}
