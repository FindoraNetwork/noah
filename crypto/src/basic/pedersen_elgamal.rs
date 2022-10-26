use crate::basic::elgamal::{ElGamalCiphertext, ElGamalEncKey};
use crate::basic::matrix_sigma::{sigma_prove, sigma_verify_scalars, SigmaProof, SigmaTranscript};
use crate::basic::pedersen_comm::PedersenCommitmentRistretto;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use merlin::Transcript;
use noah_algebra::prelude::*;
use noah_algebra::ristretto::RistrettoPoint;
use noah_algebra::ristretto::RistrettoScalar;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// The Pedersen ElGamal equality proof.
pub struct PedersenElGamalEqProof {
    #[serde(with = "noah_obj_serde")]
    /// `z1` = `c * m + r_1`.
    z1: RistrettoScalar,
    #[serde(with = "noah_obj_serde")]
    /// `z2` = `c * r + r_2`.
    z2: RistrettoScalar,
    #[serde(with = "noah_obj_serde")]
    /// `e1` is a ciphertext, `(r_2 * G, r_1 * G + r_2 * PK)`.
    e1: ElGamalCiphertext<RistrettoPoint>,
    #[serde(with = "noah_obj_serde")]
    /// `e2` = `r_1 * g + r_2 * H`.
    c1: RistrettoPoint,
}

/// Initialize the transcript for Pedersen-Elgamal equality proof.
fn init_pedersen_elgamal_transcript(
    transcript: &mut Transcript,
    public_key: &ElGamalEncKey<RistrettoPoint>,
    ctexts: &[ElGamalCiphertext<RistrettoPoint>],
    commitments: &[RistrettoPoint],
) {
    let pc_gens = PedersenCommitmentRistretto::default();
    let mut public_elems = vec![];
    let b = pc_gens.B;
    let b_blinding = pc_gens.B_blinding;
    public_elems.push(b);
    public_elems.push(b_blinding);
    public_elems.push(public_key.0);
    for ctext in ctexts {
        public_elems.push(ctext.e1);
        public_elems.push(ctext.e2);
    }
    for commitment in commitments {
        public_elems.push(*commitment);
    }
    transcript.init_sigma(b"PedersenElGamalAggEq", &[], public_elems.as_slice());
}

// Initiate transcript for PedersenElgamal proof and return proof elements,
// lhs indices matrix and rhs indices vector to be used as input to the sigma protocol
fn init_pok_pedersen_elgamal(
    transcript: &mut Transcript,
    identity: &RistrettoPoint,
    public_key: &ElGamalEncKey<RistrettoPoint>,
    ct: &ElGamalCiphertext<RistrettoPoint>,
    commitment: &RistrettoPoint,
) -> (Vec<RistrettoPoint>, Vec<Vec<usize>>, Vec<usize>) {
    let pc_gens = PedersenCommitmentRistretto::default();
    transcript.append_message(b"new_domain", b"Dlog proof");
    let elems = vec![
        *identity,
        pc_gens.B,
        pc_gens.B_blinding,
        public_key.0,
        ct.e1,
        ct.e2,
        *commitment,
    ];
    let lhs_matrix = vec![
        vec![0, 1], // m*0 + r*B = ctext.e1
        vec![1, 3], // m*B + r*PK = ctext.e2
        vec![1, 2], // m*B + r*B_blinding = commitment
    ];
    let rhs_vec = vec![4, 5, 6]; // e1, e2, commitment
    (elems, lhs_matrix, rhs_vec)
}

/// Compute a proof that ciphertext and commitment holds the same message, the same randomness.
/// This function assumes transcript already contains ciphertexts and commitments.
pub fn pedersen_elgamal_eq_prove<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    m: &RistrettoScalar,
    r: &RistrettoScalar,
    public_key: &ElGamalEncKey<RistrettoPoint>,
    ctext: &ElGamalCiphertext<RistrettoPoint>,
    commitment: &RistrettoPoint,
) -> PedersenElGamalEqProof {
    let identity = RistrettoPoint::get_identity();
    let (elems, lhs_matrix, _) =
        init_pok_pedersen_elgamal(transcript, &identity, public_key, ctext, commitment);
    let proof = sigma_prove(
        transcript,
        prng,
        elems.as_slice(),
        lhs_matrix.as_slice(),
        &[m, r],
    );
    PedersenElGamalEqProof {
        z1: proof.responses[0],
        z2: proof.responses[1],
        e1: ElGamalCiphertext {
            e1: proof.commitments[0],
            e2: proof.commitments[1],
        },
        c1: proof.commitments[2],
    }
}

fn pedersem_elgamal_eq_verify_scalars<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    public_key: &ElGamalEncKey<RistrettoPoint>,
    ctext: &ElGamalCiphertext<RistrettoPoint>,
    commitment: &RistrettoPoint,
    proof: &PedersenElGamalEqProof,
) -> Vec<RistrettoScalar> {
    let identity = RistrettoPoint::get_identity();
    let (elems, lhs_matrix, rhs_vec) =
        init_pok_pedersen_elgamal(transcript, &identity, public_key, ctext, commitment);
    let sigma_proof = SigmaProof {
        commitments: vec![proof.e1.e1, proof.e1.e2, proof.c1],
        responses: vec![proof.z1, proof.z2],
    };
    let mut scalar_vec = sigma_verify_scalars(
        transcript,
        prng,
        &elems,
        &lhs_matrix,
        &rhs_vec,
        &sigma_proof,
    );
    scalar_vec.remove(0);
    scalar_vec
}

// verify a pedersen/elgamal equality proof against ctext and commitment using aggregation
// technique and a single multiexponentiation check.
// assumes transcript already contains ciphertexts and commitments
#[allow(dead_code)]
fn pedersen_elgamal_eq_verify<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    public_key: &ElGamalEncKey<RistrettoPoint>,
    ctext: &ElGamalCiphertext<RistrettoPoint>,
    commitment: &RistrettoPoint,
    proof: &PedersenElGamalEqProof,
) -> Result<()> {
    let pc_gens = PedersenCommitmentRistretto::default();
    let scalars =
        pedersem_elgamal_eq_verify_scalars(transcript, prng, public_key, ctext, commitment, proof);

    let elems = [
        pc_gens.B,
        pc_gens.B_blinding,
        public_key.0,
        ctext.e1,
        ctext.e2,
        *commitment,
        proof.e1.e1,
        proof.e1.e2,
        proof.c1,
    ];
    let multi_exp = curve25519_dalek::ristretto::RistrettoPoint::multiscalar_mul(
        scalars.iter().map(|x| x.0),
        elems.iter().map(|x| x.0),
    );

    if multi_exp != curve25519_dalek::ristretto::RistrettoPoint::identity() {
        Err(eg!(NoahError::ZKProofVerificationError))
    } else {
        Ok(())
    }
}

fn get_linear_combination_scalars(transcript: &mut Transcript, n: usize) -> Vec<RistrettoScalar> {
    if n == 0 {
        return vec![];
    }
    let mut r = vec![RistrettoScalar::one()];
    for _ in 0..n - 1 {
        r.push(transcript.get_challenge::<RistrettoScalar>());
    }
    r
}

/// Proof of knowledge for PedersenElGamal equality proof, for a set of statement.
pub fn pedersen_elgamal_aggregate_eq_proof<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    m: &[RistrettoScalar],
    r: &[RistrettoScalar],
    public_key: &ElGamalEncKey<RistrettoPoint>,
    ctexts: &[ElGamalCiphertext<RistrettoPoint>],
    commitments: &[RistrettoPoint],
) -> PedersenElGamalEqProof {
    let n = m.len();
    assert_eq!(n, m.len());
    assert_eq!(n, r.len());
    assert_eq!(n, ctexts.len());
    assert_eq!(n, commitments.len());

    init_pedersen_elgamal_transcript(transcript, public_key, ctexts, commitments);

    // 1. compute x vector
    let x = get_linear_combination_scalars(transcript, n);
    // 2. compute linear combination
    let mut lc_m = RistrettoScalar::zero();
    let mut lc_r = RistrettoScalar::zero();
    let mut lc_e1 = RistrettoPoint::get_identity();
    let mut lc_e2 = RistrettoPoint::get_identity();
    let mut lc_c = RistrettoPoint::get_identity();
    for (xi, mi, ri, ctext, com) in izip!(
        x.iter(),
        m.iter(),
        r.iter(),
        ctexts.iter(),
        commitments.iter()
    ) {
        lc_m = lc_m.add(&xi.mul(mi));
        lc_r = lc_r.add(&xi.mul(ri));
        lc_e1 = lc_e1.add(&ctext.e1.mul(xi));
        lc_e2 = lc_e2.add(&ctext.e2.mul(xi));
        lc_c = lc_c.add(&com.mul(xi));
    }
    let lc_ctext = ElGamalCiphertext {
        e1: lc_e1,
        e2: lc_e2,
    };
    // 3. call proof
    pedersen_elgamal_eq_prove(transcript, prng, &lc_m, &lc_r, public_key, &lc_ctext, &lc_c)
}

/// A Pedersen-ElGamal equality proof.
pub struct PedersenElGamalProofInstance<'a> {
    /// The ElGamal encryption key.
    pub public_key: &'a ElGamalEncKey<RistrettoPoint>,
    /// The ElGamal ciphertexts.
    pub cts: Vec<ElGamalCiphertext<RistrettoPoint>>,
    /// The Pedersen commitments.
    pub commitments: Vec<RistrettoPoint>,
    /// The equality proof.
    pub proof: &'a PedersenElGamalEqProof,
}

/// Verify a batch of PedersenElGamal aggregate proof instances with a single multiexponentiation
/// of size `2 + n*7` elems. Each instance verification equation is scaled by a random factor.
/// Then, scaled equations are aggregated into a single equation of size 2 + n*7 elements.
pub fn pedersen_elgamal_batch_verify<'a, R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    instances: &[PedersenElGamalProofInstance<'a>],
) -> Result<()> {
    let m = instances.len();
    let pc_gens = PedersenCommitmentRistretto::default();
    // 2 common elems: B, B_blinding
    // 7 elems per instance: public key,
    //                       ctext.e1, ctext.e2, commitment,
    //                       proof.ctext.e1, proof.ctext.e2, proof.commitment
    let mut all_scalars = Vec::with_capacity(2 + m * 7);
    let mut all_elems = Vec::with_capacity(2 + m * 7);
    all_scalars.push(RistrettoScalar::zero());
    all_scalars.push(RistrettoScalar::zero());
    all_elems.push(pc_gens.B);
    all_elems.push(pc_gens.B_blinding);
    for instance in instances {
        let n = instance.cts.len();
        assert_eq!(n, instance.commitments.len());
        let mut inst_transcript = transcript.clone();
        let alpha = RistrettoScalar::random(prng);
        init_pedersen_elgamal_transcript(
            &mut inst_transcript,
            instance.public_key,
            &instance.cts,
            &instance.commitments,
        );
        // 1. compute x vector
        let x = get_linear_combination_scalars(&mut inst_transcript, n);
        // 2. compute linear combination
        let mut lc_e1 = RistrettoPoint::get_identity();
        let mut lc_e2 = RistrettoPoint::get_identity();
        let mut lc_c = RistrettoPoint::get_identity();
        for (xi, ei, ci) in izip!(x.iter(), instance.cts.iter(), instance.commitments.iter()) {
            lc_e1 = lc_e1.add(&ei.e1.mul(xi));
            lc_e2 = lc_e2.add(&ei.e2.mul(xi));
            lc_c = lc_c.add(&ci.mul(xi));
        }
        let lc_e = ElGamalCiphertext {
            e1: lc_e1,
            e2: lc_e2,
        };

        let instance_scalars = pedersem_elgamal_eq_verify_scalars(
            &mut inst_transcript,
            prng,
            instance.public_key,
            &lc_e,
            &lc_c,
            instance.proof,
        );

        all_scalars[0] = all_scalars[0].add(&alpha.mul(&instance_scalars[0]));
        all_scalars[1] = all_scalars[1].add(&alpha.mul(&instance_scalars[1]));
        all_elems.push(instance.public_key.0);
        all_elems.push(lc_e1);
        all_elems.push(lc_e2);
        all_elems.push(lc_c);
        all_elems.push(instance.proof.e1.e1);
        all_elems.push(instance.proof.e1.e2);
        all_elems.push(instance.proof.c1);
        for scalar in instance_scalars[2..].iter() {
            all_scalars.push(alpha.mul(scalar));
        }
    }

    let multi_exp = curve25519_dalek::ristretto::RistrettoPoint::multiscalar_mul(
        all_scalars.iter().map(|x| x.0),
        all_elems.iter().map(|x| x.0),
    );
    if multi_exp != curve25519_dalek::ristretto::RistrettoPoint::identity() {
        return Err(eg!(NoahError::ZKProofBatchVerificationError));
    }

    Ok(())
}
/// Verify Proof of Knowledge for PedersenElGamal equality proof, for a set of statement.
pub fn pedersen_elgamal_aggregate_eq_verify<R: CryptoRng + RngCore>(
    transcript: &mut Transcript,
    prng: &mut R,
    public_key: &ElGamalEncKey<RistrettoPoint>,
    ctexts: &[ElGamalCiphertext<RistrettoPoint>],
    commitments: &[RistrettoPoint],
    proof: &PedersenElGamalEqProof,
) -> Result<()> {
    let instance = PedersenElGamalProofInstance {
        public_key,
        cts: ctexts.to_vec(),
        commitments: commitments.to_vec(),
        proof,
    };

    pedersen_elgamal_batch_verify(transcript, prng, &[instance])
        .c(d!(NoahError::ZKProofVerificationError))
}

#[cfg(test)]
mod test {
    use super::PedersenElGamalEqProof;
    use crate::basic::elgamal::{
        elgamal_encrypt, elgamal_key_gen, ElGamalCiphertext, ElGamalEncKey,
    };
    use crate::basic::pedersen_comm::{PedersenCommitment, PedersenCommitmentRistretto};
    use crate::basic::pedersen_elgamal::{
        pedersen_elgamal_aggregate_eq_proof, pedersen_elgamal_aggregate_eq_verify,
        pedersen_elgamal_batch_verify, PedersenElGamalProofInstance,
    };
    use merlin::Transcript;
    use noah_algebra::prelude::*;
    use noah_algebra::ristretto::{RistrettoPoint, RistrettoScalar};

    #[test]
    fn good_proof_verify() {
        let m = RistrettoScalar::from(10u32);
        let r = RistrettoScalar::from(7657u32);
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();

        let (_sk, pk) = elgamal_key_gen::<_, RistrettoPoint>(&mut prng);

        let ctext = elgamal_encrypt(&m, &r, &pk);
        let commitment = pc_gens.commit(m, r);

        let mut prover_transcript = Transcript::new(b"test");
        let mut verifier_transcript = Transcript::new(b"test");

        let proof = super::pedersen_elgamal_eq_prove(
            &mut prover_transcript,
            &mut prng,
            &m,
            &r,
            &pk,
            &ctext,
            &commitment,
        );
        let verify = super::pedersen_elgamal_eq_verify(
            &mut verifier_transcript,
            &mut prng,
            &pk,
            &ctext,
            &commitment,
            &proof,
        );
        assert_eq!(true, verify.is_ok());
    }

    #[test]
    fn bad_proof_verify() {
        let m = RistrettoScalar::from(10u32);
        let m2 = RistrettoScalar::from(11u32);
        let r = RistrettoScalar::from(7657u32);
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();

        let (_sk, pk) = elgamal_key_gen::<_, RistrettoPoint>(&mut prng);

        let ctext = elgamal_encrypt(&m, &r, &pk);
        let commitment = pc_gens.commit(m2, r);

        let mut prover_transcript = Transcript::new(b"test");
        let mut verifier_transcript = Transcript::new(b"test");
        let proof = super::pedersen_elgamal_eq_prove(
            &mut prover_transcript,
            &mut prng,
            &m,
            &r,
            &pk,
            &ctext,
            &commitment,
        );
        let verify = super::pedersen_elgamal_eq_verify(
            &mut verifier_transcript,
            &mut prng,
            &pk,
            &ctext,
            &commitment,
            &proof,
        );
        assert_eq!(true, verify.is_err());
        msg_eq!(NoahError::ZKProofVerificationError, verify.unwrap_err());
    }

    #[test]
    fn proof_aggregate() {
        let m1 = RistrettoScalar::from(11u32);
        let r1 = RistrettoScalar::from(7657u32);
        let m2 = RistrettoScalar::from(12u32);
        let r2 = RistrettoScalar::from(7658u32);
        let m3 = RistrettoScalar::from(13u32);
        let r3 = RistrettoScalar::from(7659u32);
        let m4 = RistrettoScalar::from(14u32);
        let r4 = RistrettoScalar::from(7660u32);
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();

        let (_sk, pk) = elgamal_key_gen::<_, RistrettoPoint>(&mut prng);

        let ctext1 = elgamal_encrypt(&m1, &r1, &pk);
        let commitment1 = pc_gens.commit(m1, r1);
        let ctext2 = elgamal_encrypt(&m2, &r2, &pk);
        let commitment2 = pc_gens.commit(m2, r2);
        let ctext3 = elgamal_encrypt(&m3, &r3, &pk);
        let commitment3 = pc_gens.commit(m3, r3);
        let ctext4 = elgamal_encrypt(&m4, &r4, &pk);
        let commitment4 = pc_gens.commit(m4, r4);

        let ctexts = [ctext1, ctext2, ctext3, ctext4];
        let commitments = [commitment1, commitment2, commitment3, commitment4];
        let mut prover_transcript = Transcript::new(b"test");
        let mut verifier_transcript = Transcript::new(b"test");

        let proof = pedersen_elgamal_aggregate_eq_proof(
            &mut prover_transcript,
            &mut prng,
            &[m1, m2, m3, m4],
            &[r1, r2, r3, r4],
            &pk,
            &ctexts,
            &commitments,
        );
        let verify = pedersen_elgamal_aggregate_eq_verify(
            &mut verifier_transcript,
            &mut prng,
            &pk,
            &ctexts,
            &commitments,
            &proof,
        );
        pnk!(verify);

        let mut prover_transcript = Transcript::new(b"test");
        let mut verifier_transcript = Transcript::new(b"test");
        let proof = pedersen_elgamal_aggregate_eq_proof(
            &mut prover_transcript,
            &mut prng,
            &[m1],
            &[r1],
            &pk,
            &ctexts[..1],
            &commitments[..1],
        );
        let verify = pedersen_elgamal_aggregate_eq_verify(
            &mut verifier_transcript,
            &mut prng,
            &pk,
            &ctexts[..1],
            &commitments[..1],
            &proof,
        );
        pnk!(verify);

        let mut prover_transcript = Transcript::new(b"test");
        let mut verifier_transcript = Transcript::new(b"test");
        let proof = pedersen_elgamal_aggregate_eq_proof(
            &mut prover_transcript,
            &mut prng,
            &[m2],
            &[r2],
            &pk,
            &ctexts[1..2],
            &commitments[1..2],
        );
        let verify = pedersen_elgamal_aggregate_eq_verify(
            &mut verifier_transcript,
            &mut prng,
            &pk,
            &ctexts[1..2],
            &commitments[1..2],
            &proof,
        );
        pnk!(verify);

        let mut prover_transcript = Transcript::new(b"test");
        let mut verifier_transcript = Transcript::new(b"test");
        let proof = pedersen_elgamal_aggregate_eq_proof(
            &mut prover_transcript,
            &mut prng,
            &[m2, m3],
            &[r2, r3],
            &pk,
            &ctexts[1..3],
            &commitments[1..3],
        );
        let verify = pedersen_elgamal_aggregate_eq_verify(
            &mut verifier_transcript,
            &mut prng,
            &pk,
            &ctexts[1..3],
            &commitments[1..3],
            &proof,
        );
        assert!(verify.is_ok());

        let mut prover_transcript = Transcript::new(b"test");
        let mut verifier_transcript = Transcript::new(b"test");
        let proof = pedersen_elgamal_aggregate_eq_proof(
            &mut prover_transcript,
            &mut prng,
            &[m1, m2, m3, m3],
            &[r1, r2, r3, r4],
            &pk,
            &ctexts,
            &commitments,
        );
        let verify = pedersen_elgamal_aggregate_eq_verify(
            &mut verifier_transcript,
            &mut prng,
            &pk,
            &ctexts,
            &commitments,
            &proof,
        );
        assert!(verify.is_err());
        msg_eq!(
            NoahError::ZKProofBatchVerificationError,
            verify.unwrap_err()
        );

        let mut prover_transcript = Transcript::new(b"test");
        let mut verifier_transcript = Transcript::new(b"test");
        let proof = pedersen_elgamal_aggregate_eq_proof(
            &mut prover_transcript,
            &mut prng,
            &[m1, m2, m3, m4],
            &[r1, r2, r3, r1],
            &pk,
            &ctexts,
            &commitments,
        );
        let verify = pedersen_elgamal_aggregate_eq_verify(
            &mut verifier_transcript,
            &mut prng,
            &pk,
            &ctexts,
            &commitments,
            &proof,
        );
        assert!(verify.is_err());
        msg_eq!(
            NoahError::ZKProofBatchVerificationError,
            verify.unwrap_err()
        );

        let mut prover_transcript = Transcript::new(b"test");
        let mut verifier_transcript = Transcript::new(b"test");
        let proof = pedersen_elgamal_aggregate_eq_proof(
            &mut prover_transcript,
            &mut prng,
            &[m1, m2, m3, m4],
            &[r2, r2, r3, r4],
            &pk,
            &ctexts,
            &commitments,
        );

        let verify = pedersen_elgamal_aggregate_eq_verify(
            &mut verifier_transcript,
            &mut prng,
            &pk,
            &ctexts,
            &commitments,
            &proof,
        );
        assert!(verify.is_err());
        msg_eq!(
            NoahError::ZKProofBatchVerificationError,
            verify.unwrap_err()
        );
    }

    #[test]
    fn batch_aggregate_eq_verify() {
        let mut prover_transcript = Transcript::new(b"test");
        let mut verifier_transcript = Transcript::new(b"test");
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();
        fn get_proof_instance<'a, R: RngCore + CryptoRng>(
            transcript: &mut Transcript,
            prng: &mut R,
            pk: &'a ElGamalEncKey<RistrettoPoint>,
            plaintexts: &[RistrettoScalar],
            rands: &[RistrettoScalar],
            pc_gens: &PedersenCommitmentRistretto,
        ) -> (
            Vec<ElGamalCiphertext<RistrettoPoint>>,
            Vec<RistrettoPoint>,
            PedersenElGamalEqProof,
        ) {
            let ctexts = plaintexts
                .iter()
                .zip(rands.iter())
                .map(|(p, r)| elgamal_encrypt(p, r, pk))
                .collect_vec();
            let commitments = plaintexts
                .iter()
                .zip(rands.iter())
                .map(|(p, r)| pc_gens.commit(*p, *r))
                .collect_vec();
            let proof = pedersen_elgamal_aggregate_eq_proof(
                transcript,
                prng,
                &plaintexts,
                &rands,
                &pk,
                &ctexts,
                &commitments,
            );
            (ctexts, commitments, proof)
        }
        let (_, pk1) = elgamal_key_gen(&mut prng);
        let plaintexts1 = [
            RistrettoScalar::from(1u32),
            RistrettoScalar::from(2u32),
            RistrettoScalar::from(3u32),
        ];
        let rands1 = [
            RistrettoScalar::from(10u32),
            RistrettoScalar::from(20u32),
            RistrettoScalar::from(30u32),
        ];
        let (ctexts1, commitments1, proof1) = get_proof_instance(
            &mut prover_transcript.clone(),
            &mut prng,
            &pk1,
            &plaintexts1,
            &rands1,
            &pc_gens,
        );
        let (_, pk2) = elgamal_key_gen(&mut prng);
        let plaintexts2 = [
            RistrettoScalar::from(100u32),
            RistrettoScalar::from(200u32),
            RistrettoScalar::from(300u32),
        ];
        let rands2 = [
            RistrettoScalar::from(1000u32),
            RistrettoScalar::from(2000u32),
            RistrettoScalar::from(3000u32),
        ];
        let (ctexts2, commitments2, proof2) = get_proof_instance(
            &mut prover_transcript,
            &mut prng,
            &pk2,
            &plaintexts2,
            &rands2,
            &pc_gens,
        );

        let instances = [
            PedersenElGamalProofInstance {
                public_key: &pk1,
                cts: ctexts1,
                commitments: commitments1,
                proof: &proof1,
            },
            PedersenElGamalProofInstance {
                public_key: &pk2,
                cts: ctexts2,
                commitments: commitments2,
                proof: &proof2,
            },
        ];
        assert!(
            pedersen_elgamal_batch_verify(&mut verifier_transcript, &mut prng, &instances).is_ok()
        );
    }
}
