use crate::algebra::groups::Group;
use crate::crypto::sigma::{sigma_prove, sigma_verify, SigmaProof, SigmaTranscript};
use crate::errors::ZeiError;
use crate::errors::ZeiError::ZKProofVerificationError;
use crate::serialization;
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct ChaumPedersenProof {
  /// A Chaum-Perdersen equality of commitment proof
  #[serde(with = "serialization::zei_obj_serde")]
  pub(crate) c3: RistrettoPoint,
  #[serde(with = "serialization::zei_obj_serde")]
  pub(crate) c4: RistrettoPoint,
  #[serde(with = "serialization::zei_obj_serde")]
  pub(crate) z1: Scalar,
  #[serde(with = "serialization::zei_obj_serde")]
  pub(crate) z2: Scalar,
  #[serde(with = "serialization::zei_obj_serde")]
  pub(crate) z3: Scalar,
}

/// A Chaum-Perdersen equality of multiple commitments proof
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct ChaumPedersenProofX {
  pub(crate) c1_eq_c2: ChaumPedersenProof,
  pub(crate) zero: Option<ChaumPedersenProof>,
}

fn init_chaum_pedersen_multiple(transcript: &mut Transcript,
                                pc_gens: &PedersenGens,
                                commitments: &[RistrettoPoint]) {
  let mut public_elems = vec![&pc_gens.B, &pc_gens.B_blinding];
  for c in commitments.iter() {
    public_elems.push(c);
  }
  transcript.init_sigma(b"ChaumPedersenMultiple", &[], public_elems.as_slice())
}

fn init_chaum_pedersen<'a>(transcript: &mut Transcript,
                           identity: &'a RistrettoPoint,
                           pc_gens: &'a PedersenGens,
                           c1: &'a RistrettoPoint,
                           c2: &'a RistrettoPoint)
                           -> (Vec<&'a RistrettoPoint>, Vec<Vec<usize>>, Vec<usize>) {
  transcript.append_message(b"new_domain", b"Chaum Pedersen");
  let elems = vec![identity, &pc_gens.B, &pc_gens.B_blinding, c1, c2];
  let lhs_matrix = vec![vec![1, 2, 0], vec![1, 0, 2]];
  let rhs_vec = vec![3, 4];
  (elems, lhs_matrix, rhs_vec)
}

/// Computes a Chaum-Pedersen proof of knowledge of openings of two commitments to the same value
pub fn chaum_pedersen_prove_eq<R: CryptoRng + RngCore>(transcript: &mut Transcript,
                                                       prng: &mut R,
                                                       pc_gens: &PedersenGens,
                                                       value: &Scalar,
                                                       c1: &RistrettoPoint,
                                                       c2: &RistrettoPoint,
                                                       blinding_factor1: &Scalar,
                                                       blinding_factor2: &Scalar)
                                                       -> ChaumPedersenProof {
  let identity = RistrettoPoint::get_identity();
  let (elems, lhs_matrix, _) = init_chaum_pedersen(transcript, &identity, pc_gens, c1, c2);
  let secrets = [value, blinding_factor1, blinding_factor2];
  let proof = sigma_prove(transcript,
                          prng,
                          elems.as_slice(),
                          lhs_matrix.as_slice(),
                          &secrets[..]);

  ChaumPedersenProof { c3: proof.commitments[0],
                       c4: proof.commitments[1],
                       z1: proof.responses[0],
                       z2: proof.responses[1],
                       z3: proof.responses[2] }
}

/// Verify a Chaum-Pedersen equality proof. Return Ok() in case of success,
/// Err(ZeiError::ZKVerificationError) in case of verification failure, and
/// Err(Error::DecompressElementError) in case some CompressedRistretto can not be decompressed.
/// Use aggregation technique and a single multi-exponentiation check
pub fn chaum_pedersen_verify_eq<R: CryptoRng + RngCore>(transcript: &mut Transcript,
                                                        prng: &mut R,
                                                        pc_gens: &PedersenGens,
                                                        c1: &RistrettoPoint,
                                                        c2: &RistrettoPoint,
                                                        proof: &ChaumPedersenProof)
                                                        -> Result<(), ZeiError> {
  let identity = RistrettoPoint::get_identity();
  let (elems, lhs_matrix, rhs_vec) = init_chaum_pedersen(transcript, &identity, pc_gens, c1, c2);

  let sigma_proof = SigmaProof { commitments: vec![proof.c3, proof.c4],
                                 responses: vec![proof.z1, proof.z2, proof.z3] };

  sigma_verify::<_, Scalar, RistrettoPoint>(transcript,
                                            prng,
                                            elems.as_slice(),
                                            lhs_matrix.as_slice(),
                                            rhs_vec.as_slice(),
                                            &sigma_proof)
}

// Helper functions for the proof of multiple commitments equality below

// Obtain a fake compressed commitment to zero, eg The identity
fn get_fake_zero_commitment() -> RistrettoPoint {
  RistrettoPoint::identity()
}

// Obtain the blinding used in the get_fake_zero_commitment
fn get_fake_zero_commitment_blinding() -> Scalar {
  Scalar::zero()
}

fn get_lc_scalars(transcript: &mut Transcript, n: usize) -> Vec<Scalar> {
  if n == 0 {
    return vec![];
  }
  let mut r = vec![Scalar::one()];
  for _ in 1..n {
    r.push(transcript.get_challenge::<Scalar>());
  }
  r
}

// Compute a proof of knowledge of openings of a set of commitments to the same value.
pub fn chaum_pedersen_prove_multiple_eq<R: CryptoRng + RngCore>(
  transcript: &mut Transcript,
  prng: &mut R,
  pc_gens: &PedersenGens,
  value: &Scalar,
  commitments: &[RistrettoPoint],
  blinding_factors: &[Scalar])
  -> Result<ChaumPedersenProofX, ZeiError> {
  let n = commitments.len();
  if n != blinding_factors.len() || n < 2 {
    return Err(ZeiError::ParameterError);
  }

  init_chaum_pedersen_multiple(transcript, pc_gens, commitments);
  let proof_c0_c1 = chaum_pedersen_prove_eq(transcript,
                                            prng,
                                            pc_gens,
                                            value,
                                            &commitments[0],
                                            &commitments[1],
                                            &blinding_factors[0],
                                            &blinding_factors[1]);

  if commitments.len() == 2 {
    return Ok(ChaumPedersenProofX { c1_eq_c2: proof_c0_c1,
                                    zero: None });
  }
  let lc_scalars = get_lc_scalars(transcript, commitments.len() - 2);
  let mut d = RistrettoPoint::identity();
  let mut z = Scalar::from(0u8);
  let c0 = &commitments[0];
  let r0 = &blinding_factors[0];
  for (ai, ri, ci) in izip!(lc_scalars.iter(),
                            blinding_factors.iter().skip(2),
                            commitments.iter().skip(2))
  {
    let di = ai * (c0 - ci);
    let zi = ai * (*r0 - *ri);
    d += di;
    z += zi;
  }

  //TODO can we produce proof to zero commitment in a more direct way?
  // it seems a simple Dlog proof should be enough
  //produce fake commitment to 0 for chaum pedersen commitment
  let proof_zero = chaum_pedersen_prove_eq(transcript,
                                           prng,
                                           pc_gens,
                                           &Scalar::from(0u8),
                                           &d,
                                           &get_fake_zero_commitment(),
                                           &z,
                                           &get_fake_zero_commitment_blinding());
  Ok(ChaumPedersenProofX { c1_eq_c2: proof_c0_c1,
                           zero: Some(proof_zero) })
}

/// Verify a proof that all commitments are to the same value.
///  * Return Ok() in case of success, Err(ZeiError:ZKVerificationError) in case of verification failure,
///  * and Err(Error::DecompressElementError) in case some CompressedRistretto can not be decompressed
pub fn chaum_pedersen_verify_multiple_eq<R: CryptoRng + RngCore>(transcript: &mut Transcript,
                                                                 prng: &mut R,
                                                                 pc_gens: &PedersenGens,
                                                                 commitments: &[RistrettoPoint],
                                                                 proof: &ChaumPedersenProofX)
                                                                 -> Result<(), ZeiError> {
  if commitments.len() < 2 {
    return Err(ZeiError::ParameterError);
  }

  init_chaum_pedersen_multiple(transcript, pc_gens, commitments);
  chaum_pedersen_verify_eq(transcript,
                           prng,
                           pc_gens,
                           &commitments[0],
                           &commitments[1],
                           &proof.c1_eq_c2)?;

  if commitments.len() == 2 {
    return match proof.zero {
      //check proof structure is consistent
      None => Ok(()),
      Some(_) => Err(ZKProofVerificationError),
    };
  }

  if proof.zero.is_none() {
    return Err(ZKProofVerificationError);
  }

  let lc_scalars = get_lc_scalars(transcript, commitments.len() - 2);
  let mut d = RistrettoPoint::identity();
  let c0 = commitments[0];
  for (ai, ci) in lc_scalars.iter().zip(commitments.iter().skip(2)) {
    let di = ai * (c0 - ci);
    d += di;
  }

  chaum_pedersen_verify_eq(transcript,
                           prng,
                           pc_gens,
                           &d,
                           &get_fake_zero_commitment(),
                           proof.zero.as_ref().unwrap())
}

#[cfg(test)]
mod test {
  use super::*;
  use bulletproofs::PedersenGens;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  pub fn test_chaum_pedersen_equality_commitment() {
    let mut csprng: ChaChaRng;
    csprng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();
    let value1 = Scalar::from(16u8);
    let value2 = Scalar::from(32u8);
    let bf1 = Scalar::from(10u8);
    let bf2 = Scalar::from(100u8);
    let pedersen_bases = PedersenGens::default();
    let c1 = pedersen_bases.commit(value1, bf1);
    let c2 = pedersen_bases.commit(value2, bf2);

    let mut prover_transcript = Transcript::new(b"test");

    let proof = chaum_pedersen_prove_eq(&mut prover_transcript,
                                        &mut csprng,
                                        &pc_gens,
                                        &value1,
                                        &c1,
                                        &c2,
                                        &bf1,
                                        &bf2);

    let mut verifier_transcript = Transcript::new(b"test");
    assert_eq!(Err(ZeiError::ZKProofVerificationError),
               chaum_pedersen_verify_eq(&mut verifier_transcript,
                                        &mut csprng,
                                        &pc_gens,
                                        &c1,
                                        &c2,
                                        &proof));

    let mut prover_transcript = Transcript::new(b"test");
    let proof = chaum_pedersen_prove_eq(&mut prover_transcript,
                                        &mut csprng,
                                        &pc_gens,
                                        &value2,
                                        &c1,
                                        &c2,
                                        &bf1,
                                        &bf2);
    let mut verifier_transcript = Transcript::new(b"test");
    assert_eq!(Err(ZeiError::ZKProofVerificationError),
               chaum_pedersen_verify_eq(&mut verifier_transcript,
                                        &mut csprng,
                                        &pc_gens,
                                        &c1,
                                        &c2,
                                        &proof));

    let mut prover_transcript = Transcript::new(b"test");
    let c3 = pedersen_bases.commit(value1, bf2);
    let proof = chaum_pedersen_prove_eq(&mut prover_transcript,
                                        &mut csprng,
                                        &pc_gens,
                                        &value1,
                                        &c1,
                                        &c3,
                                        &bf1,
                                        &bf2);
    let mut verifier_transcript = Transcript::new(b"test");
    assert!(chaum_pedersen_verify_eq(&mut verifier_transcript,
                                     &mut csprng,
                                     &pc_gens,
                                     &c1,
                                     &c3,
                                     &proof).is_ok());
  }

  #[test]
  fn test_chaum_pedersen_multiple_eq_proof() {
    let mut csprng: ChaChaRng;
    csprng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();
    let value1 = Scalar::from(16u8);
    let value2 = Scalar::from(32u8);
    let bf1 = Scalar::from(10u8);
    let bf2 = Scalar::from(100u8);
    let bf3 = Scalar::from(1000u32);
    let pedersen_bases = PedersenGens::default();
    let c1 = pedersen_bases.commit(value1, bf1);
    let c2 = pedersen_bases.commit(value2, bf2);
    let c3 = pedersen_bases.commit(value1, bf3);

    let com_vec = &[c1, c2, c3];
    let blind_vec = vec![bf1, bf2, bf3];
    let mut prover_transcript = Transcript::new(b"Test");
    let proof = chaum_pedersen_prove_multiple_eq(&mut prover_transcript,
                                                 &mut csprng,
                                                 &pc_gens,
                                                 &value1,
                                                 com_vec,
                                                 &blind_vec).unwrap();

    let mut verifier_transcript = Transcript::new(b"Test");
    assert_eq!(Err(ZeiError::ZKProofVerificationError),
               chaum_pedersen_verify_multiple_eq(&mut verifier_transcript,
                                                 &mut csprng,
                                                 &pc_gens,
                                                 com_vec,
                                                 &proof));

    let c1 = pedersen_bases.commit(value1, bf1);
    let c2 = pedersen_bases.commit(value1, bf2);
    let c3 = pedersen_bases.commit(value1, bf3);

    let com_vec = &[c1, c2, c3];
    let blind_vec = vec![bf1, bf2, bf3];

    let mut prover_transcript = Transcript::new(b"Test");
    let proof = chaum_pedersen_prove_multiple_eq(&mut prover_transcript,
                                                 &mut csprng,
                                                 &pc_gens,
                                                 &value1,
                                                 com_vec,
                                                 &blind_vec).unwrap();
    let mut verifier_transcript = Transcript::new(b"Test");
    assert!(chaum_pedersen_verify_multiple_eq(&mut verifier_transcript,
                                              &mut csprng,
                                              &pc_gens,
                                              com_vec,
                                              &proof).is_ok());
  }

  #[test]
  fn test_chaum_pedersen_multiple_eq_proof_using_two() {
    let mut csprng: ChaChaRng;
    csprng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();
    let value1 = Scalar::from(16u8);
    let value2 = Scalar::from(32u8);
    let bf1 = Scalar::from(10u8);
    let bf2 = Scalar::from(100u8);
    let pedersen_bases = PedersenGens::default();
    let c1 = pedersen_bases.commit(value1, bf1);
    let c2 = pedersen_bases.commit(value2, bf2);

    let com_vec = &[c1, c2];
    let blind_vec = vec![bf1, bf2];

    let mut prover_transcript = Transcript::new(b"Test");
    let proof = chaum_pedersen_prove_multiple_eq(&mut prover_transcript,
                                                 &mut csprng,
                                                 &pc_gens,
                                                 &value1,
                                                 com_vec,
                                                 &blind_vec).unwrap();

    let mut verifier_transcript = Transcript::new(b"Test");
    assert_eq!(Err(ZeiError::ZKProofVerificationError),
               chaum_pedersen_verify_multiple_eq(&mut verifier_transcript,
                                                 &mut csprng,
                                                 &pc_gens,
                                                 com_vec,
                                                 &proof),
               "Values were different");

    let c1 = pedersen_bases.commit(value1, bf1);
    let c2 = pedersen_bases.commit(value1, bf2);

    let com_vec = &[c1, c2];
    let blind_vec = vec![bf1, bf2];

    let mut prover_transcript = Transcript::new(b"Test");
    let proof = chaum_pedersen_prove_multiple_eq(&mut prover_transcript,
                                                 &mut csprng,
                                                 &pc_gens,
                                                 &value1,
                                                 com_vec,
                                                 &blind_vec).unwrap();
    let mut verifier_transcript = Transcript::new(b"Test");
    assert!(chaum_pedersen_verify_multiple_eq(&mut verifier_transcript,
                                              &mut csprng,
                                              &pc_gens,
                                              com_vec,
                                              &proof).is_ok(),
            "Values are the same");
  }
}
