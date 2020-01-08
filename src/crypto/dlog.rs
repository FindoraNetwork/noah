use crate::algebra::groups::{Group, Scalar as ZeiScalar};
use crate::crypto::sigma::SigmaTranscript;
use merlin::Transcript;
//use bulletproofs::PedersenGens;
//use curve25519_dalek::ristretto::RistrettoPoint;
//use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct DlogProof<G, S> {
  pub proof_commitment: G,
  pub response: S,
}

pub fn prove_knowledge_dlog<R: CryptoRng + RngCore, S: ZeiScalar, G: Group<S>>(
  transcript: &mut Transcript,
  prng: &mut R,
  base: &G,
  point: &G,
  dlog: &S)
  -> DlogProof<G, S> {
  /*! I compute a proof for the knowledge of dlog for point with respect to base*/
  transcript.init_sigma(b"PoK Dlog", &[], &[base, point]);
  let u = S::random_scalar(prng);
  let proof_commitment = base.mul(&u);
  transcript.append_proof_commitment(&proof_commitment);
  let challenge = transcript.get_challenge::<S>();
  let response = challenge.mul(dlog).add(&u);

  DlogProof { proof_commitment,
              response }
}

pub fn verify_proof_of_knowledge_dlog<S: ZeiScalar, G: Group<S>>(transcript: &mut Transcript,
                                                                 base: &G,
                                                                 point: &G,
                                                                 proof: &DlogProof<G, S>)
                                                                 -> bool {
  /*! I verify a proof of knowledge of dlog for point with respect to base*/
  transcript.init_sigma(b"PoK Dlog", &[], &[base, point]);
  transcript.append_proof_commitment(&proof.proof_commitment);
  let challenge = transcript.get_challenge::<S>();
  base.mul(&proof.response) == point.mul(&challenge).add(&proof.proof_commitment)
}

pub fn prove_multiple_knowledge_dlog<R: CryptoRng + RngCore, S: ZeiScalar, G: Group<S>>(
  transcript: &mut Transcript,
  prng: &mut R,
  base: &G,
  points: &[G],
  dlogs: &[S])
  -> DlogProof<G, S> {
  /*! I compute a proof for the knowledge of dlogs for points for the base*/
  let mut public_elems = vec![base];
  let mut ref_points: Vec<&G> = points.iter().map(|x| x).collect();
  public_elems.append(&mut ref_points);
  transcript.init_sigma(b"PoK Dlog Multiple", &[], public_elems.as_slice());

  let u = S::random_scalar(prng);
  let proof_commitment = base.mul(&u);
  transcript.append_proof_commitment(&proof_commitment);
  //context.extend_from_slice(points.iter());
  //let challenge = compute_challenge_ref::<S, G>(context.as_slice());
  let mut response = u;
  for item in dlogs.iter() {
    let challenge_i = transcript.get_challenge::<S>();
    response = response.add(&challenge_i.mul(item));
  }

  DlogProof { proof_commitment,
              response }
}

pub fn verify_multiple_knowledge_dlog<S: ZeiScalar, G: Group<S>>(transcript: &mut Transcript,
                                                                 base: &G,
                                                                 points: &[G],
                                                                 proof: &DlogProof<G, S>)
                                                                 -> bool {
  /*! I verify a proof of knowledge of dlogs for points in the base*/
  let mut pub_elems = vec![base];
  for point in points {
    pub_elems.push(point);
  }
  transcript.init_sigma(b"PoK Dlog Multiple", &[], pub_elems.as_slice());
  transcript.append_proof_commitment(&proof.proof_commitment);
  let mut check = proof.proof_commitment.clone();
  for point in points {
    let challenge_i = transcript.get_challenge::<S>();
    check = check.add(&point.mul(&challenge_i));
  }

  check == base.mul(&proof.response)
}

#[cfg(test)]
mod test {
  //use bulletproofs::PedersenGens;
  use super::{prove_knowledge_dlog, verify_proof_of_knowledge_dlog};
  use curve25519_dalek::ristretto::RistrettoPoint;
  use curve25519_dalek::scalar::Scalar;
  //use bulletproofs::PedersenGens;
  use crate::crypto::dlog::{prove_multiple_knowledge_dlog, verify_multiple_knowledge_dlog};
  use merlin::Transcript;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn test_pok_dlog() {
    let mut csprng: ChaChaRng;
    csprng = ChaChaRng::from_seed([0u8; 32]);

    let mut prover_transcript = Transcript::new(b"test");
    let mut verifier_transcript = Transcript::new(b"test");
    let base = RistrettoPoint::random(&mut csprng);
    let scalar = Scalar::random(&mut csprng);
    let scalar2 = scalar + Scalar::from(1u8);
    let point = scalar * base;

    let proof = prove_knowledge_dlog(&mut prover_transcript, &mut csprng, &base, &point, &scalar);
    assert_eq!(true,
               verify_proof_of_knowledge_dlog(&mut verifier_transcript, &base, &point, &proof));

    let proof = prove_knowledge_dlog(&mut prover_transcript, &mut csprng, &base, &point, &scalar2);
    assert_eq!(false,
               verify_proof_of_knowledge_dlog(&mut verifier_transcript, &base, &point, &proof))
  }

  #[test]
  fn test_multiple_pok_dlog() {
    let mut csprng: ChaChaRng;
    csprng = ChaChaRng::from_seed([0u8; 32]);

    let mut prover_transcript = Transcript::new(b"test");
    let mut verifier_transcript = Transcript::new(b"test");

    let base = RistrettoPoint::random(&mut csprng);
    let scalar1 = Scalar::random(&mut csprng);
    let scalar2 = Scalar::random(&mut csprng);
    let scalar3 = Scalar::random(&mut csprng);
    let scalar4 = Scalar::random(&mut csprng);
    let scalar5 = Scalar::random(&mut csprng);
    let scalar6 = Scalar::random(&mut csprng);
    let scalar7 = Scalar::random(&mut csprng);

    let point1 = scalar1 * base;
    let point2 = scalar2 * base;
    let point3 = scalar3 * base;
    let point4 = scalar4 * base;
    let point5 = scalar5 * base;
    let point6 = scalar6 * base;
    let point7 = scalar7 * base;

    let proof = prove_multiple_knowledge_dlog(&mut prover_transcript,
                                              &mut csprng,
                                              &base,
                                              &[point1, point2, point3, point4, point5, point6,
                                                point7],
                                              &[scalar1, scalar2, scalar3, scalar4, scalar5,
                                                scalar6, scalar7]);

    assert_eq!(true,
               verify_multiple_knowledge_dlog(&mut verifier_transcript,
                                              &base,
                                              &[point1, point2, point3, point4, point5, point6,
                                                point7],
                                              &proof));
  }
}
