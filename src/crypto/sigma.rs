use crate::algebra::groups::{Group, Scalar};
use crate::errors::ZeiError;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

pub trait SigmaTranscript {
  fn init_sigma<S: Scalar, G: Group<S>>(&mut self,
                                        instance_name: &'static [u8],
                                        public_scalars: &[&S],
                                        public_elems: &[&G]);
  fn append_proof_commitment<S: Scalar, G: Group<S>>(&mut self, elem: &G);
  fn get_challenge<S: Scalar>(&mut self) -> S;
}

impl SigmaTranscript for Transcript {
  fn init_sigma<S: Scalar, G: Group<S>>(&mut self,
                                        instance_name: &'static [u8],
                                        public_scalars: &[&S],
                                        public_elems: &[&G]) {
    self.append_message(b"Sigma Protocol domain",
                        b"Sigma protocol single group v.0.1");
    self.append_message(b"Sigma Protocol instance", instance_name);
    for scalar in public_scalars {
      self.append_message(b"public scalar", scalar.to_bytes().as_slice())
    }
    for elem in public_elems {
      self.append_message(b"public elem", elem.to_compressed_bytes().as_slice())
    }
  }
  fn append_proof_commitment<S: Scalar, G: Group<S>>(&mut self, elem: &G) {
    self.append_message(b"proof_commitment", elem.to_compressed_bytes().as_slice());
  }
  fn get_challenge<S: Scalar>(&mut self) -> S {
    let mut buffer = vec![0u8; 32]; // TODO(fernando) get number of bytes needed from S and remove the number 32
    self.challenge_bytes(b"Sigma challenge", &mut buffer);
    S::from_bytes(buffer.as_slice())
  }
}

fn init_sigma_protocol<S: Scalar, G: Group<S>>(transcript: &mut Transcript, elems: &[&G]) {
  transcript.init_sigma(b"New Sigma Protocol", &[], elems);
}

fn sample_blindings<R: CryptoRng + RngCore, S: Scalar>(prng: &mut R, n: usize) -> Vec<S> {
  let mut r = vec![];
  for _ in 0..n {
    r.push(S::random_scalar(prng));
  }
  r
}

fn compute_proof_commitments<S: Scalar, G: Group<S>>(transcript: &mut Transcript,
                                                     blindings: &[S],
                                                     lhs_matrix: &[&[&G]])
                                                     -> Vec<G> {
  let mut pf_commitments = vec![];

  for row in lhs_matrix.iter() {
    let mut pf_commitment = G::get_identity();
    assert_eq!(row.len(), blindings.len());
    for (elem, blind) in (*row).iter().zip(blindings) {
      pf_commitment = pf_commitment.add(&elem.mul(blind));
    }
    transcript.append_proof_commitment(&pf_commitment);
    pf_commitments.push(pf_commitment);
  }
  pf_commitments
}

pub struct SigmaProof<S, G> {
  pub(crate) commitments: Vec<G>,
  pub(crate) responses: Vec<S>,
}

/// Simple Sigma protocol PoK for the statement `lhs_matrix` * `secrets_scalars` = `rhs_vec`
/// Elements in `lhs_matrix` and `rhs_vec` must be in `elems` slice
pub fn sigma_prove<R: CryptoRng + RngCore, S: Scalar, G: Group<S>>(transcript: &mut Transcript,
                                                                   prng: &mut R,
                                                                   elems: &[&G], // public elements of the proofs
                                                                   lhs_matrix: &[&[&G]], // each row defines a lhs of a constraint
                                                                   secret_scalars: &[&S])
                                                                   -> SigmaProof<S, G> {
  init_sigma_protocol::<S, G>(transcript, elems);
  let blindings = sample_blindings::<_, S>(prng, secret_scalars.len());
  let proof_commitments =
    compute_proof_commitments::<S, G>(transcript, blindings.as_slice(), lhs_matrix);

  let challenge = transcript.get_challenge::<S>();

  let mut responses = vec![];

  for (secret, blind) in secret_scalars.iter().zip(blindings.iter()) {
    responses.push(secret.mul(&challenge).add(blind))
  }
  SigmaProof { commitments: proof_commitments,
               responses }
}

#[allow(non_snake_case)]
fn collect_multi_exp_scalars<R: CryptoRng + RngCore, S: Scalar, G: Group<S>>(prng: &mut R,
                                                                             elems: &[&G], // all public group elements
                                                                             matrix: &[&[&G]], // matrix defining LHS of constrains
                                                                             rhs: &[&G], // RHS of constrant
                                                                             responses: &[S], // proof challenge responses
                                                                             challenge: &S // challenge
) -> Vec<S> {
  // verifier needs to check that matrix * responses = challenge * rhs + proof_commitment
  // rows are merges using a random linear combination
  // this functions collects the scalars factors for each element in order to apply a single
  // multiexponentiation to verify all equations
  let n = elems.len();
  let mut s = vec![S::from_u32(0); n + rhs.len()]; // n elements + m proof commitments
  let mut alphas = vec![]; // linear combination scalars
                           // find in the matrix each element and multiply corresponding response by alpha
  for (j, row) in matrix.iter().enumerate() {
    let alpha = S::random_scalar(prng);
    for (i, E) in elems.iter().enumerate() {
      for (M, r) in row.iter().zip(responses) {
        if E == M {
          s[i] = s[i].add(&alpha.mul(r))
        }
      }
    }
    s[n + j] = s[n + j].sub(&alpha);
    alphas.push(alpha);
  }
  for (R, alpha) in rhs.iter().zip(alphas.iter()) {
    for (i, E) in elems.iter().enumerate() {
      if E == R {
        s[i] = s[i].sub(&alpha.mul(challenge));
      }
    }
  }
  s
}

/// Simple Sigma protocol PoK verification for the statement `lhs_matrix` * `secrets_scalars` = `rhs_vec`
/// Elements in `lhs_matrix` and `rhs_vec` must be in `elems` slice
pub fn sigma_verify<R: CryptoRng + RngCore, S: Scalar, G: Group<S>>(transcript: &mut Transcript,
                                                                    prng: &mut R, //use of for linear combination multiexp
                                                                    elems: &[&G],
                                                                    lhs_matrix: &[&[&G]],
                                                                    rhs_vec: &[&G],
                                                                    proof: &SigmaProof<S, G>)
                                                                    -> Result<(), ZeiError> {
  assert_eq!(lhs_matrix.len(), rhs_vec.len());
  assert_eq!(rhs_vec.len(), proof.commitments.len());

  init_sigma_protocol::<S, G>(transcript, elems);
  for c in proof.commitments.iter() {
    transcript.append_proof_commitment(c);
  }
  let challenge = transcript.get_challenge::<S>();
  let me_scalars = collect_multi_exp_scalars(prng,
                                             elems,
                                             lhs_matrix,
                                             rhs_vec,
                                             &proof.responses,
                                             &challenge);
  let mut me_elems = vec![];
  for e in elems {
    me_elems.push((*e).clone());
  }
  for e in proof.commitments.iter() {
    me_elems.push(e.clone());
  }
  let result = G::vartime_multi_exp(me_scalars.as_slice(), me_elems.as_slice());
  match result != G::get_identity() {
    true => Err(ZeiError::ZKProofVerificationError),
    false => Ok(()),
  }
}

#[cfg(test)]
mod tests {
  use crate::algebra::groups::Group;
  use curve25519_dalek::ristretto::RistrettoPoint;
  use curve25519_dalek::scalar::Scalar;
  use curve25519_dalek::traits::Identity;
  use merlin::Transcript;
  use rand_core::SeedableRng;

  #[test]
  #[allow(non_snake_case)]
  fn test_sigma() {
    let G = RistrettoPoint::get_base();
    let secret = Scalar::from(10u8);
    let H = G * secret;

    let mut prover_transcript = Transcript::new(b"Test");
    let mut verifier_transcript = Transcript::new(b"Test");
    let mut prng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);

    //test 1 simple dlog
    let matrix: &[&[&RistrettoPoint]] = &[&[&G]];
    let dlog_proof = super::sigma_prove(&mut prover_transcript,
                                        &mut prng,
                                        &[&G, &H],
                                        matrix,
                                        &[&secret]);
    assert!(super::sigma_verify(&mut verifier_transcript,
                                &mut prng,
                                &[&G, &H],
                                matrix,
                                &[&H],
                                &dlog_proof).is_ok());

    let bad_matrix: &[&[&RistrettoPoint]] = &[&[&H]];
    let dlog_proof = super::sigma_prove(&mut prover_transcript,
                                        &mut prng,
                                        &[&G, &H],
                                        bad_matrix,
                                        &[&secret]);
    assert!(super::sigma_verify(&mut verifier_transcript,
                                &mut prng,
                                &[&G, &H],
                                bad_matrix,
                                &[&H],
                                &dlog_proof).is_err());

    // test2: two contrains, two secrets
    let secret2 = Scalar::from(20u8);
    let H2 = G * secret2;
    let zero = RistrettoPoint::identity();
    let matrix: &[&[&RistrettoPoint]] = &[&[&G, &zero], &[&zero, &G]];
    let dlog_proof = super::sigma_prove(&mut prover_transcript,
                                        &mut prng,
                                        &[&G, &H, &H2],
                                        matrix,
                                        &[&secret, &secret2]);
    assert!(super::sigma_verify(&mut verifier_transcript,
                                &mut prng,
                                &[&G, &H, &H2],
                                matrix,
                                &[&H, &H2],
                                &dlog_proof).is_ok());

    let matrix: &[&[&RistrettoPoint]] = &[&[&G, &G], &[&zero, &G]]; // bad row 1
    let dlog_proof = super::sigma_prove(&mut prover_transcript,
                                        &mut prng,
                                        &[&G, &H, &H2],
                                        matrix,
                                        &[&secret, &secret2]);
    assert!(super::sigma_verify(&mut verifier_transcript,
                                &mut prng,
                                &[&G, &H, &H2],
                                matrix,
                                &[&H, &H2],
                                &dlog_proof).is_err());

    let matrix: &[&[&RistrettoPoint]] = &[&[&G, &zero], &[&zero, &zero]]; // bad row 2
    let dlog_proof = super::sigma_prove(&mut prover_transcript,
                                        &mut prng,
                                        &[&G, &H, &H2],
                                        matrix,
                                        &[&secret, &secret2]);
    assert!(super::sigma_verify(&mut verifier_transcript,
                                &mut prng,
                                &[&G, &H, &H2],
                                matrix,
                                &[&H, &H2],
                                &dlog_proof).is_err());

    // test3: two constarains, 5 secrets
    let secret3 = Scalar::from(30u8);
    let secret4 = Scalar::from(40u8);
    let secret5 = Scalar::from(50u8);
    let Z1 = G * secret + H * secret2;
    let Z2 = G * secret3 + H * secret4 + H2 * secret5;

    let matrix: &[&[&RistrettoPoint]] =
      &[&[&G, &H, &zero, &zero, &zero], &[&zero, &zero, &G, &H, &H2]];
    let secrets: &[&Scalar] = &[&secret, &secret2, &secret3, &secret4, &secret5];
    let dlog_proof = super::sigma_prove(&mut prover_transcript,
                                        &mut prng,
                                        &[&G, &H, &H2, &Z1, &Z2],
                                        matrix,
                                        secrets);
    assert!(super::sigma_verify(&mut verifier_transcript,
                                &mut prng,
                                &[&G, &H, &H2, &Z1, &Z2],
                                matrix,
                                &[&Z1, &Z2],
                                &dlog_proof).is_ok());

    let secrets: &[&Scalar] = &[&secret, &secret2, &secret3, &secret4, &Scalar::zero()]; // bad secrets
    let dlog_proof = super::sigma_prove(&mut prover_transcript,
                                        &mut prng,
                                        &[&G, &H, &H2, &Z1, &Z2],
                                        matrix,
                                        secrets);
    assert!(super::sigma_verify(&mut verifier_transcript,
                                &mut prng,
                                &[&G, &H, &H2, &Z1, &Z2],
                                matrix,
                                &[&Z1, &Z2],
                                &dlog_proof).is_err());
  }
}
