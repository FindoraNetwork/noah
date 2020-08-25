use crate::crypto::sigma::SigmaTranscript;
use crate::errors::ZeiError;
use algebra::groups::{Group, GroupArithmetic, Scalar};
use algebra::pairing::Pairing;
use merlin::Transcript;

/// The purpose of the code below is to implement the inner product pairing proof system
/// described in https://eprint.iacr.org/2019/1177.pdf

#[allow(dead_code)]
pub struct OPProof<P: Pairing> {
  elems: Vec<(P::Gt, P::Gt)>,
}

pub trait InnerPairingProductTranscript: SigmaTranscript {
  #[allow(non_snake_case)]
  fn init_inner_pairing_product<P: Pairing>(&mut self, A: &[P::G1], B: &[P::G2], Z: &P::Gt);
  fn append_round_commitments<P: Pairing>(&mut self,
                                          left_commitment: &P::Gt,
                                          right_commitment: &P::Gt);
}

impl InnerPairingProductTranscript for Transcript {
  #[allow(non_snake_case)]
  fn init_inner_pairing_product<P: Pairing>(&mut self, A: &[P::G1], B: &[P::G2], Z: &P::Gt) {
    self.append_message(b"New Domain", b"Inner Product Pairing argument");
    let n = A.len();
    self.append_u64(b"Number of pairs", n as u64);
    for (a, b) in A.iter().zip(B.iter()) {
      self.append_message(b"G1 input value", a.to_compressed_bytes().as_slice());
      self.append_message(b"G2 input value", b.to_compressed_bytes().as_slice());
    }
    self.append_message(b"Pairing value", Z.to_compressed_bytes().as_slice());
  }
  fn append_round_commitments<P: Pairing>(&mut self,
                                          left_commitment: &P::Gt,
                                          right_commitment: &P::Gt) {
    self.append_message(b"proof_commitment left",
                        left_commitment.to_compressed_bytes().as_slice());
    self.append_message(b"proof_commitment right",
                        right_commitment.to_compressed_bytes().as_slice());
  }
}
#[allow(non_snake_case)]
#[allow(dead_code)]
pub fn outsource_pairings_prover<P: Pairing>(A: &[P::G1],
                                             B: &[P::G2],
                                             C: &[P::G1],
                                             D: &[P::G2])
                                             -> Result<OPProof<P>, ZeiError> {
  let m = A.len();

  if !(m == B.len() && m == C.len() && m == D.len()) {
    Err(ZeiError::ParameterError)
  } else {
    let (new_A, new_B) = to_inner_product::<P>(A, B, C, D);
    outsource_inner_pairing_product_prover::<P>(&new_A[..], &new_B[..], &P::Gt::get_identity())
  }
}

#[allow(non_snake_case)]
#[allow(dead_code)]
pub fn outsource_pairings_verifier<P: Pairing>(A: &[P::G1],
                                               B: &[P::G2],
                                               C: &[P::G1],
                                               D: &[P::G2],
                                               proof: &OPProof<P>)
                                               -> Result<(), ZeiError> {
  let m = A.len();

  if m != B.len() || m != C.len() || m != D.len() {
    Err(ZeiError::ParameterError)
  } else {
    let (new_A, new_B) = to_inner_product::<P>(A, B, C, D);
    outsource_inner_pairing_product_verifier::<P>(&new_A[..],
                                                  &new_B[..],
                                                  &P::Gt::get_identity(),
                                                  proof)
  }
}

#[allow(non_snake_case)]
fn to_inner_product<P: Pairing>(A: &[P::G1],
                                B: &[P::G2],
                                C: &[P::G1],
                                D: &[P::G2])
                                -> (Vec<P::G1>, Vec<P::G2>) {
  let m = A.len();
  // use transcript as a way of hashing, not as a protocol tool
  let mut transcript = Transcript::new(b"Outsource Pairings Computations");
  transcript.append_u64(b"pairing count", m as u64);
  for (a, b, c, d) in izip!(A.iter(), B.iter(), C.iter(), D.iter()) {
    transcript.append_message(b"A value", a.to_compressed_bytes().as_slice());
    transcript.append_message(b"B value", b.to_compressed_bytes().as_slice());
    transcript.append_message(b"C value", c.to_compressed_bytes().as_slice());
    transcript.append_message(b"D value", d.to_compressed_bytes().as_slice());
  }
  let mut new_A = vec![];
  let mut new_C = vec![];
  let mut new_B = B.to_vec();
  new_B.extend_from_slice(D);
  let r = transcript.get_challenge::<P::ScalarField>();
  let mut r_to_i_prev = P::ScalarField::from_u32(1);
  for (a, c) in A.iter().zip(C.iter()) {
    let r_to_i = r_to_i_prev.mul(&r);
    new_A.push(a.mul(&r_to_i));
    new_C.push(c.mul(&r_to_i.neg()));
    r_to_i_prev = r_to_i;
  }
  new_A.append(&mut new_C);

  (new_A, new_B)
}
#[allow(non_snake_case)]
#[allow(dead_code)]
pub fn outsource_inner_pairing_product_prover<P: Pairing>(A: &[P::G1],
                                                          B: &[P::G2],
                                                          Z: &P::Gt)
                                                          -> Result<OPProof<P>, ZeiError> {
  if A.len() != B.len() || !A.len().is_power_of_two() {
    Err(ZeiError::ParameterError)
  } else {
    let mut transcript = Transcript::new(b"Inner Pairing Product");
    transcript.init_inner_pairing_product::<P>(A, B, Z);
    let mut elems: Vec<(P::Gt, P::Gt)> = vec![];
    prover::<P>(&mut transcript, A, B, Z, &mut elems);
    Ok(OPProof { elems })
  }
}

#[allow(non_snake_case)]
fn prover<P: Pairing>(transcript: &mut Transcript,
                      A: &[P::G1],
                      B: &[P::G2],
                      Z: &P::Gt,
                      proof_elems: &mut Vec<(P::Gt, P::Gt)>) {
  let m = A.len();
  if m == 1 {
    return;
  }

  let ZL = inner_pairing_product::<P>(&A[m / 2..], &B[..m / 2]);
  let ZR = inner_pairing_product::<P>(&A[..m / 2], &B[m / 2..]);
  transcript.append_round_commitments::<P>(&ZL, &ZR);
  let challenge = transcript.get_challenge::<P::ScalarField>();
  let (newA, newB, newZ) = compute_next_round_input::<P>(&challenge, A, B, &Z, &ZL, &ZR);
  proof_elems.push((ZL, ZR));
  prover::<P>(transcript,
              newA.as_slice(),
              newB.as_slice(),
              &newZ,
              proof_elems);
}

#[allow(dead_code)]
#[allow(non_snake_case)]
pub fn outsource_inner_pairing_product_verifier<P: Pairing>(A: &[P::G1],
                                                            B: &[P::G2],
                                                            Z: &P::Gt,
                                                            proof: &OPProof<P>)
                                                            -> Result<(), ZeiError> {
  if A.len() != B.len() {
    Err(ZeiError::ParameterError)
  } else {
    let mut transcript = Transcript::new(b"Inner Pairing Product");
    transcript.init_inner_pairing_product::<P>(A, B, Z);
    verifier::<P>(&mut transcript, A, B, Z, proof.elems.as_slice())
  }
}

#[allow(non_snake_case)]
fn verifier<P: Pairing>(transcript: &mut Transcript,
                        A: &[P::G1],
                        B: &[P::G2],
                        Z: &P::Gt,
                        proof_elems: &[(P::Gt, P::Gt)])
                        -> Result<(), ZeiError> {
  let m = A.len();
  if m == 0 {
    return Err(ZeiError::ParameterError);
  }
  if m == 1 {
    let expected = P::pairing(&A[0], &B[0]);
    if *Z != expected {
      return Err(ZeiError::ArgumentVerificationError);
    } else {
      return Ok(());
    }
  }

  let (ZL, ZR) = &proof_elems[0];
  transcript.append_round_commitments::<P>(&ZL, &ZR);
  let challenge = transcript.get_challenge::<P::ScalarField>();
  let (newA, newB, newZ) = compute_next_round_input::<P>(&challenge, A, B, &Z, &ZL, &ZR);
  verifier::<P>(transcript,
                newA.as_slice(),
                newB.as_slice(),
                &newZ,
                &proof_elems[1..])
}

#[allow(non_snake_case)]
pub fn inner_pairing_product<P: Pairing>(A: &[P::G1], B: &[P::G2]) -> P::Gt {
  assert_eq!(A.len(), B.len());
  let mut base = P::Gt::get_identity();
  for (a, b) in A.iter().zip(B.iter()) {
    base = base.add(&P::pairing(a, b));
  }
  base
}

#[allow(non_snake_case)]
pub fn dot_product<G: Group>(A: &[G], B: &[G]) -> Vec<G> {
  assert_eq!(A.len(), B.len());
  let mut result = vec![];
  for (a, b) in A.iter().zip(B.iter()) {
    result.push(a.add(b));
  }
  result
}

#[allow(non_snake_case)]
pub fn vec_exp<G: Group>(A: &[G], exp: &G::S) -> Vec<G> {
  let mut result = vec![];
  for a in A.iter() {
    result.push(a.mul(exp));
  }
  result
}

#[allow(non_snake_case)]
fn compute_next_round_input<P: Pairing>(challenge: &P::ScalarField,
                                        A: &[P::G1],
                                        B: &[P::G2],
                                        Z: &P::Gt,
                                        ZL: &P::Gt,
                                        ZR: &P::Gt)
                                        -> (Vec<P::G1>, Vec<P::G2>, P::Gt) {
  let m = A.len();
  let challenge_inv = challenge.inv().unwrap(); // TODO remove this unwrap()
  let newZ = ZL.mul(&challenge).add(&Z).add(&ZR.mul(&challenge_inv));

  let A_to_x = vec_exp(&A[m / 2..], &challenge);
  let newA = dot_product(A_to_x.as_slice(), &A[..m / 2]);
  let B_to_x_inv = vec_exp(&B[m / 2..], &challenge_inv);
  let newB = dot_product(B_to_x_inv.as_slice(), &B[..m / 2]);
  (newA, newB, newZ)
}

#[cfg(test)]
mod tests {
  use crate::errors::ZeiError;
  use algebra::bls12_381::Bls12381;
  use algebra::groups::{Group, GroupArithmetic, Scalar};
  use algebra::pairing::Pairing;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[allow(non_snake_case)]
  fn test_outsource_inner_product_pairing<P: Pairing>() {
    let A = vec![];
    let B = vec![];
    let g1 = P::G1::get_base();
    let g2 = P::G2::get_base();
    let mut Z = P::Gt::get_identity();
    let mut prng = ChaChaRng::from_seed([0u8; 32]);

    // Error handling

    // Empty vector
    let proof = super::outsource_inner_pairing_product_prover::<P>(A.as_slice(), B.as_slice(), &Z);
    assert!(proof.is_err());

    // Vectors with different sizes
    let A = vec![P::G1::get_base()];
    let B = vec![P::G2::get_base(), P::G2::get_base()];
    let proof = super::outsource_inner_pairing_product_prover::<P>(A.as_slice(), B.as_slice(), &Z);
    assert!(proof.is_err());

    // Size of vector is not a power of 2
    let A = vec![P::G1::get_base(), P::G1::get_base(), P::G1::get_base()];
    let B = vec![P::G2::get_base(), P::G2::get_base(), P::G2::get_base()];
    let proof = super::outsource_inner_pairing_product_prover::<P>(A.as_slice(), B.as_slice(), &Z);
    assert!(proof.is_err());

    let mut A = vec![];
    let mut B = vec![];

    for _ in 0..8 {
      let a = P::ScalarField::random_scalar(&mut prng);
      let b = P::ScalarField::random_scalar(&mut prng);

      let ga = g1.mul(&a);
      let gb = g2.mul(&b);

      let pairing = P::pairing(&ga, &gb);
      Z = Z.add(&pairing);
      A.push(ga);
      B.push(gb);
    }
    let proof =
      super::outsource_inner_pairing_product_prover::<P>(A.as_slice(), B.as_slice(), &Z).unwrap();
    assert_eq!(Ok(()),
               super::outsource_inner_pairing_product_verifier(A.as_slice(),
                                                               B.as_slice(),
                                                               &Z,
                                                               &proof));

    let a1 = A.pop();
    A.pop();
    let b1 = B.pop();
    B.pop();
    A.push(g1.add(&g1));
    A.push(a1.unwrap());
    B.push(g2.add(&g2));
    B.push(b1.unwrap());
    // not updating Z
    let proof =
      super::outsource_inner_pairing_product_prover::<P>(A.as_slice(), B.as_slice(), &Z).unwrap();
    assert_eq!(Err(ZeiError::ArgumentVerificationError),
               super::outsource_inner_pairing_product_verifier(A.as_slice(),
                                                               B.as_slice(),
                                                               &Z,
                                                               &proof))
  }

  #[test]
  fn test_outsource_inner_product_pairing_bls() {
    test_outsource_inner_product_pairing::<Bls12381>();
  }

  #[allow(non_snake_case)]
  #[allow(clippy::many_single_char_names)]
  fn test_outsource_pairing_computation<P: Pairing>() {
    let mut A = vec![];
    let mut B = vec![];
    let mut C = vec![];
    let mut D = vec![];
    let g1 = P::G1::get_base();
    let g2 = P::G2::get_base();
    let mut prng = ChaChaRng::from_seed([0u8; 32]);

    // Error handling
    // The arrays do not have the same size
    let A_prime = vec![P::G1::get_base()];
    let proof = super::outsource_pairings_prover::<P>(A_prime.as_slice(),
                                                      B.as_slice(),
                                                      C.as_slice(),
                                                      D.as_slice());
    assert!(proof.is_err());

    for _ in 0..8 {
      let a = P::ScalarField::random_scalar(&mut prng);
      let b = P::ScalarField::random_scalar(&mut prng);
      let v = &a.mul(&b);
      let w = P::ScalarField::random_scalar(&mut prng);
      let inv_w = &w.inv().unwrap();

      let c = &v.mul(&inv_w);
      let d = w;

      let ga = g1.mul(&a);
      let gb = g2.mul(&b);
      let gc = g1.mul(&c);
      let gd = g2.mul(&d);

      A.push(ga);
      B.push(gb);
      C.push(gc);
      D.push(gd);
    }
    let proof = super::outsource_pairings_prover::<P>(A.as_slice(),
                                                      B.as_slice(),
                                                      C.as_slice(),
                                                      D.as_slice()).unwrap();

    assert_eq!(super::outsource_pairings_verifier::<P>(A.as_slice(),
                                                       B.as_slice(),
                                                       C.as_slice(),
                                                       D.as_slice(),
                                                       &proof),
               Ok(()));

    A.pop();
    B.pop();
    C.pop();
    D.pop();
    A.push(g1.add(&g1));
    B.push(g2.clone());
    C.push(g1);
    D.push(g2);

    let proof = super::outsource_pairings_prover::<P>(A.as_slice(),
                                                      B.as_slice(),
                                                      C.as_slice(),
                                                      D.as_slice()).unwrap();
    assert_eq!(Err(ZeiError::ArgumentVerificationError),
               super::outsource_pairings_verifier::<P>(A.as_slice(),
                                                       B.as_slice(),
                                                       C.as_slice(),
                                                       D.as_slice(),
                                                       &proof))
  }

  #[test]
  fn test_outsource_pairing_computation_bls() {
    test_outsource_pairing_computation::<Bls12381>();
  }
}
