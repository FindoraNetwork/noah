use super::{compute_challenge_ref, compute_sub_challenge};
use crate::errors::ZeiError;
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use rand::{CryptoRng, Rng};

/*
* This file implements Chaum-Pedersen proof of equality of commitments.
* Proof algorithm:
  a) Let C1 = pedersen(a, r1) = C2 = pedersen(a, r2), (G,H) pedersen base points
  b) Sample random scalars r3, r4 and r5
  c) Compute new commitments on C3 = pedersen(r3,r4) and C4 = (r3,r5)
  d) Compute challenge c = HASH(C1,C2,C3,C4)
  e) Compute response z1 = cm + r3, z2 = cr1 + r4, z3 = cr2 + r5
  f) Output proof = C1,C2,z1,z2,z3

* Verify algorithm:
  a) Compute challenge c = HASH(C1,C2,C3,C4)
  b) Output true iff c3 + c*c1 = z1*G + z2*H AND c4 + c*c2 == z1*G + z3*H

* Proof equality for multiple commitments
  a) {challenge_i = HASH(C1,...,Cn, i)}
  b) {di = challenge_i * (C1 - Ci)}
  c) {zi = challenge_i * (r1 - ri)}
  d) Ouput Chaum-Pedersen Zero-Knowledge proof that D = \sum di commits to 0
     (using blinding z = sum zi}
  (Current implementation uses equality proof above with (D,  Commit(0, 0)) commitment pair)
*/

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct ChaumPedersenProof {
  /// I represent a Chaum-Perdersen equality of commitment proof
  //#[serde(with = "serialization::zei_obj_serde")]
  pub(crate) c3: RistrettoPoint,
  //#[serde(with = "serialization::zei_obj_serde")]
  pub(crate) c4: RistrettoPoint,
  //#[serde(with = "serialization::zei_obj_serde")]
  pub(crate) z1: Scalar,
  //#[serde(with = "serialization::zei_obj_serde")]
  pub(crate) z2: Scalar,
  //#[serde(with = "serialization::zei_obj_serde")]
  pub(crate) z3: Scalar,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct ChaumPedersenProofX {
  /// I represent a Chaum-Perdersen equality of commitment proof
  pub(crate) c1_eq_c2: ChaumPedersenProof,
  pub(crate) zero: Option<ChaumPedersenProof>,
}

/// I compute a Chaum-Pedersen proof of knowledge of openings of two commitments to the same value
pub fn chaum_pedersen_prove_eq<R: CryptoRng + Rng>(prng: &mut R,
                                                   pedersen_gens: &PedersenGens,
                                                   value: &Scalar,
                                                   commitment1: &RistrettoPoint,
                                                   commitment2: &RistrettoPoint,
                                                   blinding_factor1: &Scalar,
                                                   blinding_factor2: &Scalar)
                                                   -> ChaumPedersenProof {
  let r1 = blinding_factor1;
  let r2 = blinding_factor2;
  let r3 = Scalar::random(prng);
  let r4 = Scalar::random(prng);
  let r5 = Scalar::random(prng);

  let c3 = pedersen_gens.commit(r3, r4);
  let c4 = pedersen_gens.commit(r3, r5);

  let c = compute_challenge_ref::<Scalar, RistrettoPoint>(&[commitment1, commitment2, &c3, &c4]);

  let z1 = c * value + r3;
  let z2 = c * r1 + r4;
  let z3 = c * r2 + r5;

  ChaumPedersenProof { c3, c4, z1, z2, z3 }
}

/// I verify a chaum-pedersen equality proof. Return Ok(true) in case of success, Ok(false)
/// in case of verification failure, and Err(Error::DecompressElementError) in case some
/// CompressedRistretto can not be decompressed*/
pub fn chaum_pedersen_verify_eq(pc_gens: &PedersenGens,
                                c1: &RistrettoPoint,
                                c2: &RistrettoPoint,
                                proof: &ChaumPedersenProof)
                                -> Result<bool, ZeiError> {
  let z1 = proof.z1;
  let z2 = proof.z2;
  let z3 = proof.z3;
  let g = &pc_gens.B;
  let h = &pc_gens.B_blinding;

  let c = compute_challenge_ref::<Scalar, RistrettoPoint>(&[c1, c2, &proof.c3, &proof.c4]);

  let mut vrfy_ok = proof.c3 + c * c1 == z1 * g + z2 * h;
  vrfy_ok = vrfy_ok && proof.c4 + c * c2 == z1 * g + z3 * h;
  Ok(vrfy_ok)
}

/// I verify a chaum-pedersen equality proof. Return Ok(true) in case of success, Ok(false)
/// in case of verification failure, and Err(Error::DecompressElementError) in case some
/// CompressedRistretto can not be decompressed. I use aggregation technique and a single
/// multi-exponentiation check
pub fn chaum_pedersen_verify_eq_fast<R: CryptoRng + Rng>(prng: &mut R,
                                                         pc_gens: &PedersenGens,
                                                         c1: &RistrettoPoint,
                                                         c2: &RistrettoPoint,
                                                         proof: &ChaumPedersenProof)
                                                         -> Result<bool, ZeiError> {
  let z1 = proof.z1;
  let z2 = proof.z2;
  let z3 = proof.z3;
  let g = pc_gens.B;
  let h = pc_gens.B_blinding;

  let c = compute_challenge_ref::<Scalar, RistrettoPoint>(&[c1, c2, &proof.c3, &proof.c4]);

  let a = Scalar::random(prng);

  let verify =
    RistrettoPoint::multiscalar_mul(&[-a, -c * a, a * z1 + z1, a * z2 + z3, -Scalar::one(), -c],
                                    &[proof.c3, *c1, g, h, proof.c4, *c2]);

  Ok(verify == RistrettoPoint::identity())
}

//Helper functions for the proof of multiple commitments equality below
/// I return a fake compressed commitment to zero, eg The identity
fn get_fake_zero_commitment() -> RistrettoPoint {
  RistrettoPoint::identity()
}

/// I return the blinding used in the get_fake_zero_commitment
fn get_fake_zero_commitment_blinding() -> Scalar {
  Scalar::zero()
}

/// I produce a proof of knowledge of openings of a set of commitments to the same value.
pub fn chaum_pedersen_prove_multiple_eq<R: CryptoRng + Rng>(
  prng: &mut R,
  pedersen_gens: &PedersenGens,
  value: &Scalar,
  commitments: &[RistrettoPoint],
  blinding_factors: &[Scalar])
  -> Result<ChaumPedersenProofX, ZeiError> {
  if commitments.len() <= 1 || commitments.len() != blinding_factors.len() {
    return Err(ZeiError::ParameterError);
  }
  let proof_c1_c2 = chaum_pedersen_prove_eq(prng,
                                            pedersen_gens,
                                            value,
                                            &commitments[0],
                                            &commitments[1],
                                            &blinding_factors[0],
                                            &blinding_factors[1]);

  if commitments.len() == 2 {
    return Ok(ChaumPedersenProofX { c1_eq_c2: proof_c1_c2,
                                    zero: None });
  }
  let mut points_refs = vec![];
  for com in commitments {
    points_refs.push(com);
  }
  let k = compute_challenge_ref::<Scalar, RistrettoPoint>(points_refs.as_slice());
  let mut d = RistrettoPoint::identity();
  let mut z = Scalar::from(0u8);
  let c1 = commitments.get(0).ok_or(ZeiError::IndexError)?;
  let r1 = blinding_factors.get(0).ok_or(ZeiError::IndexError)?;
  for i in 3..commitments.len() {
    let ci = commitments.get(i).ok_or(ZeiError::IndexError)?;
    let ai = compute_sub_challenge::<Scalar>(&k, i as u32);
    let di = ai * (c1 - ci);
    let ri = blinding_factors.get(i).ok_or(ZeiError::IndexError)?;
    let zi = ai * (*r1 - *ri);
    d = d + di;
    z = z + zi;
  }

  //TODO can we produce proof to zero commitment in a more direct way?
  //produce fake commitment to 0 for chaum pedersen commitment
  let proof_zero = chaum_pedersen_prove_eq(prng,
                                           pedersen_gens,
                                           &Scalar::from(0u8),
                                           &d,
                                           &get_fake_zero_commitment(),
                                           &z,
                                           &get_fake_zero_commitment_blinding());
  Ok(ChaumPedersenProofX { c1_eq_c2: proof_c1_c2,
                           zero: Some(proof_zero) })
}

/// I verify a proof that all commitments are to the same value.
///  * Return Ok(true) in case of success, Ok(false) in case of verification failure,
///  * and Err(Error::DecompressElementError) in case some CompressedRistretto can not be decompressed
pub fn chaum_pedersen_verify_multiple_eq<R: CryptoRng + Rng>(prng: &mut R,
                                                             pedersen_gens: &PedersenGens,
                                                             commitments: &[RistrettoPoint],
                                                             proof: &ChaumPedersenProofX)
                                                             -> Result<bool, ZeiError> {
  let mut points_refs = vec![];
  for com in commitments {
    points_refs.push(com);
  }
  let k = compute_challenge_ref::<Scalar, RistrettoPoint>(points_refs.as_slice());
  let mut d = RistrettoPoint::identity();
  let c1 = commitments.get(0).ok_or(ZeiError::IndexError)?;
  for i in 3..commitments.len() {
    let ci = commitments.get(i).ok_or(ZeiError::IndexError)?;
    let ai = compute_sub_challenge::<Scalar>(&k, i as u32);
    let di = ai * (c1 - ci);
    d = d + di;
  }

  //TODO can we produce proof to zero commitment in a more direct way?
  //produce fake commitment to 0 for chaum pedersen commitment
  let mut vrfy_ok = chaum_pedersen_verify_eq_fast(prng,
                                                  pedersen_gens,
                                                  &commitments[0],
                                                  &commitments[1],
                                                  &proof.c1_eq_c2)?;

  if commitments.len() == 2 {
    return Ok(vrfy_ok);
  }
  vrfy_ok = vrfy_ok
            && chaum_pedersen_verify_eq_fast(prng,
                                             pedersen_gens,
                                             &d,
                                             &get_fake_zero_commitment(),
                                             proof.zero.as_ref().unwrap())?;
  Ok(vrfy_ok)
}

#[cfg(test)]
mod test {
  use super::*;
  use bulletproofs::PedersenGens;
  use rand::SeedableRng;
  use rand_chacha::ChaChaRng;

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

    let proof = chaum_pedersen_prove_eq(&mut csprng, &pc_gens, &value1, &c1, &c2, &bf1, &bf2);

    assert_eq!(false,
               chaum_pedersen_verify_eq(&pc_gens, &c1, &c2, &proof).unwrap());

    assert_eq!(false,
               chaum_pedersen_verify_eq_fast(&mut csprng, &pc_gens, &c1, &c2, &proof).unwrap());

    let proof = chaum_pedersen_prove_eq(&mut csprng, &pc_gens, &value2, &c1, &c2, &bf1, &bf2);

    assert_eq!(false,
               chaum_pedersen_verify_eq(&pc_gens, &c1, &c2, &proof).unwrap());

    assert_eq!(false,
               chaum_pedersen_verify_eq_fast(&mut csprng, &pc_gens, &c1, &c2, &proof).unwrap());

    let c3 = pedersen_bases.commit(value1, bf2);
    let proof = chaum_pedersen_prove_eq(&mut csprng, &pc_gens, &value1, &c1, &c3, &bf1, &bf2);

    assert_eq!(true,
               chaum_pedersen_verify_eq(&pc_gens, &c1, &c3, &proof).unwrap());

    assert_eq!(true,
               chaum_pedersen_verify_eq_fast(&mut csprng, &pc_gens, &c1, &c3, &proof).unwrap());
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

    let proof = chaum_pedersen_prove_multiple_eq(&mut csprng,
                                                 &pc_gens,
                                                 &value1,
                                                 com_vec,
                                                 &blind_vec).unwrap();

    assert_eq!(false,
               chaum_pedersen_verify_multiple_eq(&mut csprng, &pc_gens, com_vec, &proof).unwrap());

    let c1 = pedersen_bases.commit(value1, bf1);
    let c2 = pedersen_bases.commit(value1, bf2);
    let c3 = pedersen_bases.commit(value1, bf3);

    let com_vec = &[c1, c2, c3];
    let blind_vec = vec![bf1, bf2, bf3];

    let proof = chaum_pedersen_prove_multiple_eq(&mut csprng,
                                                 &pc_gens,
                                                 &value1,
                                                 com_vec,
                                                 &blind_vec).unwrap();

    assert_eq!(true,
               chaum_pedersen_verify_multiple_eq(&mut csprng, &pc_gens, com_vec, &proof).unwrap());
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

    let proof = chaum_pedersen_prove_multiple_eq(&mut csprng,
                                                 &pc_gens,
                                                 &value1,
                                                 com_vec,
                                                 &blind_vec).unwrap();

    assert_eq!(false,
               chaum_pedersen_verify_multiple_eq(&mut csprng, &pc_gens, com_vec, &proof).unwrap(),
               "Values were different");

    let c1 = pedersen_bases.commit(value1, bf1);
    let c2 = pedersen_bases.commit(value1, bf2);

    let com_vec = &[c1, c2];
    let blind_vec = vec![bf1, bf2];

    let proof = chaum_pedersen_prove_multiple_eq(&mut csprng,
                                                 &pc_gens,
                                                 &value1,
                                                 com_vec,
                                                 &blind_vec).unwrap();
    assert_eq!(true,
               chaum_pedersen_verify_multiple_eq(&mut csprng, &pc_gens, com_vec, &proof).unwrap(),
               "Values are the same");
  }
}
