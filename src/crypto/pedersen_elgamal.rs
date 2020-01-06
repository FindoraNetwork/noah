use super::compute_challenge_ref;
use crate::basic_crypto::elgamal::{elgamal_encrypt, ElGamalCiphertext, ElGamalPublicKey};
use crate::errors::ZeiError;
use crate::serialization;
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

/*
* This file implements a Chaum-Pedersen proof of equality of
* a commitment C = m*G + r*H, and ciphertext E = (r*G, m*G + r*PK)

* Proof algorithm:
  a) Sample random scalars r1, r2
  b) Compute commitment on r1 using r2 as randomness: C1 = r1*G + r2*H
  c) Compute encryption of r1 using r2 as randomness: E1 = (r2*G, r1*G + r2*PK)
  d) Compute challenge c = HASH(C, E, C1, E1)
  e) Compute response z1 = cm + r1, z2 = cr + r2
  f) Output proof = C1,E1,z1,z2

* Verify algorithm:
  a) Compute challenge c = HASH(C, E, C, E)
  b) Output Ok iff C1 + c * C == z1 * G + z2 * H
         and       E1 + c * E == (z2 * G, z1 * pc_gens.B + z2 * PK)
*/
const ELGAMAL_CTEXT_LEN: usize = 64;
pub const PEDERSEN_ELGAMAL_EQ_PROOF_LEN: usize = 96 + ELGAMAL_CTEXT_LEN;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenElGamalEqProof {
  #[serde(with = "serialization::zei_obj_serde")]
  z1: Scalar, // c*m + r_1
  #[serde(with = "serialization::zei_obj_serde")]
  z2: Scalar, // c*r + r_2
  #[serde(with = "serialization::zei_obj_serde")]
  e1: ElGamalCiphertext<RistrettoPoint>, // (r_2*G, r1*g + r2*PK)
  #[serde(with = "serialization::zei_obj_serde")]
  c1: RistrettoPoint, // r_1*g + r_2*H
}

/// I compute a proof that ctext and commitment encrypts/holds m under same randomness r.
pub fn pedersen_elgamal_eq_prove<R: CryptoRng + RngCore>(prng: &mut R,
                                                     m: &Scalar,
                                                     r: &Scalar,
                                                     public_key: &ElGamalPublicKey<RistrettoPoint>,
                                                     ctext: &ElGamalCiphertext<RistrettoPoint>,
                                                     commitment: &RistrettoPoint)
                                                     -> PedersenElGamalEqProof {
  let r1 = Scalar::random(prng);
  let r2 = Scalar::random(prng);
  let pc_gens = PedersenGens::default();
  let com = pc_gens.commit(r1, r2);
  let enc = elgamal_encrypt(&pc_gens.B, &r1, &r2, public_key);
  let c = compute_challenge_ref::<Scalar, RistrettoPoint>(&[&ctext.e1, &ctext.e2, commitment,
                                                            &enc.e1, &enc.e2, &com]);
  let z1 = c * m + r1;
  let z2 = c * r + r2;

  PedersenElGamalEqProof { z1,
                           z2,
                           e1: enc,
                           c1: com }
}

/// I verify perdersen/elgamal equality proof againts ctext and commitment.
pub fn pedersen_elgamal_eq_verify(public_key: &ElGamalPublicKey<RistrettoPoint>,
                                  ctext: &ElGamalCiphertext<RistrettoPoint>,
                                  commitment: &RistrettoPoint,
                                  proof: &PedersenElGamalEqProof)
                                  -> Result<(), ZeiError> {
  let pc_gens = PedersenGens::default();
  let c = compute_challenge_ref::<Scalar, RistrettoPoint>(&[&ctext.e1,
                                                            &ctext.e2,
                                                            commitment,
                                                            &proof.e1.e1,
                                                            &proof.e1.e2,
                                                            &proof.c1]);

  let proof_enc_e1 = &proof.e1.e1;
  let proof_enc_e2 = &proof.e1.e2;

  if (proof.c1 + c * commitment == proof.z1 * pc_gens.B + proof.z2 * pc_gens.B_blinding)
     && (proof_enc_e1 + c * ctext.e1 == proof.z2 * pc_gens.B
         && proof_enc_e2 + c * ctext.e2
            == proof.z1 * pc_gens.B + proof.z2 * public_key.get_point_ref())
  {
    return Ok(());
  }

  Err(ZeiError::VerifyPedersenElGamalEqError)
}

/// verify a pedersen/elgamal equality proof against ctext and commitment using aggregation
/// technique and a single multiexponentiation check.
pub fn pedersen_elgamal_eq_verify_fast<R: CryptoRng + RngCore>(prng: &mut R,
                                                           public_key: &ElGamalPublicKey<RistrettoPoint>,
                                                           ctext: &ElGamalCiphertext<RistrettoPoint>,
                                                           commitment: &RistrettoPoint,
                                                           proof: &PedersenElGamalEqProof)
                                                           -> Result<(), ZeiError> {
  let pc_gens = PedersenGens::default();
  let c = compute_challenge_ref::<Scalar, RistrettoPoint>(&[&ctext.e1,
                                                            &ctext.e2,
                                                            commitment,
                                                            &proof.e1.e1,
                                                            &proof.e1.e2,
                                                            &proof.c1]);

  let proof_enc_e1 = proof.e1.e1;
  let proof_enc_e2 = proof.e1.e2;

  let a1 = Scalar::random(prng);
  let a2 = Scalar::random(prng);

  let ver = RistrettoPoint::multiscalar_mul(&[-a1,
                                              -c * a1,
                                              proof.z1 * (a1 + Scalar::one()) + proof.z2 * a2,
                                              proof.z2 * a1,
                                              -a2,
                                              -c * a2,
                                              -Scalar::one(),
                                              -c,
                                              proof.z2],
                                            &[proof.c1,
                                              *commitment,
                                              pc_gens.B,
                                              pc_gens.B_blinding,
                                              proof_enc_e1,
                                              ctext.e1,
                                              proof_enc_e2,
                                              ctext.e2,
                                              public_key.get_point()]);

  if ver != RistrettoPoint::identity() {
    return Err(ZeiError::VerifyPedersenElGamalEqError);
  }

  Ok(())
}

fn compute_linear_combination_scalar_vector(commitments: &[RistrettoPoint],
                                            ctexts: &[ElGamalCiphertext<RistrettoPoint>],
                                            public_key: &ElGamalPublicKey<RistrettoPoint>)
                                            -> Vec<Scalar> {
  let mut input = vec![];
  for c in commitments.iter() {
    input.push(c);
  }
  input.push(public_key.get_point_ref());
  for ct in ctexts {
    input.push(&ct.e1);
    input.push(&ct.e2);
  }
  let mut x = vec![];
  let mut xi = compute_challenge_ref(input.as_slice());
  for _ in 1..commitments.len() {
    let mut hash = Sha512::new();
    hash.input(xi.to_bytes());
    let new_x = Scalar::from_hash(hash);
    x.push(xi);
    xi = new_x;
  }
  x.push(xi);
  x
}
pub fn pedersen_elgamal_aggregate_eq_proof<R: CryptoRng + RngCore>(prng: &mut R,
                                                               m: &[Scalar],
                                                               r: &[Scalar],
                                                               public_key: &ElGamalPublicKey<RistrettoPoint>,
                                                               ctexts: &[ElGamalCiphertext<RistrettoPoint>],
                                                               commitments: &[RistrettoPoint])
                                                               -> PedersenElGamalEqProof {
  let pc_gens = PedersenGens::default();

  // 1. compute x vector
  let x = compute_linear_combination_scalar_vector(commitments, ctexts, public_key);
  // 2. sampling blinding vector r1 and r2
  let mut r1_vec = vec![];
  let mut r2_vec = vec![];
  for _ in 0..m.len() {
    r1_vec.push(Scalar::random(prng));
    r2_vec.push(Scalar::random(prng));
  }

  // 3. commpute proof commitment vector
  let mut com_vec = vec![];
  let mut enc_vec = vec![];
  for (r1, r2) in r1_vec.iter().zip(r2_vec.iter()) {
    com_vec.push(pc_gens.commit(*r1, *r2));
    enc_vec.push(elgamal_encrypt(&pc_gens.B, &r1, &r2, public_key));
  }
  //4. aggregate vectors
  let mut com = RistrettoPoint::identity();
  for (x_i, com_i) in x.iter().zip(commitments.iter()) {
    com += com_i * x_i;
  }
  let mut enc1 = RistrettoPoint::identity();
  let mut enc2 = RistrettoPoint::identity();
  for (x_i, enc_i) in x.iter().zip(ctexts.iter()) {
    enc1 += enc_i.e1 * x_i;
    enc2 += enc_i.e2 * x_i;
  }

  let mut proof_enc1 = RistrettoPoint::identity();
  let mut proof_enc2 = RistrettoPoint::identity();
  for (x_i, enc_i) in x.iter().zip(enc_vec.iter()) {
    proof_enc1 += enc_i.e1 * x_i;
    proof_enc2 += enc_i.e2 * x_i;
  }
  let mut proof_com = RistrettoPoint::identity();
  for (x_i, com_i) in x.iter().zip(com_vec.iter()) {
    proof_com += com_i * x_i
  }
  //5. compute challenge
  let c = compute_challenge_ref::<Scalar, RistrettoPoint>(&[&pc_gens.B,
                                                            &pc_gens.B_blinding,
                                                            public_key.get_point_ref(),
                                                            &enc1,
                                                            &enc2,
                                                            &com,
                                                            &proof_enc1,
                                                            &proof_enc2,
                                                            &proof_com]);

  //6. compute challenge responses
  let mut z1 = Scalar::zero();
  for ((m_i, r1_i), x_i) in m.iter().zip(r1_vec.iter()).zip(x.iter()) {
    z1 += (m_i * c + r1_i) * x_i;
  }
  let mut z2 = Scalar::zero();
  for ((r_i, r2_i), x_i) in r.iter().zip(r2_vec.iter()).zip(x.iter()) {
    z2 += (r_i * c + r2_i) * x_i;
  }

  let proof_enc = ElGamalCiphertext { e1: proof_enc1,
                                      e2: proof_enc2 };
  PedersenElGamalEqProof { z1,
                           z2,
                           e1: proof_enc,
                           c1: proof_com }
}

pub fn pedersen_elgamal_eq_aggregate_verify_fast<R: CryptoRng + RngCore>(prng: &mut R,
                                                                     public_key: &ElGamalPublicKey<RistrettoPoint>,
                                                                     ctexts: &[ElGamalCiphertext<RistrettoPoint>],
                                                                     commitments: &[RistrettoPoint],
                                                                     proof: &PedersenElGamalEqProof)
                                                                     -> Result<(), ZeiError> {
  // 1. compute x vector
  let x = compute_linear_combination_scalar_vector(commitments, ctexts, public_key);

  // 2. aggragate commitments and ciphertexts
  let mut com = RistrettoPoint::identity();
  for (x_i, com_i) in x.iter().zip(commitments.iter()) {
    com += com_i * x_i;
  }
  let mut enc1 = RistrettoPoint::identity();
  let mut enc2 = RistrettoPoint::identity();
  for (x_i, enc_i) in x.iter().zip(ctexts.iter()) {
    enc1 += enc_i.e1 * x_i;
    enc2 += enc_i.e2 * x_i;
  }

  let pc_gens = PedersenGens::default();
  let c = compute_challenge_ref::<Scalar, RistrettoPoint>(&[&pc_gens.B,
                                                            &pc_gens.B_blinding,
                                                            public_key.get_point_ref(),
                                                            &enc1,
                                                            &enc2,
                                                            &com,
                                                            &proof.e1.e1,
                                                            &proof.e1.e2,
                                                            &proof.c1]);

  let proof_enc_e1 = proof.e1.e1;
  let proof_enc_e2 = proof.e1.e2;

  let a1 = Scalar::random(prng);
  let a2 = Scalar::random(prng);

  let ver = RistrettoPoint::multiscalar_mul(&[-a1,
                                              -c * a1,
                                              proof.z1 * (a1 + Scalar::one()) + proof.z2 * a2,
                                              proof.z2 * a1,
                                              -a2,
                                              -c * a2,
                                              -Scalar::one(),
                                              -c,
                                              proof.z2],
                                            &[proof.c1,
                                              com,
                                              pc_gens.B,
                                              pc_gens.B_blinding,
                                              proof_enc_e1,
                                              enc1,
                                              proof_enc_e2,
                                              enc2,
                                              public_key.get_point()]);

  if ver != RistrettoPoint::identity() {
    return Err(ZeiError::VerifyPedersenElGamalEqError);
  }

  Ok(())
}

#[cfg(test)]
mod test {
  use super::PedersenElGamalEqProof;
  use crate::basic_crypto::elgamal::{elgamal_encrypt, elgamal_keygen};
  use crate::errors::ZeiError;
  use bulletproofs::PedersenGens;
  use curve25519_dalek::ristretto::RistrettoPoint;
  use curve25519_dalek::scalar::Scalar;
  use rand_core::SeedableRng;
  use rand_chacha::ChaChaRng;
  use rmp_serde::Deserializer;
  use serde::de::Deserialize;
  use serde::ser::Serialize;

  #[test]
  fn good_proof_verify() {
    let m = Scalar::from(10u8);
    let r = Scalar::from(7657u32);
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let (_sk, pk) = elgamal_keygen::<_, Scalar, RistrettoPoint>(&mut prng, &pc_gens.B);

    let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk);
    let commitment = pc_gens.commit(m, r);

    let proof = super::pedersen_elgamal_eq_prove(&mut prng, &m, &r, &pk, &ctext, &commitment);
    let verify = super::pedersen_elgamal_eq_verify(&pk, &ctext, &commitment, &proof);
    assert_eq!(true, verify.is_ok());

    let verify =
      super::pedersen_elgamal_eq_verify_fast(&mut prng, &pk, &ctext, &commitment, &proof);
    assert_eq!(true, verify.is_ok());
  }

  #[test]
  fn bad_proof_verify() {
    let m = Scalar::from(10u8);
    let m2 = Scalar::from(11u8);
    let r = Scalar::from(7657u32);
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let (_sk, pk) = elgamal_keygen::<_, Scalar, RistrettoPoint>(&mut prng, &pc_gens.B);

    let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk);
    let commitment = pc_gens.commit(m2, r);

    let proof = super::pedersen_elgamal_eq_prove(&mut prng, &m, &r, &pk, &ctext, &commitment);
    let verify = super::pedersen_elgamal_eq_verify(&pk, &ctext, &commitment, &proof);
    assert_eq!(true, verify.is_err());
    assert_eq!(ZeiError::VerifyPedersenElGamalEqError,
               verify.err().unwrap());
    let verify =
      super::pedersen_elgamal_eq_verify_fast(&mut prng, &pk, &ctext, &commitment, &proof);
    assert_eq!(true, verify.is_err());
    assert_eq!(ZeiError::VerifyPedersenElGamalEqError,
               verify.err().unwrap());
  }

  #[test]
  fn proof_aggregate() {
    let m1 = Scalar::from(11u8);
    let r1 = Scalar::from(7657u32);
    let m2 = Scalar::from(12u8);
    let r2 = Scalar::from(7658u32);
    let m3 = Scalar::from(13u8);
    let r3 = Scalar::from(7659u32);
    let m4 = Scalar::from(14u8);
    let r4 = Scalar::from(7660u32);
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let (_sk, pk) = elgamal_keygen::<_, Scalar, RistrettoPoint>(&mut prng, &pc_gens.B);

    let ctext1 = elgamal_encrypt(&pc_gens.B, &m1, &r1, &pk);
    let commitment1 = pc_gens.commit(m1, r1);
    let ctext2 = elgamal_encrypt(&pc_gens.B, &m2, &r2, &pk);
    let commitment2 = pc_gens.commit(m2, r2);
    let ctext3 = elgamal_encrypt(&pc_gens.B, &m3, &r3, &pk);
    let commitment3 = pc_gens.commit(m3, r3);
    let ctext4 = elgamal_encrypt(&pc_gens.B, &m4, &r4, &pk);
    let commitment4 = pc_gens.commit(m4, r4);

    let ctexts = [ctext1, ctext2, ctext3, ctext4];
    let commitments = [commitment1, commitment2, commitment3, commitment4];

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prng,
                                                           &[m1, m2, m3, m4],
                                                           &[r1, r2, r3, r4],
                                                           &pk,
                                                           &ctexts,
                                                           &commitments);
    let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng,
                                                                  &pk,
                                                                  &ctexts,
                                                                  &commitments,
                                                                  &proof);
    assert_eq!(true, verify.is_ok());

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prng,
                                                           &[m1],
                                                           &[r1],
                                                           &pk,
                                                           &ctexts[..1],
                                                           &commitments[..1]);
    let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng,
                                                                  &pk,
                                                                  &ctexts[..1],
                                                                  &commitments[..1],
                                                                  &proof);
    assert_eq!(true, verify.is_ok());

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prng,
                                                           &[m2],
                                                           &[r2],
                                                           &pk,
                                                           &ctexts[1..2],
                                                           &commitments[1..2]);
    let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng,
                                                                  &pk,
                                                                  &ctexts[1..2],
                                                                  &commitments[1..2],
                                                                  &proof);
    assert_eq!(true, verify.is_ok());

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prng,
                                                           &[m2, m3],
                                                           &[r2, r3],
                                                           &pk,
                                                           &ctexts[1..3],
                                                           &commitments[1..3]);
    let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng,
                                                                  &pk,
                                                                  &ctexts[1..3],
                                                                  &commitments[1..3],
                                                                  &proof);
    assert_eq!(true, verify.is_ok());

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prng,
                                                           &[m1, m2, m3, m3],
                                                           &[r1, r2, r3, r4],
                                                           &pk,
                                                           &ctexts,
                                                           &commitments);
    let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng,
                                                                  &pk,
                                                                  &ctexts,
                                                                  &commitments,
                                                                  &proof);
    assert_eq!(true, verify.is_err());
    assert_eq!(ZeiError::VerifyPedersenElGamalEqError,
               verify.err().unwrap());

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prng,
                                                           &[m1, m2, m3, m4],
                                                           &[r1, r2, r3, r1],
                                                           &pk,
                                                           &ctexts,
                                                           &commitments);
    let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng,
                                                                  &pk,
                                                                  &ctexts,
                                                                  &commitments,
                                                                  &proof);
    assert_eq!(true, verify.is_err());
    assert_eq!(ZeiError::VerifyPedersenElGamalEqError,
               verify.err().unwrap());

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prng,
                                                           &[m1, m2, m3, m4],
                                                           &[r2, r2, r3, r4],
                                                           &pk,
                                                           &ctexts,
                                                           &commitments);
    let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng,
                                                                  &pk,
                                                                  &ctexts,
                                                                  &commitments,
                                                                  &proof);
    assert_eq!(true, verify.is_err());
    assert_eq!(ZeiError::VerifyPedersenElGamalEqError,
               verify.err().unwrap());
  }

  #[test]
  fn to_json() {
    let m = Scalar::from(10u8);
    let r = Scalar::from(7657u32);
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let (_sk, pk) = elgamal_keygen::<_, Scalar, RistrettoPoint>(&mut prng, &pc_gens.B);
    let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk);
    let commitment = pc_gens.commit(m, r);
    let proof = super::pedersen_elgamal_eq_prove(&mut prng, &m, &r, &pk, &ctext, &commitment);

    let json_str = serde_json::to_string(&proof).unwrap();
    let proof_de = serde_json::from_str(&json_str).unwrap();
    assert_eq!(proof, proof_de, "Deserialized proof does not match");
  }

  #[test]
  fn to_message_pack() {
    let m = Scalar::from(10u8);
    let r = Scalar::from(7657u32);
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let (_sk, pk) = elgamal_keygen::<_, Scalar, RistrettoPoint>(&mut prng, &pc_gens.B);

    let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk);
    let commitment = pc_gens.commit(m, r);
    let proof = super::pedersen_elgamal_eq_prove(&mut prng, &m, &r, &pk, &ctext, &commitment);

    let mut vec = vec![];
    proof.serialize(&mut rmp_serde::Serializer::new(&mut vec))
         .unwrap();

    let mut de = Deserializer::new(&vec[..]);
    let proof_de: PedersenElGamalEqProof = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(proof, proof_de);
  }
}
