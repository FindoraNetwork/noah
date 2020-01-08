use crate::basic_crypto::elgamal::{elgamal_encrypt, ElGamalCiphertext, ElGamalPublicKey};
use crate::errors::ZeiError;
use crate::serialization;
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use merlin::Transcript;
use crate::crypto::sigma::SigmaTranscript;

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

fn init_pedersen_elgamal_aggregate(
  transcript: &mut Transcript,
  pc_gens: &PedersenGens,
  public_key: &ElGamalPublicKey<RistrettoPoint>,
  ctexts: &[ElGamalCiphertext<RistrettoPoint>],
  commitments: &[RistrettoPoint]){
  let mut public_elems = vec![];
  public_elems.push(&pc_gens.B);
  public_elems.push(&pc_gens.B_blinding);
  public_elems.push(&public_key.0);
  for ctext in ctexts{
    public_elems.push(&ctext.e1);
    public_elems.push(&ctext.e2);
  }
  for commitment in commitments{
    public_elems.push(commitment);
  }
  transcript.init_sigma(b"PedersenElGamalAggEq", &[], public_elems.as_slice());
}

// I compute a proof that ctext and commitment encrypts/holds m under same randomness r.
// assumes transcript already contains ciphertexts and commitments
fn pedersen_elgamal_eq_prove<R: CryptoRng + RngCore>(transcript: &mut Transcript,
                                                         prng: &mut R,
                                                         m: &Scalar,
                                                         r: &Scalar,
                                                         public_key: &ElGamalPublicKey<RistrettoPoint>)
                                                         -> PedersenElGamalEqProof {
  let pc_gens = PedersenGens::default();

  let r1 = Scalar::random(prng);
  let r2 = Scalar::random(prng);
  let com = pc_gens.commit(r1, r2);
  let enc = elgamal_encrypt(&pc_gens.B, &r1, &r2, public_key);

  transcript.append_proof_commitment(&enc.e1);
  transcript.append_proof_commitment(&enc.e2);
  transcript.append_proof_commitment(&com);

  let c = transcript.get_challenge::<Scalar>();

  let z1 = c * m + r1;
  let z2 = c * r + r2;

  PedersenElGamalEqProof { z1,
                           z2,
                           e1: enc,
                           c1: com }
}

// verify a pedersen/elgamal equality proof against ctext and commitment using aggregation
// technique and a single multiexponentiation check.
// assumes transcript already contains ciphertexts and commitments
fn pedersen_elgamal_eq_verify<R: CryptoRng + RngCore>(transcript: &mut Transcript,
                                                      prng: &mut R,
                                                      public_key: &ElGamalPublicKey<RistrettoPoint>,
                                                      ctext: &ElGamalCiphertext<RistrettoPoint>,
                                                      commitment: &RistrettoPoint,
                                                      proof: &PedersenElGamalEqProof)
                                                      -> Result<(), ZeiError> {
  let pc_gens = PedersenGens::default();

  let proof_enc_e1 = proof.e1.e1;
  let proof_enc_e2 = proof.e1.e2;

  transcript.append_proof_commitment(&proof_enc_e1);
  transcript.append_proof_commitment(&proof_enc_e2);
  transcript.append_proof_commitment(&proof.c1);
  let c = transcript.get_challenge::<Scalar>();

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

fn get_linear_combination_scalars(transcript: &mut Transcript, n: usize) -> Vec<Scalar> {
  if n == 0 {
    return vec![];
  }
  let mut r = vec![Scalar::one()];
  for _ in 0..n-1 {
    r.push(transcript.get_challenge::<Scalar>());
  }
  r
}

pub fn pedersen_elgamal_aggregate_eq_proof<R: CryptoRng + RngCore>(transcript: &mut Transcript,
                                                                   prng: &mut R,
                                                                   m: &[Scalar],
                                                                   r: &[Scalar],
                                                                   public_key: &ElGamalPublicKey<RistrettoPoint>,
                                                                   ctexts: &[ElGamalCiphertext<RistrettoPoint>],
                                                                   commitments: &[RistrettoPoint]) -> PedersenElGamalEqProof
{
  let n = m.len();
  assert_eq!(n, m.len());
  assert_eq!(n, r.len());
  assert_eq!(n, ctexts.len());
  assert_eq!(n, commitments.len());

  let pc_gens = PedersenGens::default();
  init_pedersen_elgamal_aggregate(transcript, &pc_gens, public_key, ctexts, commitments);

  // 1. compute x vector
  let x = get_linear_combination_scalars(transcript, n);

  // 2. compute linear combination
  let mut lc_m = Scalar::zero();
  let mut lc_r = Scalar::zero();
  for (xi, mi, ri) in izip!(x.iter(),m.iter(),r.iter()) {
    lc_m = lc_m + xi * mi;
    lc_r = lc_r + xi * ri;
  }
  // 3. call proof
  pedersen_elgamal_eq_prove(transcript, prng, &lc_m, &lc_r, public_key)
}

pub fn pedersen_elgamal_aggregate_eq_verify<R: CryptoRng + RngCore>(
  transcript: &mut Transcript,
  prng: &mut R,
  public_key: &ElGamalPublicKey<RistrettoPoint>,
  ctexts: &[ElGamalCiphertext<RistrettoPoint>],
  commitments: &[RistrettoPoint],
  proof: &PedersenElGamalEqProof)
  -> Result<(), ZeiError> {
  let n = ctexts.len();
  assert_eq!(n, commitments.len());

  let pc_gens = PedersenGens::default();
  init_pedersen_elgamal_aggregate(transcript, &pc_gens, public_key, ctexts, commitments);
  // 1. compute x vector
  let x = get_linear_combination_scalars(transcript, n);
  // 2. compute linear combination
  let mut lc_e1 = RistrettoPoint::identity();
  let mut lc_e2 = RistrettoPoint::identity();
  let mut lc_c = RistrettoPoint::identity();
  for (xi, ei, ci) in izip!(x.iter(), ctexts.iter(), commitments.iter()) {
    lc_e1 = lc_e1 + xi * ei.e1;
    lc_e2 = lc_e2 + xi * ei.e2;
    lc_c = lc_c + xi * ci;
  }
  let lc_e = ElGamalCiphertext{
    e1: lc_e1,
    e2: lc_e2,
  };

  // 3. call verify for single statement
  pedersen_elgamal_eq_verify(transcript, prng, public_key, &lc_e, &lc_c, proof)
}

#[cfg(test)]
mod test {
  use super::PedersenElGamalEqProof;
  use crate::basic_crypto::elgamal::{elgamal_encrypt, elgamal_keygen};
  use crate::errors::ZeiError;
  use bulletproofs::PedersenGens;
  use curve25519_dalek::ristretto::RistrettoPoint;
  use curve25519_dalek::scalar::Scalar;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
  use rmp_serde::Deserializer;
  use serde::de::Deserialize;
  use serde::ser::Serialize;
  use merlin::Transcript;

  #[test]
  fn good_proof_verify() {
    let m = Scalar::from(10u8);
    let r = Scalar::from(7657u32);
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let (_sk, pk) = elgamal_keygen::<_, Scalar, RistrettoPoint>(&mut prng, &pc_gens.B);

    let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk);
    let commitment = pc_gens.commit(m, r);

    let mut prover_transcript = Transcript::new(b"test");
    let mut verifier_transcript = Transcript::new(b"test");

    super::init_pedersen_elgamal_aggregate(&mut prover_transcript, &pc_gens, &pk, &[ctext.clone()], &[commitment.clone()]);
    super::init_pedersen_elgamal_aggregate(&mut verifier_transcript, &pc_gens, &pk, &[ctext.clone()], &[commitment.clone()]);

    let proof = super::pedersen_elgamal_eq_prove(&mut prover_transcript, &mut prng, &m, &r, &pk);
    let verify =
      super::pedersen_elgamal_eq_verify(&mut verifier_transcript, &mut prng, &pk, &ctext, &commitment, &proof);
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

    let mut prover_transcript = Transcript::new(b"test");
    let mut verifier_transcript = Transcript::new(b"test");
    super::init_pedersen_elgamal_aggregate(&mut prover_transcript, &pc_gens, &pk, &[ctext.clone()], &[commitment.clone()]);
    super::init_pedersen_elgamal_aggregate(&mut verifier_transcript, &pc_gens, &pk, &[ctext.clone()], &[commitment.clone()]);

    let proof = super::pedersen_elgamal_eq_prove(&mut prover_transcript,  &mut prng, &m, &r, &pk);
    let verify =
      super::pedersen_elgamal_eq_verify(&mut verifier_transcript, &mut prng, &pk, &ctext, &commitment, &proof);
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
    let mut prover_transcript = Transcript::new(b"test");
    let mut verifier_transcript = Transcript::new(b"test");

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prover_transcript,
                                                           &mut prng,
                                                           &[m1, m2, m3, m4],
                                                           &[r1, r2, r3, r4],
                                                           &pk,
                                                           &ctexts,
                                                           &commitments);
    let verify = super::pedersen_elgamal_aggregate_eq_verify(&mut verifier_transcript, &mut prng,
                                                             &pk,
                                                             &ctexts,
                                                             &commitments,
                                                             &proof);
    assert_eq!(true, verify.is_ok());

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prover_transcript,
                                                           &mut prng,
                                                           &[m1],
                                                           &[r1],
                                                           &pk,
                                                           &ctexts[..1],
                                                           &commitments[..1]);
    let verify = super::pedersen_elgamal_aggregate_eq_verify(&mut verifier_transcript,
                                                             &mut prng,
                                                             &pk,
                                                             &ctexts[..1],
                                                             &commitments[..1],
                                                             &proof);
    assert_eq!(true, verify.is_ok());

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prover_transcript,
                                                           &mut prng,
                                                           &[m2],
                                                           &[r2],
                                                           &pk,
                                                           &ctexts[1..2],
                                                           &commitments[1..2]);
    let verify = super::pedersen_elgamal_aggregate_eq_verify(&mut verifier_transcript,
                                                             &mut prng,
                                                             &pk,
                                                             &ctexts[1..2],
                                                             &commitments[1..2],
                                                             &proof);
    assert_eq!(true, verify.is_ok());

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prover_transcript,
                                                           &mut prng,
                                                           &[m2, m3],
                                                           &[r2, r3],
                                                           &pk,
                                                           &ctexts[1..3],
                                                           &commitments[1..3]);
    let verify = super::pedersen_elgamal_aggregate_eq_verify(&mut verifier_transcript,
                                                             &mut prng,
                                                             &pk,
                                                             &ctexts[1..3],
                                                             &commitments[1..3],
                                                             &proof);
    assert_eq!(true, verify.is_ok());

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prover_transcript,
                                                           &mut prng,
                                                           &[m1, m2, m3, m3],
                                                           &[r1, r2, r3, r4],
                                                           &pk,
                                                           &ctexts,
                                                           &commitments);
    let verify = super::pedersen_elgamal_aggregate_eq_verify(&mut verifier_transcript,
                                                             &mut prng,
                                                             &pk,
                                                             &ctexts,
                                                             &commitments,
                                                             &proof);
    assert_eq!(true, verify.is_err());
    assert_eq!(ZeiError::VerifyPedersenElGamalEqError,
               verify.err().unwrap());

    let mut prover_transcript = Transcript::new(b"test");
    let mut verifier_transcript = Transcript::new(b"test");

    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prover_transcript,
                                                           &mut prng,
                                                           &[m1, m2, m3, m4],
                                                           &[r1, r2, r3, r1],
                                                           &pk,
                                                           &ctexts,
                                                           &commitments);
    let verify = super::pedersen_elgamal_aggregate_eq_verify(&mut verifier_transcript,
                                                             &mut prng,
                                                             &pk,
                                                             &ctexts,
                                                             &commitments,
                                                             &proof);
    assert_eq!(true, verify.is_err());
    assert_eq!(ZeiError::VerifyPedersenElGamalEqError,
               verify.err().unwrap());

    let mut prover_transcript = Transcript::new(b"test");
    let mut verifier_transcript = Transcript::new(b"test");
    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut prover_transcript,
                                                           &mut prng,
                                                           &[m1, m2, m3, m4],
                                                           &[r2, r2, r3, r4],
                                                           &pk,
                                                           &ctexts,
                                                           &commitments);

    let verify = super::pedersen_elgamal_aggregate_eq_verify(&mut verifier_transcript,
                                                             &mut prng,
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
    let mut transcript = Transcript::new(b"test");
    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut transcript, &mut prng, &[m], &[r], &pk, &[ctext], &[commitment]);

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
    let mut transcript = Transcript::new(b"test");
    let proof = super::pedersen_elgamal_aggregate_eq_proof(&mut transcript, &mut prng, &[m], &[r], &pk, &[ctext], &[commitment]);

    let mut vec = vec![];
    proof.serialize(&mut rmp_serde::Serializer::new(&mut vec))
         .unwrap();

    let mut de = Deserializer::new(&vec[..]);
    let proof_de: PedersenElGamalEqProof = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(proof, proof_de);
  }
}
