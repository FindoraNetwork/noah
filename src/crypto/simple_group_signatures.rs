use crate::algebra::bls12_381::{BLSGt, BLSScalar, BLSG1, BLSG2};
use crate::algebra::groups::{Group, Scalar};
use crate::algebra::pairing::PairingTargetGroup;
use crate::basic_crypto::elgamal::{elgamal_decrypt_elem, elgamal_encrypt, ElGamalPublicKey, ElGamalSecretKey, ElGamalCiphertext, elgamal_keygen};
use crate::basic_crypto::signatures::pointcheval_sanders::{
  ps_gen_keys, ps_randomize_sig, ps_sign_scalar, PSPublicKey, PSSecretKey, PSSignature,
};
use crate::errors::ZeiError;
use digest::Digest;
use rand::{CryptoRng, Rng};
use sha2::Sha512;

/// The public key of the group manager contains a public signing key `ver_key`
/// and an Elgamal encryption public key `enc_key`.
pub struct GroupPublicKey {
  ver_key: PSPublicKey,
  enc_key: ElGamalPublicKey<BLSG1>,
}

/// The secret key of the group manager contains a private signing key `sig_key`
/// and a private Elgamal encryption key `dec_key`.
pub struct GroupSecretKey {
  sig_key: PSSecretKey,
  dec_key: ElGamalSecretKey<BLSScalar>,
}

/// A group signature contains a Pointcheval-Sanders signature `cert`,
/// an Elgamal ciphertext `enc` containing the encryption of the identity of the signer
/// and a proof-of-knowledge `PoK` to prove that the identity of the signer corresponds
/// to the private key used to produce `cert`.
pub struct GroupSignature {
  cert: PSSignature,
  enc: ElGamalCiphertext<BLSG1>,
  spok: PoK,
}

/// I generate the private and public parameters for the Group manager.
/// * `prng` - source of randomness
/// * `returns` - a group public key and a group secret key
pub fn gpsig_setup<R: CryptoRng + Rng>(prng: &mut R) -> (GroupPublicKey, GroupSecretKey) {
  let (ver_key, sig_key) = ps_gen_keys(prng);
  let (dec_key, enc_key) = elgamal_keygen(prng, &BLSG1::get_base());
  (GroupPublicKey { ver_key, enc_key }, GroupSecretKey { sig_key, dec_key })
}

/// When a user joins the group, the Group Manager sends him a certificate
/// that will enable the user to prove he his part of the group when signing.
pub struct JoinCert {
  pub tag: BLSScalar,
  pub sig: PSSignature,
}

/// I produce a join certificate for a new user.
/// This algorithm is run by the Group Manager.
/// * `prng` - source of randomness
/// * `msk` - group secret key
/// * `return` join certificate
pub fn gpsig_join_cert<R: CryptoRng + Rng>(prng: &mut R, msk: &GroupSecretKey) -> JoinCert {
  let tag = BLSScalar::random_scalar(prng);
  let sig = ps_sign_scalar(prng, &msk.sig_key, &tag);
  JoinCert { tag, sig }
}

/// I produce a group signature.
/// This algorithm is run by a user.
/// * `prng` - source of randomness
/// * `gpk` - group public key
/// * `join_cert` - join certificate
/// * `msg` - message to be signed
/// # Example
/// ```
/// use zei::crypto::simple_group_signatures::{gpsig_setup, gpsig_join_cert, gpsig_sign, gpsig_verify};
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let (gpk, msk) = gpsig_setup(&mut prng);
/// let join_cert = gpsig_join_cert(&mut prng, &msk);
/// let sig = gpsig_sign(&mut prng, &gpk, &join_cert, b"Some message");
/// assert!(gpsig_verify(&gpk, &sig, b"Some message").is_ok());
/// ```
pub fn gpsig_sign<R: CryptoRng + Rng>(prng: &mut R,
                                      gpk: &GroupPublicKey,
                                      join_cert: &JoinCert,
                                      msg: &[u8])
                                      -> GroupSignature {
  let g1_base = BLSG1::get_base();

  // 1. randomize signature
  let (_, rsig) = ps_randomize_sig(prng, &join_cert.sig);

  // 2. Encrypt tag
  let r = BLSScalar::random_scalar(prng);
  let enc = elgamal_encrypt(&g1_base, &join_cert.tag, &r, &gpk.enc_key);

  // 3. Signature proof of knowledge of r and tag such that ps_verify(rsig, tag) = 1 and enc = ElGamal(tag, r)
  let spok = signature_proof_of_knowledge(prng, gpk, &join_cert.tag, &r, msg);

  GroupSignature { cert: rsig,
                   enc,
                   spok }
}

/// Proof of knowledge containing the commitments and the responses.
pub struct PoK {
  commitments_g1: Vec<BLSG1>,
  commitments_g2: Vec<BLSG2>,
  responses: Vec<BLSScalar>,
}

/// I compute a signature of knowledge
/// * `prng` - source of randomness
/// * `gpk`- group public key
/// * `tag` - identity of the user
/// * `r` - randomness of the ciphertext
/// * `msg` - message to be signed
fn signature_proof_of_knowledge<R: CryptoRng + Rng>(prng: &mut R,
                                                    gpk: &GroupPublicKey,
                                                    tag: &BLSScalar,
                                                    r: &BLSScalar,
                                                    msg: &[u8])
                                                    -> PoK {
  let g1_base = BLSG1::get_base();
  let g2_base = BLSG2::get_base();

  // 1. Sample blindings
  let blind_tag = BLSScalar::random_scalar(prng);
  let blind_r = BLSScalar::random_scalar(prng);

  // 2. Compute proof commitments
  let com_yy_blind_tag = gpk.ver_key.yy.mul(&blind_tag); // commitment of tag under Y
  let com_g1_blind_tag = g1_base.mul(&blind_tag); // commitment of tag under g1
  let com_pk_blind_r = gpk.enc_key.0.mul(&blind_r); // commitment of r under PK
  let com_g1_blind_r = g1_base.mul(&blind_r); // commitment of r under g1
  let commitments_g1 = vec![com_g1_blind_tag, com_pk_blind_r, com_g1_blind_r];
  let commitments_g2 = vec![com_yy_blind_tag];

  // 3. Compute the challenge
  let challenge = compute_signature_pok_challenge(&g1_base,
                                                  &g2_base,
                                                  gpk,
                                                  commitments_g1.as_slice(),
                                                  commitments_g2.as_slice(),
                                                  msg);

  // 4. compute the response
  let tag_response = tag.mul(&challenge).add(&blind_tag);
  let r_response = r.mul(&challenge).add(&blind_r);

  PoK { commitments_g1,
        commitments_g2,
        responses: vec![tag_response, r_response] }
}

/// I compute the challenge based on the transcript
/// * `g1` - base of group G1
/// * `g2` - base of group G2
/// * `gpk` - group public key
/// * `commitments_g1` - commitments from group G1
/// * `commitments_g2` - commmitments from group G2
/// * `msg` - message
fn compute_signature_pok_challenge(g1: &BLSG1,
                                   g2: &BLSG2,
                                   gpk: &GroupPublicKey,
                                   commitments_g1: &[BLSG1],
                                   commitments_g2: &[BLSG2],
                                   msg: &[u8])
                                   -> BLSScalar {
  let mut hasher = Sha512::new();
  hasher.input(b"spok traceable group signature");
  hasher.input(g1.to_compressed_bytes());
  hasher.input(g2.to_compressed_bytes());
  hasher.input(gpk.enc_key.0.to_compressed_bytes());
  hasher.input(gpk.ver_key.xx.to_compressed_bytes());
  hasher.input(gpk.ver_key.yy.to_compressed_bytes());
  for e1 in commitments_g1 {
    hasher.input(e1.to_compressed_bytes());
  }
  for e2 in commitments_g2 {
    hasher.input(e2.to_compressed_bytes());
  }
  hasher.input(msg);
  BLSScalar::from_hash(hasher)
}

/// I verify a signature of knowledge
/// * `gpk` - group public key
/// * `sig` - group signature on message `msg`
/// * `msg` - message
fn verify_signature_pok(gpk: &GroupPublicKey,
                        sig: &GroupSignature,
                        msg: &[u8])
                        -> Result<(), ZeiError> {
  let g1_base = BLSG1::get_base();
  let g2_base = BLSG2::get_base();
  let commitments_g1 = &sig.spok.commitments_g1;
  let commitments_g2 = &sig.spok.commitments_g2;
  let challenge = compute_signature_pok_challenge(&g1_base,
                                                  &g2_base,
                                                  gpk,
                                                  commitments_g1.as_slice(),
                                                  commitments_g2.as_slice(),
                                                  msg);

  // 1 Verify ps_signature
  let xx = &gpk.ver_key.xx;
  let yy = &gpk.ver_key.yy;
  let com_yy_blind_tag = &commitments_g2[0];
  let response_tag = &sig.spok.responses[0];
  let elem = xx.mul(&challenge)
               .add(&yy.mul(response_tag))
               .sub(com_yy_blind_tag);
  let p1 = BLSGt::pairing(&sig.cert.s1, &elem);
  let p2 = BLSGt::pairing(&sig.cert.s2.mul(&challenge), &g2_base);

  if p1 != p2 {
    return Err(ZeiError::ZKProofVerificationError);
  }

  // 2 Verify tag encryption
  let com_g1_blind_tag = &sig.spok.commitments_g1[0];
  let com_pk_blind_r = &sig.spok.commitments_g1[1];
  let com_g1_blind_r = &sig.spok.commitments_g1[2];
  let response_r = &sig.spok.responses[1];
  let e1 = &sig.enc.e1;
  let e2 = &sig.enc.e2;

  // Check e1 correctness: e1 = r * G1
  if e1.mul(&challenge) != g1_base.mul(&response_r).sub(com_g1_blind_r) {
    return Err(ZeiError::ZKProofVerificationError);
  }

  // Check e2 correctness: e2 = tag * G1 + r * PK
  let a = g1_base.mul(&response_tag).sub(com_g1_blind_tag);
  let b = gpk.enc_key.0.mul(&response_r).sub(com_pk_blind_r);
  if e2.mul(&challenge) != a.add(&b) {
    return Err(ZeiError::ZKProofVerificationError);
  }

  Ok(())
}

/// I verify a group signature
/// * `gpk` - group public key
/// * `sig` - group signature
/// * `msg` - message
/// # Example
/// ```
/// // See gpsig_sign
/// ```
pub fn gpsig_verify(gpk: &GroupPublicKey,
                    sig: &GroupSignature,
                    msg: &[u8])
                    -> Result<(), ZeiError> {
  verify_signature_pok(gpk, sig, msg)
}

/// I recover the identity of the producer of a group signature.
/// This algorithm is run by the Group Manager.
/// * `sig` - signature
/// * `gp_sk` - group secret key
pub fn gpsig_open(sig: &GroupSignature, gp_sk: &GroupSecretKey) -> BLSG1 {
  elgamal_decrypt_elem(&sig.enc, &gp_sk.dec_key)
}
