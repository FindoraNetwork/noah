use crate::algebra::groups::{Group, Scalar};
use crate::algebra::pairing::PairingTargetGroup;
use crate::algebra::utils::group_linear_combination_rows;
use crate::basic_crypto::elgamal::{elgamal_encrypt, ElGamalCiphertext, ElGamalPublicKey};
use crate::crypto::anon_creds::{
  ac_vrfy_hidden_terms_addition, ACIssuerPublicKey, ACRevealSig,
  AC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE,
};
use crate::crypto::sigma::{SigmaTranscript, SigmaTranscriptPairing};
use crate::errors::ZeiError;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::ser::Serialize;
use sha2::{Digest, Sha512};

const CAC_REVEAL_PROOF_DOMAIN: &[u8] = b"Confidential AC Reveal PoK";
const CAC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE: &[u8] = b"Confidential AC Reveal PoK New Instance";

trait CACTranscript: SigmaTranscriptPairing {
  fn cac_init<P: PairingTargetGroup>(&mut self,
                                     ac_issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
                                     recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
                                     ac_reveal_sigs: &[&ACRevealSig<P::G1,
                                                    P::G2,
                                                    P::ScalarField>],
                                     ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]]);
  fn append_issuer_pk<P: PairingTargetGroup>(&mut self,
                                             ac_issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>);
  fn append_encryption_key<P: PairingTargetGroup>(&mut self, key: &ElGamalPublicKey<P::G1>);
  fn append_ciphertext<P: PairingTargetGroup>(&mut self, ctext: &ElGamalCiphertext<P::G1>);
  fn append_ac_reveal_sig<P: PairingTargetGroup>(&mut self,
                                                 ac_reveal_sig: &ACRevealSig<P::G1,
                                                              P::G2,
                                                              P::ScalarField>);
}

impl CACTranscript for Transcript {
  fn cac_init<P: PairingTargetGroup>(&mut self,
                                     ac_issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
                                     recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
                                     ac_reveal_sigs: &[&ACRevealSig<P::G1,
                                                    P::G2,
                                                    P::ScalarField>],
                                     ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]]) {
    self.append_message(b"New Domain", CAC_REVEAL_PROOF_DOMAIN);
    self.append_group_element(b"G1", &P::G1::get_base());
    self.append_group_element(b"G2", &P::G2::get_base());
    self.append_issuer_pk::<P>(ac_issuer_pk);
    for key in recv_enc_pub_keys.iter() {
      self.append_encryption_key::<P>(key);
    }
    for sig in ac_reveal_sigs.iter() {
      self.append_ac_reveal_sig::<P>(sig);
    }
    for ctexts in ctexts_vecs.iter() {
      for ctext in ctexts.iter() {
        self.append_ciphertext::<P>(ctext);
      }
    }
  }
  fn append_issuer_pk<P: PairingTargetGroup>(&mut self,
                                             ac_issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>) {
    self.append_group_element(b"issuer_pk.G2", &ac_issuer_pk.gen2);
    self.append_group_element(b"issuer_pk.Z1", &ac_issuer_pk.zz1);
    self.append_group_element(b"issuer_pk.Z2", &ac_issuer_pk.zz2);
    self.append_group_element(b"issuer_pk.X2", &ac_issuer_pk.xx2);
    for y2 in ac_issuer_pk.yy2.iter() {
      self.append_group_element(b"issuer_pk.Y2", y2);
    }
  }
  fn append_encryption_key<P: PairingTargetGroup>(&mut self, key: &ElGamalPublicKey<P::G1>) {
    self.append_group_element(b"encription key", key.get_point_ref());
  }
  fn append_ciphertext<P: PairingTargetGroup>(&mut self, ctext: &ElGamalCiphertext<P::G1>) {
    self.append_group_element(b"ctext.e1", &ctext.e1);
    self.append_group_element(b"ctext.e2", &ctext.e2);
  }
  fn append_ac_reveal_sig<P: PairingTargetGroup>(&mut self,
                                                 ac_reveal_sig: &ACRevealSig<P::G1,
                                                              P::G2,
                                                              P::ScalarField>) {
    self.append_group_element(b"sigma1", &ac_reveal_sig.sig.sigma1);
    self.append_group_element(b"sigma2", &ac_reveal_sig.sig.sigma2);
    self.append_group_element(b"pok.com", &ac_reveal_sig.pok.commitment);
    self.append_field_element(b"pok.response_t", &ac_reveal_sig.pok.response_t);
    self.append_field_element(b"pok.response_sk", &ac_reveal_sig.pok.response_sk);
    for response_attr in ac_reveal_sig.pok.response_attrs.iter() {
      self.append_field_element(b"pok.response_attr", response_attr);
    }
  }
}
/// Aggregated proof of knowledge of revealed attributes for an anonymous credential reveal signature
/// that are encrypted under ElGamal
/// # Arguments
///
/// * `attr_sum_com_yy2` - {sum blind_{attr_{j,k}} * Y2_j }_k for attr_{j,k} in encrypted attributes for each instance k. Cannot be aggregated
/// * `agg_attrs_coms_g` - \sum_k x_k* blind_{a_{j,k}} * G1 for attr_{j,k} in encrypted attributes
/// * `attrs_resps` - {{c*attr_{j,k} + blind_{attr_{j,k}} }_j}_k for each instance k, Cannot be aggregated
/// * `agg_rands_coms_g` - {\sum_k x_k * blind_{r_{j,k}} * G}_j
/// * `agg_rands_coms_pk` - {\sum_k x_k  * blind_{r_{j,k}} * PK_k }_j
/// * `rands_resps` - {(c*r_{j,k} + blind_{r_{i,k}})}_j}_k, this cannot be aggregated unless public keys are all equal

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggPoKAttrs<G1, G2, S> {
  pub attr_sum_com_yy2: Vec<G2>,
  pub agg_attrs_coms_g: Vec<G1>,
  pub attrs_resps: Vec<Vec<S>>,
  pub agg_rands_coms_g: Vec<G1>,
  pub agg_rands_coms_pk: Vec<G1>,
  pub rands_resps: Vec<Vec<S>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAC<P: PairingTargetGroup> {
  ctexts: Vec<ElGamalCiphertext<P::G1>>,
  ac_reveal_sig: ACRevealSig<P::G1, P::G2, P::ScalarField>,
  pok: AggPoKAttrs<P::G1, P::G2, P::ScalarField>,
}

pub fn cac_create<R: CryptoRng + RngCore, P: PairingTargetGroup>(
  prng: &mut R,
  cred_issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
  enc_key: &ElGamalPublicKey<P::G1>,
  attrs: &[P::ScalarField],
  reveal_map: &[bool],
  ac_reveal_sig: &ACRevealSig<P::G1, P::G2, P::ScalarField>)
  -> Result<ConfidentialAC<P>, ZeiError> {
  let mut ctexts = vec![];
  let mut rands = vec![];
  let base = P::G1::get_base();
  let mut revealed_attrs = vec![];
  for (attr, b) in attrs.iter().zip(reveal_map.iter()) {
    if *b {
      let r = P::ScalarField::random_scalar(prng);
      let ctext = elgamal_encrypt::<P::ScalarField, P::G1>(&base, attr, &r, enc_key);
      rands.push(r);
      ctexts.push(ctext);
      revealed_attrs.push(attr.clone());
    }
  }
  let mut transcript = Transcript::new(CAC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
  let pok_attrs_proof = agg_pok_attrs_prove::<_, P>(&mut transcript,
                                                    prng,
                                                    cred_issuer_pk,
                                                    &[enc_key],
                                                    &[revealed_attrs.as_slice()],
                                                    &[rands.as_slice()],
                                                    reveal_map,
                                                    &[ctexts.as_slice()],
                                                    &[ac_reveal_sig])?;

  Ok(ConfidentialAC { ctexts,
                      ac_reveal_sig: ac_reveal_sig.clone(),
                      pok: pok_attrs_proof })
}

pub fn cac_verify<P: PairingTargetGroup>(issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
                                         enc_key: &ElGamalPublicKey<P::G1>,
                                         reveal_map: &[bool],
                                         cac: &ConfidentialAC<P>)
                                         -> Result<(), ZeiError> {
  let mut transcript = Transcript::new(CAC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
  agg_pok_attrs_verify::<P>(&mut transcript,
                            issuer_pk,
                            &[&enc_key],
                            &[&cac.ac_reveal_sig],
                            &[&cac.ctexts],
                            &cac.pok,
                            reveal_map)
}

/// Computes an aggregated proof of knowledge of identity attribute sets to be verified against
/// encryption of these and a set of anonymous credential reveal proofs
/// * `prng` - source of randomness
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_keys` - list of encryption public keys for the receivers
/// * `attrs_vecs` - collection of list of attributes
/// * `ctexts_rand_vecs`- collection of lists containing the randomness used to encrypt the attributes
/// * `bitmap` - indicates which attributes should be revealed to the receiver
/// * `ctexts_vecs` - collection of lists containing ciphertexts that encrypt the attributes
/// * `ac_reveal_sigs` - collection of proofs that the issuer has signed some attributes
/// * `returns` - aggregated proof of knowledge for the attributes and randomness of ciphertexts
// TODO rewrite this function so that it has less arguments / handles simpler types.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub(crate) fn agg_pok_attrs_prove<R, P>(
  transcript: &mut Transcript,
  prng: &mut R,
  ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
  recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
  attrs_vecs: &[&[P::ScalarField]],
  ctexts_rand_vecs: &[&[P::ScalarField]],
  bitmap: &[bool],
  ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
  ac_reveal_sigs: &[&ACRevealSig<P::G1, P::G2, P::ScalarField>])
  -> Result<AggPoKAttrs<P::G1, P::G2, P::ScalarField>, ZeiError>
  where R: CryptoRng + RngCore,
        P: PairingTargetGroup
{
  // 0: sanity check on vector length
  let n_instances = attrs_vecs.len();
  if n_instances != ctexts_rand_vecs.len()
     || n_instances != ctexts_vecs.len()
     || n_instances != ac_reveal_sigs.len()
  {
    return Err(ZeiError::ParameterError);
  }
  let n_attrs = bitmap.iter().filter(|x| **x).count();
  if n_attrs > bitmap.len() {
    return Err(ZeiError::ParameterError);
  }

  transcript.cac_init::<P>(ac_issuer_pub_key,
                           recv_enc_pub_keys,
                           ac_reveal_sigs,
                           ctexts_vecs);
  // 1: sample secrets' blinds and compute proof commitments.
  let (attr_sum_com_yy2, (attrs_coms_g, rands_coms_g, rands_coms_pk), (attrs_blinds, rands_blinds)) =
    sample_blinds_compute_commitments::<_, P>(prng,
                                              ac_issuer_pub_key,
                                              recv_enc_pub_keys,
                                              bitmap,
                                              n_attrs,
                                              n_instances)?;

  // 2: sample linear combination scalars
  let lc_scalars = compute_linear_combination_scalars::<P>(ctexts_vecs, ac_reveal_sigs);

  // 3: aggregate attributes blinding commitments under G and PK
  let agg_attrs_coms_g =
    group_linear_combination_rows(lc_scalars.as_slice(), attrs_coms_g.as_slice());
  let agg_rands_coms_g =
    group_linear_combination_rows(lc_scalars.as_slice(), rands_coms_g.as_slice());
  let agg_rands_coms_pk =
    group_linear_combination_rows(lc_scalars.as_slice(), rands_coms_pk.as_slice());

  // 4: Compute challenge for the proof and scalars for linear combination
  for e in attr_sum_com_yy2.iter() {
    transcript.append_proof_commitment::<P::ScalarField, P::G2>(e);
  }
  for e in agg_attrs_coms_g.iter() {
    transcript.append_proof_commitment::<P::ScalarField, P::G1>(e);
  }
  for e in agg_rands_coms_g.iter() {
    transcript.append_proof_commitment::<P::ScalarField, P::G1>(e);
  }
  for e in agg_rands_coms_pk.iter() {
    transcript.append_proof_commitment::<P::ScalarField, P::G1>(e);
  }

  let challenge = transcript.get_challenge::<P::ScalarField>();

  // 5: compute proof responses
  let mut attrs_resps = vec![];
  let mut rands_resps = vec![];
  for (attrs_k, rands_k, attrs_blinds_k, rands_blinds_k) in
    izip!(attrs_vecs, ctexts_rand_vecs, attrs_blinds, rands_blinds)
  {
    let (attrs_resps_k, rands_resps_k) =
      compute_proof_responses::<P::ScalarField>(&challenge,
                                                *attrs_k,
                                                attrs_blinds_k.as_slice(),
                                                *rands_k,
                                                rands_blinds_k.as_slice());
    attrs_resps.push(attrs_resps_k);
    rands_resps.push(rands_resps_k);
  }

  // 6: build struct and return
  Ok(AggPoKAttrs { attr_sum_com_yy2,
                   agg_attrs_coms_g,
                   agg_rands_coms_g,
                   agg_rands_coms_pk,
                   attrs_resps,
                   rands_resps })
}

/// Verifies an aggregated proof of knowledge involving identity attributes and ciphertexts
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_keys` - list of encryption public keys for the receivers
/// * `ac_reveal_sigs` - collection of proofs that the issuer has signed some attributes
/// * `ctexts_vecs` - collection of lists containing ciphertexts that encrypt the attributes
/// * `agg_pok_attrs` - aggregated proof of knowledge computed through the function agg_pok_attrs_prove
/// * `bitmap` - indicates which attributes should be revealed to the receiver
/// * `returns` - nothing if the verification passes, an error otherwise
pub(crate) fn agg_pok_attrs_verify<P: PairingTargetGroup>(transcript: &mut Transcript,
                                                          ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                          recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
                                                          ac_reveal_sigs: &[&ACRevealSig<P::G1, P::G2, P::ScalarField>],
                                                          ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
                                                          agg_pok_attrs: &AggPoKAttrs<P::G1,
                                                            P::G2,
                                                            P::ScalarField>,
                                                          bitmap: &[bool] // indicates which attributes should be revealed to the receiver
) -> Result<(), ZeiError> {
  transcript.cac_init::<P>(ac_issuer_pub_key,
                           recv_enc_pub_keys,
                           ac_reveal_sigs,
                           ctexts_vecs);
  // 1. compute linear combination scalars
  let lc_scalars = compute_linear_combination_scalars::<P>(ctexts_vecs, ac_reveal_sigs);

  // 2. compute challenge
  for e in agg_pok_attrs.attr_sum_com_yy2.iter() {
    transcript.append_proof_commitment::<P::ScalarField, P::G2>(e);
  }
  for e in agg_pok_attrs.agg_attrs_coms_g.iter() {
    transcript.append_proof_commitment::<P::ScalarField, P::G1>(e);
  }
  for e in agg_pok_attrs.agg_rands_coms_g.iter() {
    transcript.append_proof_commitment::<P::ScalarField, P::G1>(e);
  }
  for e in agg_pok_attrs.agg_rands_coms_pk.iter() {
    transcript.append_proof_commitment::<P::ScalarField, P::G1>(e);
  }

  let challenge = transcript.get_challenge::<P::ScalarField>();

  // 3. verify ciphertexts
  verify_ciphertext::<P>(&challenge,
                         &lc_scalars[..],
                         ctexts_vecs,
                         &agg_pok_attrs.agg_attrs_coms_g[..],
                         &agg_pok_attrs.agg_rands_coms_g[..],
                         &agg_pok_attrs.agg_rands_coms_pk[..],
                         &agg_pok_attrs.attrs_resps[..],
                         &agg_pok_attrs.rands_resps[..],
                         recv_enc_pub_keys)?;

  // 4. verify credentials
  verify_credential_agg::<P>(&challenge,
                             lc_scalars.as_slice(),
                             ac_reveal_sigs,
                             agg_pok_attrs.attr_sum_com_yy2.as_slice(),
                             agg_pok_attrs.attrs_resps.as_slice(),
                             ac_issuer_pub_key,
                             bitmap)?;
  Ok(())
}

/// I hash the parameters to sample a set of scalars used to aggregate proofs,
/// one scalar per instance. First scalar is 1.
/// * `ctexts_vecs` - collection of lists containing ciphertexts
/// * `ac_reveal_sigs` - collection of proofs that the issuer has signed some attributes
/// * `returns` - a vector of scalars
fn compute_linear_combination_scalars<P: PairingTargetGroup>(ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
                                                             ac_reveal_sigs: &[&ACRevealSig<P::G1, P::G2, P::ScalarField>])
                                                             -> Vec<P::ScalarField> {
  if ctexts_vecs.is_empty() {
    return vec![];
  }

  let mut scalars = vec![P::ScalarField::from_u32(1)];
  if ctexts_vecs.len() == 1 {
    return scalars;
  }

  let mut hash = Sha512::new();
  let mut ac_reveal_sig_vec = vec![];
  ac_reveal_sigs.serialize(&mut rmp_serde::Serializer::new(&mut ac_reveal_sig_vec))
                .unwrap();
  hash.input(ac_reveal_sig_vec.as_slice());

  for ctext_vec in ctexts_vecs.iter() {
    for ctext in *ctext_vec {
      hash.input(ctext.e1.to_compressed_bytes());
      hash.input(ctext.e1.to_compressed_bytes());
    }
  }
  let mut xi = P::ScalarField::from_hash(hash);
  for _ in 2..ctexts_vecs.len() {
    let mut hash = Sha512::new();
    hash.input(xi.to_bytes());
    let new_xi = P::ScalarField::from_hash(hash);
    scalars.push(xi);
    xi = new_xi;
  }

  scalars.push(xi);
  scalars
}

/// I verify a proof of knowledge of a set of ElGamal encrypted messages
/// * `challenge` - challenge value generated using Fiat-Shamir
/// * `lc_scalars` - scalars obtained via linear combination of other scalars
/// * `ctexts_vec`- collection of lists of ciphertexts of attributes
/// * `attr_commitments` - commitments for the attributes
/// * `rand_commitments_g` - Encryption randomness commitments related to base g
/// * `rand_commitments_pk` - Encryption randomness commitments relative the public key
/// * `attr_responses` - response to challenge for the attributes
/// * `rand_responses` - encryption random response
/// * `recv_enc_pub_keys`- encryption public keys of the recipients
/// * `return` - nothing if the verification is successful, error otherwise
// TODO rewrite this function so that it has less arguments
#[allow(clippy::too_many_arguments)]
fn verify_ciphertext<P: PairingTargetGroup>(challenge: &P::ScalarField,
                                            lc_scalars: &[P::ScalarField],
                                            ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
                                            attr_commitments: &[P::G1],
                                            rand_commitments_g: &[P::G1],
                                            rand_commitments_pk: &[P::G1],
                                            attr_responses: &[Vec<P::ScalarField>],
                                            rand_responses: &[Vec<P::ScalarField>],
                                            recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>])
                                            -> Result<(), ZeiError> {
  //1. Aggregate attributes and rand responses, and ciphertexts
  let mut agg_g_x_attr_resp = vec![]; // {sum_k x_k * r_{attr_{i,k}} * G}_i
  let mut agg_g_x_rand_resp = vec![]; // {sum_k x_k * r_{rand_{i,k}} * G}_i
  let mut agg_pk_x_rand_resp = vec![]; // {sum_k x_k * r_{rand_{i,k}} * PK_k}_i
  let mut agg_ctexts = vec![]; // {( sum x_k * e1_{i,k}, \sum x_k * e2_{i,k})}_i

  let n_attrs = attr_responses[0].len();
  for i in 0..n_attrs {
    let mut sum_pk_rand = P::G1::get_identity();
    let mut sum_g_rand = P::ScalarField::from_u32(0); // aggregate scalars first
    let mut sum_g_attr = P::ScalarField::from_u32(0); // aggregate scalars first

    let mut sum_e1 = P::G1::get_identity(); // ElGamalCiphertext 1st coordinate
    let mut sum_e2 = P::G1::get_identity(); // ElGamalCiphertext 2nd coordinate

    for (pub_key, rand_resp_inst, attr_resp_inst, ctexts_inst, scalar) in
      izip!(recv_enc_pub_keys.iter(),
            rand_responses.iter(),
            attr_responses.iter(),
            ctexts_vecs.iter(),
            lc_scalars.iter())
    {
      let scalar_factor = rand_resp_inst[i].mul(scalar);
      sum_pk_rand = sum_pk_rand.add(&(*pub_key).get_point_ref().mul(&scalar_factor));

      sum_g_rand = sum_g_rand.add(&scalar_factor);
      sum_g_attr = sum_g_attr.add(&attr_resp_inst[i].mul(scalar));

      sum_e1 = sum_e1.add(&ctexts_inst[i].e1.mul(scalar));
      sum_e2 = sum_e2.add(&ctexts_inst[i].e2.mul(scalar));
    }
    // aggregates rand responses
    agg_pk_x_rand_resp.push(sum_pk_rand);
    agg_g_x_rand_resp.push(P::G1::get_base().mul(&sum_g_rand));

    // aggregates attribute responses
    agg_g_x_attr_resp.push(P::G1::get_base().mul(&sum_g_attr));

    //aggregated ciphertexs
    agg_ctexts.push(ElGamalCiphertext { e1: sum_e1,
                                        e2: sum_e2 })
  }

  //TODO Use multi-exponentiation, then aggregate
  for (ctext, attr_com, rand_coms_g, rand_coms_pk, g_x_attr_resp, g_x_rand_resp, pk_x_rand_resp) in
    izip!(agg_ctexts,
          attr_commitments,
          rand_commitments_g,
          rand_commitments_pk,
          agg_g_x_attr_resp,
          agg_g_x_rand_resp,
          agg_pk_x_rand_resp)
  {
    let e1 = &ctext.e1;
    let e2 = &ctext.e2;

    let verify_e1 = e1.mul(challenge).add(rand_coms_g) == g_x_rand_resp;
    let verify_e2 =
      e2.mul(&challenge).add(rand_coms_pk).add(attr_com) == g_x_attr_resp.add(&pk_x_rand_resp);
    if !(verify_e1 && verify_e2) {
      return Err(ZeiError::IdentityRevealVerifyError);
    }
  }
  Ok(())
}

/// I verify a proof of knowledge of attributes that verify an anonymous credential reveal proof.
/// * `challenge` - challenge from the verifier
/// * `lc_scalars` - scalars obtained via linear combination of other scalars
/// * `ac_reveal_sigs` -  collection of proofs that the issuer has signed some attributes
/// * `attr_sum_com_yy2` - attributes commitment
/// * `attr_resps` - attribute responses
/// * `issuer_pub_key` - (signing) public key of the issuer
/// * `bitmap` - policy, indicates which attributes needs to be revealed to the receiver
fn verify_credential_agg<P: PairingTargetGroup>(challenge: &P::ScalarField,
                                                lc_scalars: &[P::ScalarField],
                                                ac_reveal_sigs: &[&ACRevealSig<P::G1,
                                                  P::G2,
                                                  P::ScalarField>],
                                                attr_sum_com_yy2: &[P::G2],
                                                attr_resps: &[Vec<P::ScalarField>],
                                                issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                bitmap: &[bool])
                                                -> Result<(), ZeiError> {
  // 1. For each credential instance k compute challenge c_k
  // 2. For each credential instance k compute P_k = challenge * H_k + challenges_k * R_k where
  //  A is credential proof terms for x, t, sk, Hidden attributes
  //  and R_k correspond to the credential proof "revealed" attributes
  // 3. Aggregate signatures for the righ-hand-side of the pairing:
  //    \sigma2 = challenge * \sum_k x_k * challenges_k * sigma2_k
  let mut pp = vec![];
  let mut agg_sigma2 = P::G1::get_identity();
  let mut ck_vec = vec![];
  for (lc_scalar_k, reveal_sig_k, attr_sum_com_k, attr_resp_k) in
    izip!(lc_scalars, ac_reveal_sigs, attr_sum_com_yy2, attr_resps)
  {
    let mut transcript = Transcript::new(AC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
    crate::crypto::anon_creds::init_transcript::<P>(&mut transcript,
                                                    issuer_pub_key,
                                                    &reveal_sig_k.sig);
    transcript.append_proof_commitment(&reveal_sig_k.pok.commitment);
    let c_k = transcript.get_challenge::<P::ScalarField>();

    let hidden_k = ac_vrfy_hidden_terms_addition::<P>(&c_k, reveal_sig_k, issuer_pub_key, bitmap)?;

    let revealed_k =
      ac_vrfy_zk_revealed_terms_addition::<P>(issuer_pub_key, attr_sum_com_k, attr_resp_k, bitmap)?;

    let pp_k = hidden_k.mul(challenge).add(&revealed_k.mul(&c_k));
    pp.push(pp_k);
    agg_sigma2 = agg_sigma2.add(&reveal_sig_k.sig.sigma2.mul(&c_k.mul(lc_scalar_k)));

    ck_vec.push(c_k);
  }
  agg_sigma2 = agg_sigma2.mul(challenge);

  //3. Compute right hand side pairing: e(sigma2, G2)
  let rhs = P::pairing(&agg_sigma2, &issuer_pub_key.gen2);

  //4. Compute left hand side as \sum_k e(sigma1_k, P_k)
  let mut lhs = P::get_identity();
  for (lc_scalar_k, ac_reveal_sig_k, pp_k) in izip!(lc_scalars, ac_reveal_sigs, pp) {
    let lhs_i = P::pairing(&ac_reveal_sig_k.sig.sigma1.mul(lc_scalar_k), &pp_k);
    lhs = lhs.add(&lhs_i);
  }

  //5. return Ok if LHS = RHS
  if lhs == rhs {
    Ok(())
  } else {
    Err(ZeiError::IdentityRevealVerifyError)
  }
}

/// For each secret value,
/// a) sample a blinding scalar,
/// b) compute proof commitments of this scalars to be used in a PoK of the secret values that
/// verify an anonymous credential reveal proof and matched ElGamal encryptions
/// * `prng` - randomness source
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_keys` - list of encryption keys of the receivers
/// * `bitmap` - policy, indicates which attributes needs to be revealed to the receiver
/// * `n_attrs` - number of attributes
/// * `n_instances` - number of ac instances (also equal to the number of recipients
/// * `returns` - vector of random commitments
#[allow(clippy::type_complexity)]
fn sample_blinds_compute_commitments<R, P>(
  prng: &mut R,
  ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
  recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
  bitmap: &[bool],
  n_attrs: usize,
  n_instances: usize)
  -> Result<(Vec<P::G2>,
             (Vec<Vec<P::G1>>, Vec<Vec<P::G1>>, Vec<Vec<P::G1>>),
             (Vec<Vec<P::ScalarField>>, Vec<Vec<P::ScalarField>>)),
            ZeiError>
  where R: CryptoRng + RngCore,
        P: PairingTargetGroup
{
  let mut attr_sum_com_yy2 = Vec::with_capacity(n_instances);
  let mut attrs_coms_g: Vec<Vec<P::G1>> = Vec::with_capacity(n_instances);
  let mut rands_coms_g = Vec::with_capacity(n_instances);
  let mut rands_coms_pk = Vec::with_capacity(n_instances);

  let (attrs_blinds, rands_blinds) = sample_blinds::<R, P::ScalarField>(prng, n_attrs, n_instances);

  for k in 0..n_instances {
    attr_sum_com_yy2.push(compute_attr_sum_yy2::<P>(
      ac_issuer_pub_key,
      attrs_blinds.get(k).ok_or(ZeiError::ParameterError)?,
      bitmap)?);
    attrs_coms_g.push(Vec::with_capacity(n_attrs));
    rands_coms_g.push(Vec::with_capacity(n_attrs));
    rands_coms_pk.push(Vec::with_capacity(n_attrs));
    for (attr_blind, rand_blind) in
      izip!(attrs_blinds.get(k).unwrap(), rands_blinds.get(k).unwrap())
    {
      attrs_coms_g[k].push(P::G1::get_base().mul(&attr_blind));
      rands_coms_g[k].push(P::G1::get_base().mul(&rand_blind));
      rands_coms_pk[k].push(recv_enc_pub_keys[k].get_point_ref().mul(&rand_blind));
    }
  }

  Ok((attr_sum_com_yy2, (attrs_coms_g, rands_coms_g, rands_coms_pk), (attrs_blinds, rands_blinds)))
}
/// Helper function
/// Computes proof commitments
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `attr_blinds` - vector of random commitments used to hide the attributes
/// * `bitmap` - policy, indicates which attributes needs to be revealed to the receiver
/// * `returns`- group element in G2
fn compute_attr_sum_yy2<P: PairingTargetGroup>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1,
                                                                  P::G2>,
                                               attr_blinds: &[P::ScalarField],
                                               bitmap: &[bool])
                                               -> Result<P::G2, ZeiError> {
  let mut attr_sum_com_yy2 = P::G2::get_identity();
  let mut blind_iter = attr_blinds.iter();
  for (yy2j, shown) in ac_issuer_pub_key.yy2.iter().zip(bitmap.iter()) {
    if *shown {
      let attr_com_y2j = yy2j.mul(blind_iter.next().ok_or(ZeiError::ParameterError)?);
      attr_sum_com_yy2 = attr_sum_com_yy2.add(&attr_com_y2j);
    }
  }
  Ok(attr_sum_com_yy2)
}

/// I sample proof blindings for every attribute and encryption randomness for every instance
/// * `prng` - randomness source
/// * `n_attrs` - number of attributes
/// * `n_instances` - number of ac instances (also equal to the number of recipients
/// * `returns` - a vector of blinded attributes and a vector of random blinding value
fn sample_blinds<R, S>(prng: &mut R,
                       n_attrs: usize,
                       n_instances: usize)
                       -> (Vec<Vec<S>>, Vec<Vec<S>>)
  where R: CryptoRng + RngCore,
        S: Scalar
{
  let mut attr_blinds = vec![];
  let mut rand_blinds = vec![];
  for j in 0..n_instances {
    attr_blinds.push(vec![]);
    rand_blinds.push(vec![]);
    for _ in 0..n_attrs {
      attr_blinds[j].push(S::random_scalar(prng));
      rand_blinds[j].push(S::random_scalar(prng));
    }
  }
  (attr_blinds, rand_blinds)
}

/// Using a challenge, secret values and their blindings, I compute the proof responses of a PoK
/// * `challenge` - challenge obtained from function cac_reveal_challenge_agg
/// * `attrs` - list of attributes
/// * `attr_blind` - blinding factors for attributes
/// * `ctexts_rand` - ciphertexts randomness
/// * `rand_blind` - randomness blinding factor
/// * `returns` - responses to the challenge
fn compute_proof_responses<S: Scalar>(challenge: &S,
                                      attrs: &[S],
                                      attr_blind: &[S],
                                      ctexts_rand: &[S],
                                      rand_blind: &[S])
                                      -> (Vec<S>, Vec<S>) {
  let m = attr_blind.len();
  let mut attr_responses = Vec::with_capacity(m);
  let mut rand_responses = Vec::with_capacity(m);

  for (attr, blind) in attrs.iter().zip(attr_blind.iter()) {
    attr_responses.push(attr.mul(&challenge).add(&blind));
  }
  for (rand, blind) in ctexts_rand.iter().zip(rand_blind.iter()) {
    rand_responses.push(rand.mul(&challenge).add(&blind));
  }

  (attr_responses, rand_responses)
}

/// Helper function that compute the term of an anonymous credential verification
/// that DO include the revealed attributes, using the proof of knowledge of these attributes
/// rather than the plain attributes. That is:
/// sum_{j\in Revealed} b'_{attr_j} * Y2_j - PoK.attr_sum_com_yy2
///  = c' * sum_{j\in Revealed} attr_j * y_j * G2
/// * `ac_issuer_public_key` - (signing) public key of the issuer
/// * `attr_sum_com` - commitment to attributed blinding
/// * `attr_resps` - attributes responses
/// * `bitmap` - policy, indicates which attributes needs to be revealed to the receiver`
/// * `return` - group element of G2
fn ac_vrfy_zk_revealed_terms_addition<P: PairingTargetGroup>(ac_issuer_public_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                             attr_sum_com: &P::G2,
                                                             attr_resps: &[P::ScalarField],
                                                             bitmap: &[bool])
                                                             -> Result<P::G2, ZeiError> {
  let mut addition = P::G2::get_identity();
  let mut attr_resp_iter = attr_resps.iter();
  for (bj, yy2_j) in bitmap.iter().zip(ac_issuer_public_key.yy2.iter()) {
    if *bj {
      let attr_resp = attr_resp_iter.next().ok_or(ZeiError::ParameterError)?;
      addition = addition.add(&yy2_j.mul(attr_resp));
    }
  }
  addition = addition.sub(attr_sum_com);
  Ok(addition)
}

#[cfg(test)]
pub(crate) mod test_helper {
  use crate::algebra::groups::Group;
  use crate::algebra::pairing::PairingTargetGroup;
  use crate::basic_crypto::elgamal::elgamal_keygen;
  use crate::crypto::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_reveal, ac_sign};
  use crate::crypto::conf_cred_reveal::{cac_create, cac_verify};
  use crate::errors::ZeiError;
  use crate::utils::byte_slice_to_scalar;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  pub fn test_confidential_ac_reveal<P: PairingTargetGroup>(reveal_bitmap: &[bool]) {
    let num_attr = reveal_bitmap.len();
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let (issuer_pk, issuer_sk) = ac_keygen_issuer::<_, P>(&mut prng, num_attr);
    let (user_pk, user_sk) = ac_keygen_user::<_, P>(&mut prng, &issuer_pk);
    let (_, enc_key) = elgamal_keygen::<_, P::ScalarField, P::G1>(&mut prng, &P::G1::get_base());

    let mut attrs = Vec::new();
    for i in 0..num_attr {
      attrs.push(byte_slice_to_scalar(format!("attr{}!", i).as_bytes()));
    }

    let ac_sig = ac_sign::<_, P>(&mut prng, &issuer_sk, &user_pk, &attrs[..]);
    let credential = ac_reveal::<_, P>(&mut prng,
                                       &user_sk,
                                       &issuer_pk,
                                       &ac_sig,
                                       &attrs[..],
                                       &reveal_bitmap[..]).unwrap();
    let conf_reveal_proof = cac_create::<_, P>(&mut prng,
                                               &issuer_pk,
                                               &enc_key,
                                               &attrs[..],
                                               &reveal_bitmap[..],
                                               &credential).unwrap();
    assert!(cac_verify(&issuer_pk, &enc_key, &reveal_bitmap[..], &conf_reveal_proof).is_ok());

    // Error cases /////////////////////////////////////////////////////////////////////////////////

    // Tampered bitmap
    let mut tampered_bitmap = vec![];
    tampered_bitmap.extend_from_slice(reveal_bitmap);

    let b = reveal_bitmap.get(0).unwrap();

    tampered_bitmap[0] = !(*b);

    let vrfy = cac_verify(&issuer_pk,
                          &enc_key,
                          &tampered_bitmap[..],
                          &conf_reveal_proof);
    assert_eq!(Err(ZeiError::ParameterError), vrfy, "proof should fail");

    // Empty bitmap
    let empty_bitmap = vec![];
    let vrfy = cac_verify(&issuer_pk, &enc_key, &empty_bitmap[..], &conf_reveal_proof);
    assert_eq!(Err(ZeiError::IdentityRevealVerifyError),
               vrfy,
               "proof should fail");

    // Wrong issuer public key
    let (another_issuer_pk, _) = ac_keygen_issuer::<_, P>(&mut prng, num_attr);
    let vrfy = cac_verify(&another_issuer_pk,
                          &enc_key,
                          &tampered_bitmap[..],
                          &conf_reveal_proof);
    assert!(vrfy == Err(ZeiError::IdentityRevealVerifyError)
            || vrfy == Err(ZeiError::ParameterError),
            "proof should fail");

    // Wrong encryption public key
    let (_, another_enc_key) =
      elgamal_keygen::<_, P::ScalarField, P::G1>(&mut prng, &P::G1::get_base());
    let vrfy = cac_verify(&issuer_pk,
                          &another_enc_key,
                          &empty_bitmap[..],
                          &conf_reveal_proof);
    assert_eq!(Err(ZeiError::IdentityRevealVerifyError),
               vrfy,
               "proof should fail");
  }
}

#[cfg(test)]
mod test_bn {
  use crate::algebra::bn::BNGt;
  use crate::crypto::conf_cred_reveal::test_helper::test_confidential_ac_reveal;

  #[test]
  fn confidential_reveal_one_attr_hidden() {
    test_confidential_ac_reveal::<BNGt>(&[false, false, false]);
  }

  #[test]
  fn confidential_reveal_one_attr_revealed() {
    test_confidential_ac_reveal::<BNGt>(&[true]);
  }

  #[test]
  fn confidential_reveal_two_attr_hidden_first() {
    test_confidential_ac_reveal::<BNGt>(&[false, false]);
    test_confidential_ac_reveal::<BNGt>(&[false, true]);
  }

  #[test]
  fn confidential_reveal_two_attr_revealed_first() {
    test_confidential_ac_reveal::<BNGt>(&[true, false]);
    test_confidential_ac_reveal::<BNGt>(&[true, true]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_hidden() {
    test_confidential_ac_reveal::<BNGt>(&[false; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_revealed() {
    test_confidential_ac_reveal::<BNGt>(&[true; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_half_revealed() {
    test_confidential_ac_reveal::<BNGt>(&[true, false, true, false, true, false, true, false,
                                          true, false]);
    test_confidential_ac_reveal::<BNGt>(&[false, true, false, true, false, true, false, true,
                                          false, true]);
  }
}

#[cfg(test)]
mod test_bls12_381 {
  use crate::algebra::bls12_381::BLSGt;
  use crate::crypto::conf_cred_reveal::test_helper::test_confidential_ac_reveal;

  #[test]
  fn confidential_reveal_one_attr_hidden() {
    test_confidential_ac_reveal::<BLSGt>(&[false]);
  }

  #[test]
  fn confidential_reveal_one_attr_revealed() {
    test_confidential_ac_reveal::<BLSGt>(&[true]);
  }

  #[test]
  fn confidential_reveal_two_attr_hidden_first() {
    test_confidential_ac_reveal::<BLSGt>(&[false, false]);
    test_confidential_ac_reveal::<BLSGt>(&[false, true]);
  }

  #[test]
  fn confidential_reveal_two_attr_revealed_first() {
    test_confidential_ac_reveal::<BLSGt>(&[true, false]);
    test_confidential_ac_reveal::<BLSGt>(&[true, true]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_hidden() {
    test_confidential_ac_reveal::<BLSGt>(&[false; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_revealed() {
    test_confidential_ac_reveal::<BLSGt>(&[true; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_half_revealed() {
    test_confidential_ac_reveal::<BLSGt>(&[true, false, true, false, true, false, true, false,
                                           true, false]);
    test_confidential_ac_reveal::<BLSGt>(&[false, true, false, true, false, true, false, true,
                                           false, true]);
  }
}

#[cfg(test)]
mod test_serialization {

  use crate::algebra::bls12_381::BLSGt;
  use crate::algebra::bn::BNGt;
  use crate::algebra::groups::Group;
  use crate::algebra::pairing::PairingTargetGroup;
  use crate::basic_crypto::elgamal::elgamal_keygen;
  use crate::crypto::anon_creds::ac_sign;
  use crate::crypto::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_reveal};
  use crate::crypto::conf_cred_reveal::cac_create;
  use crate::crypto::conf_cred_reveal::ConfidentialAC;
  use crate::utils::byte_slice_to_scalar;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
  use rmp_serde::Deserializer;
  use serde::{Deserialize, Serialize};

  fn gen_confidential_ac<P>() -> ConfidentialAC<P>
    where P: PairingTargetGroup + std::fmt::Debug
  {
    let reveal_bitmap = [true, false, true, true];
    let num_attr = reveal_bitmap.len();

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let (issuer_pk, issuer_sk) = ac_keygen_issuer::<_, P>(&mut prng, num_attr);
    let (user_pk, user_sk) = ac_keygen_user::<_, P>(&mut prng, &issuer_pk);
    let (_, enc_key) = elgamal_keygen::<_, P::ScalarField, P::G1>(&mut prng, &P::G1::get_base());

    let mut attrs = Vec::new();
    for i in 0..num_attr {
      attrs.push(byte_slice_to_scalar(format!("attr{}!", i).as_bytes()));
    }

    let ac_sig = ac_sign::<_, P>(&mut prng, &issuer_sk, &user_pk, &attrs[..]);
    let credential = ac_reveal::<_, P>(&mut prng,
                                       &user_sk,
                                       &issuer_pk,
                                       &ac_sig,
                                       &attrs[..],
                                       &reveal_bitmap[..]).unwrap();
    let conf_reveal_proof = cac_create::<_, P>(&mut prng,
                                               &issuer_pk,
                                               &enc_key,
                                               &attrs[..],
                                               &reveal_bitmap[..],
                                               &credential).unwrap();
    conf_reveal_proof
  }

  fn to_json<P: PairingTargetGroup + std::fmt::Debug>() {
    let confidential_ac = gen_confidential_ac::<P>();

    let json_str = serde_json::to_string(&confidential_ac).unwrap();
    let confidential_ac_de: ConfidentialAC<P> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(confidential_ac, confidential_ac_de);
  }

  fn to_msg_pack<P: PairingTargetGroup + std::fmt::Debug>() {
    let confidential_ac = gen_confidential_ac::<P>();
    //keys serialization
    let mut vec = vec![];
    confidential_ac.serialize(&mut rmp_serde::Serializer::new(&mut vec))
                   .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let confidential_ac_de: ConfidentialAC<P> = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(confidential_ac, confidential_ac_de);
  }

  #[test]
  fn to_json_bls() {
    to_json::<BLSGt>();
  }

  #[test]
  fn to_json_bn() {
    to_json::<BNGt>();
  }

  #[test]
  fn to_msg_pack_bls() {
    to_msg_pack::<BLSGt>();
  }

  #[test]
  fn to_msg_pack_bn() {
    to_msg_pack::<BNGt>();
  }
}
