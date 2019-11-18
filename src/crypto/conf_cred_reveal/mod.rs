pub mod test_helpers;

use crate::algebra::groups::{Group, Scalar};
use crate::algebra::pairing::PairingTargetGroup;
use crate::algebra::utils::group_linear_combination_rows;
use crate::basic_crypto::elgamal::{ElGamalCiphertext, ElGamalPublicKey};
use crate::crypto::anon_creds::{
  ac_challenge, ac_vrfy_hidden_terms_addition, ACIssuerPublicKey, ACRevealSig,
};
use crate::errors::ZeiError;
use rand::{CryptoRng, Rng};
use serde::ser::Serialize;
use sha2::{Digest, Sha512};

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

/// Proof of knowledge of attributes that a) are elgamal encrypted, and b) verify an anonymous credential reveal proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CACProof<G1, G2, S>(pub(crate) AggPoKAttrs<G1, G2, S>);

/// I produce a CACProof for a single instance of a confidential anonymous reveal. Proof asserts
/// that a list of attributes can be decrypted from a list of ciphertexts under recv_enc_pub_key,
/// and that these attributed verify an anonymous credential reveal proof.
/// * `prng` - randomness source
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_key` - encryption public key of the receiver
/// * `attrs` - attributes to prove knowledge of
/// * `ctexts_rand` - randomness used to encrypt attrs
/// * `bitmap` - indicates position of each attribute to prove
/// * `ctexts` - list of ciphertexts that encrypt the attributes
/// * `ac_reveal_sig` - proof that the issuer has signed some attributes
/// * `returns` - proof that the ciphertexts contains the attributes that have been signed by some issuer for the user.
/// # Example
/// ```
/// use zei::crypto::conf_cred_reveal::test_helpers::{setup_ac, ac_gen_proofs_and_ciphertexts};
/// use zei::crypto::conf_cred_reveal::{cac_prove, cac_verify};
/// use zei::algebra::bls12_381::BLSGt;
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// let mut prng: ChaChaRng;
///
/// let mut prng: ChaChaRng;
/// prng = ChaChaRng::from_seed([0u8; 32]);
/// let reveal_bitmap = [true, false, true, false, true, false, true, false, true, false];
/// let (ac_issuer_pub_key, ac_issuer_sk, user_pk, user_sk, recv_enc_pub_key, _) =
///    setup_ac::<BLSGt>(&mut prng, reveal_bitmap.len());
/// let (revealed_attrs, mut ctexts, ctext_rands, mut proof) =
///    ac_gen_proofs_and_ciphertexts::<BLSGt>(&mut prng,
///                                       &ac_issuer_pub_key,
///                                       &ac_issuer_sk,
///                                       &user_pk,
///                                       &user_sk,
///                                       &recv_enc_pub_key,
///                                       &reveal_bitmap);
///
/// let mut cac_proof = cac_prove::<_, BLSGt>(&mut prng,
///                                        &ac_issuer_pub_key,
///                                        &recv_enc_pub_key,
///                                        &revealed_attrs.as_slice(),
///                                        &ctext_rands.as_slice(),
///                                        &reveal_bitmap,
///                                        &ctexts.as_slice(),
///                                        &proof).unwrap();
///
/// let vrfy = cac_verify::<BLSGt>(&ac_issuer_pub_key,
///                             &recv_enc_pub_key,
///                             &proof,
///                             ctexts.as_slice(),
///                             &cac_proof,
///                             &reveal_bitmap);
///
///  assert_eq!(Ok(()), vrfy);
/// ```
pub fn cac_prove<R, P>(prng: &mut R,
                       ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                       recv_enc_pub_key: &ElGamalPublicKey<P::G1>,
                       attrs: &[P::ScalarField],
                       ctexts_rand: &[P::ScalarField],
                       bitmap: &[bool],
                       ctexts: &[ElGamalCiphertext<P::G1>],
                       ac_reveal_sig: &ACRevealSig<P::G1, P::G2, P::ScalarField>)
                       -> Result<CACProof<P::G1, P::G2, P::ScalarField>, ZeiError>
  where R: CryptoRng + Rng,
        P: PairingTargetGroup
{
  cac_multi_prove::<R, P>(prng,
                          ac_issuer_pub_key,
                          &[&recv_enc_pub_key],
                          &[attrs],
                          &[ctexts_rand],
                          bitmap,
                          &[ctexts],
                          &[ac_reveal_sig])
}

/// I produce a CACProof for a set of instances of confidential anonymous reveal proofs.
/// For n > 1, instances, the proof produced is shorter than n independent CAC proofs produced by
/// cac_prove function.
/// * `prng` - randomness source
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_keys` - list of encryption public keys of different receivers
/// * `attrs_vecs` - collection of list of attributes
/// * `ctexts_rand_vecs` - collection of lists containing the randomness used to encrypt the attributes
/// * `bitmap` - indicates position of each attribute to prove. Note that the same bitmap is used for all lists of attributes.
/// * `ctexts_vecs` - collection of lists containing ciphertexts that encrypt the attributes
/// * `ac_reveal_sigs` - collection of proofs that the issuer has signed some attributes
/// * `returns` - a single (short) proof corresponding to all the collections of ciphertexts / ac reveal signatures
/// # Example
/// ```
/// use zei::crypto::conf_cred_reveal::test_helpers::{setup_agg, gen_ac_reveal_sig};
/// use zei::crypto::conf_cred_reveal::{cac_multi_prove, cac_multi_verify};
/// use zei::algebra::bls12_381::BLSGt;
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// let mut prng: ChaChaRng;
/// prng = ChaChaRng::from_seed([0u8; 32]);
/// let reveal_bitmap = [true, false];
/// let (ac_issuer_pub_key, ac_issuer_sec_key, user_pub_key, user_sec_key) =
///      setup_agg::<BLSGt>(&mut prng, reveal_bitmap.len());
///
/// let mut prng: ChaChaRng;
///  prng = ChaChaRng::from_seed([0u8; 32]);
///
///  let (ac_issuer_pub_key, ac_issuer_sec_key, user_pub_key, user_sec_key) =
///    setup_agg::<BLSGt>(&mut prng, reveal_bitmap.len());
///
///  let (ctexts1, ctexts_rands1, revealed_attrs1, proof1, recv_pub_key1) =
///    gen_ac_reveal_sig::<BLSGt>(&mut prng,
///                           &ac_issuer_pub_key,
///                           &ac_issuer_sec_key,
///                           &user_pub_key,
///                           &user_sec_key,
///                           &reveal_bitmap);
///
///  let (ctexts2, ctexts_rands2, revealed_attrs2, proof2, recv_pub_key2) =
///    gen_ac_reveal_sig::<BLSGt>(&mut prng,
///                           &ac_issuer_pub_key,
///                           &ac_issuer_sec_key,
///                           &user_pub_key,
///                           &user_sec_key,
///                           &reveal_bitmap);
///
///  let (ctexts3, ctexts_rands3, revealed_attrs3, proof3, recv_pub_key3) =
///    gen_ac_reveal_sig::<BLSGt>(&mut prng,
///                           &ac_issuer_pub_key,
///                           &ac_issuer_sec_key,
///                           &user_pub_key,
///                           &user_sec_key,
///                           &reveal_bitmap);
///
///  let mut cac_proof =
///    cac_multi_prove::<_, BLSGt>(&mut prng,
///                            &ac_issuer_pub_key,
///                            &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
///                            &[revealed_attrs1.as_slice(),
///                              revealed_attrs2.as_slice(),
///                              revealed_attrs3.as_slice()],
///                            &[ctexts_rands1.as_slice(),
///                              ctexts_rands2.as_slice(),
///                              ctexts_rands3.as_slice()],
///                            &reveal_bitmap,
///                            &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
///                            &[&proof1, &proof2, &proof3]).unwrap();
///
///  let vrfy = cac_multi_verify::<BLSGt>(&ac_issuer_pub_key,
///                                   &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
///                                   &[&proof1, &proof2, &proof3],
///                                   &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
///                                   &cac_proof,
///                                   &reveal_bitmap);
///
///  assert_eq!(Ok(()), vrfy);
/// ```
pub fn cac_multi_prove<R, P>(prng: &mut R,
                             ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                             recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
                             attrs_vecs: &[&[P::ScalarField]],
                             ctexts_rand_vecs: &[&[P::ScalarField]],
                             bitmap: &[bool],
                             ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
                             ac_reveal_sigs: &[&ACRevealSig<P::G1, P::G2, P::ScalarField>])
                             -> Result<CACProof<P::G1, P::G2, P::ScalarField>, ZeiError>
  where R: CryptoRng + Rng,
        P: PairingTargetGroup
{
  Ok(CACProof(agg_pok_attrs_prove::<R, P>(prng,
                                          ac_issuer_pub_key,
                                          recv_enc_pub_keys,
                                          attrs_vecs,
                                          ctexts_rand_vecs,
                                          bitmap,
                                          ctexts_vecs,
                                          ac_reveal_sigs)?))
}

/// I verify a CACProof.
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_key` - encryption public key of the receiver
/// * `ac_reveal_sig` - proof that the issuer has signed some attributes
/// * `ctexts` - list of ciphertexts that encrypt the attributes
/// * `cac_proof` - proof that the ciphertexts contains the attributes that have been signed by some issuer for the user.
/// * `bitmap` - indicates which attributes should be revealed to the receiver.
/// * `returns` - nothing if the verification is successful an error otherwise.
/// # Example
/// ```
/// //See zei:crypto:conf_cred_reveal::cac_prove
/// ```
pub fn cac_verify<P: PairingTargetGroup>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                         recv_enc_pub_key: &ElGamalPublicKey<P::G1>,
                                         ac_reveal_sig: &ACRevealSig<P::G1,
                                                      P::G2,
                                                      P::ScalarField>,
                                         ctexts: &[ElGamalCiphertext<P::G1>],
                                         cac_proof: &CACProof<P::G1, P::G2, P::ScalarField>,
                                         bitmap: &[bool])
                                         -> Result<(), ZeiError> {
  cac_multi_verify::<P>(ac_issuer_pub_key,
                        &[recv_enc_pub_key],
                        &[ac_reveal_sig],
                        &[ctexts],
                        cac_proof,
                        bitmap)
}

/// I verify a CACProof for a set of Confidential Anonymous Credential instances.
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_keys` - list of encryption public keys for the receivers
/// * `ac_reveal_sigs` - collection of proofs that the issuer has signed some attributes
/// * `ctexts_vecs` - collection of lists containing ciphertexts that encrypt the attributes
/// * `cac_proof` - a single (short) proof corresponding to all the collections of ciphertexts / ac reveal signatures
/// * `bitmap` - indicates which attributes should be revealed to the receiver
/// * `returns` - nothing or an error if the verification fails
/// # Example
/// ```
/// //See zei::crypto::conf_cred_reveal::cac_multi_prove
/// ```
pub fn cac_multi_verify<P: PairingTargetGroup>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1,
                                                                  P::G2>,
                                               recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
                                               ac_reveal_sigs: &[&ACRevealSig<P::G1,
                                                              P::G2,
                                                              P::ScalarField>],
                                               ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
                                               cac_proof: &CACProof<P::G1,
                                                         P::G2,
                                                         P::ScalarField>,
                                               bitmap: &[bool])
                                               -> Result<(), ZeiError> {
  agg_pok_attrs_verify::<P>(ac_issuer_pub_key,
                            recv_enc_pub_keys,
                            ac_reveal_sigs,
                            ctexts_vecs,
                            &cac_proof.0,
                            bitmap)
}

/// I compute a proof of knowledge of identity attributes to be verified against encryption of these
/// and a anonymous credential reveal proof
/// * `prng` - randomness source
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_key` - encryption public key of the receiver
/// * `attrs` - attributes to prove knowledge of
/// * `ctexts_rand` - randomness used to encrypt the attributes
/// * `bitmap` - indicates position of each attribute to prove
/// * `ctexts` - list of ciphertexts that encrypt the attributes
/// * `ac_reveal_sig`-  proof that the issuer has signed some attributes
/// * `returns` - proof of knowledge of the attributes and encryption randomness
pub(crate) fn pok_attrs_prove<R, P>(
  prng: &mut R,
  ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
  recv_enc_pub_key: &ElGamalPublicKey<P::G1>,
  attrs: &[P::ScalarField],
  ctexts_rand: &[P::ScalarField],
  bitmap: &[bool],
  ctexts: &[ElGamalCiphertext<P::G1>],
  ac_reveal_sig: &ACRevealSig<P::G1, P::G2, P::ScalarField>)
  -> Result<AggPoKAttrs<P::G1, P::G2, P::ScalarField>, ZeiError>
  where R: CryptoRng + Rng,
        P: PairingTargetGroup
{
  agg_pok_attrs_prove::<R, P>(prng,
                              ac_issuer_pub_key,
                              &[recv_enc_pub_key],
                              &[attrs],
                              &[ctexts_rand],
                              bitmap,
                              &[ctexts],
                              &[ac_reveal_sig])
}

/// I verify a proof of knowledge of attributes that
/// a) satisfy a single anonymous credential reveal proof
/// b) are encrypted under ctexts (ElGamal encryptions)
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_key` - encryption public key of the receiver
/// * `ac_reveal_sig` - proof that the issuer has signed some attributes
/// * `ctexts` - list of ciphertexts that encrypt the attributes
/// * `pok_attrs` - proof of knowledge computed through the function pok_attrs_prove
/// * `bitmap` - indicates which attributes should be revealed to the receiver
/// * `returns`- nothing if the verification is successful an error otherwise.
pub(crate) fn pok_attrs_verify<P: PairingTargetGroup>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                      recv_enc_pub_key: &ElGamalPublicKey<P::G1>,
                                                      ac_reveal_sig: &ACRevealSig<P::G1,
                                                                   P::G2,
                                                                   P::ScalarField>,
                                                      ctexts: &[ElGamalCiphertext<P::G1>],
                                                      pok_attrs: &AggPoKAttrs<P::G1,
                                                                   P::G2,
                                                                   P::ScalarField>,
                                                      bitmap: &[bool])
                                                      -> Result<(), ZeiError> {
  agg_pok_attrs_verify::<P>(ac_issuer_pub_key,
                            &[recv_enc_pub_key],
                            &[ac_reveal_sig],
                            &[ctexts],
                            pok_attrs,
                            bitmap)
}

/// I compute an aggregated proof of knowledge of identity attribute sets to be verified against
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
pub(crate) fn agg_pok_attrs_prove<R, P>(
  prng: &mut R,
  ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
  recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
  attrs_vecs: &[&[P::ScalarField]],
  ctexts_rand_vecs: &[&[P::ScalarField]],
  bitmap: &[bool],
  ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
  ac_reveal_sigs: &[&ACRevealSig<P::G1, P::G2, P::ScalarField>])
  -> Result<AggPoKAttrs<P::G1, P::G2, P::ScalarField>, ZeiError>
  where R: CryptoRng + Rng,
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
  let challenge = cac_reveal_challenge_agg::<P>(&ac_issuer_pub_key,
                                                recv_enc_pub_keys,
                                                ac_reveal_sigs,
                                                ctexts_vecs,
                                                attr_sum_com_yy2.as_slice(),
                                                agg_attrs_coms_g.as_slice(),
                                                agg_rands_coms_g.as_slice(),
                                                agg_rands_coms_pk.as_slice())?;

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
pub(crate) fn agg_pok_attrs_verify<P: PairingTargetGroup>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                          recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
                                                          ac_reveal_sigs: &[&ACRevealSig<P::G1, P::G2, P::ScalarField>],
                                                          ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
                                                          agg_pok_attrs: &AggPoKAttrs<P::G1,
                                                                          P::G2,
                                                                            P::ScalarField>,
                                                          bitmap: &[bool] // indicates which attributes should be revealed to the receiver
) -> Result<(), ZeiError> {
  // 1. compute linear combination scalars
  let lc_scalars = compute_linear_combination_scalars::<P>(ctexts_vecs, ac_reveal_sigs);

  // 2. compute challenge
  let challenge = cac_reveal_challenge_agg::<P>(ac_issuer_pub_key,
                                                recv_enc_pub_keys,
                                                ac_reveal_sigs,
                                                ctexts_vecs,
                                                agg_pok_attrs.attr_sum_com_yy2.as_slice(),
                                                agg_pok_attrs.agg_attrs_coms_g.as_slice(),
                                                agg_pok_attrs.agg_rands_coms_g.as_slice(),
                                                agg_pok_attrs.agg_rands_coms_pk.as_slice())?;

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
  if ctexts_vecs.len() == 0 {
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
    let c_k = ac_challenge::<P>(issuer_pub_key,
                                &reveal_sig_k.sig,
                                &reveal_sig_k.pok.commitment)?;

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
  match lhs == rhs {
    true => Ok(()),
    false => Err(ZeiError::IdentityRevealVerifyError),
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
  where R: CryptoRng + Rng,
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
                                               attr_blinds: &Vec<P::ScalarField>,
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
  where R: CryptoRng + Rng,
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

/// I compute a challenge for the PoK of knowledge protocol for confidential anonymous credential
/// reveal. This challenge is computed using the Fiat-Shamir transform.
/// * `ac_issuer_pub_key` - (signing) issuer public key
/// * `recv_pub_keys` - list of encryption public keys for the recipients
/// * `ac_reveal_sigs` - collection of proofs that the issuer has signed some attributes
/// * `ctexts_vecs`- collection of lists of ciphertexts of attributes
/// * `ac_coms` - commitments from the aggregated encrypted attributes
/// * `agg_proof_coms_attrs` - aggregated proof commitments for attributes
/// * `agg_proof_coms_rands_g` - blinding factors in base g
/// * `agg_proof_coms_rands_pk` - blinding factors related to the public keys
/// * `return` - challenge which is a hash value
fn cac_reveal_challenge_agg<P: PairingTargetGroup>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1,
                                                                      P::G2>,
                                                   recv_pub_keys: &[&ElGamalPublicKey<P::G1>],
                                                   ac_reveal_sigs: &[&ACRevealSig<P::G1,
                                                                     P::G2,
                                                                     P::ScalarField>],
                                                   ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
                                                   ac_coms: &[P::G2],
                                                   agg_proof_coms_attrs: &[P::G1],
                                                   agg_proof_coms_rands_g: &[P::G1],
                                                   agg_proof_coms_rands_pk: &[P::G1])
                                                   -> Result<P::ScalarField, ZeiError> {
  let encoded_ac_pub_key =
    bincode::serialize(ac_issuer_pub_key).map_err(|_| ZeiError::SerializationError)?;

  let encoded_recv_pub_keys =
    bincode::serialize(recv_pub_keys).map_err(|_| ZeiError::SerializationError)?;

  let encoded_sigs = bincode::serialize(ac_reveal_sigs).map_err(|_| ZeiError::SerializationError)?;

  let encoded_ctexts = bincode::serialize(ctexts_vecs).map_err(|_| ZeiError::SerializationError)?;

  let mut hash = Sha512::new();
  hash.input("Zei CACReveal");
  hash.input(&encoded_ac_pub_key[..]);
  hash.input(&encoded_recv_pub_keys[..]);
  hash.input(&encoded_sigs[..]);
  hash.input(&encoded_ctexts[..]);

  for ac_com in ac_coms {
    hash.input(ac_com.to_compressed_bytes());
  }
  for (a_g, r_g, r_pk) in izip!(agg_proof_coms_attrs,
                                agg_proof_coms_rands_g,
                                agg_proof_coms_rands_pk)
  {
    hash.input(a_g.to_compressed_bytes());
    hash.input(r_g.to_compressed_bytes());
    hash.input(r_pk.to_compressed_bytes());
  }
  Ok(P::ScalarField::from_hash(hash))
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
mod test_bn {
  use super::test_helpers::confidential_ac_reveal;
  use crate::algebra::bn::BNGt;

  #[test]
  fn confidential_reveal_one_attr_hidden() {
    confidential_ac_reveal::<BNGt>(&[false]);
  }

  #[test]
  fn confidential_reveal_one_attr_revealed() {
    confidential_ac_reveal::<BNGt>(&[true]);
  }

  #[test]
  fn confidential_reveal_two_attr_hidden_first() {
    confidential_ac_reveal::<BNGt>(&[false, false]);
    confidential_ac_reveal::<BNGt>(&[false, true]);
  }

  #[test]
  fn confidential_reveal_two_attr_revealed_first() {
    confidential_ac_reveal::<BNGt>(&[true, false]);
    confidential_ac_reveal::<BNGt>(&[true, true]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_hidden() {
    confidential_ac_reveal::<BNGt>(&[false; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_revealed() {
    confidential_ac_reveal::<BNGt>(&[true; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_half_revealed() {
    confidential_ac_reveal::<BNGt>(&[true, false, true, false, true, false, true, false, true,
                                     false]);
    confidential_ac_reveal::<BNGt>(&[false, true, false, true, false, true, false, true, false,
                                     true]);
  }

  #[test]
  fn confidential_reveal_agg() {
    super::test_helpers::confidential_reveal_agg::<BNGt>(&[true, true, false, false]);
  }
}

#[cfg(test)]
mod test_bls12_381 {
  use super::test_helpers::confidential_ac_reveal;
  use crate::algebra::bls12_381::BLSGt;

  #[test]
  fn confidential_reveal_one_attr_hidden() {
    confidential_ac_reveal::<BLSGt>(&[false]);
  }

  #[test]
  fn confidential_reveal_one_attr_revealed() {
    confidential_ac_reveal::<BLSGt>(&[true]);
  }

  #[test]
  fn confidential_reveal_two_attr_hidden_first() {
    confidential_ac_reveal::<BLSGt>(&[false, false]);
    confidential_ac_reveal::<BLSGt>(&[false, true]);
  }

  #[test]
  fn confidential_reveal_two_attr_revealed_first() {
    confidential_ac_reveal::<BLSGt>(&[true, false]);
    confidential_ac_reveal::<BLSGt>(&[true, true]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_hidden() {
    confidential_ac_reveal::<BLSGt>(&[false; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_revealed() {
    confidential_ac_reveal::<BLSGt>(&[true; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_half_revealed() {
    confidential_ac_reveal::<BLSGt>(&[true, false, true, false, true, false, true, false, true,
                                      false]);
    confidential_ac_reveal::<BLSGt>(&[false, true, false, true, false, true, false, true, false,
                                      true]);
  }

  #[test]
  fn confidential_reveal_agg() {
    super::test_helpers::confidential_reveal_agg::<BLSGt>(&[true, true, false, false]);
  }
}

#[cfg(test)]
mod test_serialization {
  use super::{AggPoKAttrs, CACProof};
  use crate::algebra::bls12_381::{BLSScalar, BLSG1, BLSG2};
  use crate::algebra::groups::{Group, Scalar};
  use rand::SeedableRng;
  use rand_chacha::ChaChaRng;
  use rmp_serde::Deserializer;
  use serde::{Deserialize, Serialize};

  fn to_json<G1: Group<S>, G2: Group<S>, S: Scalar>() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let cac_proof = CACProof(AggPoKAttrs { //2 instances 3 attributes
                                           attr_sum_com_yy2: vec![G2::get_base(),
                                                                  G2::get_base()],
                                           agg_attrs_coms_g: vec![G1::get_identity(),
                                                                  G1::get_identity(),
                                                                  G1::get_identity()],
                                           agg_rands_coms_g: vec![G1::get_base(),
                                                                  G1::get_identity(),
                                                                  G1::get_identity()],
                                           agg_rands_coms_pk: vec![G1::get_identity(),
                                                                   G1::get_base(),
                                                                   G1::get_identity()],
                                           attrs_resps: vec![vec![S::from_u32(0),
                                                                  S::random_scalar(&mut prng),
                                                                  S::from_u32(10)],
                                                             vec![S::from_u32(1),
                                                                  S::random_scalar(&mut prng),
                                                                  S::from_u32(20)],],
                                           rands_resps: vec![vec![S::from_u32(60),
                                                                  S::from_u32(40),
                                                                  S::from_u32(20)],
                                                             vec![S::from_u32(70),
                                                                  S::from_u32(50),
                                                                  S::from_u32(30)],] });

    let json_str = serde_json::to_string(&cac_proof).unwrap();
    let cac_proof_de: CACProof<G1, G2, S> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(cac_proof, cac_proof_de);
  }

  fn to_msg_pack<G1: Group<S>, G2: Group<S>, S: Scalar>() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let cac_proof = CACProof(AggPoKAttrs { //2 instances 3 attributes
                                           attr_sum_com_yy2: vec![G2::get_base(),
                                                                  G2::get_base()],
                                           agg_attrs_coms_g: vec![G1::get_identity(),
                                                                  G1::get_identity(),
                                                                  G1::get_identity()],
                                           agg_rands_coms_g: vec![G1::get_base(),
                                                                  G1::get_identity(),
                                                                  G1::get_identity()],
                                           agg_rands_coms_pk: vec![G1::get_identity(),
                                                                   G1::get_base(),
                                                                   G1::get_identity()],
                                           attrs_resps: vec![vec![S::from_u32(0),
                                                                  S::random_scalar(&mut prng),
                                                                  S::from_u32(10)],
                                                             vec![S::from_u32(1),
                                                                  S::random_scalar(&mut prng),
                                                                  S::from_u32(20)],],
                                           rands_resps: vec![vec![S::from_u32(60),
                                                                  S::from_u32(40),
                                                                  S::from_u32(20)],
                                                             vec![S::from_u32(70),
                                                                  S::from_u32(50),
                                                                  S::from_u32(30)],] });
    //keys serialization
    let mut vec = vec![];
    cac_proof.serialize(&mut rmp_serde::Serializer::new(&mut vec))
             .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let cac_proof_de: CACProof<G1, G2, S> = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(cac_proof, cac_proof_de);
  }

  #[test]
  fn to_json_bls12_381() {
    to_json::<BLSG1, BLSG2, BLSScalar>();
  }

  #[test]
  fn to_msg_pack_bls12_381() {
    to_msg_pack::<BLSG1, BLSG2, BLSScalar>();
  }
}
