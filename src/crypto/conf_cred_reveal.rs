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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AggPoKAttrs<G1, G2, S> {
  pub attr_sum_com_yy2: Vec<G2>, // {sum blind_{attr_{j,k}} * Y2_j }_k for attr_{j,k} in encrypted attributes for each instance k. Cannot be aggregated
  pub agg_attrs_coms_g: Vec<G1>, // \sum_k x_k* blind_{a_{j,k}} * G1 for attr_{j,k} in encrypted attributes
  pub attrs_resps: Vec<Vec<S>>, // {{c*attr_{j,k} + blind_{attr_{j,k}} }_j}_k for each instance k, Cannot be aggregated
  pub agg_rands_coms_g: Vec<G1>, // {\sum_k x_k * blind_{r_{j,k}} * G}_j
  pub agg_rands_coms_pk: Vec<G1>, // {\sum_k x_k  * blind_{r_{j,k}} * PK_k }_j
  pub rands_resps: Vec<Vec<S>>, //  {(c*r_{j,k} + blind_{r_{i,k}})}_j}_k, this cannot be aggregated unless public keys are all equal
}

/// Proof of knowlege of attributes that a) are elgamal encrypted, and b) verify an anonymous credential reveal proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CACProof<G1, G2, S>(pub(crate) AggPoKAttrs<G1, G2, S>);

/// I produce a CACProof for a single instance of a confidential anonymous reveal. Proof asserts
/// that a list of attributes can be decrypted from a list of ciphertexts under recv_enc_pub_key,
/// and that these attributed verify an anonymous credential reveal proof.
pub fn cac_prove<R, S, P>(prng: &mut R,
                          ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                          recv_enc_pub_key: &ElGamalPublicKey<P::G1>,
                          attrs: &[S],       // attributes to prove knowledge of
                          ctexts_rand: &[S], // randomness used to encrypt attrs
                          bitmap: &[bool],   // indicates position of each attribute to prove
                          ctexts: &[ElGamalCiphertext<P::G1>],
                          ac_reveal_sig: &ACRevealSig<P::G1, P::G2, S>)
                          -> Result<CACProof<P::G1, P::G2, S>, ZeiError>
  where R: CryptoRng + Rng,
        S: Scalar,
        P: PairingTargetGroup<S>
{
  cac_multi_prove::<R, S, P>(prng,
                             ac_issuer_pub_key,
                             &[&recv_enc_pub_key],
                             &[attrs],
                             &[ctexts_rand],
                             bitmap,
                             &[ctexts],
                             &[ac_reveal_sig])
}

/// I produce a CACProof for a set of instance of confidential anonymous reveal proofs.
/// For n > 1, instances, the proof produced is shorter than n independent CAC proofs produced by
/// cac_prove function.
pub fn cac_multi_prove<R, S, P>(prng: &mut R,
                                ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
                                attrs: &[&[S]],
                                ctexts_rand: &[&[S]],
                                bitmap: &[bool],
                                ctexts: &[&[ElGamalCiphertext<P::G1>]],
                                ac_reveal_sigs: &[&ACRevealSig<P::G1, P::G2, S>])
                                -> Result<CACProof<P::G1, P::G2, S>, ZeiError>
  where R: CryptoRng + Rng,
        S: Scalar,
        P: PairingTargetGroup<S>
{
  Ok(CACProof(agg_pok_attrs_prove::<R, S, P>(prng,
                                             ac_issuer_pub_key,
                                             recv_enc_pub_keys,
                                             attrs,
                                             ctexts_rand,
                                             bitmap,
                                             ctexts,
                                             ac_reveal_sigs)?))
}

/// I verify a CACProof.
pub fn cac_verify<S: Scalar, P: PairingTargetGroup<S>>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                       recv_enc_pub_key: &ElGamalPublicKey<P::G1>,
                                                       reveal_sig: &ACRevealSig<P::G1, P::G2, S>,
                                                       ctexts: &[ElGamalCiphertext<P::G1>],
                                                       cac_proof: &CACProof<P::G1, P::G2, S>,
                                                       bitmap: &[bool] // indicates which attributes should be revealed to the receiver
) -> Result<(), ZeiError> {
  cac_multi_verify::<S, P>(ac_issuer_pub_key,
                           &[recv_enc_pub_key],
                           &[reveal_sig],
                           &[ctexts],
                           cac_proof,
                           bitmap)
}

/// I verify a CACProof for a set of Confidential Anonumous Credental instances.
pub fn cac_multi_verify<S: Scalar, P: PairingTargetGroup<S>>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1,
                                                                     P::G2>,
                                                             recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
                                                             ac_reveal_sigs: &[&ACRevealSig<P::G1,
                                                                 P::G2,
                                                                 S>],
                                                             ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
                                                             cac_proof: &CACProof<P::G1, P::G2, S>,
                                                             bitmap: &[bool] // indicates which attributes should be revealed to the receiver
) -> Result<(), ZeiError> {
  agg_pok_attrs_verify::<S, P>(ac_issuer_pub_key,
                               recv_enc_pub_keys,
                               ac_reveal_sigs,
                               ctexts_vecs,
                               &cac_proof.0,
                               bitmap)
}

/// I compute a proof of knowledge of identity attributes to be verified against encryption of these
/// and a anonymous credential reveal proof
pub(crate) fn pok_attrs_prove<R, S, P>(prng: &mut R,
                                       ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                       recv_enc_pub_key: &ElGamalPublicKey<P::G1>,
                                       attrs: &[S], // attributes to prove knowledge of
                                       ctexts_rand: &[S], // randomness used to encrypt attrs
                                       bitmap: &[bool], // indicates position of each attribute to prove
                                       ctexts: &[ElGamalCiphertext<P::G1>],
                                       ac_reveal_sig: &ACRevealSig<P::G1, P::G2, S>)
                                       -> Result<AggPoKAttrs<P::G1, P::G2, S>, ZeiError>
  where R: CryptoRng + Rng,
        S: Scalar,
        P: PairingTargetGroup<S>
{
  agg_pok_attrs_prove::<R, S, P>(prng,
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
pub(crate) fn pok_attrs_verify<S: Scalar, P: PairingTargetGroup<S>>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                                    recv_enc_pub_key: &ElGamalPublicKey<P::G1>,
                                                                    reveal_sig: &ACRevealSig<P::G1,
                                                                      P::G2,
                                                                      S>,
                                                                    ctexts: &[ElGamalCiphertext<P::G1>],
                                                                    pok_attrs: &AggPoKAttrs<P::G1,
                                                                      P::G2,
                                                                      S>,
                                                                    bitmap: &[bool] // indicates which attributes should be revealed to the receiver
) -> Result<(), ZeiError> {
  agg_pok_attrs_verify::<S, P>(ac_issuer_pub_key,
                               &[recv_enc_pub_key],
                               &[reveal_sig],
                               &[ctexts],
                               pok_attrs,
                               bitmap)
}

/// I compute an aggregated proof of knowledge of identity attribute sets to be verified against
/// encryption of these and a set of anonymous credential reveal proofs
pub(crate) fn agg_pok_attrs_prove<R, S, P>(prng: &mut R,
                                           ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                           recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
                                           attrs: &[&[S]],
                                           ctexts_rand: &[&[S]],
                                           bitmap: &[bool],
                                           ctexts: &[&[ElGamalCiphertext<P::G1>]],
                                           ac_reveal_sigs: &[&ACRevealSig<P::G1, P::G2, S>])
                                           -> Result<AggPoKAttrs<P::G1, P::G2, S>, ZeiError>
  where R: CryptoRng + Rng,
        S: Scalar,
        P: PairingTargetGroup<S>
{
  //0: santity check on vector length
  let n_instances = attrs.len();
  if n_instances != ctexts_rand.len()
     || n_instances != ctexts.len()
     || n_instances != ac_reveal_sigs.len()
  {
    return Err(ZeiError::ParameterError);
  }
  let n_attrs = bitmap.iter().filter(|x| **x).count();
  if n_attrs > bitmap.len() {
    return Err(ZeiError::ParameterError);
  }

  //1: sample secrets' blinds and compute proof commitments.
  let (attr_sum_com_yy2, (attrs_coms_g, rands_coms_g, rands_coms_pk), (attrs_blinds, rands_blinds)) =
    sample_blinds_compute_commitments::<_, S, P>(prng,
                                                 ac_issuer_pub_key,
                                                 recv_enc_pub_keys,
                                                 bitmap,
                                                 n_attrs,
                                                 n_instances)?;

  //2: sample linear combination scalars
  let lc_scalars = compute_linear_combination_scalars::<S, P>(ctexts, ac_reveal_sigs);

  //3: aggregate attributes blinding commitments under G and PK
  let agg_attrs_coms_g =
    group_linear_combination_rows(lc_scalars.as_slice(), attrs_coms_g.as_slice());
  let agg_rands_coms_g =
    group_linear_combination_rows(lc_scalars.as_slice(), rands_coms_g.as_slice());
  let agg_rands_coms_pk =
    group_linear_combination_rows(lc_scalars.as_slice(), rands_coms_pk.as_slice());

  //4: Compute challenge for the proof and scalars for linear combination
  let challenge = cac_reveal_challenge_agg::<S, P>(&ac_issuer_pub_key,
                                                   recv_enc_pub_keys,
                                                   ac_reveal_sigs,
                                                   ctexts,
                                                   attr_sum_com_yy2.as_slice(),
                                                   agg_attrs_coms_g.as_slice(),
                                                   agg_rands_coms_g.as_slice(),
                                                   agg_rands_coms_pk.as_slice())?;

  //3: compute proof responses
  let mut attrs_resps = vec![];
  let mut rands_resps = vec![];
  for (attrs_k, rands_k, attrs_blinds_k, rands_blinds_k) in
    izip!(attrs, ctexts_rand, attrs_blinds, rands_blinds)
  {
    let (attrs_resps_k, rands_resps_k) = compute_proof_responses::<S>(&challenge,
                                                                      *attrs_k,
                                                                      attrs_blinds_k.as_slice(),
                                                                      *rands_k,
                                                                      rands_blinds_k.as_slice());
    attrs_resps.push(attrs_resps_k);
    rands_resps.push(rands_resps_k);
  }

  //5: build struct and return
  Ok(AggPoKAttrs { attr_sum_com_yy2,
                   agg_attrs_coms_g,
                   agg_rands_coms_g,
                   agg_rands_coms_pk,
                   attrs_resps,
                   rands_resps })
}

pub(crate) fn agg_pok_attrs_verify<S: Scalar, P: PairingTargetGroup<S>>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                                        recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
                                                                        ac_reveal_sigs: &[&ACRevealSig<P::G1, P::G2, S>],
                                                                        ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
                                                                        agg_pok_attrs: &AggPoKAttrs<P::G1,
                                                                          P::G2,
                                                                          S>,
                                                                        bitmap: &[bool] // indicates which attributes should be revealed to the receiver
) -> Result<(), ZeiError> {
  // 1. compute linear combination scalars
  let lc_scalars = compute_linear_combination_scalars::<S, P>(ctexts_vecs, ac_reveal_sigs);

  // 2. compute challenge
  let challenge = cac_reveal_challenge_agg::<S, P>(ac_issuer_pub_key,
                                                   recv_enc_pub_keys,
                                                   ac_reveal_sigs,
                                                   ctexts_vecs,
                                                   agg_pok_attrs.attr_sum_com_yy2.as_slice(),
                                                   agg_pok_attrs.agg_attrs_coms_g.as_slice(),
                                                   agg_pok_attrs.agg_rands_coms_g.as_slice(),
                                                   agg_pok_attrs.agg_rands_coms_pk.as_slice())?;

  // 3. verify ciphertexts
  verify_ciphertext::<S, P>(&challenge,
                            &lc_scalars[..],
                            ctexts_vecs,
                            &agg_pok_attrs.agg_attrs_coms_g[..],
                            &agg_pok_attrs.agg_rands_coms_g[..],
                            &agg_pok_attrs.agg_rands_coms_pk[..],
                            &agg_pok_attrs.attrs_resps[..],
                            &agg_pok_attrs.rands_resps[..],
                            recv_enc_pub_keys)?;

  // 4. verify credentials
  verify_credential_agg::<S, P>(&challenge,
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
fn compute_linear_combination_scalars<S: Scalar, P: PairingTargetGroup<S>>(ctexts: &[&[ElGamalCiphertext<P::G1>]],
                                                                           ac_reveal_sigs: &[&ACRevealSig<P::G1, P::G2, S>])
                                                                           -> Vec<S> {
  if ctexts.len() == 0 {
    return vec![];
  }

  let mut scalars = vec![S::from_u32(1)];
  if ctexts.len() == 1 {
    return scalars;
  }

  let mut hash = Sha512::new();
  let mut ac_reveal_sig_vec = vec![];
  ac_reveal_sigs.serialize(&mut rmp_serde::Serializer::new(&mut ac_reveal_sig_vec))
                .unwrap();
  hash.input(ac_reveal_sig_vec.as_slice());

  for ctext_vec in ctexts.iter() {
    for ctext in *ctext_vec {
      hash.input(ctext.e1.to_compressed_bytes());
      hash.input(ctext.e1.to_compressed_bytes());
    }
  }
  let mut xi = S::from_hash(hash);
  for _ in 2..ctexts.len() {
    let mut hash = Sha512::new();
    hash.input(xi.to_bytes());
    let new_xi = S::from_hash(hash);
    scalars.push(xi);
    xi = new_xi;
  }

  scalars.push(xi);
  scalars
}

/// I verify a proof of knowledge of a set of ElGamal encrypted messages
fn verify_ciphertext<S: Scalar, P: PairingTargetGroup<S>>(challenge: &S,
                                                          lc_scalars: &[S],
                                                          ctexts: &[&[ElGamalCiphertext<P::G1>]],
                                                          attr_commitments: &[P::G1],
                                                          rand_commitments_g: &[P::G1],
                                                          rand_commitments_pk: &[P::G1],
                                                          attr_responses: &[Vec<S>],
                                                          rand_responses: &[Vec<S>],
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
    let mut sum_g_rand = S::from_u32(0); // aggregate scalars first
    let mut sum_g_attr = S::from_u32(0); // aggregate scalars first

    let mut sum_e1 = P::G1::get_identity(); // ElGamalCiphertext 1st coordinate
    let mut sum_e2 = P::G1::get_identity(); // ElGamalCiphertext 1st coordinate

    for (pub_key, rand_resp_inst, attr_resp_inst, ctexts_inst, scalar) in
      izip!(recv_enc_pub_keys.iter(),
            rand_responses.iter(),
            attr_responses.iter(),
            ctexts.iter(),
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

/// I verify a proof of knowledge of attributed that verify an anonymous credential reveal proof.
fn verify_credential_agg<S: Scalar, P: PairingTargetGroup<S>>(challenge: &S,
                                                              lc_scalars: &[S],
                                                              reveal_sigs: &[&ACRevealSig<P::G1,
                                                                  P::G2,
                                                                  S>],
                                                              attr_sum_com_yy2: &[P::G2],
                                                              attr_resps: &[Vec<S>],
                                                              issuer_pub_key: &ACIssuerPublicKey<P::G1,
                                                                      P::G2>,
                                                              bitmap: &[bool] //policy, indicates which attributes needs to be revealed to the receiver
) -> Result<(), ZeiError> {
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
    izip!(lc_scalars, reveal_sigs, attr_sum_com_yy2, attr_resps)
  {
    let c_k = ac_challenge::<S, P>(issuer_pub_key,
                                   &reveal_sig_k.sig,
                                   &reveal_sig_k.pok.commitment)?;

    let hidden_k =
      ac_vrfy_hidden_terms_addition::<S, P>(&c_k, reveal_sig_k, issuer_pub_key, bitmap)?;

    let revealed_k = ac_vrfy_zk_revealed_terms_addition::<S, P>(issuer_pub_key,
                                                                attr_sum_com_k,
                                                                attr_resp_k,
                                                                bitmap)?;

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
  for (lc_scalar_k, reveal_sig_k, pp_k) in izip!(lc_scalars, reveal_sigs, pp) {
    let lhs_i = P::pairing(&reveal_sig_k.sig.sigma1.mul(lc_scalar_k), &pp_k);
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
fn sample_blinds_compute_commitments<R, S, P>(
  prng: &mut R,
  ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
  recv_enc_pub_keys: &[&ElGamalPublicKey<P::G1>],
  bitmap: &[bool],
  n_attrs: usize,
  n_instances: usize)
  -> Result<(Vec<P::G2>,
             (Vec<Vec<P::G1>>, Vec<Vec<P::G1>>, Vec<Vec<P::G1>>),
             (Vec<Vec<S>>, Vec<Vec<S>>)),
            ZeiError>
  where R: CryptoRng + Rng,
        S: Scalar,
        P: PairingTargetGroup<S>
{
  let mut attr_sum_com_yy2 = Vec::with_capacity(n_instances);
  let mut attrs_coms_g: Vec<Vec<P::G1>> = Vec::with_capacity(n_instances);
  let mut rands_coms_g = Vec::with_capacity(n_instances);
  let mut rands_coms_pk = Vec::with_capacity(n_instances);

  let (attrs_blinds, rands_blinds) = sample_blinds::<R, S>(prng, n_attrs, n_instances);

  for k in 0..n_instances {
    attr_sum_com_yy2.push(compute_attr_sum_yy2::<S,P>(
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

fn compute_attr_sum_yy2<S: Scalar, P: PairingTargetGroup<S>>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1,
                                                                     P::G2>,
                                                             attr_blinds: &Vec<S>,
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
/// reveal
fn cac_reveal_challenge_agg<S: Scalar, P: PairingTargetGroup<S>>(ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                                 recv_pub_keys: &[&ElGamalPublicKey<P::G1>],
                                                                 ac_reveal_sigs: &[&ACRevealSig<P::G1,
                                                                     P::G2,
                                                                     S>],
                                                                 ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
                                                                 ac_coms: &[P::G2],
                                                                 agg_proof_coms_attrs: &[P::G1],
                                                                 agg_proof_coms_rands_g: &[P::G1],
                                                                 agg_proof_coms_rands_pk: &[P::G1])
                                                                 -> Result<S, ZeiError> {
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
  Ok(S::from_hash(hash))
}

/// Using a challenge, secret values and their blindings, I compute the proof responses of a PoK
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
fn ac_vrfy_zk_revealed_terms_addition<S: Scalar, P: PairingTargetGroup<S>>(ac_issuer_public_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                                           attr_sum_com: &P::G2,
                                                                           attr_resps: &[S],
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
mod test {
  use super::{cac_multi_prove, cac_multi_verify, cac_prove, cac_verify};
  use crate::algebra::groups::{Group, Scalar};
  use crate::algebra::pairing::PairingTargetGroup;
  use crate::basic_crypto::elgamal::{
    elgamal_derive_public_key, elgamal_encrypt, elgamal_generate_secret_key, ElGamalCiphertext,
    ElGamalPublicKey,
  };
  use crate::crypto::anon_creds::{
    ac_keygen_issuer, ac_keygen_user, ac_reveal, ac_sign, ACIssuerPublicKey, ACIssuerSecretKey,
    ACRevealSig, ACUserPublicKey, ACUserSecretKey,
  };
  use crate::errors::ZeiError;
  use rand::SeedableRng;
  use rand_chacha::ChaChaRng;

  fn setup<S: Scalar, P: PairingTargetGroup<S>>(
    prng: &mut ChaChaRng,
    n_attr: usize)
    -> (ACIssuerPublicKey<P::G1, P::G2>,
        ACIssuerSecretKey<P::G1, S>,
        ACUserPublicKey<P::G1>,
        ACUserSecretKey<S>) {
    let ac_issuer_keypair = ac_keygen_issuer::<_, S, P>(prng, n_attr);
    let ac_issuer_pub_key = ac_issuer_keypair.0;
    let ac_issuer_sec_key = ac_issuer_keypair.1;
    let (user_pub_key, user_sec_key) = ac_keygen_user::<_, S, P>(prng, &ac_issuer_pub_key);
    (ac_issuer_pub_key, ac_issuer_sec_key, user_pub_key, user_sec_key)
  }

  fn gen_ac_reveal_sig<S: Scalar, P: PairingTargetGroup<S>>(
    prng: &mut ChaChaRng,
    ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
    ac_issuer_sec_key: &ACIssuerSecretKey<P::G1, S>,
    user_pub_key: &ACUserPublicKey<P::G1>,
    user_sec_key: &ACUserSecretKey<S>,
    reveal_bitmap: &[bool])
    -> (Vec<ElGamalCiphertext<P::G1>>,
        Vec<S>,
        Vec<S>,
        ACRevealSig<P::G1, P::G2, S>,
        ElGamalPublicKey<P::G1>) {
    let recv_sec_key = elgamal_generate_secret_key::<_, S>(prng);
    let recv_pub_key = elgamal_derive_public_key(&P::G1::get_base(), &recv_sec_key);

    let num_attr = reveal_bitmap.len();
    let mut attrs = vec![];
    for _ in 0..num_attr {
      attrs.push(S::random_scalar(prng));
    }
    let signature = ac_sign::<_, S, P>(prng, &ac_issuer_sec_key, &user_pub_key, attrs.as_slice());

    let proof = ac_reveal::<_, S, P>(prng,
                                     &user_sec_key,
                                     ac_issuer_pub_key,
                                     &signature,
                                     &attrs,
                                     reveal_bitmap).unwrap();

    let mut ctexts_rands = vec![];
    let mut ctexts = vec![];
    let mut revealed_attrs = vec![];
    for (attr, reveal) in attrs.iter().zip(reveal_bitmap) {
      if *reveal {
        let rand = S::random_scalar(prng);
        let ctext = elgamal_encrypt(&P::G1::get_base(), attr, &rand, &recv_pub_key);

        ctexts_rands.push(rand);
        ctexts.push(ctext);
        revealed_attrs.push(attr.clone());
      }
    }

    (ctexts, ctexts_rands, revealed_attrs, proof, recv_pub_key)
  }

  pub(super) fn confidential_reveal_agg<S: Scalar, P: PairingTargetGroup<S>>(reveal_bitmap: &[bool]) {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);

    let (ac_issuer_pub_key, ac_issuer_sec_key, user_pub_key, user_sec_key) =
      setup::<S, P>(&mut prng, reveal_bitmap.len());

    let (ctexts1, ctexts_rands1, revealed_attrs1, proof1, recv_pub_key1) =
      gen_ac_reveal_sig::<S, P>(&mut prng,
                                &ac_issuer_pub_key,
                                &ac_issuer_sec_key,
                                &user_pub_key,
                                &user_sec_key,
                                reveal_bitmap);

    let (ctexts2, ctexts_rands2, revealed_attrs2, proof2, recv_pub_key2) =
      gen_ac_reveal_sig::<S, P>(&mut prng,
                                &ac_issuer_pub_key,
                                &ac_issuer_sec_key,
                                &user_pub_key,
                                &user_sec_key,
                                reveal_bitmap);

    let (ctexts3, ctexts_rands3, revealed_attrs3, proof3, recv_pub_key3) =
      gen_ac_reveal_sig::<S, P>(&mut prng,
                                &ac_issuer_pub_key,
                                &ac_issuer_sec_key,
                                &user_pub_key,
                                &user_sec_key,
                                reveal_bitmap);

    let mut cac_proof =
      cac_multi_prove::<_, S, P>(&mut prng,
                                 &ac_issuer_pub_key,
                                 &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
                                 &[revealed_attrs1.as_slice(),
                                   revealed_attrs2.as_slice(),
                                   revealed_attrs3.as_slice()],
                                 &[ctexts_rands1.as_slice(),
                                   ctexts_rands2.as_slice(),
                                   ctexts_rands3.as_slice()],
                                 reveal_bitmap,
                                 &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
                                 &[&proof1, &proof2, &proof3]).unwrap();

    let vrfy =
      cac_multi_verify::<S, P>(&ac_issuer_pub_key,
                               &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
                               &[&proof1, &proof2, &proof3],
                               &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
                               &cac_proof,
                               reveal_bitmap);

    assert_eq!(Ok(()), vrfy);

    //making one proof fail
    let old = cac_proof.0.attr_sum_com_yy2[2].clone();
    cac_proof.0.attr_sum_com_yy2[2] = P::G2::get_identity(); //making last proof fail due to bad credential

    let vrfy =
      cac_multi_verify::<S, P>(&ac_issuer_pub_key,
                               &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
                               &[&proof1, &proof2, &proof3],
                               &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
                               &cac_proof,
                               reveal_bitmap);

    assert_eq!(Err(ZeiError::IdentityRevealVerifyError), vrfy);

    cac_proof.0.attr_sum_com_yy2[2] = old; //restoring credential
    cac_proof.0.agg_rands_coms_g[0] = P::G1::get_identity(); //making ciphertext fail

    let vrfy =
      cac_multi_verify::<S, P>(&ac_issuer_pub_key,
                               &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
                               &[&proof1, &proof2, &proof3],
                               &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
                               &cac_proof,
                               reveal_bitmap);

    assert_eq!(Err(ZeiError::IdentityRevealVerifyError), vrfy);
  }
  pub(super) fn confidential_ac_reveal<S: Scalar, P: PairingTargetGroup<S>>(reveal_bitmap: &[bool]) {
    let num_attr = reveal_bitmap.len();
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let ac_issuer_keypair = ac_keygen_issuer::<_, S, P>(&mut prng, num_attr);

    let ac_issuer_pub_key = &ac_issuer_keypair.0;
    let ac_issuer_sk = &ac_issuer_keypair.1;

    let recv_secret_key = elgamal_generate_secret_key::<_, S>(&mut prng);
    let recv_enc_pub_key = elgamal_derive_public_key(&P::G1::get_base(), &recv_secret_key);

    let (user_pk, user_sk) = ac_keygen_user::<_, S, P>(&mut prng, ac_issuer_pub_key);

    let mut attrs = vec![];

    for _ in 0..num_attr {
      attrs.push(S::random_scalar(&mut prng));
    }

    let signature = ac_sign::<_, S, P>(&mut prng, &ac_issuer_sk, &user_pk, attrs.as_slice());

    let mut proof = ac_reveal::<_, S, P>(&mut prng,
                                         &user_sk,
                                         ac_issuer_pub_key,
                                         &signature,
                                         &attrs,
                                         reveal_bitmap).unwrap();

    let mut ctext_rands = vec![];
    let mut ctexts = vec![];
    let mut revealed_attrs = vec![];
    for (attr, reveal) in attrs.iter().zip(reveal_bitmap) {
      if *reveal {
        let rand = S::random_scalar(&mut prng);
        let ctext = elgamal_encrypt(&P::G1::get_base(), attr, &rand, &recv_enc_pub_key);

        ctext_rands.push(rand);
        ctexts.push(ctext);
        revealed_attrs.push(attr.clone());
      }
    }

    let mut cac_proof = cac_prove::<_, S, P>(&mut prng,
                                             ac_issuer_pub_key,
                                             &recv_enc_pub_key,
                                             &revealed_attrs.as_slice(),
                                             &ctext_rands.as_slice(),
                                             reveal_bitmap,
                                             &ctexts.as_slice(),
                                             &proof).unwrap();

    let vrfy = cac_verify::<S, P>(ac_issuer_pub_key,
                                  &recv_enc_pub_key,
                                  &proof,
                                  ctexts.as_slice(),
                                  &cac_proof,
                                  reveal_bitmap);

    assert_eq!(Ok(()), vrfy);

    let mut tampered_bitmap = vec![];
    tampered_bitmap.extend_from_slice(reveal_bitmap);

    let b = reveal_bitmap.get(0).unwrap();

    tampered_bitmap[0] = !(*b);
    if *b {
      ctexts.remove(0);
      cac_proof.0.agg_rands_coms_g.remove(0);
      cac_proof.0.agg_rands_coms_pk.remove(0);
      cac_proof.0.agg_attrs_coms_g.remove(0);
      cac_proof.0.attrs_resps[0].remove(0);
      cac_proof.0.rands_resps[0].remove(0);
      proof.pok.response_attrs.push(S::from_u32(0));
    } else {
      ctexts.push(elgamal_encrypt(&P::G1::get_base(),
                                  &S::from_u32(0),
                                  &S::from_u32(0),
                                  &recv_enc_pub_key));
      cac_proof.0.agg_rands_coms_g.push(P::G1::get_identity());
      cac_proof.0.agg_rands_coms_pk.push(P::G1::get_identity());
      cac_proof.0.agg_attrs_coms_g.push(P::G1::get_identity());
      if cac_proof.0.attrs_resps.len() > 0 {
        cac_proof.0.attrs_resps[0].push(S::from_u32(0u32));
        cac_proof.0.rands_resps[0].push(S::from_u32(0u32));
      } else {
        cac_proof.0.attrs_resps.push(vec![S::from_u32(0u32)]);
        cac_proof.0.rands_resps.push(vec![S::from_u32(0u32)]);
      }
    }

    let vrfy = cac_verify::<S, P>(ac_issuer_pub_key,
                                  &recv_enc_pub_key,
                                  &proof,
                                  ctexts.as_slice(),
                                  &cac_proof,
                                  tampered_bitmap.as_slice());

    assert_eq!(Err(ZeiError::IdentityRevealVerifyError),
               vrfy,
               "proof should fail");
  }
}

#[cfg(test)]
mod test_bn {
  use super::test::confidential_ac_reveal;
  use crate::algebra::bn::{BNGt, BNScalar};

  #[test]
  fn confidential_reveal_one_attr_hidden() {
    confidential_ac_reveal::<BNScalar, BNGt>(&[false]);
  }

  #[test]
  fn confidential_reveal_one_attr_revealed() {
    confidential_ac_reveal::<BNScalar, BNGt>(&[true]);
  }

  #[test]
  fn confidential_reveal_two_attr_hidden_first() {
    confidential_ac_reveal::<BNScalar, BNGt>(&[false, false]);
    confidential_ac_reveal::<BNScalar, BNGt>(&[false, true]);
  }

  #[test]
  fn confidential_reveal_two_attr_revealed_first() {
    confidential_ac_reveal::<BNScalar, BNGt>(&[true, false]);
    confidential_ac_reveal::<BNScalar, BNGt>(&[true, true]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_hidden() {
    confidential_ac_reveal::<BNScalar, BNGt>(&[false; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_revealed() {
    confidential_ac_reveal::<BNScalar, BNGt>(&[true; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_half_revealed() {
    confidential_ac_reveal::<BNScalar, BNGt>(&[true, false, true, false, true, false, true,
                                               false, true, false]);
    confidential_ac_reveal::<BNScalar, BNGt>(&[false, true, false, true, false, true, false,
                                               true, false, true]);
  }

  #[test]
  fn confidential_reveal_agg() {
    super::test::confidential_reveal_agg::<BNScalar, BNGt>(&[true, true, false, false]);
  }
}

#[cfg(test)]
mod test_bls12_381 {
  use super::test::confidential_ac_reveal;
  use crate::algebra::bls12_381::{BLSGt, BLSScalar};

  #[test]
  fn confidential_reveal_one_attr_hidden() {
    confidential_ac_reveal::<BLSScalar, BLSGt>(&[false]);
  }

  #[test]
  fn confidential_reveal_one_attr_revealed() {
    confidential_ac_reveal::<BLSScalar, BLSGt>(&[true]);
  }

  #[test]
  fn confidential_reveal_two_attr_hidden_first() {
    confidential_ac_reveal::<BLSScalar, BLSGt>(&[false, false]);
    confidential_ac_reveal::<BLSScalar, BLSGt>(&[false, true]);
  }

  #[test]
  fn confidential_reveal_two_attr_revealed_first() {
    confidential_ac_reveal::<BLSScalar, BLSGt>(&[true, false]);
    confidential_ac_reveal::<BLSScalar, BLSGt>(&[true, true]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_hidden() {
    confidential_ac_reveal::<BLSScalar, BLSGt>(&[false; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_all_revealed() {
    confidential_ac_reveal::<BLSScalar, BLSGt>(&[true; 10]);
  }

  #[test]
  fn confidential_reveal_ten_attr_half_revealed() {
    confidential_ac_reveal::<BLSScalar, BLSGt>(&[true, false, true, false, true, false, true,
                                                 false, true, false]);
    confidential_ac_reveal::<BLSScalar, BLSGt>(&[false, true, false, true, false, true, false,
                                                 true, false, true]);
  }

  #[test]
  fn confidential_reveal_agg() {
    super::test::confidential_reveal_agg::<BLSScalar, BLSGt>(&[true, true, false, false]);
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
