/*
This file implements anonymous credentials based on the signature scheme of
David Pointcheval and Olivier Sanders. Short Randomizable Signatures. CT RSA 2015.
https://eprint.iacr.org/2015/525.pdf. Details are described below:

Credential issuers can issue credentials for a set of n attributes by providing a signature
on this attributes for a given user.

Given a credential signature, users can selectively reveal a subset of attributes that are signed
in the credentials by
 a) Randomizing the signature (provide unlinkability between reveals)
 b) Revealing a subset of attributes
 c) Provide a zero knowledge proof of knowledge of the user secret key and hidden attributes for
 the credential signature

 Specifications:
 Let G1, G2,Gt be groups of prime order and a bilinear map e: G1 x G2 -> Gt. In what follows,
 additive notation is used.
 Issuer secret key:
     - G1 // random generator of group 1
     - x // random scalar
     - {y_i} one y_i per attribute // random scalars

 Issuer public key:
     - G2  // random generator of group 2
     - X2 = x * G2
     - Z1 = z * G1 //for a random scalar z
     - Z2 = z * G2
     - {Y2_i} = {y_i * G2} // one y_i per attribute

 User secret key: sk // random scalar
 User public key: sk * Z2


 + Signature over attributes {attr_i} for user public key user_pub_key = user_sec_key * Z1:
   - Sample random scalar u
   - Compute C = (issuer_sec_key.x + \sum attr_i * y_i) * issuer_sec_key.G1
   - sigma1 = u * issuer_sec_key.G1 // u * G1
   - sigma2 = u * (C + user_pub_key) // u* (x + \sum attr_i * y_i + user_sec_key * z) * G1
   - output (sigma1, sigma2)

 + Signature Verification for a set of attributes {attr_i} for user public key user_pub_key over
   - compare e(sigma1, \sum attr_i * Y2_i + user_pk + X2) =? e(sigma2, G2)
      // Left hand side: e(G1, G2) * u * (\sum attr_i * y_i + user_sec_key * z + x)
      // Right hand side e(G1, G2) * u * (x + \sum attr_i * y_i + user_sec_key * z)

 + Selective revealing: prove that a signature verify against a set of attributes,
 some of which are hidden to the verifier. Strategy:
    a) Randomize the signature to provide unlinkability (and hence anonymity ) different reveals
    of the same underlying signature.
    b) provide a proof of knowledge of user's secret key,
      hidden attributes and scalar used to randomize the signature.

   Reveal Algorithm:
    a) signature randomization
      i) sigma1' = r * sigma1
      ii) sigma2' = r* (sigma2 + t * sigma1)
    b) NI proof of knowledge
        i) Produce blinding scalar b_t, b_sk, {b_attr_i: one for each attributes to hide}
       ii) Compute an aggregated proof commitment C = b_t * G2 + b_sk * Z2 + \sum b_attr_i * Y2_i
            (sum over attrs to hide)
      iii) Compute challenge c as Hash("ZeiACReveal", IssuerPubKey, sigma1', sigma2', {attrs_j}, C)
           where j ranges for the hidden attributes subset.
       iv) Compute challenge responses
           r_t = c * t + r_t,
           r_sk = c * sk + b_sk, and
           {r_attr_i = c* attr_i + b_attr_i} for each hidden attribute attr_i
    c) Output (sigma1', sigma2', C, r_t, r_sk, {r_attri})

  + Selective reveal verification:
   (Input: (sigma1', sigma2', C, r_t, r_sk, {r_attr_i}), revealed attributes: {attr_j}, issuer_pk)
     i) Compute challenge c as Hash("ZeiACReveal", IssuerPubKey, sigma1', sigma2', {attrs_j}, C)
    ii) Compute P = c * (X2 + \sum Y2_j attr_j) + r_t * G2 + r_sk * Z2 + \sum r_attr_i * Y2_i - C
        (where i ranges for all hidden attributes and j ranges for all revealed attributes)
   iii) Compare e(sigma1, P) =? e(sigma2, c * G2) (output 1 if equals, 0 otherwise)
        (e(sigma1',P) = e(r * u * G1, c * (X2 + \sum attr_i * Y2_j + t * G2 + sk * Z2) )
                      = e(G1,G2) * r * u * c( x + \sum attr_i * y_i + t + sk * z), and
         e(sigma2', c * G2) = e(G1,G2) * r * c * u * (x + \sum attr_i * y_i + t + sk * x)
*/

use crate::algebra::groups::{Group, Scalar};
use crate::algebra::pairing::PairingTargetGroup;
use crate::crypto::sigma::{SigmaTranscript, SigmaTranscriptPairing};
use crate::errors::ZeiError;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

pub(crate) const AC_REVEAL_PROOF_DOMAIN: &[u8] = b"AC Reveal PoK";
pub(crate) const AC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE: &[u8] = b"AC Reveal PoK Instance";

/// I contain Credentials' Issuer Public key fields
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACIssuerPublicKey<G1, G2> {
  pub(crate) gen2: G2,     //random generator for G2
  pub(crate) xx2: G2,      //gen2^x, x in CredIssuerSecretKey
  pub(crate) zz1: G1,      //gen1^z, z random scalar, gen1 in CredIssuerSecretKey
  pub(crate) zz2: G2,      //gen2^z, same z as above
  pub(crate) yy2: Vec<G2>, //gen2^{y_i}, y_i in CredIssuerSecretKey
}

/// I contain the Credentials' Issuer Secret key fields
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACIssuerSecretKey<G1, S> {
  pub(crate) gen1: G1, //random generator for G1
  pub(crate) x: S,
  pub(crate) y: Vec<S>,
}

/// I'm a signature for a set of attributes produced by issuer for a user
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACSignature<G1> {
  pub(crate) sigma1: G1,
  pub(crate) sigma2: G1,
}

///I'm a user public key used to request a signature for a set of attributes (credential)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACUserPublicKey<G1>(pub(crate) G1);

///I'm a user's secret key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACUserSecretKey<S>(pub(crate) S);

/// I'm a proof computed by the UserSecretKey holder that an Issuer has signed certain
/// attributes for the corresponding UserPublicKey
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACRevealSig<G1, G2, S> {
  pub sig: ACSignature<G1>,
  pub rnd: (S, S),
  pub pok: ACPoK<G2, S>,
}

/// I'm a proof of knowledge for t, sk (UserSecretKey), and hidden attributes that satisfy a
/// certain relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACPoK<G2, S> {
  pub(crate) commitment: G2, // r_t*G2 + r_sk*Z2 + sum_{a_i in hidden attrs} r_{a_i}*Y2_i
  pub(crate) response_t: S,  // c*t + r_t
  pub(crate) response_sk: S, // c*sk + r_sk
  pub(crate) response_attrs: Vec<S>, // {c*a_i + r_{a_i}; a_i in hidden}
}

/// I generate e key pair for a credential issuer
#[allow(clippy::type_complexity)]
pub(crate) fn ac_keygen_issuer<R: CryptoRng + RngCore, P: PairingTargetGroup>(
  prng: &mut R,
  num_attrs: usize)
  -> (ACIssuerPublicKey<P::G1, P::G2>, ACIssuerSecretKey<P::G1, P::ScalarField>) {
  let x = P::ScalarField::random_scalar(prng);
  let z = P::ScalarField::random_scalar(prng);
  //TODO check that G1 and G2 are of prime order so that every element is generator
  let gen1: P::G1 = P::G1::get_base().mul(&P::ScalarField::random_scalar(prng));
  let gen2 = P::G2::get_base().mul(&P::ScalarField::random_scalar(prng));
  let mut y = vec![];
  let mut yy2 = vec![];
  for _ in 0..num_attrs {
    let yi = P::ScalarField::random_scalar(prng);
    yy2.push(gen2.mul(&yi));
    y.push(yi);
  }
  let xx2 = gen2.mul(&x);
  let zz1 = gen1.mul(&z);
  let zz2 = gen2.mul(&z);
  (ACIssuerPublicKey { gen2,
                       xx2,
                       zz1,
                       zz2,
                       yy2 },
   ACIssuerSecretKey { gen1, x, y })
}

/// I generate a credential user key pair for a given credential issuer
pub(crate) fn ac_keygen_user<R: CryptoRng + RngCore, P: PairingTargetGroup>(
  prng: &mut R,
  issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>)
  -> (ACUserPublicKey<P::G1>, ACUserSecretKey<P::ScalarField>) {
  let secret = P::ScalarField::random_scalar(prng);
  let pk = issuer_pk.zz1.mul(&secret);
  (ACUserPublicKey(pk), ACUserSecretKey(secret))
}

/// I Compute a credential signature for a set of attributes. User can represent Null attributes by
/// a fixes scalar (e.g. 0)
pub(crate) fn ac_sign<R: CryptoRng + RngCore, P: PairingTargetGroup>(prng: &mut R,
                                                                     issuer_sk: &ACIssuerSecretKey<P::G1, P::ScalarField>,
                                                                     user_pk: &ACUserPublicKey<P::G1>,
                                                                     attrs: &[P::ScalarField])
                                                                     -> ACSignature<P::G1> {
  let u = P::ScalarField::random_scalar(prng);
  let mut exponent = issuer_sk.x.clone();
  for (attr, yi) in attrs.iter().zip(issuer_sk.y.iter()) {
    exponent = exponent.add(&attr.mul(yi));
  }
  let cc = issuer_sk.gen1.mul(&exponent);
  ACSignature::<P::G1> { sigma1: issuer_sk.gen1.mul(&u),
                         sigma2: user_pk.0.add(&cc).mul(&u) }
}

pub(crate) fn ac_sample_random_factors<R: CryptoRng + RngCore, P: PairingTargetGroup>(
  prng: &mut R)
  -> (P::ScalarField, P::ScalarField) {
  (P::ScalarField::random_scalar(prng), P::ScalarField::random_scalar(prng))
}

/// I produce a AttrsRevealProof, bitmap indicates which attributes are revealed.
#[allow(clippy::type_complexity)]
pub(crate) fn ac_reveal<R: CryptoRng + RngCore, P: PairingTargetGroup>(
  prng: &mut R,
  user_sk: &ACUserSecretKey<P::ScalarField>,
  issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
  sig: &ACSignature<P::G1>,
  attrs: &[P::ScalarField],
  bitmap: &[bool] // indicates which attributes are revealed
) -> Result<ACRevealSig<P::G1, P::G2, P::ScalarField>, ZeiError> {
  let randomization = ac_sample_random_factors::<_, P>(prng);
  ac_reveal_with_rand::<_, P>(prng, user_sk, issuer_pk, sig, attrs, bitmap, randomization)
}

/// Produce an AttrsRevealProof with randomness supplied by caller via a random_pair
#[allow(clippy::type_complexity)]
pub(crate) fn ac_reveal_with_rand<R: CryptoRng + RngCore, P: PairingTargetGroup>(
  prng: &mut R,
  user_sk: &ACUserSecretKey<P::ScalarField>,
  issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
  sig: &ACSignature<P::G1>,
  attrs: &[P::ScalarField],
  bitmap: &[bool],
  random_pair: (P::ScalarField, P::ScalarField))
  -> Result<ACRevealSig<P::G1, P::G2, P::ScalarField>, ZeiError> {
  let (r1, r2) = random_pair;
  let sigma1_r = sig.sigma1.mul(&r1);
  let sigma1_t = sig.sigma1.mul(&r2);
  let sigma2_aux = sig.sigma2.add(&sigma1_t);
  let sigma2_r = sigma2_aux.mul(&r1);
  let rand_sig = ACSignature::<P::G1>{
        sigma1: sigma1_r,
        sigma2: sigma2_r, //sigma2: r*(sigma2 + t*sigma1)
    };

  let mut hidden_attrs = vec![];
  for (attr, revealed) in attrs.iter().zip(bitmap) {
    if !(*revealed) {
      hidden_attrs.push(attr.clone());
    }
  }
  let mut transcript = Transcript::new(AC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
  let proof = prove_pok::<_, P>(&mut transcript,
                                prng,
                                user_sk,
                                issuer_pk,
                                &r2,
                                hidden_attrs.as_slice(),
                                bitmap,
                                &rand_sig)?;

  Ok(ACRevealSig { sig: rand_sig,
                   rnd: (r1, r2),
                   pok: proof })
}

pub(super) fn init_transcript<P: PairingTargetGroup>(transcript: &mut Transcript,
                                                     issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
                                                     signature: &ACSignature<P::G1>) {
  let g1 = P::G1::get_base();
  let g2 = P::G2::get_base();
  let g1_elems = vec![&g1, &issuer_pk.zz1, &signature.sigma1, &signature.sigma2];
  let mut g2_elems = vec![&g2, &issuer_pk.gen2, &issuer_pk.xx2, &issuer_pk.zz2];
  for e in issuer_pk.yy2.iter() {
    g2_elems.push(e);
  }
  transcript.init_sigma_pairing::<P>(AC_REVEAL_PROOF_DOMAIN,
                                     &[],
                                     &g1_elems[..],
                                     g2_elems.as_slice(),
                                     &[]);
}
/// I produce selective attribute disclose proof of knowledge
/// Algorithm:
///     1. Sample beta1, beta2 and {gamma_j} (One for each hidden attribute)
///     2. Compute a sigma proof commitment for the values in 1:
///        beta1*g2 + beta2*Z2 + \sum gamma_j Y2_{j_i} for each j_i s.t revealed_itmap[j_i] = false
///     3. Sample the challenge as a hash of the commitment.
///     4. Compute challenge's responses  c*t + \beta1, c*sk + beta2, {c*y_i + gamma_i}
///     5. Return proof commitment and responses
#[allow(clippy::too_many_arguments)]
fn prove_pok<R: CryptoRng + RngCore, P: PairingTargetGroup>(
  transcript: &mut Transcript,
  prng: &mut R,
  user_sk: &ACUserSecretKey<P::ScalarField>,
  issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
  t: &P::ScalarField,
  hidden_attrs: &[P::ScalarField],
  bitmap: &[bool], // indicates revealed attributed
  sig: &ACSignature<P::G1>)
  -> Result<ACPoK<P::G2, P::ScalarField>, ZeiError> {
  init_transcript::<P>(transcript, issuer_pk, sig);

  let beta1 = P::ScalarField::random_scalar(prng);
  let beta2 = P::ScalarField::random_scalar(prng);
  let mut gamma = vec![];
  for _ in 0..hidden_attrs.len() {
    gamma.push(P::ScalarField::random_scalar(prng));
  }
  let mut commitment = issuer_pk.gen2.mul(&beta1).add(&issuer_pk.zz2.mul(&beta2));
  let mut gamma_iter = gamma.iter();
  for (yy2i, x) in issuer_pk.yy2.iter().zip(bitmap) {
    if !(*x) {
      let gammai = gamma_iter.next().unwrap();
      let elem = yy2i.mul(gammai);
      commitment = commitment.add(&elem);
    }
  }
  transcript.append_proof_commitment(&commitment);
  let challenge = transcript.get_challenge::<P::ScalarField>();
  let response_t = challenge.mul(t).add(&beta1); // challente*t + beta1
  let response_sk = challenge.mul(&user_sk.0).add(&beta2);
  let mut response_attrs = vec![];
  let mut gamma_iter = gamma.iter();
  let mut attr_iter = hidden_attrs.iter();
  for y in bitmap {
    if !(*y) {
      let gamma = gamma_iter.next().unwrap();
      let attr = attr_iter.next().unwrap();
      let resp_attr_i = challenge.mul(attr).add(gamma);
      response_attrs.push(resp_attr_i);
    }
  }
  Ok(ACPoK { commitment,
             response_t,
             response_sk,
             response_attrs })
}

/// Given a list of revealed attributes_{k}, and a credential structure composed by a signature
/// (sigma1,sigma2) and a proof of
/// knowledge of t, sk and some hidden attributes, I verify that
/// e(sigma1,X2) + e(sigma1, g_2^t) + e(sigma1, Z2^sk) + e(sigma1, \\sum Y2_i^attr_i)
/// equals e(sigma2, g_2)
/// Revealed attributes attr corresponds to the positions where the bitmap is true
/// I return Ok() in case signatures and proofs are correct.
/// Otherwise, I return Err(ZeiError:SignatureError)
/// Algorithm:
/// 1. Compute challenge c as hash of proof_commitment
/// 2. Compute p \= -proof_commitment + c*X2 + proof_response\_t*g\_2 + proof\_response\_sk*Z2 +
///  sum_{i\in hidden} proof_response_attr_i * Y2_i + sum_{i\in revealed} c*attr_i * Y2_i
/// 3. Compare e(sigma1, p) against e(sigma2, c*g2)
pub(crate) fn ac_verify<P: PairingTargetGroup>(issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                               revealed_attrs: &[P::ScalarField],
                                               bitmap: &[bool],
                                               ac_sig: &ACSignature<P::G1>,
                                               reveal_sig_pok: &ACPoK<P::G2, P::ScalarField>)
                                               -> Result<(), ZeiError> {
  let mut transcript = Transcript::new(AC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
  init_transcript::<P>(&mut transcript, issuer_pub_key, &ac_sig);
  transcript.append_proof_commitment(&reveal_sig_pok.commitment);
  let challenge = transcript.get_challenge::<P::ScalarField>();
  // hidden = X_2*c - proof_commitment + &G2 * r_t + Z2 * r_sk + \sum r_attr_i * Y2_i;
  let hidden =
    ac_vrfy_hidden_terms_addition::<P>(&challenge, &reveal_sig_pok, issuer_pub_key, bitmap)?;
  // revealed = c * \sum attr_j * Y2_j;
  let revealed =
    ac_vrfy_revealed_terms_addition::<P>(&challenge, revealed_attrs, issuer_pub_key, bitmap)?;

  // p = c * (X2 + t*G2 + sk * Z2 \sum attr_i Y2_i)
  let p = hidden.add(&revealed);

  let lhs = P::pairing(&ac_sig.sigma1, &p);
  let rhs = P::pairing(&ac_sig.sigma2.mul(&challenge), &issuer_pub_key.gen2);

  if lhs == rhs {
    Ok(())
  } else {
    Err(ZeiError::SignatureError)
  }
}

/// Helper function that compute the term of an anonymous credential verification
/// that do not include the revealed attributes. That is:
/// c * X2 + b_t * G1  + b_sk * Z2 + sum_{i\in Hidden} b_{attr_i} * Y2_i - reveal_sig.COM
/// = c( x + t + sk * z + sum_{i\in Hidden} attr_i * y2_i) * G2
pub(crate) fn ac_vrfy_hidden_terms_addition<P: PairingTargetGroup>(challenge: &P::ScalarField,
                                                                   reveal_sig_pok: &ACPoK<P::G2, P::ScalarField>,
                                                                   issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                                   bitmap: &[bool])
                                                                   -> Result<P::G2, ZeiError> {
  //compute X_2 * challenge - commitment + G2 * &response_t + PK.Z2 * response_sk +
  // sum PK.Y2_i * response_attr_i
  let mut q = issuer_pub_key.xx2
                            .mul(&challenge)
                            .sub(&reveal_sig_pok.commitment); //X_2*challenge - proof.commitment

  q = q.add(&issuer_pub_key.gen2.mul(&reveal_sig_pok.response_t));
  q = q.add(&issuer_pub_key.zz2.mul(&reveal_sig_pok.response_sk));

  let mut resp_attr_iter = reveal_sig_pok.response_attrs.iter();
  for (b, yy2i) in bitmap.iter().zip(issuer_pub_key.yy2.iter()) {
    if !b {
      let response = resp_attr_iter.next().ok_or(ZeiError::ParameterError)?;
      q = q.add(&yy2i.mul(response));
    }
  }
  Ok(q)
}

fn ac_vrfy_revealed_terms_addition<P: PairingTargetGroup>(challenge: &P::ScalarField,
                                                          revealed_attrs: &[P::ScalarField],
                                                          issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                                          bitmap: &[bool])
                                                          -> Result<P::G2, ZeiError> {
  let mut attr_prod_yy2 = P::G2::get_identity();
  let mut attr_iter = revealed_attrs.iter();
  for (b, yy2i) in bitmap.iter().zip(issuer_pub_key.yy2.iter()) {
    if *b {
      let attr = attr_iter.next().ok_or(ZeiError::ParameterError)?;
      attr_prod_yy2 = attr_prod_yy2.add(&yy2i.mul(attr));
    }
  }
  Ok(attr_prod_yy2.mul(challenge))
}

#[cfg(test)]
pub(crate) mod credentials_tests {
  use super::*;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;
  use rmp_serde::Deserializer;
  use serde::{Deserialize, Serialize};

  fn reveal<P: PairingTargetGroup>(bitmap: &[bool]) {
    let n = bitmap.len();
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let issuer_keypair = super::ac_keygen_issuer::<_, P>(&mut prng, n);
    let issuer_pk = &issuer_keypair.0;
    let issuer_sk = &issuer_keypair.1;
    let (user_pk, user_sk) = super::ac_keygen_user::<_, P>(&mut prng, issuer_pk);

    let mut attrs = vec![];

    for _ in bitmap {
      attrs.push(P::ScalarField::random_scalar(&mut prng));
    }

    let sig = super::ac_sign::<_, P>(&mut prng, &issuer_sk, &user_pk, attrs.as_slice());

    let reveal_sig = super::ac_reveal::<_, P>(&mut prng,
                                              &user_sk,
                                              issuer_pk,
                                              &sig,
                                              attrs.as_slice(),
                                              bitmap).unwrap();

    let mut revealed_attrs = vec![];

    for (attr, b) in attrs.iter().zip(bitmap) {
      if *b {
        revealed_attrs.push(attr.clone());
      }
    }

    assert_eq!(true,
               ac_verify::<P>(&issuer_pk,
                              revealed_attrs.as_slice(),
                              bitmap,
                              &reveal_sig.sig,
                              &reveal_sig.pok).is_ok())
  }

  pub fn single_attribute<P: PairingTargetGroup>() {
    reveal::<P>(&[false]);
    reveal::<P>(&[true]);
  }

  pub fn two_attributes<P: PairingTargetGroup>() {
    reveal::<P>(&[false, false]);
    reveal::<P>(&[true, false]);
    reveal::<P>(&[false, true]);
    reveal::<P>(&[true, true]);
  }

  pub fn ten_attributes<P: PairingTargetGroup>() {
    reveal::<P>(&[false; 10]);
    reveal::<P>(&[true, false, true, false, true, false, true, false, true, false]);
    reveal::<P>(&[false, true, false, true, false, true, false, true, false, true]);
    reveal::<P>(&[true; 10]);
  }

  pub fn to_json_credential_structures<P: PairingTargetGroup>() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    //issuer keys
    let issuer_keys = ac_keygen_issuer::<_, P>(&mut prng, 10);
    let json_str = serde_json::to_string(&issuer_keys.0).unwrap();
    let issuer_pub_key_de: ACIssuerPublicKey<P::G1, P::G2> =
      serde_json::from_str(&json_str).unwrap();
    assert_eq!(issuer_keys.0, issuer_pub_key_de);

    let json_str = serde_json::to_string(&issuer_keys.1).unwrap();
    let issuer_sec_key_de: ACIssuerSecretKey<P::G1, P::ScalarField> =
      serde_json::from_str(&json_str).unwrap();
    assert_eq!(issuer_keys.1, issuer_sec_key_de);

    //user keys
    let user_keys = super::ac_keygen_user::<_, P>(&mut prng, &issuer_keys.0);
    let json_str = serde_json::to_string(&user_keys.0).unwrap();
    let user_pub_key_de: ACUserPublicKey<P::G1> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(user_keys.0, user_pub_key_de);

    let json_str = serde_json::to_string(&user_keys.1).unwrap();
    let user_sec_key_de: ACUserSecretKey<P::ScalarField> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(user_keys.1, user_sec_key_de);

    // reveal proof containing signature and pok
    let attrs = [P::ScalarField::from_u32(10), P::ScalarField::from_u32(10)];
    let credential = super::ac_sign::<_, P>(&mut prng, &issuer_keys.1, &user_keys.0, &attrs);
    let reveal_sig = super::ac_reveal::<_, P>(&mut prng,
                                              &user_keys.1,
                                              &issuer_keys.0,
                                              &credential,
                                              &attrs,
                                              &[true, false]).unwrap();
    let json_str = serde_json::to_string(&reveal_sig).unwrap();
    let reveal_sig_de: ACRevealSig<P::G1, P::G2, P::ScalarField> =
      serde_json::from_str(&json_str).unwrap();
    assert_eq!(reveal_sig, reveal_sig_de);
  }

  pub fn to_msg_pack_credential_structures<P: PairingTargetGroup>() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    //issuer keys
    let issuer_keys = ac_keygen_issuer::<_, P>(&mut prng, 10);
    let mut vec = vec![];
    issuer_keys.0
               .serialize(&mut rmp_serde::Serializer::new(&mut vec))
               .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let issuer_pub_key_de: ACIssuerPublicKey<P::G1, P::G2> =
      Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(issuer_keys.0, issuer_pub_key_de);

    let mut vec = vec![];
    issuer_keys.1
               .serialize(&mut rmp_serde::Serializer::new(&mut vec))
               .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let issuer_priv_key_de: ACIssuerSecretKey<P::G1, P::ScalarField> =
      Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(issuer_keys.1, issuer_priv_key_de);

    //user keys
    let user_keys = super::ac_keygen_user::<_, P>(&mut prng, &issuer_keys.0);
    let mut vec = vec![];
    user_keys.0
             .serialize(&mut rmp_serde::Serializer::new(&mut vec))
             .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let user_pub_key_de: ACUserPublicKey<P::G1> = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(user_keys.0, user_pub_key_de);

    let mut vec = vec![];
    user_keys.1
             .serialize(&mut rmp_serde::Serializer::new(&mut vec))
             .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let user_priv_key_de: ACUserSecretKey<P::ScalarField> =
      Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(user_keys.1, user_priv_key_de);

    // reveal proof containing signature and pok
    let attrs = [P::ScalarField::from_u32(10), P::ScalarField::from_u32(10)];
    let credential = super::ac_sign::<_, P>(&mut prng, &issuer_keys.1, &user_keys.0, &attrs);
    let reveal_sig = super::ac_reveal::<_, P>(&mut prng,
                                              &user_keys.1,
                                              &issuer_keys.0,
                                              &credential,
                                              &attrs,
                                              &[true, false]).unwrap();

    let mut vec = vec![];
    reveal_sig.serialize(&mut rmp_serde::Serializer::new(&mut vec))
              .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let reveal_sig_de: ACRevealSig<P::G1, P::G2, P::ScalarField> =
      Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(reveal_sig, reveal_sig_de);
  }
}
