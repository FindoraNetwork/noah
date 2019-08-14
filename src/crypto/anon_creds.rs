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
use crate::algebra::pairing::Pairing;
use crate::errors::ZeiError;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha512};

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
  pub(crate) sig: ACSignature<G1>,
  pub(crate) pok: ACPoK<G2, S>,
}

/// I'm a proof of knowledge for t, sk (UserSecretKey), and hidden attributes that satisfy a
/// certain relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ACPoK<G2, S> {
  pub(crate) commitment: G2, // r_t*G2 + r_sk*Z2 + sum_{a_i in hidden attrs} r_{a_i}*Y2_i
  pub(crate) response_t: S,  // c*t + r_t
  pub(crate) response_sk: S, // c*sk + r_sk
  pub(crate) response_attrs: Vec<S>, // {c*a_i + r_{a_i}; a_i in hidden}
}

/// I generate e key pair for a credential issuer
pub fn ac_keygen_issuer<R: CryptoRng + Rng, S: Scalar, P: Pairing<S>>(
  prng: &mut R,
  num_attrs: usize)
  -> (ACIssuerPublicKey<P::G1, P::G2>, ACIssuerSecretKey<P::G1, S>) {
  let x = S::random_scalar(prng);
  let z = S::random_scalar(prng);
  //TODO check that G1 and G2 are of prime order so that every element is generator
  let gen1 = P::g1_mul_scalar(&P::G1::get_base(), &S::random_scalar(prng));
  let gen2 = P::g2_mul_scalar(&P::G2::get_base(), &S::random_scalar(prng));
  let mut y = vec![];
  let mut yy2 = vec![];
  for _ in 0..num_attrs {
    let yi = S::random_scalar(prng);
    yy2.push(P::g2_mul_scalar(&gen2, &yi));
    y.push(yi);
  }
  let xx2 = P::g2_mul_scalar(&gen2, &x);
  let zz1 = P::g1_mul_scalar(&gen1, &z);
  let zz2 = P::g2_mul_scalar(&gen2, &z);
  (ACIssuerPublicKey { gen2,
                       xx2,
                       zz1,
                       zz2,
                       yy2 },
   ACIssuerSecretKey { gen1: gen1, x, y })
}

/// I generate a credential user key pair for a given credential issuer
pub fn ac_keygen_user<R: CryptoRng + Rng, S: Scalar, P: Pairing<S>>(
  prng: &mut R,
  issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>)
  -> (ACUserPublicKey<P::G1>, ACUserSecretKey<S>) {
  let secret = S::random_scalar(prng);
  let pk = P::g1_mul_scalar(&issuer_pk.zz1, &secret);
  (ACUserPublicKey(pk), ACUserSecretKey(secret))
}

/// I Compute a credential signature for a set of attributes. User can represent Null attributes by
/// a fixes scalar (e.g. 0)
pub fn ac_sign<R: CryptoRng + Rng, S: Scalar, P: Pairing<S>>(prng: &mut R,
                                                             issuer_sk: &ACIssuerSecretKey<P::G1, S>,
                                                             user_pk: &ACUserPublicKey<P::G1>,
                                                             attrs: &[S])
                                                             -> ACSignature<P::G1> {
  let u = S::random_scalar(prng);
  let mut exponent = issuer_sk.x.clone();
  for (attr, yi) in attrs.iter().zip(issuer_sk.y.iter()) {
    exponent = exponent.add(&attr.mul(yi));
  }
  let cc = P::g1_mul_scalar(&issuer_sk.gen1, &exponent);
  ACSignature::<P::G1> { sigma1: P::g1_mul_scalar(&issuer_sk.gen1, &u),
                         sigma2: P::g1_mul_scalar(&user_pk.0.add(&cc), &u) }
}

/// I produce a AttrsRevealProof, bitmap indicates which attributes are revealed
pub fn ac_reveal<R: CryptoRng + Rng, S: Scalar, P: Pairing<S>>(
  prng: &mut R,
  user_sk: &ACUserSecretKey<S>,
  issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
  sig: &ACSignature<P::G1>,
  attrs: &[S],
  bitmap: &[bool] // indicates which attributes are revealed
) -> Result<ACRevealSig<P::G1, P::G2, S>, ZeiError> {
  let r = S::random_scalar(prng);
  let t = S::random_scalar(prng);
  let sigma1_r = P::g1_mul_scalar(&sig.sigma1, &r);
  let sigma1_t = P::g1_mul_scalar(&sig.sigma1, &t);
  let sigma2_aux = sig.sigma2.add(&sigma1_t);
  let sigma2_r = P::g1_mul_scalar(&sigma2_aux, &r);
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
  let proof = prove_pok::<_, S, P>(prng,
                                   user_sk,
                                   issuer_pk,
                                   &t,
                                   hidden_attrs.as_slice(),
                                   bitmap,
                                   &rand_sig)?;

  Ok(ACRevealSig { sig: rand_sig,
                   pok: proof })
}

/// I produce selective attribute disclose proof of knowledge
/// Algorithm:
///     1. Sample beta1, beta2 and {gamma_j} (One for each hidden attribute)
///     2. Compute a sigma proof commitment for the values in 1:
///        beta1*g2 + beta2*Z2 + \sum gamma_j Y2_{j_i} for each j_i s.t revealed_itmap[j_i] = false
///     3. Sample the challenge as a hash of the commitment.
///     4. Compute challenge's responses  c*t + \beta1, c*sk + beta2, {c*y_i + gamma_i}
///     5. Return proof commitment and responses
fn prove_pok<R: CryptoRng + Rng, S: Scalar, P: Pairing<S>>(prng: &mut R,
                                                           user_sk: &ACUserSecretKey<S>,
                                                           issuer_pk: &ACIssuerPublicKey<P::G1,
                                                                              P::G2>,
                                                           t: &S,
                                                           hidden_attrs: &[S],
                                                           bitmap: &[bool], // indicates revealed attributed
                                                           sig: &ACSignature<P::G1>)
                                                           -> Result<ACPoK<P::G2, S>, ZeiError> {
  let beta1 = S::random_scalar(prng);
  let beta2 = S::random_scalar(prng);
  let mut gamma = vec![];
  for _ in 0..hidden_attrs.len() {
    gamma.push(S::random_scalar(prng));
  }
  let mut commitment =
    P::g2_mul_scalar(&issuer_pk.gen2, &beta1).add(&P::g2_mul_scalar(&issuer_pk.zz2, &beta2));
  let mut gamma_iter = gamma.iter();
  for (yy2i, x) in issuer_pk.yy2.iter().zip(bitmap) {
    if !(*x) {
      let gammai = gamma_iter.next().unwrap();
      let elem = P::g2_mul_scalar(&yy2i, gammai);
      commitment = commitment.add(&elem);
    }
  }
  let challenge: S = ac_challenge::<S, P>(issuer_pk, sig, &commitment)?;
  let response_t = challenge.mul(t).add(&beta1); // challente*t + beta1
  let response_sk = challenge.mul(&user_sk.0).add(&beta2);
  let mut response_attrs = vec![];
  let mut gamma_iter = gamma.iter();
  let mut attr_iter = hidden_attrs.iter();
  for y in bitmap {
    if (*y) == false {
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

/// I compute proof of knowledge challenge for selective attribute disclosure proof
pub(crate) fn ac_challenge<S: Scalar, P: Pairing<S>>(issuer_pub_key: &ACIssuerPublicKey<P::G1,
                                                                        P::G2>,
                                                     sig: &ACSignature<P::G1>,
                                                     commitment: &P::G2)
                                                     -> Result<S, ZeiError> {
  let c = commitment.to_compressed_bytes();
  let mut hasher = Sha512::new();
  let encoded_key = bincode::serialize(&issuer_pub_key).map_err(|_| ZeiError::SerializationError)?;
  let encoded_sig = bincode::serialize(&sig).map_err(|_| ZeiError::SerializationError)?;

  hasher.input("ZeiACReveal");
  hasher.input(encoded_key.as_slice());
  hasher.input(encoded_sig.as_slice());
  hasher.input(c.as_slice());

  Ok(S::from_hash(hasher))
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
pub fn ac_verify<S: Scalar, P: Pairing<S>>(issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
                                           revealed_attrs: &[S],
                                           bitmap: &[bool],
                                           reveal_sig: &ACRevealSig<P::G1, P::G2, S>)
                                           -> Result<(), ZeiError> {
  let challenge =
    ac_challenge::<S, P>(issuer_pub_key, &reveal_sig.sig, &reveal_sig.pok.commitment)?;
  // hidden = X_2*c - proof_commitment + &G2 * r_t + Z2 * r_sk + \sum r_attr_i * Y2_i;
  let hidden =
    ac_vrfy_hidden_terms_addition::<S, P>(&challenge, &reveal_sig, issuer_pub_key, bitmap)?;
  // revealed = c * \sum attr_j * Y2_j;
  let revealed =
    ac_vrfy_revealed_terms_addition::<S, P>(&challenge, revealed_attrs, issuer_pub_key, bitmap)?;

  // p = c * (X2 + t*G2 + sk * Z2 \sum attr_i Y2_i)
  let p = hidden.add(&revealed);

  let lhs = P::pairing(&reveal_sig.sig.sigma1, &p);
  let rhs = P::pairing(&reveal_sig.sig.sigma2.mul(&challenge), &issuer_pub_key.gen2);

  match lhs == rhs {
    true => Ok(()),
    false => Err(ZeiError::SignatureError),
  }
}

/// Helper function that compute the term of an anonymous credential verification
/// that do not include the revealed attributes. That is:
/// c * X2 + b_t * G1  + b_sk * Z2 + sum_{i\in Hidden} b_{attr_i} * Y2_i - reveal_sig.COM
/// = c( x + t + sk * z + sum_{i\in Hidden} attr_i * y2_i) * G2
pub(crate) fn ac_vrfy_hidden_terms_addition<S: Scalar, P: Pairing<S>>(
  challenge: &S,
  reveal_sig: &ACRevealSig<P::G1, P::G2, S>,
  issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
  bitmap: &[bool])
  -> Result<P::G2, ZeiError> {
  //compute X_2 * challenge - commitment + G2 * &response_t + PK.Z2 * response_sk +
  // sum PK.Y2_i * response_attr_i
  let mut q = issuer_pub_key.xx2
                            .mul(&challenge)
                            .sub(&reveal_sig.pok.commitment); //X_2*challenge - proof.commitment

  q = q.add(&issuer_pub_key.gen2.mul(&reveal_sig.pok.response_t));
  q = q.add(&issuer_pub_key.zz2.mul(&reveal_sig.pok.response_sk));

  let mut resp_attr_iter = reveal_sig.pok.response_attrs.iter();
  for (b, yy2i) in bitmap.iter().zip(issuer_pub_key.yy2.iter()) {
    if !b {
      let response = resp_attr_iter.next().ok_or(ZeiError::ParameterError)?;
      q = q.add(&yy2i.mul(response));
    }
  }
  Ok(q)
}

fn ac_vrfy_revealed_terms_addition<S: Scalar, P: Pairing<S>>(challenge: &S,
                                                             revealed_attrs: &[S],
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
  use rand::SeedableRng;
  use rand_chacha::ChaChaRng;
  use rmp_serde::Deserializer;
  use serde::{Deserialize, Serialize};

  fn reveal<S: Scalar, P: Pairing<S>>(bitmap: &[bool]) {
    let n = bitmap.len();
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let issuer_keypair = super::ac_keygen_issuer::<_, S, P>(&mut prng, n);
    let issuer_pk = &issuer_keypair.0;
    let issuer_sk = &issuer_keypair.1;
    let (user_pk, user_sk) = super::ac_keygen_user::<_, S, P>(&mut prng, issuer_pk);

    let mut attrs = vec![];

    for _ in bitmap {
      attrs.push(S::random_scalar(&mut prng));
    }

    let sig = super::ac_sign::<_, S, P>(&mut prng, &issuer_sk, &user_pk, attrs.as_slice());

    let reveal_sig = super::ac_reveal::<_, S, P>(&mut prng,
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

    assert_eq!(true, ac_verify::<S,P>(
            &issuer_pk,
            revealed_attrs.as_slice(),
            bitmap,
            &reveal_sig,
        ).is_ok())
  }

  pub fn single_attribute<S: Scalar, P: Pairing<S>>() {
    reveal::<S, P>(&[false]);
    reveal::<S, P>(&[true]);
  }

  pub fn two_attributes<S: Scalar, P: Pairing<S>>() {
    reveal::<S, P>(&[false, false]);
    reveal::<S, P>(&[true, false]);
    reveal::<S, P>(&[false, true]);
    reveal::<S, P>(&[true, true]);
  }

  pub fn ten_attributes<S: Scalar, P: Pairing<S>>() {
    reveal::<S, P>(&[false; 10]);
    reveal::<S, P>(&[true, false, true, false, true, false, true, false, true, false]);
    reveal::<S, P>(&[false, true, false, true, false, true, false, true, false, true]);
    reveal::<S, P>(&[true; 10]);
  }

  pub fn to_json_credential_structures<S: Scalar, P: Pairing<S>>() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    //issuer keys
    let issuer_keys = ac_keygen_issuer::<_, S, P>(&mut prng, 10);
    let json_str = serde_json::to_string(&issuer_keys.0).unwrap();
    let issuer_pub_key_de: ACIssuerPublicKey<P::G1, P::G2> =
      serde_json::from_str(&json_str).unwrap();
    assert_eq!(issuer_keys.0, issuer_pub_key_de);

    let json_str = serde_json::to_string(&issuer_keys.1).unwrap();
    let issuer_sec_key_de: ACIssuerSecretKey<P::G1, S> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(issuer_keys.1, issuer_sec_key_de);

    //user keys
    let user_keys = super::ac_keygen_user::<_, S, P>(&mut prng, &issuer_keys.0);
    let json_str = serde_json::to_string(&user_keys.0).unwrap();
    let user_pub_key_de: ACUserPublicKey<P::G1> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(user_keys.0, user_pub_key_de);

    let json_str = serde_json::to_string(&user_keys.1).unwrap();
    let user_sec_key_de: ACUserSecretKey<S> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(user_keys.1, user_sec_key_de);

    // reveal proof containing signature and pok
    let attrs = [S::from_u32(10), S::from_u32(10)];
    let credential = super::ac_sign::<_, S, P>(&mut prng, &issuer_keys.1, &user_keys.0, &attrs);
    let reveal_sig = super::ac_reveal::<_, S, P>(&mut prng,
                                                 &user_keys.1,
                                                 &issuer_keys.0,
                                                 &credential,
                                                 &attrs,
                                                 &[true, false]).unwrap();
    let json_str = serde_json::to_string(&reveal_sig).unwrap();
    let reveal_sig_de: ACRevealSig<P::G1, P::G2, S> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(reveal_sig, reveal_sig_de);
  }

  pub fn to_msg_pack_credential_structures<S: Scalar, P: Pairing<S>>() {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    //issuer keys
    let issuer_keys = ac_keygen_issuer::<_, S, P>(&mut prng, 10);
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
    let issuer_priv_key_de: ACIssuerSecretKey<P::G1, S> =
      Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(issuer_keys.1, issuer_priv_key_de);

    //user keys
    let user_keys = super::ac_keygen_user::<_, S, P>(&mut prng, &issuer_keys.0);
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
    let user_priv_key_de: ACUserSecretKey<S> = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(user_keys.1, user_priv_key_de);

    // reveal proof containing signature and pok
    let attrs = [S::from_u32(10), S::from_u32(10)];
    let credential = super::ac_sign::<_, S, P>(&mut prng, &issuer_keys.1, &user_keys.0, &attrs);
    let reveal_sig = super::ac_reveal::<_, S, P>(&mut prng,
                                                 &user_keys.1,
                                                 &issuer_keys.0,
                                                 &credential,
                                                 &attrs,
                                                 &[true, false]).unwrap();

    let mut vec = vec![];
    reveal_sig.serialize(&mut rmp_serde::Serializer::new(&mut vec))
              .unwrap();
    let mut de = Deserializer::new(&vec[..]);
    let reveal_sig_de: ACRevealSig<P::G1, P::G2, S> = Deserialize::deserialize(&mut de).unwrap();
    assert_eq!(reveal_sig, reveal_sig_de);
  }
}
