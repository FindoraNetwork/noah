/* This file implements simple regulator tracking capabilities.
  The regulator has a group signature secret key. User can register with the regulator by providing
  an anonymous credential revealing all their identity attributes, and receive a join certificate back.
  The user can sign messages (transactions) using this certificate.
  The regulator can infer the identity of the signer from the transaction signature.
  From each group signature the regulator can obtain a trace tag that it can use to search for the user identity in its DB.
*/

use crate::api::anon_creds::{
  ac_reveal, ac_verify, ACIssuerPublicKey, ACRevealSig, ACSignature, ACUserSecretKey,
};
use crate::api::gp_sig::{
  gpsig_join_cert, gpsig_open, gpsig_verify, GroupPublicKey, GroupSecretKey, GroupSignature,
  JoinCert, TagKey,
};
use crate::errors::ZeiError;
use rand_core::{CryptoRng, RngCore};

/// JoinRequest message from the User to the Regulator. It contains the identity of the user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinRequest<B: AsRef<[u8]>> {
  credential_proof: ACRevealSig,
  attrs: Vec<B>,
}

/// Users that register with regulators must produce a JoinRequest message using this function
/// # Example
/// see zei::api::regulator_tracking::rt_get_trace_tag;
pub fn rt_user_gen_join_request<'a, R: CryptoRng + RngCore, B: AsRef<[u8]> + Clone>(
  prng: &mut R,
  ac_issuer_pk: &ACIssuerPublicKey,
  ac_user_sk: &ACUserSecretKey,
  credential: &ACSignature,
  attrs: &'a [B])
  -> Result<JoinRequest<B>, ZeiError> {
  // all attributed are revealed to the regulator
  let mut bitmap = vec![];
  for _ in 0..attrs.len() {
    bitmap.push(true);
  }
  let cred_proof = ac_reveal(prng,
                             ac_user_sk,
                             ac_issuer_pk,
                             credential,
                             attrs,
                             bitmap.as_slice())?;
  Ok(JoinRequest { credential_proof: cred_proof,
                   attrs: attrs.to_vec() })
}

/// Regulator process the user's join request message and returning a join certificate for the client
/// and a trace tag to store locally.
/// # Example
/// see zei::api::regulator_tracking::rt_get_trace_tag;
pub fn rt_process_join_request<R: CryptoRng + RngCore, B: AsRef<[u8]>>(
  prng: &mut R,
  rsk: &GroupSecretKey,
  user_join_req: &JoinRequest<B>,
  ac_issuer_pk: &ACIssuerPublicKey)
  -> Result<(JoinCert, TagKey), ZeiError> {
  // 1 check credential
  let mut bitmap = vec![];
  for _ in 0..user_join_req.attrs.len() {
    bitmap.push(true);
  }
  ac_verify(ac_issuer_pk,
            user_join_req.attrs.as_slice(),
            bitmap.as_slice(),
            &user_join_req.credential_proof)?;

  // 2 generate tag
  Ok(gpsig_join_cert(prng, rsk))
}

/// Group signature verification function
/// # Example
/// see zei::api::regulator_tracking::rt_get_trace_tag;
pub fn rt_verify_sig<B: AsRef<[u8]>>(rpk: &GroupPublicKey,
                                     sig: &GroupSignature,
                                     msg: &B)
                                     -> Result<(), ZeiError> {
  gpsig_verify(rpk, sig, msg)
}

/// Regulator obtains tag from signature
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user, ac_sign};
/// use zei::api::regulator_tracking::{rt_user_gen_join_request, rt_process_join_request, rt_get_trace_tag};
/// use zei::api::gp_sig::{gpsig_sign, gpsig_verify, gpsig_setup};
///  // setup user anonymous credentials
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user(&mut prng, &issuer_pk);
/// let attributes = [b"attr1", b"attr2"];
/// let cred = ac_sign(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
///
/// let (reg_pk, reg_sk) = gpsig_setup(&mut prng);
/// let join_req = rt_user_gen_join_request(&mut prng, &issuer_pk, &user_sk, &cred, &attributes[..]).unwrap();
/// let (join_cert, trace_tag) = rt_process_join_request(&mut prng, &reg_sk, &join_req, &issuer_pk).unwrap();
///
/// let sig = gpsig_sign(&mut prng, &reg_pk, &join_cert, b"Some message");
/// assert!(gpsig_verify(&reg_pk, &sig, b"Some message").is_ok());
///
/// let signature_trace_tag = rt_get_trace_tag(&reg_sk, &sig);
/// assert_eq!(trace_tag, signature_trace_tag);
/// ```
pub fn rt_get_trace_tag(rsk: &GroupSecretKey, sig: &GroupSignature) -> TagKey {
  gpsig_open(sig, rsk)
}
