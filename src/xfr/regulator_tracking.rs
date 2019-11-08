/* This file implements simple regulator tracking capabilities.
  The regulator has a group signature secret key. User can register with the regulator by providing
  an anonymous credential revealing all their identity attributes, and receive a join certificate back.
  The user can sign messages (transactions) using this certificate.
  The regulator can infer the identity of the signer from the transaction signature.
  From each group signature the regulator can obtain a trace tag that it can use to search for the user identity in its DB.
*/
use crate::algebra::bls12_381::{BLSGt, BLSScalar, BLSG1, BLSG2};
use crate::algebra::groups::Group;
use crate::crypto::anon_creds::{
  ac_reveal, ac_verify, ACIssuerPublicKey, ACRevealSig, ACSignature, ACUserSecretKey,
};
use crate::crypto::simple_group_signatures::{
  gpsig_join_cert, gpsig_open, gpsig_verify, GroupPublicKey, GroupSecretKey, GroupSignature,
  JoinCert,
};
use crate::errors::ZeiError;
use rand::{CryptoRng, Rng};

/// JoinRequest message from the User to the Regulator. It contains the identity of the user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinRequest {
  credential_proof: ACRevealSig<BLSG1, BLSG2, BLSScalar>,
  attrs: Vec<BLSScalar>,
}

/// Users that register with regulators must produce a JoinRequest message using this function
/// # Example
/// see zei::xfr::regulator_tracking::rt_get_trace_tag;
pub fn rt_user_gen_join_request<'a, R: CryptoRng + Rng>(prng: &mut R,
                                                        ac_issuer_pk: &ACIssuerPublicKey<BLSG1,
                                                                           BLSG2>,
                                                        ac_user_sk: &ACUserSecretKey<BLSScalar>,
                                                        credential: &ACSignature<BLSG1>,
                                                        attrs: &'a [BLSScalar])
                                                        -> Result<JoinRequest, ZeiError> {
  // all attributed are revealed to the regulator
  let mut bitmap = vec![];
  for _ in 0..attrs.len() {
    bitmap.push(true);
  }
  let cred_proof = ac_reveal::<_, BLSGt>(prng,
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
/// see zei::xfr::regulator_tracking::rt_get_trace_tag;
pub fn rt_process_join_request<R: CryptoRng + Rng>(prng: &mut R,
                                                   rsk: &GroupSecretKey,
                                                   user_join_req: &JoinRequest,
                                                   ac_issuer_pk: &ACIssuerPublicKey<BLSG1,
                                                                      BLSG2>)
                                                   -> Result<(JoinCert, BLSG1), ZeiError> {
  // 1 check credential
  let mut bitmap = vec![];
  for _ in 0..user_join_req.attrs.len() {
    bitmap.push(true);
  }
  ac_verify::<BLSGt>(ac_issuer_pk,
                     user_join_req.attrs.as_slice(),
                     bitmap.as_slice(),
                     &user_join_req.credential_proof)?;

  // 2 generate tag
  let join_cert = gpsig_join_cert(prng, rsk);

  // 3 compute key value for DB entry storing JoinCert
  let key = BLSG1::get_base().mul(&join_cert.tag);
  Ok((join_cert, key))
}

/// Group signature verification function
/// # Example
/// see zei::xfr::regulator_tracking::rt_get_trace_tag;
pub fn rt_verify_sig(rpk: &GroupPublicKey,
                     sig: &GroupSignature,
                     msg: &[u8])
                     -> Result<(), ZeiError> {
  gpsig_verify(rpk, sig, msg)
}

/// Regulator obtains tag from signature
/// # Example
/// ```
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::crypto::anon_creds::{ac_keygen_issuer,ac_keygen_user, ac_sign};
/// use zei::algebra::bls12_381::{BLSScalar, BLSGt};
/// use zei::algebra::groups::Scalar;
/// use zei::xfr::regulator_tracking::{rt_user_gen_join_request, rt_process_join_request, rt_get_trace_tag};
/// use zei::crypto::simple_group_signatures::{gpsig_sign, gpsig_verify, gpsig_setup};
///  // setup user anonymous credentials
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer::<_, BLSGt>(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user::<_,BLSGt>(&mut prng, &issuer_pk);
/// let attributes = [BLSScalar::from_u32(0), BLSScalar::from_u32(1)];
/// let cred = ac_sign::<_,BLSGt>(&mut prng, &issuer_sk, &user_pk, &attributes);
///
/// let (reg_pk, reg_sk) = gpsig_setup(&mut prng);
/// let join_req = rt_user_gen_join_request(&mut prng, &issuer_pk, &user_sk, &cred, &attributes).unwrap();
/// let (join_cert, trace_tag) = rt_process_join_request(&mut prng, &reg_sk, &join_req, &issuer_pk).unwrap();
///
/// let sig = gpsig_sign(&mut prng, &reg_pk, &join_cert, b"Some message");
/// assert!(gpsig_verify(&reg_pk, &sig, b"Some message").is_ok());
///
/// let signature_trace_tag = rt_get_trace_tag(&reg_sk, &sig);
/// assert_eq!(trace_tag, signature_trace_tag);
/// ```
pub fn rt_get_trace_tag(rsk: &GroupSecretKey, sig: &GroupSignature) -> BLSG1 {
  gpsig_open(sig, rsk)
}
