use crate::algebra::bls12_381::{BLSGt, BLSScalar, BLSG1, BLSG2};
use crate::algebra::groups::Group;
use crate::crypto::anon_creds::{
  ac_reveal, ac_verify, ACIssuerPublicKey, ACRevealSig, ACSignature, ACUserSecretKey,
};
use crate::crypto::simple_group_signatures::{
  gpsig_join_cert, gpsig_open, gpsig_setup, gpsig_verify, GroupPublicKey, GroupSecretKey,
  GroupSignature, JoinCert,
};
use crate::errors::ZeiError;
use rand::{CryptoRng, Rng};

pub struct JoinRequest<'a> {
  credential_proof: ACRevealSig<BLSG1, BLSG2, BLSScalar>,
  attrs: &'a [BLSScalar],
}

pub fn rt_keygen<R: CryptoRng + Rng>(prng: &mut R) -> (GroupPublicKey, GroupSecretKey) {
  gpsig_setup(prng)
}

pub fn rt_user_gen_join_request<'a, R: CryptoRng + Rng>(prng: &mut R,
                                                        ac_issuer_pk: &ACIssuerPublicKey<BLSG1,
                                                                           BLSG2>,
                                                        ac_user_sk: &ACUserSecretKey<BLSScalar>,
                                                        credential: &ACSignature<BLSG1>,
                                                        attrs: &'a [BLSScalar])
                                                        -> Result<JoinRequest<'a>, ZeiError> {
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
                   attrs })
}

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
                     user_join_req.attrs,
                     bitmap.as_slice(),
                     &user_join_req.credential_proof)?;

  // 2 generate tag
  let join_cert = gpsig_join_cert(prng, rsk);

  // 3 compute key value for DB entry storing JoinCert
  let key = BLSG1::get_base().mul(&join_cert.tag);
  Ok((join_cert, key))
}

pub fn rt_verify_sig(rpk: &GroupPublicKey,
                     sig: &GroupSignature,
                     msg: &[u8])
                     -> Result<(), ZeiError> {
  gpsig_verify(rpk, sig, msg)
}

pub fn rt_trace_tag(rsk: &GroupSecretKey, sig: &GroupSignature) -> BLSG1 {
  gpsig_open(sig, rsk)
}
