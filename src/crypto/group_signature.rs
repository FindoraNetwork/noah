use crate::algebra::bls12_381::{BLSGt, BLSScalar, BLSG1, BLSG2};
use crate::algebra::groups::{Group, Scalar};
use crate::algebra::pairing::PairingTargetGroup;
use crate::basic_crypto::signatures::pointcheval_sanders::{
  ps_gen_keys, ps_randomize_sig, PSPublicKey, PSSecretKey, PSSignature,
};
use crate::basic_crypto::signatures::signatures::{
  bls_sign, bls_verify, BlsPublicKey, BlsSecretKey, BlsSignature,
};
use crate::errors::ZeiError;
use digest::Digest;
use rand::{CryptoRng, Rng};
use sha2::Sha512;

// Zero-Knowledge proofs needed
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FPK {
  // proof of knowledge for sigma protocols allowing pairing based statements
  g1_elems: Vec<BLSG1>,
  g2_elems: Vec<BLSG2>,
  responses: Vec<BLSScalar>,
}

fn signature_proof_of_knowledge<R: CryptoRng + Rng>(prng: &mut R,
                                                    tag: &BLSScalar, //\kappa + \tau
                                                    message: &[u8],
                                                    gpk: &GroupPublicKey)
                                                    -> FPK {
  let yy = &gpk.get_ps_pubkey_ref().yy;
  let blind_tag = BLSScalar::random_scalar(prng);
  let proof_commitment = yy.mul(&blind_tag);
  let challenge = compute_spok_challenge(&proof_commitment, gpk, message);
  let response = challenge.mul(tag).add(&blind_tag);

  FPK { g1_elems: vec![],
        g2_elems: vec![proof_commitment],
        responses: vec![response] }
}

fn verify_signature_proof_of_knowledge_for_ps_signatures(fpk: &FPK,
                                                         message: &[u8],
                                                         gpk: &GroupPublicKey,
                                                         ps_sig: &PSSignature)
                                                         -> Result<(), ZeiError> {
  let proof_commmitment = &fpk.g2_elems[0];
  let challenge = compute_spok_challenge(&proof_commmitment, gpk, message);
  let response = &fpk.responses[0]; //challenge response

  // p = challenge*X - COMMITMENT + response*Y = challenge*(X + tag*Y)
  let p = gpk.0
             .xx
             .mul(&challenge)
             .sub(proof_commmitment)
             .add(&gpk.0.yy.mul(response));
  let e1 = BLSGt::pairing(&ps_sig.s1, &p);
  let e2 = BLSGt::pairing(&ps_sig.s2.mul(&challenge), &BLSG2::get_base());

  match e1 == e2 {
    false => Err(ZeiError::ZKProofVerificationError),
    true => Ok(()),
  }
}

fn compute_spok_challenge(proof_commitment: &BLSG2,
                          gpk: &GroupPublicKey,
                          message: &[u8])
                          -> BLSScalar {
  let mut hasher = Sha512::new();
  hasher.input(b"gpsig_sign");
  hasher.input(proof_commitment.to_compressed_bytes());
  hasher.input(gpk.0.xx.to_compressed_bytes());
  hasher.input(gpk.0.yy.to_compressed_bytes());
  hasher.input(message); // makingint it a signature proof of knowledge

  BLSScalar::from_hash(hasher)
}

//proof of knowledge of tau st s = tau * G1 and r = tau*YY
fn zk_prove_knowledge_tau<R: CryptoRng + Rng>(prng: &mut R,
                                              g1_base: &BLSG1,
                                              tau: &BLSScalar,
                                              gpk: &GroupPublicKey)
                                              -> FPK {
  let yy = &gpk.get_ps_pubkey_ref().yy;
  let blind_tau = BLSScalar::random_scalar(prng);
  let commitment_g_tau = g1_base.mul(&blind_tau);
  let commitment_y_tau = yy.mul(&blind_tau);
  let g1_elems = vec![commitment_g_tau];
  let g2_elems = vec![commitment_y_tau];

  let challenge =
    compute_fpk_challenge(b"User FPK", g1_elems.as_slice(), &g2_elems.as_slice(), gpk);

  let z = tau.mul(&challenge).add(&blind_tau);

  FPK { g1_elems,
        g2_elems,
        responses: vec![z] }
}

//verify proof of knowledge of tau st s = tau * G1 and r = tau*XX
fn zk_verify_knowledge_tau(fpk: &FPK,
                           s: &BLSG1,
                           r: &BLSG2,
                           gpk: &GroupPublicKey)
                           -> Result<(), ZeiError> {
  let g1_base = BLSG1::get_base();
  let yy = &gpk.get_ps_pubkey_ref().yy;
  let challenge = compute_fpk_challenge(b"User FPK", &fpk.g1_elems, &fpk.g2_elems, gpk);
  let response_tau = &fpk.responses[0];
  let com_g_tau = &fpk.g1_elems[0];
  let com_y_tau = &fpk.g2_elems[0];
  if s.mul(&challenge) != g1_base.mul(response_tau).sub(&com_g_tau)
     || r.mul(&challenge) != yy.mul(response_tau).sub(&com_y_tau)
  {
    return Err(ZeiError::ZKProofVerificationError);
  }
  Ok(())
}

fn compute_fpk_challenge(instance_msg: &[u8],
                         g1_elems: &[BLSG1],
                         g2_elems: &[BLSG2],
                         gpk: &GroupPublicKey)
                         -> BLSScalar {
  let mut hasher = Sha512::new();
  hasher.input(instance_msg);
  for e1 in g1_elems {
    hasher.input(&e1.to_compressed_bytes()[..]);
  }
  for e2 in g2_elems {
    hasher.input(&e2.to_compressed_bytes()[..]);
  }
  hasher.input(&gpk.0.xx.to_compressed_bytes()[..]);
  hasher.input(&gpk.0.yy.to_compressed_bytes()[..]);

  BLSScalar::from_hash(hasher)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPublicKey(PSPublicKey);

impl GroupPublicKey {
  fn get_ps_pubkey_ref(&self) -> &PSPublicKey {
    &self.0
  }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagerSecretKey(pub(crate) PSSecretKey);

impl ManagerSecretKey {
  fn get_ps_seckey_ref(&self) -> &PSSecretKey {
    &self.0
  }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinCert(PSSignature);

impl JoinCert {
  fn get_ps_sig_ref(&self) -> &PSSignature {
    &self.0
  }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GUserSecretKey {
  tag: BLSScalar,
  join_cert: JoinCert,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSignature {
  cert: JoinCert, // randomized signature of the tag
  sok: FPK,       // proof commitment, proof response
}

impl GroupSignature {
  pub fn get_ps_signature_ref(&self) -> &PSSignature {
    &self.cert.get_ps_sig_ref()
  }
}

#[derive(Debug)]
pub struct ManagerState<'a, 'b> {
  gpk: &'a GroupPublicKey,
  msk: &'b ManagerSecretKey,
  upk: BlsPublicKey<BLSGt>,
  kappa: Option<BLSScalar>,
}

impl<'a, 'b> ManagerState<'a, 'b> {
  fn new(gpk: &'a GroupPublicKey,
         msk: &'b ManagerSecretKey,
         upk: BlsPublicKey<BLSGt>)
         -> ManagerState<'a, 'b> {
    ManagerState { gpk,
                   msk,
                   upk,
                   kappa: None }
  }
}

// join protocol
#[derive(Debug)]
pub struct UserState<'a, 'b> {
  gpk: &'a GroupPublicKey,
  usk: &'b BlsSecretKey<BLSGt>,
  s: Option<BLSG1>,
  t: Option<BLSScalar>,
  tau: Option<BLSScalar>,
}

impl<'a, 'b> UserState<'a, 'b> {
  fn new(gpk: &'a GroupPublicKey, usk: &'b BlsSecretKey<BLSGt>) -> UserState<'a, 'b> {
    UserState::<'a, 'b> { gpk,
                          usk,
                          s: None,
                          t: None,
                          tau: None }
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestMsg {
  user_pub_key: BlsPublicKey<BLSGt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestResponseMsg {
  t: BLSScalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserFinalMsg {
  s: BLSG1,                 // tau * G1
  r: BLSG2,                 // tau * X
  sig: BlsSignature<BLSGt>, // signature of e(G1, r)
  fpk: FPK,                 // proof of knowledge of tau
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerFinalMsg {
  ps_sig: PSSignature,
  kappa: BLSScalar,
  fpk: FPK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserTraceInfo {
  w: BLSG2,
  r: BLSG2,
  kappa: BLSScalar,
  sig: BlsSignature<BLSGt>,
}

/// Group signature setup function. It produces group public key and group manager secret key
/// # Example
/// ```
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::crypto::group_signature::gpsig_setup;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let (gpk, msk) = gpsig_setup(&mut prng);
/// ```
pub fn gpsig_setup<R: Rng + CryptoRng>(prng: &mut R) -> (GroupPublicKey, ManagerSecretKey) {
  let (pk, sk) = ps_gen_keys(prng);
  (GroupPublicKey(pk), ManagerSecretKey(sk))
}

// Join Protocol
// functions:
// - gpsig_join_user_send_request(user id) -> (user_state, RequestMsg)
// - gpsig_join_manager_process_request(RequestMsg) -> (manager_state, RequestResponseMsg)
// - gpsig_join_user_process_response(user_state, RequestResponseMsg) -> (user_state, UserFinalMsg)
// - gpsig_join_manager_final(manager_state, UserFinalMsg) -> (ManagerFinalMsg, TraceInfo)
// - gpsig_join_user_final(user_state, ManagerFinalMsg)->  JoinCert
/// Join Protocol. User requests a join certificate to the group Manager.
/// # Example
/// ```
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::crypto::group_signature::{gpsig_setup, gpsig_join_user_send_request, gpsig_join_manager_process_request, gpsig_join_user_final, gpsig_join_user_process_response, gpsig_join_manager_final};
/// use zei::basic_crypto::signatures::signatures::bls_gen_keys;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let (gpk, msk) = gpsig_setup(&mut prng);
/// let (user_sk, user_pk) = bls_gen_keys(&mut prng);
/// // Protocol stats
/// let (mut user_state, request_msg) = gpsig_join_user_send_request(&gpk, &user_pk, &user_sk);
/// let (mut manager_state, request_response_msg) = gpsig_join_manager_process_request(&mut prng, &gpk, &msk, &request_msg);
/// let user_final_msg = gpsig_join_user_process_response(&mut prng, &mut user_state, &request_response_msg);
/// let (manager_final_msg, user_trace_info) = gpsig_join_manager_final(&mut prng, &mut manager_state, &user_final_msg).unwrap();
/// let user_group_secret_key = gpsig_join_user_final(&mut user_state, &manager_final_msg).unwrap();
/// ```
pub fn gpsig_join_user_send_request<'a, 'b>(gpk: &'a GroupPublicKey,
                                            upk: &BlsPublicKey<BLSGt>,
                                            usk: &'b BlsSecretKey<BLSGt>)
                                            -> (UserState<'a, 'b>, RequestMsg) {
  (UserState::new(gpk, usk), RequestMsg { user_pub_key: upk.clone() })
}

pub fn gpsig_join_manager_process_request<'a, 'b, 'c, R: CryptoRng + Rng>(
  prng: &mut R,
  gpk: &'a GroupPublicKey,
  msk: &'b ManagerSecretKey,
  request_message: &RequestMsg)
  -> (ManagerState<'a, 'b>, RequestResponseMsg) {
  let kappa = BLSScalar::random_scalar(prng);
  let mut hasher = Sha512::new();
  hasher.input(&kappa.to_bytes()[..]);
  let t = BLSScalar::from_hash(hasher);
  let mut state = ManagerState::new(gpk, msk, request_message.user_pub_key.clone());
  state.kappa = Some(kappa);
  (state, RequestResponseMsg { t })
}

pub fn gpsig_join_user_process_response<R: CryptoRng + Rng>(prng: &mut R,
                                                            state: &mut UserState,
                                                            manager_message: &RequestResponseMsg)
                                                            -> UserFinalMsg {
  let g1_base = BLSG1::get_base();
  let tau = BLSScalar::random_scalar(prng);
  let s = g1_base.mul(&tau);
  let r = state.gpk.0.yy.mul(&tau);
  let k = BLSGt::pairing(&BLSG1::get_base(), &r);
  let sig = bls_sign(state.usk, k.to_bytes().as_slice());

  let fpk = zk_prove_knowledge_tau(prng, &g1_base, &tau, &state.gpk);

  state.s = Some(s.clone());
  state.tau = Some(tau);
  state.t = Some(manager_message.t.clone());

  UserFinalMsg { s, r, sig, fpk }
}

pub fn gpsig_join_manager_final<R: CryptoRng + Rng>(
  prng: &mut R,
  state: &ManagerState, //manager state
  user_msg: &UserFinalMsg)
  -> Result<(ManagerFinalMsg, UserTraceInfo), ZeiError> {
  let g1 = BLSG1::get_base();
  let yy = &state.gpk.get_ps_pubkey_ref().yy;
  let ps_seckey = state.msk.get_ps_seckey_ref();
  // 1 verify proof of knowledge of tau
  zk_verify_knowledge_tau(&user_msg.fpk, &user_msg.s, &user_msg.r, state.gpk)?;

  // 2 verify signature
  let k = BLSGt::pairing(&g1, &user_msg.r);
  bls_verify(&state.upk, k.to_bytes().as_slice(), &user_msg.sig).map_err(|_| {
                                                                  ZeiError::SignatureError
                                                                })?;

  // 3 create PS signature
  let kappa = state.kappa.as_ref().unwrap();
  let z = user_msg.s.add(&g1.mul(kappa));
  let w = user_msg.r.add(&yy.mul(kappa));
  // create PS signature homomorphically
  let rho = BLSScalar::random_scalar(prng); //PS signature randomness
  let s1 = g1.mul(&rho); //H = rhpo * G1
  let s2 = s1.mul(&ps_seckey.x).add(&z.mul(&rho.mul(&ps_seckey.y))); // (x+y*(kappa + tau))*H
  let ps_sig = PSSignature { s1, s2 };

  //4 compute proof of knowledge: this proofs that (s1, s2) is a valid signature for message m = (tau + kappa)
  let aa = z.mul(&rho);
  let blind_rho = BLSScalar::random_scalar(prng);
  let blind_x = BLSScalar::random_scalar(prng);
  let blind_y = BLSScalar::random_scalar(prng);
  let com_rho_g1 = g1.mul(&blind_rho);
  let com_x_s1 = ps_sig.s1.mul(&blind_x);
  let com_y_aa = aa.mul(&blind_y);
  let com_rho_z = z.mul(&blind_rho);

  let g1_elems = vec![aa, com_rho_g1, com_x_s1, com_y_aa, com_rho_z];

  let challenge = compute_fpk_challenge(b"Manager FPK", g1_elems.as_slice(), &[], &state.gpk);

  let response_rho = challenge.mul(&rho).add(&blind_rho);
  let response_x = challenge.mul(&ps_seckey.x).add(&blind_x);
  let response_y = challenge.mul(&ps_seckey.y).add(&blind_y);

  let fpk = FPK { g1_elems,
                  g2_elems: vec![],
                  responses: vec![response_rho, response_x, response_y] };

  Ok((ManagerFinalMsg { ps_sig,
                        kappa: kappa.clone(),
                        fpk },
      UserTraceInfo { w,
                      r: user_msg.r.clone(),
                      kappa: kappa.clone(),
                      sig: user_msg.sig.clone() }))
}

pub fn gpsig_join_user_final(state: &UserState,
                             manager_msg_final: &ManagerFinalMsg)
                             -> Result<GUserSecretKey, ZeiError> {
  let s = state.s.as_ref().unwrap();
  let t = state.t.as_ref().unwrap();
  let tau = state.tau.as_ref().unwrap();
  let g1 = BLSG1::get_base();
  let kappa = &manager_msg_final.kappa;
  let z = s.add(&g1.mul(kappa));
  let s1 = &manager_msg_final.ps_sig.s1;
  let s2 = &manager_msg_final.ps_sig.s2;
  let aa = &manager_msg_final.fpk.g1_elems[0];
  let com_rho_g1 = &manager_msg_final.fpk.g1_elems[1];
  let com_x_s1 = &manager_msg_final.fpk.g1_elems[2];
  let com_y_aa = &manager_msg_final.fpk.g1_elems[3];
  let com_rho_z = &manager_msg_final.fpk.g1_elems[4];
  let response_rho = &manager_msg_final.fpk.responses[0];
  let response_x = &manager_msg_final.fpk.responses[1];
  let response_y = &manager_msg_final.fpk.responses[2];
  //1. verify FPK
  let challenge = compute_fpk_challenge(b"Manager FPK",
                                        manager_msg_final.fpk.g1_elems.as_slice(),
                                        manager_msg_final.fpk.g2_elems.as_slice(),
                                        state.gpk);
  //check that s1 = rho* G1
  let mut vrfy = s1.mul(&challenge) == g1.mul(response_rho).sub(com_rho_g1);
  //check that s2 = x*s1 + y*aa
  vrfy = vrfy
         && s2.mul(&challenge)
            == s1.mul(response_x)
                 .sub(com_x_s1)
                 .add(&aa.mul(response_y))
                 .sub(com_y_aa);
  //check that A = z*rho
  vrfy = vrfy && aa.mul(&challenge) == z.mul(response_rho).sub(com_rho_z);

  if !vrfy {
    return Err(ZeiError::ZKProofVerificationError);
  }
  //2. verify kappa
  let mut hasher = Sha512::new();
  hasher.input(kappa.to_bytes().as_slice());
  let t_prime = BLSScalar::from_hash(hasher);
  if *t != t_prime {
    return Err(ZeiError::SignatureError); //todo change error
  }
  Ok(GUserSecretKey { tag: tau.add(kappa),
                      join_cert: JoinCert(manager_msg_final.ps_sig.clone()) })
}

/// Signature function. User requests uses its secret key to produce anonymous signature
/// # Example
/// ```
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::crypto::group_signature::{gpsig_setup, gpsig_join_user_send_request, gpsig_join_manager_process_request, gpsig_join_user_final, gpsig_join_user_process_response, gpsig_join_manager_final, gpsig_sign, gpsig_verify};
/// use zei::basic_crypto::signatures::signatures::bls_gen_keys;
/// use zei::errors::ZeiError;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let (gpk, msk) = gpsig_setup(&mut prng);
/// let (user_sk, user_pk) = bls_gen_keys(&mut prng);
/// // Join Protocol starts
/// let (mut user_state, request_msg) = gpsig_join_user_send_request(&gpk, &user_pk, &user_sk);
/// let (mut manager_state, request_response_msg) = gpsig_join_manager_process_request(&mut prng, &gpk, &msk, &request_msg);
/// let user_final_msg = gpsig_join_user_process_response(&mut prng, &mut user_state, &request_response_msg);
/// let (manager_final_msg, user_trace_info) = gpsig_join_manager_final(&mut prng, &mut manager_state, &user_final_msg).unwrap();
/// let user_group_secret_key = gpsig_join_user_final(&mut user_state, &manager_final_msg).unwrap();
///
/// // signature
/// let sig = gpsig_sign(&mut prng, &gpk, &user_group_secret_key, b"Some message");
///
/// assert!(gpsig_verify(&gpk, b"Some message", &sig).is_ok());
/// assert_eq!(ZeiError::SignatureError, gpsig_verify(&gpk, b"Some other message", &sig).err().unwrap());
/// ```
///
pub fn gpsig_sign<R: Rng + CryptoRng>(prng: &mut R,
                                      group_pk: &GroupPublicKey,
                                      user_sk: &GUserSecretKey,
                                      message: &[u8])
                                      -> GroupSignature {
  let (_, rand_sig) = ps_randomize_sig(prng, &user_sk.join_cert.0);
  // signature proof of knowledge of user_sk.tag such that
  //   verify_manager_sig(group_pk, user_sk.tag, rand_sig) = 1
  let sok = signature_proof_of_knowledge(prng, &user_sk.tag, message, group_pk);

  GroupSignature { cert: JoinCert(rand_sig),
                   sok }
}

pub fn gpsig_verify(gpk: &GroupPublicKey,
                    message: &[u8],
                    sig: &GroupSignature)
                    -> Result<(), ZeiError> {
  let ps_sig = sig.cert.get_ps_sig_ref();
  verify_signature_proof_of_knowledge_for_ps_signatures(&sig.sok, message, gpk, ps_sig).map_err(|_| ZeiError::SignatureError)
}

/// Signature function. User requests uses its secret key to produce anonymous signature
/// # Example
/// ```
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::crypto::group_signature::{gpsig_setup, gpsig_join_user_send_request, gpsig_join_manager_process_request, gpsig_join_user_final, gpsig_join_user_process_response, gpsig_join_manager_final, gpsig_sign, gpsig_verify, gpsig_test_entry};
/// use zei::basic_crypto::signatures::signatures::bls_gen_keys;
/// use zei::errors::ZeiError;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let (gpk, msk) = gpsig_setup(&mut prng);
/// let (user_sk, user_pk) = bls_gen_keys(&mut prng);
/// // Join Protocol starts
/// let (mut user_state, request_msg) = gpsig_join_user_send_request(&gpk, &user_pk, &user_sk);
/// let (mut manager_state, request_response_msg) = gpsig_join_manager_process_request(&mut prng, &gpk, &msk, &request_msg);
/// let user_final_msg = gpsig_join_user_process_response(&mut prng, &mut user_state, &request_response_msg);
/// let (manager_final_msg, user_trace_info) = gpsig_join_manager_final(&mut prng, &mut manager_state, &user_final_msg).unwrap();
/// let user_group_secret_key = gpsig_join_user_final(&mut user_state, &manager_final_msg).unwrap();
///
/// // signature
/// let sig = gpsig_sign(&mut prng, &gpk, &user_group_secret_key, b"Some message");
/// // test tracing
/// assert!(gpsig_test_entry(&gpk, &sig, b"Some message", &user_trace_info).is_ok());
/// assert!(gpsig_test_entry(&gpk, &sig, b"Some other message", &user_trace_info).is_err());
/// ```
pub fn gpsig_test_entry(gpk: &GroupPublicKey,
                        sig: &GroupSignature,
                        message: &[u8],
                        trace_info: &UserTraceInfo)
                        -> Result<(), ZeiError> {
  //1 verify signature
  gpsig_verify(gpk, message, sig)?;
  //2 check entries
  let g2_base = BLSG2::get_base();
  let ps_sig = sig.get_ps_signature_ref();
  let ps_pk = gpk.get_ps_pubkey_ref();
  let e1 = BLSGt::pairing(&ps_sig.s1, &ps_pk.xx.add(&trace_info.w));
  let e2 = BLSGt::pairing(&ps_sig.s2, &g2_base);

  match e1 == e2 {
    true => Ok(()),
    false => Err(ZeiError::GroupSignatureTraceError),
  }
}
