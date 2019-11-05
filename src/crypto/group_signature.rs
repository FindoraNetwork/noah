use crate::algebra::bls12_381::{BLSGt, BLSScalar, BLSG1, BLSG2};
use crate::algebra::groups::{Group, Scalar};
use crate::algebra::pairing::PairingTargetGroup;
use crate::basic_crypto::signatures::pointcheval_sanders::{
  ps_gen_keys, randomize_ps_sig, PSPublicKey, PSSecretKey, PSSignature,
};
use crate::basic_crypto::signatures::signatures::{
  bls_sign, bls_verify, BlsPublicKey, BlsSecretKey, BlsSignature,
};
use crate::errors::ZeiError;
use digest::Digest;
use rand::{CryptoRng, Rng};
use sha2::Sha512;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPublicKey(pub(crate) PSPublicKey);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagerSecretKey(pub(crate) PSSecretKey);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinCert(pub(crate) PSSignature);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GUserSecretKey {
  tag: BLSScalar,
  signature: JoinCert,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSignature {
  sig: JoinCert,           // randomized signature of the tag
  pok: (BLSG2, BLSScalar), // proof commitment, proof response
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag(BLSScalar);

pub fn gpsig_setup<R: Rng + CryptoRng>(prng: &mut R) -> (GroupPublicKey, ManagerSecretKey) {
  let (pk, sk) = ps_gen_keys(prng);
  (GroupPublicKey(pk), ManagerSecretKey(sk))
}

pub fn gpsig_sign<R: Rng + CryptoRng>(prng: &mut R,
                                      group_pk: &GroupPublicKey,
                                      user_sk: GUserSecretKey,
                                      message: &[u8])
                                      -> GroupSignature {
  let (_, rand_sig) = randomize_ps_sig(prng, &user_sk.signature.0);
  // signature proof of knowledge of user_sk.tag such that
  //   verify_manager_sig(group_pk, user_sk.tag, rand_sig) = 1
  let blind_tag = BLSScalar::random_scalar(prng);
  let proof_commitment = group_pk.0.yy.mul(&blind_tag);
  let challenge = compute_spok_challenge(&proof_commitment, group_pk, message);
  let response = challenge.mul(&user_sk.tag).add(&blind_tag);

  GroupSignature { sig: JoinCert(rand_sig),
                   pok: (proof_commitment, response) }
}

pub fn gpsig_verify(gpk: &GroupPublicKey,
                    message: &[u8],
                    sig: &GroupSignature)
                    -> Result<(), ZeiError> {
  let proof_commmitment = &sig.pok.0;
  let challenge = compute_spok_challenge(&sig.pok.0, gpk, message);
  let response = &sig.pok.1; //challenge response

  // p = challenge*X - COMMITMENT + response*Y = challenge*(X + tag*Y)
  let p = gpk.0
             .xx
             .mul(&challenge)
             .sub(proof_commmitment)
             .add(&gpk.0.yy.mul(response));
  let e1 = BLSGt::pairing(&sig.sig.0.s1, &p);
  let e2 = BLSGt::pairing(&sig.sig.0.s2.mul(&challenge), &BLSG2::get_base());

  match e1 == e2 {
    false => Err(ZeiError::SignatureError),
    true => Ok(()),
  }
}

fn compute_spok_challenge(proof_commitment: &BLSG2,
                          group_pk: &GroupPublicKey,
                          message: &[u8])
                          -> BLSScalar {
  let mut hasher = Sha512::new();
  hasher.input(b"gpsig_sign");
  hasher.input(proof_commitment.to_compressed_bytes());
  hasher.input(group_pk.0.xx.to_compressed_bytes());
  hasher.input(group_pk.0.yy.to_compressed_bytes());
  hasher.input(message); // makingint it a signature proof of knowledge

  BLSScalar::from_hash(hasher)
}

// join protocol
#[derive(Debug)]
pub struct UserState<'a, 'b> {
  gpk: &'a GroupPublicKey,
  usk: &'b BlsSecretKey<BLSGt>,
  t: Option<BLSScalar>,
  tau: Option<BLSScalar>,
}

impl<'a, 'b> UserState<'a, 'b> {
  fn new(gpk: &'a GroupPublicKey, usk: &'b BlsSecretKey<BLSGt>) -> UserState<'a, 'b> {
    UserState::<'a, 'b> { gpk,
                          usk,
                          t: None,
                          tau: None }
  }
}

#[derive(Debug)]
pub struct ManagerState<'a, 'b, 'c> {
  gpk: &'a GroupPublicKey,
  msk: &'b ManagerSecretKey,
  upk: &'c BlsPublicKey<BLSGt>,
  kappa: Option<BLSScalar>,
}

impl<'a, 'b, 'c> ManagerState<'a, 'b, 'c> {
  fn new(gpk: &'a GroupPublicKey,
         msk: &'b ManagerSecretKey,
         upk: &'c BlsPublicKey<BLSGt>)
         -> ManagerState<'a,'b,'c> {
    ManagerState { gpk,
                   msk,
                   upk,
                   kappa: None }
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerMsg1 {
  t: BLSScalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserMsg2 {
  s: BLSG1,                 // tau * G1
  r: BLSG2,                 // tau * X
  sig: BlsSignature<BLSGt>, // signature of e(G1, r)
  fpk: FPK,                 // proof of knowledge of tau
}

pub fn gpsig_join_send_request<'a, 'b>(gpk: &'a GroupPublicKey,
                                       usk: &'b BlsSecretKey<BLSGt>)
                                       -> UserState<'a, 'b> {
  UserState::new(gpk, usk)
}

pub fn gpsig_join_manager_process_request_step1<'a, 'b, 'c, R: CryptoRng + Rng>(
  prng: &mut R,
  gpk: &'a GroupPublicKey,
  msk: &'b ManagerSecretKey,
  upk: &'c BlsPublicKey<BLSGt>)
  -> (ManagerState<'a, 'b, 'c>, ManagerMsg1) {
  let kappa = BLSScalar::random_scalar(prng);
  let mut hasher = Sha512::new();
  hasher.input(&kappa.to_bytes()[..]);
  let t = BLSScalar::from_hash(hasher);
  let mut state = ManagerState::new(gpk, msk, upk);
  state.kappa = Some(kappa);
  (state, ManagerMsg1 { t })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FPK {
  // proof of knowledge for sigma protocols for pairing based statements
  g1_elems: Vec<BLSG1>,
  g2_elems: Vec<BLSG2>,
  responses: Vec<BLSScalar>,
}

pub fn gpsig_join_user_step2<R: CryptoRng + Rng>(prng: &mut R, state: &mut UserState) -> UserMsg2 {
  let tau = BLSScalar::random_scalar(prng);
  let s = BLSG1::get_base().mul(&tau);
  let r = state.gpk.0.xx.mul(&tau);
  let k = BLSGt::pairing(&BLSG1::get_base(), &r);
  let sig = bls_sign(state.usk, k.to_bytes().as_slice());

  let blind_tau = BLSScalar::random_scalar(prng);
  let commitment_g_tau = BLSG1::get_base().mul(&blind_tau);
  let commitment_x_tau = state.gpk.0.xx.mul(&blind_tau);
  let g1_elems = vec![commitment_g_tau];
  let g2_elems = vec![commitment_x_tau];

  let challenge = compute_fpk_challenge(b"User FPK",
                                        g1_elems.as_slice(),
                                        &g2_elems.as_slice(),
                                        state.gpk);

  let z = tau.mul(&challenge).add(&blind_tau);

  state.tau = Some(tau);

  UserMsg2 { s,
             r,
             sig,
             fpk: FPK { g1_elems,
                        g2_elems,
                        responses: vec![z] } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserTraceInfo {
  w: BLSG2,
  r: BLSG2,
  kappa: BLSScalar,
  sig: BlsSignature<BLSGt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerMsg2 {
  ps_sig: PSSignature,
  kappa: BLSScalar,
  fpk: FPK,
}
pub fn gpsig_join_manager_msg3<R: CryptoRng + Rng>(
  prng: &mut R,
  state: &ManagerState, //manager state
  gpk: &GroupPublicKey,
  msk: &ManagerSecretKey,
  user_pk: &BlsPublicKey<BLSGt>,
  user_msg: &UserMsg2)
  -> Result<(ManagerMsg2, UserTraceInfo), ZeiError> {
  let g1 = BLSG1::get_base();
  let xx = &gpk.0.xx;
  // 1 verify proof of knowledge of tau
  let challenge = compute_fpk_challenge(b"User FPK",
                                        &user_msg.fpk.g1_elems,
                                        &user_msg.fpk.g2_elems,
                                        gpk);
  // Need to verify that c*s = response_tau*G1 - com_g_tau and c*t = response_tau*X - com_x_tau
  let response_tau = &user_msg.fpk.responses[0];
  let com_g_tau = &user_msg.fpk.g1_elems[0];
  let com_x_tau = &user_msg.fpk.g2_elems[0];
  if user_msg.s.mul(&challenge) != g1.mul(response_tau).sub(&com_g_tau)
     || user_msg.r.mul(&challenge) != xx.mul(response_tau).sub(&com_x_tau)
  {
    return Err(ZeiError::ZKProofVerificationError);
  }

  // 2 verify signature
  let k = BLSGt::pairing(&g1, &user_msg.r);
  bls_verify(user_pk, k.to_bytes().as_slice(), &user_msg.sig).map_err(|_| {
                                                               ZeiError::SignatureError
                                                             })?;

  // 3 create PS signature
  let kappa = state.kappa.as_ref().unwrap();
  let z = user_msg.s.add(&g1.mul(kappa));
  let w = user_msg.r.add(&xx.mul(kappa));
  // create PS signature homomorphically
  let rho = BLSScalar::random_scalar(prng); //PS signature randomness
  let s1 = g1.mul(&rho); //H = rhpo * G1
  let s2 = s1.mul(&msk.0.x).add(&z.mul(&rho.mul(&msk.0.y))); // (x+y*(kappa + tau))*H
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

  let challenge = compute_fpk_challenge(b"Manager FPK", g1_elems.as_slice(), &[], gpk);

  let response_rho = challenge.mul(&rho).add(&blind_rho);
  let response_x = challenge.mul(&msk.0.x).add(&blind_x);
  let response_y = challenge.mul(&msk.0.y).add(&blind_y);

  let fpk = FPK { g1_elems,
                  g2_elems: vec![],
                  responses: vec![response_rho, response_x, response_y] };

  Ok((ManagerMsg2 { ps_sig,
                    kappa: kappa.clone(),
                    fpk },
      UserTraceInfo { w,
                      r: user_msg.r.clone(),
                      kappa: kappa.clone(),
                      sig: user_msg.sig.clone() }))
}

pub fn gpsig_join_user_final(s: BLSG1,
                             tau: BLSScalar,
                             t: BLSScalar,
                             manager_msg2: &ManagerMsg2,
                             gpk: &GroupPublicKey)
                             -> Result<(Tag, JoinCert), ZeiError> {
  let g1 = BLSG1::get_base();
  let kappa = &manager_msg2.kappa;
  let z = s.add(&g1.mul(kappa));
  let s1 = &manager_msg2.ps_sig.s1;
  let s2 = &manager_msg2.ps_sig.s2;
  let aa = &manager_msg2.fpk.g1_elems[0];
  let com_rho_g1 = &manager_msg2.fpk.g1_elems[1];
  let com_x_s1 = &manager_msg2.fpk.g1_elems[2];
  let com_y_aa = &manager_msg2.fpk.g1_elems[3];
  let com_rho_z = &manager_msg2.fpk.g1_elems[4];
  let response_rho = &manager_msg2.fpk.responses[0];
  let response_x = &manager_msg2.fpk.responses[1];
  let response_y = &manager_msg2.fpk.responses[2];
  //1. verify FPK
  let challenge = compute_fpk_challenge(b"Manager FPK",
                                        manager_msg2.fpk.g1_elems.as_slice(),
                                        manager_msg2.fpk.g2_elems.as_slice(),
                                        gpk);
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
  if t != t_prime {
    return Err(ZeiError::SignatureError); //todo change error
  }
  let tag = Tag(tau.add(kappa));
  Ok((tag, JoinCert(manager_msg2.ps_sig.clone())))
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
/*
pub fn gpsig_add(msk: &ManagerSecretKey, msg: &JoinReqMsg) -> (JoinCert)
{

}

pub fn gpsig_gen_trace_key(uid: &GUserID, trace_master_key: &TraceMasterKey) -> TraceSecretKey
{

}
*/
