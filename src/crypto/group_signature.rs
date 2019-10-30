use rand::{Rng, CryptoRng};
use digest::Digest;

pub struct GroupPublicKey;

pub struct ManagerSecretKey;

pub struct GUserID;

pub struct GUserSecretKey;

pub struct JoinReqMsg;

pub struct JoinCert;

pub struct GroupSignature;

pub struct TraceSecretKey;

pub struct TraceMasterKey;

pub fn gpsig_setup<R: Rng + CryptoRng>(prng: &mut R) -> (GPublicKey, ManagerSecretKey)
{

}

pub fn gpsig_request() -> (GUserSecretKey, JoinReqMsg)
{

}

pub fn gpsig_add(msk: &ManagerSecretKey, msg: &JoinReqMsg) -> (JoinCert)
{

}

pub fn gpsig_sign(join_cert: &JoinCert, user_sk: &GUserSecretKey, msg: &[u8]) -> GroupSignature
{

}

pub fn gpsig_verify(gpk: &GroupPublicKey, msg: &[u8], sig: &GroupSignature)
{

}

pub fn gpsig_gen_trace_key(uid: &GUserID, trace_master_key: &TraceMasterKey) -> TraceSecretKey
{

}