use rand::{Rng, CryptoRng};
use digest::Digest;
use crate::algebra::bls12_381::{BLSScalar, BLSG2, BLSGt};
use crate::algebra::groups::{Scalar, Group};
use sha2::Sha512;
use crate::errors::ZeiError;
use crate::algebra::pairing::PairingTargetGroup;
use crate::basic_crypto::signatures::pointcheval_sanders::{PSPublicKey, PSSecretKey, PSSignature, randomize_ps_sig, ps_gen_keys};

pub struct GroupPublicKey(pub(crate) PSPublicKey);

pub struct ManagerSecretKey(pub(crate) PSSecretKey);

pub struct JoinCert(pub(crate) PSSignature);

pub struct GUserID;

pub struct GUserSecretKey{
    tag: BLSScalar,
    signature: JoinCert,
}

pub struct GroupSignature{
    sig: JoinCert,  // randomized signature of the tag
    pok: (BLSG2, BLSScalar) // proof commitment, proof response
}

/*
pub struct JoinReqMsg;

pub struct TraceSecretKey;

pub struct TraceMasterKey;
*/

pub fn gpsig_setup<R: Rng + CryptoRng>(prng: &mut R) -> (GroupPublicKey, ManagerSecretKey)
{
    let (pk, sk) = ps_gen_keys(prng);
    (GroupPublicKey(pk), ManagerSecretKey(sk))
}


pub fn gpsig_sign<R: Rng + CryptoRng>(prng: &mut R, group_pk: &GroupPublicKey, user_sk: GUserSecretKey, message: &[u8]) -> GroupSignature{
    let (_, rand_sig) = randomize_ps_sig(prng, &user_sk.signature.0);
    // signature proof of knowledge of user_sk.tag such that
    //   verify_manager_sig(group_pk, user_sk.tag, rand_sig) = 1
    let blind_tag = BLSScalar::random_scalar(prng);
    let proof_commitment =  group_pk.0.yy.mul(&blind_tag);
    let challenge = compute_spok_challenge(&proof_commitment, group_pk, message);
    let response = challenge.mul(&user_sk.tag).add(&blind_tag);

    GroupSignature{
        sig: JoinCert(rand_sig),
        pok: (proof_commitment, response)
    }
}

pub fn gpsig_verify(gpk: &GroupPublicKey, message: &[u8], sig: &GroupSignature) -> Result<(), ZeiError>
{
    let proof_commmitment = &sig.pok.0;
    let challenge = compute_spok_challenge(&sig.pok.0, gpk, message);
    let response = &sig.pok.1; //challenge response

    // p = challenge*X - COMMITMENT + response*Y = challenge*(X + tag*Y)
    let p = gpk.0.xx.mul(&challenge).sub(proof_commmitment).add(&gpk.0.yy.mul(response));
    let e1 = BLSGt::pairing(&sig.sig.0.s1, &p);
    let e2 = BLSGt::pairing(&sig.sig.0.s2.mul(&challenge), &BLSG2::get_base());

    match e1 == e2 {
        false => Err(ZeiError::SignatureError),
        true => Ok(())
    }
}

fn compute_spok_challenge(proof_commitment: &BLSG2, group_pk: &GroupPublicKey, message: &[u8]) -> BLSScalar
{
    let mut hasher = Sha512::new();
    hasher.input(b"gpsig_sign");
    hasher.input(proof_commitment.to_compressed_bytes());
    hasher.input(group_pk.0.xx.to_compressed_bytes());
    hasher.input(group_pk.0.yy.to_compressed_bytes());
    hasher.input(message); // makingint it a signature proof of knowledge

    BLSScalar::from_hash(hasher)
}

/*
pub fn gpsig_request() -> (GUserSecretKey, JoinReqMsg)
{

}

pub fn gpsig_add(msk: &ManagerSecretKey, msg: &JoinReqMsg) -> (JoinCert)
{

}

pub fn gpsig_sign(join_cert: &JoinCert, user_sk: &GUserSecretKey, msg: &[u8]) -> GroupSignature
{

}

pub fn gpsig_gen_trace_key(uid: &GUserID, trace_master_key: &TraceMasterKey) -> TraceSecretKey
{

}
*/
