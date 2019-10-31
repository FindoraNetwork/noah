use crate::algebra::bls12_381::{BLSG2, BLSScalar, BLSG1, BLSGt};
use rand::{CryptoRng, Rng};
use crate::algebra::groups::{Scalar, Group};
use crate::algebra::pairing::PairingTargetGroup;
use crate::errors::ZeiError;
use digest::Digest;
use sha2::Sha512;

pub struct PSPublicKey{
    pub(crate) xx: BLSG2,
    pub(crate) yy: BLSG2
}

pub struct PSSecretKey{
    pub(crate) x: BLSScalar,
    pub(crate) y: BLSScalar,
}

pub struct PSSignature{
    pub(crate) s1: BLSG1,
    pub(crate) s2: BLSG1,
}

pub fn ps_gen_keys<R: CryptoRng + Rng>(prng: &mut R) -> (PSPublicKey, PSSecretKey) {
    let g2 = BLSG2::get_base(); // TODO can I use the base or does it need to be a random element
    let x = BLSScalar::random_scalar(prng);
    let y = BLSScalar::random_scalar(prng);
    let xx = g2.mul(&x);
    let yy = g2.mul(&y);

    (
        PSPublicKey { xx,yy },
        PSSecretKey { x, y}
    )
}

pub fn ps_sign_bytes<R: CryptoRng + Rng>(prng: &mut R, sk: PSSecretKey, m: &[u8]) -> PSSignature
{
    let m_scalar = hash_message(m);
    ps_sign_scalar(prng, sk, &m_scalar)
}

pub fn ps_sign_scalar<R: CryptoRng + Rng>(prng: &mut R, sk: PSSecretKey, m: &BLSScalar) -> PSSignature
{
    let a = BLSScalar::random_scalar(prng);
    let s1 = BLSG1::get_base().mul(&a);

    let s2 = s1.mul(&sk.x.add(&sk.y.mul(&m)));
    PSSignature{s1,s2}
}

pub fn ps_verify_sig_bytes(pk: PSPublicKey, m: &[u8], sig: &PSSignature) -> Result<(), ZeiError>
{
    let m_scalar = hash_message(m);
    ps_verify_sig_scalar(pk, &m_scalar, sig)
}

pub fn ps_verify_sig_scalar(pk: PSPublicKey, m: &BLSScalar, sig: &PSSignature) -> Result<(), ZeiError>
{
    let a = pk.xx.add(&pk.yy.mul(&m));
    let e1 = BLSGt::pairing(&sig.s1, &a);
    let e2 = BLSGt::pairing(&sig.s2, &BLSG2::get_base());
    if e1 != e2 || sig.s1 == BLSG1::get_identity() {
        return Err(ZeiError::SignatureError);
    }
    Ok(())
}

pub fn randomize_ps_sig<R: Rng + CryptoRng>(prng: &mut R, sig: &PSSignature)
                                            -> (BLSScalar, PSSignature)
{
    let rand_factor = BLSScalar::random_scalar(prng);
    let s1 = sig.s1.mul(&rand_factor);
    let s2 = sig.s2.mul(&rand_factor);
    (
        rand_factor,
        PSSignature {
            s1,
            s2
        }
    )
}

fn hash_message(message: &[u8]) -> BLSScalar
{
    let mut hasher = Sha512::new();
    hasher.input(message);
    BLSScalar::from_hash(hasher)
}
