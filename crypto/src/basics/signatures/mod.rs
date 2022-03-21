use rand_core::{CryptoRng, RngCore};
use ruc::err::*;

pub mod schnorr;

pub trait Signature {
    type PublicKey;
    type SecretKey;
    type Signature;
    fn gen_keys<R: CryptoRng + RngCore>(prng: &mut R) -> (Self::SecretKey, Self::PublicKey);
    fn sign<B: AsRef<[u8]>>(sk: &Self::SecretKey, msg: &B) -> Self::Signature;
    fn verify<B: AsRef<[u8]>>(pk: &Self::PublicKey, sig: &Self::Signature, msg: &B) -> Result<()>;
}
