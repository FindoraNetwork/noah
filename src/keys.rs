use schnorr::PublicKey;
use schnorr::SecretKey;
use schnorr::Keypair;
use rand::CryptoRng;
use crate::serialization::ZeiFromToBytes;
use rand::Rng;
use schnorr::Signature;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::digest::generic_array::typenum::U64;
use curve25519_dalek::ristretto::RistrettoPoint;
use crate::errors::Error;

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct ZeiPublicKey(PublicKey);
#[derive(Default, Debug)]
pub struct ZeiSecretKey(SecretKey);
#[derive(Debug)]
pub struct ZeiKeyPair {
    public: ZeiPublicKey,
    secret: ZeiSecretKey,

}
pub const ZEI_SECRET_KEY_LENGTH: usize = schnorr::SECRET_KEY_LENGTH;
pub const ZEI_PUBLIC_KEY_LENGTH: usize = schnorr::PUBLIC_KEY_LENGTH;

#[derive(Debug, Eq, PartialEq)]
pub struct ZeiSignature(pub Signature);


impl ZeiPublicKey {
    pub(crate) fn get_curve_point(&self) -> Result<RistrettoPoint, Error>{
        Ok(self.0.get_curve_point()?)
    }

    pub(crate) fn verify<D>(&self,  message: &[u8], signature: &ZeiSignature) -> Result<(), Error>
    where  D:  Digest<OutputSize = U64> + Default,
    {
        Ok(self.0.verify::<D>(message, &signature.0)?)
    }

    pub(crate) fn as_bytes(&self) -> &[u8]{
        self.0.as_bytes()
    }
}

impl ZeiFromToBytes for ZeiPublicKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.to_bytes();
        let mut vec = vec![];
        vec.extend_from_slice(&bytes[..]);
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Self {
        ZeiPublicKey(PublicKey::from_bytes(bytes).unwrap())
    }
}

impl ZeiSecretKey{
    pub fn sign<D, R>(
        &self, prng: &mut R, message: &[u8], public_key: &ZeiPublicKey) -> ZeiSignature
        where D:  Digest<OutputSize = U64> + Default, R: CryptoRng + Rng,
    {
        ZeiSignature(self.0.sign::<D, _>(prng, message, &public_key.0))
    }

    fn clone(&self) -> Self {
        let bytes = self.zei_to_bytes();
        ZeiSecretKey::zei_from_bytes(bytes.as_slice())
    }
}

impl ZeiFromToBytes for ZeiSecretKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.to_bytes();
        let mut vec = vec![];
        vec.extend_from_slice(&bytes[..]);
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Self {
        ZeiSecretKey(SecretKey::from_bytes(bytes).unwrap())
    }
}


impl ZeiKeyPair{
    pub fn generate<R: CryptoRng + Rng>(prng: &mut R)->Self{
        let kp = Keypair::generate(prng);
        ZeiKeyPair{
            public: ZeiPublicKey(kp.public),
            secret: ZeiSecretKey(kp.secret),
        }
    }

    pub fn get_pk_ref(&self)-> &ZeiPublicKey {
        &self.public
    }

    pub fn get_sk_ref(&self)-> &ZeiSecretKey {
        &self.secret
    }

    pub fn get_sk(&self) -> ZeiSecretKey {
        self.secret.clone()
    }

    pub fn sign<D,R>(&self, prng: &mut R, msg: &[u8]) -> ZeiSignature
        where D:  Digest<OutputSize = U64> + Default, R: CryptoRng + Rng,
    {
        self.secret.sign::<D,_>(prng, msg, &self.public)
    }
}

impl ZeiFromToBytes for ZeiKeyPair{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend_from_slice(self.secret.zei_to_bytes().as_slice());
        vec.extend_from_slice(self.public.zei_to_bytes().as_slice());
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Self {
        ZeiKeyPair{
            secret: ZeiSecretKey::zei_from_bytes(&bytes[0..ZEI_SECRET_KEY_LENGTH]),
            public: ZeiPublicKey::zei_from_bytes(&bytes[ZEI_SECRET_KEY_LENGTH..])
        }
    }
}