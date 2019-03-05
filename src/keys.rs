use rand::CryptoRng;
use crate::serialization::ZeiFromToBytes;
use rand::Rng;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::digest::generic_array::typenum::U64;
use crate::errors::Error;

use ed25519_dalek::Signature;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

pub const ZEI_SECRET_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
pub const ZEI_PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

pub const KEY_BASE_POINT: CompressedEdwardsY =
    curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;


#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct ZeiPublicKey(PublicKey);
#[derive(Default, Debug)]
pub struct ZeiSecretKey(SecretKey);
#[derive(Default, Debug)]
pub struct ZeiKeyPair {
    public: ZeiPublicKey,
    secret: ZeiSecretKey,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ZeiSignature(pub Signature);


impl ZeiPublicKey {
    pub(crate) fn get_curve_point(&self) -> Result<EdwardsPoint, Error>{
        let pk_point = CompressedEdwardsY::from_slice(
            self.zei_to_bytes().as_slice()).decompress()?;
        Ok(pk_point)
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
    pub fn sign<D>(
        &self, message: &[u8], public_key: &ZeiPublicKey) -> ZeiSignature
        where D:  Digest<OutputSize = U64> + Default,
    {
        let expanded = self.0.expand::<D>();
        let sign = expanded.sign::<D>(message, &public_key.0);

        ZeiSignature(sign)
    }

    pub fn as_scalar_multiply_by_curve_point<D>(&self, y: &EdwardsPoint) -> EdwardsPoint
    where D: Digest<OutputSize = U64> + Default,
    {
        let expanded = self.0.expand::<D>();
        //expanded.key is not public, I need to extract it via serialization
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&expanded.to_bytes()[0..32]); //1st 32 bytes are key
        let key_scalar = Scalar::from_bits(key_bytes);
        key_scalar * y
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
    pub fn generate<R: CryptoRng + Rng>(prng: &mut R)->Self
    where R: CryptoRng + Rng,
    {
        let kp = ed25519_dalek::Keypair::generate::<blake2::Blake2b,_>(prng);
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

    pub fn sign<D>(&self, msg: &[u8]) -> ZeiSignature
        where D:  Digest<OutputSize = U64> + Default,
    {
        self.secret.sign::<D>( msg, &self.public)
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