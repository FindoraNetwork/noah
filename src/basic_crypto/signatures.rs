use rand::CryptoRng;
use crate::serialization::ZeiFromToBytes;
use rand::Rng;
use crate::errors::ZeiError;

use ed25519_dalek::Signature;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

pub const XFR_SECRET_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
//pub const XFR_PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

pub const KEY_BASE_POINT: CompressedEdwardsY =
    curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;


#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct XfrPublicKey(pub PublicKey);
#[derive(Default, Debug)]
pub struct XfrSecretKey(SecretKey);
#[derive(Default, Debug)]
pub struct XfrKeyPair {
    public: XfrPublicKey,
    secret: XfrSecretKey,
}

//type HashFnc = sha2::Sha512;
type HashFnc = blake2::Blake2b;
#[derive(Debug, Eq, PartialEq)]
pub struct XfrSignature(pub Signature);


impl XfrPublicKey {
    pub fn get_curve_point(&self) -> Result<EdwardsPoint, ZeiError>{
        let pk_point = CompressedEdwardsY::from_slice(
            self.zei_to_bytes().as_slice()).decompress()?;
        Ok(pk_point)
    }

    pub fn verify(&self, message: &[u8], signature: &XfrSignature) -> Result<(), ZeiError>
    {
        Ok(self.0.verify::<HashFnc>(message, &signature.0)?)
    }

    pub fn as_bytes(&self) -> &[u8]{
        self.0.as_bytes()
    }
}

impl ZeiFromToBytes for XfrPublicKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.to_bytes();
        let mut vec = vec![];
        vec.extend_from_slice(&bytes[..]);
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Self {
        XfrPublicKey(PublicKey::from_bytes(bytes).unwrap())
    }
}

impl XfrSecretKey {
    pub fn sign(
        &self, message: &[u8], public_key: &XfrPublicKey) -> XfrSignature
    {
        let expanded = self.0.expand::<HashFnc>();
        let sign = expanded.sign::<HashFnc>(message, &public_key.0);

        XfrSignature(sign)
    }

    pub fn as_scalar_multiply_by_curve_point(&self, y: &EdwardsPoint) -> EdwardsPoint
    {
        let expanded = self.0.expand::<HashFnc>();
        //expanded.key is not public, I need to extract it via serialization
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&expanded.to_bytes()[0..32]); //1st 32 bytes are key
        let key_scalar = Scalar::from_bits(key_bytes);
        key_scalar * y
    }

    fn clone(&self) -> Self {
        let bytes = self.zei_to_bytes();
        XfrSecretKey::zei_from_bytes(bytes.as_slice())
    }
}

impl ZeiFromToBytes for XfrSecretKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.to_bytes();
        let mut vec = vec![];
        vec.extend_from_slice(&bytes[..]);
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Self {
        XfrSecretKey(SecretKey::from_bytes(bytes).unwrap())
    }
}


impl XfrKeyPair {
    pub fn generate<R: CryptoRng + Rng>(prng: &mut R)->Self
    where R: CryptoRng + Rng,
    {
        let kp = ed25519_dalek::Keypair::generate::<HashFnc,_>(prng);
        XfrKeyPair {
            public: XfrPublicKey(kp.public),
            secret: XfrSecretKey(kp.secret),
        }
    }

    pub fn get_pk_ref(&self)-> &XfrPublicKey {
        &self.public
    }

    pub fn get_sk_ref(&self)-> &XfrSecretKey {
        &self.secret
    }

    pub fn get_sk(&self) -> XfrSecretKey {
        self.secret.clone()
    }

    pub fn sign(&self, msg: &[u8]) -> XfrSignature
    {
        self.secret.sign( msg, &self.public)
    }
}

impl ZeiFromToBytes for XfrKeyPair {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend_from_slice(self.secret.zei_to_bytes().as_slice());
        vec.extend_from_slice(self.public.zei_to_bytes().as_slice());
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Self {
        XfrKeyPair {
            secret: XfrSecretKey::zei_from_bytes(&bytes[0..XFR_SECRET_KEY_LENGTH]),
            public: XfrPublicKey::zei_from_bytes(&bytes[XFR_SECRET_KEY_LENGTH..])
        }
    }
}

////Primitive for multisignatures /////
///A multisignature is defined as a signature on a message that must verify against a list of public keys instead of one
// naive implementation below
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub(crate) struct XfrMultiSig{
    pub(crate) signatures: Vec<XfrSignature>,
}

pub(crate) fn verify_multisig(keylist: &[XfrPublicKey],
                   message: &[u8],
                   multi_signature: &XfrMultiSig) -> Result<(), ZeiError>
{
    for (pk, signature) in keylist.iter().zip(multi_signature.signatures.iter()){
        pk.verify(message, signature)?;
    }
    Ok(())
}

pub(crate) fn sign_multisig(keylist: &[XfrKeyPair], message: &[u8]) -> XfrMultiSig {
    let mut signatures = vec![];
    for keypair in keylist.iter(){
        let signature = keypair.sign(message);
        signatures.push(signature);
    }
    XfrMultiSig{signatures}
}
