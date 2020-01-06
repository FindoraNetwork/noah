use crate::errors::ZeiError;
use crate::serialization::ZeiFromToBytes;
use rand_core::{CryptoRng, RngCore};

use crate::errors::ZeiError::SignatureError;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{PublicKey, ExpandedSecretKey};
use ed25519_dalek::SecretKey;
use ed25519_dalek::Signature;
use wasm_bindgen::prelude::*;

pub const XFR_SECRET_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
//pub const XFR_PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

pub const KEY_BASE_POINT: CompressedEdwardsY =
  curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;

#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XfrPublicKey(pub(crate) PublicKey);
#[derive(Debug, Default)]
pub struct XfrSecretKey(pub(crate) SecretKey);
#[wasm_bindgen]
#[derive(Debug, Default)]
pub struct XfrKeyPair {
  public: XfrPublicKey,
  secret: XfrSecretKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XfrSignature(pub Signature);

impl XfrPublicKey {
  pub fn get_curve_point(&self) -> Result<EdwardsPoint, ZeiError> {
    CompressedEdwardsY::from_slice(self.zei_to_bytes().as_slice()).decompress().
      ok_or(ZeiError::DecompressElementError)
  }

  pub fn verify(&self, message: &[u8], signature: &XfrSignature) -> Result<(), ZeiError> {
    Ok(self.0.verify(message, &signature.0)?)
  }

  pub fn as_bytes(&self) -> &[u8] {
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
  pub fn sign(&self, message: &[u8], public_key: &XfrPublicKey) -> XfrSignature {
    let expanded: ExpandedSecretKey = (&self.0).into();
    let sign = expanded.sign(message, &public_key.0);

    XfrSignature(sign)
  }

  pub fn as_scalar_multiply_by_curve_point(&self, y: &EdwardsPoint) -> EdwardsPoint {
    let expanded: ExpandedSecretKey = (&self.0).into();
    //expanded.key is not public, I need to extract it via serialization
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&expanded.to_bytes()[0..32]); //1st 32 bytes are key
    let key_scalar = Scalar::from_bits(key_bytes);
    key_scalar * y
  }

  #[allow(clippy::should_implement_trait)]
  pub fn clone(&self) -> Self {
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

#[wasm_bindgen]
impl XfrKeyPair {
  pub fn get_pk(&self) -> XfrPublicKey {
    self.public
  }
}
impl XfrKeyPair {
  pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self
  {
    let kp = ed25519_dalek::Keypair::generate(prng);
    XfrKeyPair { public: XfrPublicKey(kp.public),
                 secret: XfrSecretKey(kp.secret) }
  }

  pub fn get_pk_ref(&self) -> &XfrPublicKey {
    &self.public
  }

  pub fn get_sk_ref(&self) -> &XfrSecretKey {
    &self.secret
  }

  pub fn get_sk(&self) -> XfrSecretKey {
    self.secret.clone()
  }

  pub fn sign(&self, msg: &[u8]) -> XfrSignature {
    self.secret.sign(msg, &self.public)
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
    XfrKeyPair { secret: XfrSecretKey::zei_from_bytes(&bytes[0..XFR_SECRET_KEY_LENGTH]),
                 public: XfrPublicKey::zei_from_bytes(&bytes[XFR_SECRET_KEY_LENGTH..]) }
  }
}

////Primitive for multisignatures /////
///A multisignature is defined as a signature on a message that must verify against a list of public keys instead of one
// naive implementation below
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrMultiSig {
  pub signatures: Vec<XfrSignature>,
}

pub fn verify_multisig(keylist: &[XfrPublicKey],
                       message: &[u8],
                       multi_signature: &XfrMultiSig)
                       -> Result<(), ZeiError> {
  if multi_signature.signatures.len() != keylist.len() {
    return Err(SignatureError); //TODO return MultiSignatureError different length
  }
  for (pk, signature) in keylist.iter().zip(multi_signature.signatures.iter()) {
    pk.verify(message, signature)?; //TODO return MultiSignatureError
  }
  Ok(())
}

pub fn sign_multisig(keylist: &[XfrKeyPair], message: &[u8]) -> XfrMultiSig {
  let mut signatures = vec![];
  for keypair in keylist.iter() {
    let signature = keypair.sign(message);
    signatures.push(signature);
  }
  XfrMultiSig { signatures }
}

#[cfg(test)]
mod test {
  use crate::errors::ZeiError::SignatureError;
  use crate::xfr::sig::{sign_multisig, verify_multisig, XfrKeyPair, XfrPublicKey};
  use rand_core::SeedableRng;
  use rand_chacha::ChaChaRng;

  #[test]
  fn signatures() {
    let mut prng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);

    let keypair = XfrKeyPair::generate(&mut prng);
    let message = "";

    let sig = keypair.sign(message.as_bytes());
    assert_eq!(Ok(()), keypair.get_pk_ref().verify("".as_bytes(), &sig));
    //same test with secret key
    let sig = keypair.get_sk_ref()
                     .sign(message.as_bytes(), keypair.get_pk_ref());
    assert_eq!(Ok(()), keypair.get_pk_ref().verify("".as_bytes(), &sig));

    //test again with fresh same key
    let mut prng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);
    let keypair = XfrKeyPair::generate(&mut prng);
    assert_eq!(Ok(()), keypair.get_pk_ref().verify("".as_bytes(), &sig));

    let keypair = XfrKeyPair::generate(&mut prng);
    let message = [10u8; 500];
    let sig = keypair.sign(&message);
    assert_eq!(Err(SignatureError),
               keypair.get_pk_ref().verify("".as_bytes(), &sig),
               "Verifying sig on different message should have return Err(Signature Error)");
    assert_eq!(Ok(()),
               keypair.get_pk_ref().verify(&message, &sig),
               "Verifying sig on samme message should have return Ok(())");
    //test again with secret key
    let sk = keypair.get_sk_ref();
    let pk = keypair.get_pk_ref();
    let sig = sk.sign(&message, pk);
    assert_eq!(Err(SignatureError),
               keypair.get_pk_ref().verify("".as_bytes(), &sig),
               "Verifying sig on different message should have return Err(Signature Error)");
    assert_eq!(Ok(()),
               pk.verify(&message, &sig),
               "Verifying sig on samme message should have return Ok(())");

    // test with different keys
    let keypair = XfrKeyPair::generate(&mut prng);
    assert_eq!(Err(SignatureError),
               keypair.get_pk_ref().verify(&message, &sig),
               "Verifying sig on with a different key should have return Err(Signature Error)");
  }

  fn generate_keys(prng: &mut ChaChaRng, n: usize) -> Vec<XfrKeyPair> {
    let mut v = vec![];
    for _ in 0..n {
      v.push(XfrKeyPair::generate(prng));
    }
    v
  }

  #[test]
  fn multisig() {
    let mut prng = rand_chacha::ChaChaRng::from_seed([1u8; 32]);
    // test with one key
    let keypairs = generate_keys(&mut prng, 1);
    let pk = keypairs.get(0).unwrap().get_pk_ref();
    let msig = sign_multisig(keypairs.as_slice(), "HELLO".as_bytes());
    assert_eq!(Ok(()),
               verify_multisig(&[pk.clone()], "HELLO".as_bytes(), &msig),
               "Multisignature should have verify correctly");
    //try with more keys
    let extra_key = XfrKeyPair::generate(&mut prng);
    assert_eq!(Err(SignatureError),
               verify_multisig(&[pk.clone(), extra_key.get_pk_ref().clone()],
                               "HELLO".as_bytes(),
                               &msig),
               "Multisignature should have not verify correctly");

    // test with two keys
    let keypairs = generate_keys(&mut prng, 2);
    let pk0 = keypairs.get(0).unwrap().get_pk_ref();
    let pk1 = keypairs.get(1).unwrap().get_pk_ref();
    let msig = sign_multisig(keypairs.as_slice(), "HELLO".as_bytes());
    assert_eq!(Ok(()),
               verify_multisig(&[pk0.clone(), pk1.clone()], "HELLO".as_bytes(), &msig),
               "Multisignature should have verify correctly");

    let newkeypair = XfrKeyPair::generate(&mut prng);
    let pk2 = newkeypair.get_pk_ref();
    assert_eq!(Err(SignatureError),
               verify_multisig(&[pk0.clone(), pk1.clone(), pk2.clone()],
                               "HELLO".as_bytes(),
                               &msig),
               "Message was signed with two keys");
    assert_eq!(Err(SignatureError),
               verify_multisig(&[pk0.clone(), pk2.clone()], "HELLO".as_bytes(), &msig),
               "Message was signed under different key set");

    // test with 20 keys
    let keypairs = generate_keys(&mut prng, 20);
    let pks: Vec<XfrPublicKey> = keypairs.iter().map(|x| x.get_pk_ref().clone()).collect();
    let msig = sign_multisig(keypairs.as_slice(), "HELLO".as_bytes());
    assert_eq!(Ok(()),
               verify_multisig(pks.as_slice(), "HELLO".as_bytes(), &msig),
               "Multisignature should have verify correctly");
  }
}
