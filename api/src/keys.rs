use crate::errors::{NoahError, Result};
use crate::parameters::params::AddressFormat;
use crate::parameters::params::AddressFormat::{ED25519, SECP256K1};
use ark_ff::{BigInteger, PrimeField};
use ark_std::borrow::ToOwned;
use curve25519_dalek::edwards::CompressedEdwardsY;
use digest::consts::U64;
use digest::Digest;
use ed25519_dalek::{
    ExpandedSecretKey, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey,
    Signature as Ed25519Signature, Signer, Verifier,
};
use libsecp256k1::{
    curve::{Affine as LibSecp256k1G1, FieldStorage, Scalar as LibSecp256k1Scalar},
    recover, sign as secp256k1_sign, verify as secp256k1_verify, Message,
    PublicKey as Secp256k1PublicKey, RecoveryId, SecretKey as Secp256k1SecretKey,
    Signature as Secp256k1Signature,
};
use noah_algebra::{
    cmp::Ordering,
    ed25519::{Ed25519Point, Ed25519Scalar},
    hash::{Hash, Hasher},
    prelude::*,
    secp256k1::{SECP256K1Scalar, SECP256K1G1},
};
use serde::Serialize;
use sha3::Keccak256;
use wasm_bindgen::prelude::*;
use noah_algebra::bn254::BN254Scalar;

/// The length of the secret key.
pub const SECRET_KEY_LENGTH: usize = 33; // KeyType + 32 bytes

/// The length of the public key.
pub const PUBLIC_KEY_LENGTH: usize = 34; // KeyType + 33 bytes

/// The length of the public key.
pub const SIGNATURE_LENGTH: usize = 66; // KeyType + 64 bytes + 1 recovery

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Supported signature schemes.
pub enum KeyType {
    /// Ed25519
    Ed25519,
    /// Secp256k1
    Secp256k1,
    /// ETH-compatible address
    EthAddress,
}

impl KeyType {
    /// Convert to u8.
    pub fn to_byte(&self) -> u8 {
        match self {
            KeyType::Ed25519 => 0,
            KeyType::Secp256k1 => 1,
            KeyType::EthAddress => 2,
        }
    }

    /// Convert from u8.
    pub fn from_byte(byte: u8) -> KeyType {
        match byte {
            0u8 => KeyType::Ed25519,
            1u8 => KeyType::Secp256k1,
            2u8 => KeyType::EthAddress,
            _ => KeyType::Ed25519,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[wasm_bindgen]
/// The public key wrapper for anon/confidential transfer, for WASM compatability.
pub struct PublicKey(pub(crate) PublicKeyInner);

#[derive(Clone, Copy, Debug)]
/// The public key for confidential transfer.
pub enum PublicKeyInner {
    /// Ed25519 Public Key
    Ed25519(Ed25519PublicKey),
    /// Secp256k1 Public Key
    Secp256k1(Secp256k1PublicKey),
    /// Hash of the secp256k1 public key.
    EthAddress([u8; 20]),
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.noah_to_bytes().eq(&other.noah_to_bytes())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.noah_to_bytes().cmp(&other.noah_to_bytes())
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.noah_to_bytes().hash(state)
    }
}

impl NoahFromToBytes for PublicKey {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; PUBLIC_KEY_LENGTH];
        match self.0 {
            PublicKeyInner::Ed25519(pk) => {
                bytes = vec![0u8; PUBLIC_KEY_LENGTH - 2];
                bytes.copy_from_slice(pk.as_bytes());
            }
            PublicKeyInner::Secp256k1(pk) => {
                bytes[0] = KeyType::Secp256k1.to_byte();
                bytes[1..PUBLIC_KEY_LENGTH].copy_from_slice(&pk.serialize_compressed());
            }
            PublicKeyInner::EthAddress(hash) => {
                bytes[0] = KeyType::EthAddress.to_byte();
                bytes[1..21].copy_from_slice(&hash);
            }
        }
        bytes
    }

    fn noah_from_bytes(bytes: &[u8]) -> core::result::Result<PublicKey, AlgebraError> {
        // Compatible with old data.
        if bytes.len() == 32 {
            return match Ed25519PublicKey::from_bytes(bytes) {
                Ok(pk) => Ok(PublicKey(PublicKeyInner::Ed25519(pk))),
                Err(_) => Err(AlgebraError::DeserializationError),
            };
        }

        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(AlgebraError::DeserializationError);
        }

        let ktype = KeyType::from_byte(bytes[0]);
        match ktype {
            KeyType::Ed25519 => {
                let bytes = &bytes[1..PUBLIC_KEY_LENGTH - 1];
                match Ed25519PublicKey::from_bytes(bytes) {
                    Ok(pk) => Ok(PublicKey(PublicKeyInner::Ed25519(pk))),
                    Err(_) => Err(AlgebraError::DeserializationError),
                }
            }
            KeyType::Secp256k1 => {
                let mut pk_bytes = [0u8; PUBLIC_KEY_LENGTH - 1];
                pk_bytes.copy_from_slice(&bytes[1..]);
                match Secp256k1PublicKey::parse_compressed(&pk_bytes) {
                    Ok(pk) => Ok(PublicKey(PublicKeyInner::Secp256k1(pk))),
                    Err(_) => Err(AlgebraError::DeserializationError),
                }
            }
            KeyType::EthAddress => {
                let mut hash_bytes = [0u8; 20];
                hash_bytes.copy_from_slice(&bytes[1..21]);
                Ok(PublicKey(PublicKeyInner::EthAddress(hash_bytes)))
            }
        }
    }
}

impl PublicKey {
    /// Default public key
    pub fn default(address_format: AddressFormat) -> Self {
        SecretKey::default(address_format).into_keypair().pub_key
    }

    /// Get the reference of the inner type
    pub fn inner(&self) -> &PublicKeyInner {
        &self.0
    }

    /// Convert the secp256k1 keypair to ETH address
    pub fn to_eth_address(&self) -> Result<PublicKey> {
        match self.inner() {
            PublicKeyInner::Secp256k1(pk) => {
                let address = convert_libsecp256k1_public_key_to_address(&pk);
                Ok(PublicKey(PublicKeyInner::EthAddress(address)))
            }
            PublicKeyInner::EthAddress(_) => Ok(self.clone()),
            _ => Err(NoahError::ParameterError),
        }
    }

    /// Change to algebra secp256k1 Point
    pub fn to_secp256k1(&self) -> Result<SECP256K1G1> {
        match self.inner() {
            PublicKeyInner::Secp256k1(pk) => Ok(convert_point_libsecp256k1_to_algebra(&pk)?),
            _ => Err(NoahError::ParameterError),
        }
    }

    /// Change to algebra Ristretto Point
    pub fn to_ed25519(&self) -> Result<Ed25519Point> {
        match self.inner() {
            PublicKeyInner::Ed25519(pk) => Ok(convert_ed25519_pk_to_algebra(&pk)?),
            _ => Err(NoahError::ParameterError),
        }
    }

    /// Return the BN254 scalar representation of the public key.
    pub fn to_bn_scalars(&self) -> Result<[BN254Scalar; 3]> {
        let bytes = match self.inner() {
            PublicKeyInner::Secp256k1(_) => {
                let pk = self.to_secp256k1()?;
                let affine = pk.get_raw();
                let mut bytes = Vec::new();
                bytes.extend(affine.x.into_bigint().to_bytes_le());
                bytes.extend(affine.y.into_bigint().to_bytes_le());

                bytes
            }
            PublicKeyInner::Ed25519(_) => {
                let pk = self.to_ed25519()?;
                let affine = pk.get_raw();
                let mut bytes = Vec::new();
                bytes.extend(affine.x.into_bigint().to_bytes_le());
                bytes.extend(affine.y.into_bigint().to_bytes_le());

                bytes
            }
            _ => return Err(NoahError::ParameterError),
        };

        let first = BN254Scalar::from_bytes(&bytes[0..31])?;
        let second = BN254Scalar::from_bytes(&bytes[31..62])?;
        let third = BN254Scalar::from_bytes(&bytes[62..])?;

        Ok([first, second, third])
    }

    /// random a scalar and the compressed point.
    pub fn random_scalar_with_compressed_point<R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
    ) -> (KeyType, Vec<u8>, Vec<u8>) {
        match self.0 {
            PublicKeyInner::Ed25519(_) => {
                let (s, p) = Ed25519Scalar::random_scalar_with_compressed_point(prng);
                (KeyType::Ed25519, s.to_bytes(), p.to_compressed_bytes())
            }
            PublicKeyInner::Secp256k1(_) | PublicKeyInner::EthAddress(_) => {
                let (s, p) = SECP256K1Scalar::random_scalar_with_compressed_point(prng);
                (KeyType::Secp256k1, s.to_bytes(), p.to_compressed_bytes())
            }
        }
    }

    /// Convert into the point format.
    pub fn as_compressed_point(&self) -> Result<Vec<u8>> {
        match self.0 {
            PublicKeyInner::Ed25519(pk) => {
                Ok(convert_ed25519_pk_to_algebra(&pk)?.to_compressed_bytes())
            }
            PublicKeyInner::Secp256k1(pk) => {
                Ok(convert_point_libsecp256k1_to_algebra(&pk)?.to_compressed_bytes())
            }
            PublicKeyInner::EthAddress(_) => panic!("EthAddress not supported"),
        }
    }

    /// Verify a signature.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        match (self.0, signature) {
            (PublicKeyInner::Ed25519(pk), Signature::Ed25519(sign)) => pk
                .verify(message, sign)
                .map_err(|_| NoahError::SignatureError),
            (PublicKeyInner::Secp256k1(pk), Signature::Secp256k1(sign, _)) => {
                let mut hasher = Keccak256::new();
                hasher.update(message);
                let res = hasher.finalize();
                let msg = Message::parse_slice(&res[..]).map_err(|_| NoahError::SignatureError)?;
                if secp256k1_verify(&msg, sign, &pk) {
                    Ok(())
                } else {
                    Err(NoahError::SignatureError)
                }
            }
            (PublicKeyInner::EthAddress(hash), Signature::Secp256k1(sign, rec)) => {
                let mut hasher = Keccak256::new();
                hasher.update(message);
                let res = hasher.finalize();
                let msg = Message::parse_slice(&res[..]).map_err(|_| NoahError::SignatureError)?;
                let pk = recover(&msg, sign, rec).map_err(|_| NoahError::SignatureError)?;
                let other = convert_libsecp256k1_public_key_to_address(&pk);
                if hash == other {
                    Ok(())
                } else {
                    Err(NoahError::SignatureError)
                }
            }
            _ => Err(NoahError::SignatureError),
        }
    }

    /// Create a (fake) public key through hashing-to-curve from arbitrary bytes
    pub fn hash_from_bytes<D>(bytes: &[u8]) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let pk = Ed25519PublicKey::hash_from_bytes::<D>(bytes);
        Self(PublicKeyInner::Ed25519(pk))
    }
}

#[derive(Debug)]
/// The secret key for confidential transfer.
pub enum SecretKey {
    /// Ed25519 Secret Key
    Ed25519(Ed25519SecretKey),
    /// Secp256k1 Secret Key
    Secp256k1(Secp256k1SecretKey),
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self::noah_from_bytes(&self.noah_to_bytes()).unwrap()
    }
}

impl Eq for SecretKey {}

impl PartialEq for SecretKey {
    fn eq(&self, other: &SecretKey) -> bool {
        self.noah_to_bytes().eq(&other.noah_to_bytes())
    }
}

impl Ord for SecretKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.noah_to_bytes().cmp(&other.noah_to_bytes())
    }
}

impl PartialOrd for SecretKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for SecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.noah_to_bytes().hash(state)
    }
}

impl NoahFromToBytes for SecretKey {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; SECRET_KEY_LENGTH];
        match self {
            SecretKey::Ed25519(sk) => {
                bytes[0] = KeyType::Ed25519.to_byte();
                bytes[1..].copy_from_slice(sk.as_bytes());
            }
            SecretKey::Secp256k1(sk) => {
                bytes[0] = KeyType::Secp256k1.to_byte();
                bytes[1..].copy_from_slice(&sk.serialize());
            }
        }
        bytes
    }

    fn noah_from_bytes(bytes: &[u8]) -> core::result::Result<SecretKey, AlgebraError> {
        // Compatible with old data.
        if bytes.len() == 32 {
            return match Ed25519SecretKey::from_bytes(bytes) {
                Ok(sk) => Ok(SecretKey::Ed25519(sk)),
                Err(_) => Err(AlgebraError::DeserializationError),
            };
        }

        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(AlgebraError::DeserializationError);
        }

        let ktype = KeyType::from_byte(bytes[0]);
        match ktype {
            KeyType::Ed25519 => match Ed25519SecretKey::from_bytes(&bytes[1..]) {
                Ok(sk) => Ok(SecretKey::Ed25519(sk)),
                Err(_) => Err(AlgebraError::DeserializationError),
            },
            KeyType::Secp256k1 | KeyType::EthAddress => {
                match Secp256k1SecretKey::parse_slice(&bytes[1..]) {
                    Ok(sk) => Ok(SecretKey::Secp256k1(sk)),
                    Err(_) => Err(AlgebraError::DeserializationError),
                }
            }
        }
    }
}

impl SecretKey {
    /// Default secret key
    pub fn default(address_format: AddressFormat) -> Self {
        match address_format {
            SECP256K1 => Self::Secp256k1(Secp256k1SecretKey::default()),
            ED25519 => {
                let default_bytes = [0u8; 32];
                SecretKey::Ed25519(Ed25519SecretKey::from_bytes(&default_bytes).unwrap())
            }
        }
    }

    /// Change to algebra secp256k1 Point
    pub fn to_secp256k1(&self) -> Result<SECP256K1Scalar> {
        match self {
            SecretKey::Secp256k1(sk) => {
                let s: LibSecp256k1Scalar = (*sk).into();
                Ok(convert_scalar_libsecp256k1_to_algebra(&s.0)?)
            }
            _ => Err(NoahError::ParameterError),
        }
    }

    /// Change to algebra Ristretto Point
    pub fn to_ed25519(&self) -> Result<Ed25519Scalar> {
        match self {
            SecretKey::Ed25519(sk) => Ok(convert_ed25519_sk_to_algebra(&sk)?),
            _ => Err(NoahError::ParameterError),
        }
    }

    /// Return the BLS12-381 scalar representation of the secret key.
    pub fn to_bn_scalars(&self) -> Result<[BN254Scalar; 2]> {
        let bytes = match self {
            SecretKey::Secp256k1(_) => {
                let sk = self.to_secp256k1()?;
                sk.to_bytes()
            }
            SecretKey::Ed25519(_) => {
                let sk = self.to_ed25519()?;
                sk.to_bytes()
            }
        };

        let first = BN254Scalar::from_bytes(&bytes[0..31])?;
        let second = BN254Scalar::from_bytes(&bytes[31..])?;

        Ok([first, second])
    }

    #[inline(always)]
    /// Convert into a keypair.
    pub fn into_keypair(self) -> KeyPair {
        let pk = match self {
            SecretKey::Ed25519(ref sk) => PublicKey(PublicKeyInner::Ed25519(sk.into())),
            SecretKey::Secp256k1(ref sk) => PublicKey(PublicKeyInner::Secp256k1(
                Secp256k1PublicKey::from_secret_key(sk),
            )),
        };
        KeyPair {
            pub_key: pk,
            sec_key: self,
        }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        match self {
            SecretKey::Ed25519(sk) => {
                let sign = ed25519_dalek::Keypair::from(
                    ed25519_dalek::SecretKey::from_bytes(&sk.to_bytes()).unwrap(),
                )
                .sign(message);
                Ok(Signature::Ed25519(sign))
            }
            SecretKey::Secp256k1(sk) => {
                // If the Ethereum sign is used outside,
                // it needs to be dealt with first, only hash in Noah.
                let mut hasher = Keccak256::new();
                hasher.update(message);
                let res = hasher.finalize();
                let msg = Message::parse_slice(&res[..]).map_err(|_| NoahError::SignatureError)?;
                let (sign, rec) = secp256k1_sign(&msg, sk);
                Ok(Signature::Secp256k1(sign, rec))
            }
        }
    }

    /// Convert into scalar bytes.
    pub fn as_scalar_bytes(&self) -> Result<(KeyType, Vec<u8>)> {
        match self {
            SecretKey::Ed25519(sk) => Ok((
                KeyType::Ed25519,
                convert_ed25519_sk_to_algebra(sk)?.to_bytes(),
            )),

            SecretKey::Secp256k1(sk) => {
                let s: LibSecp256k1Scalar = (*sk).into();
                Ok((
                    KeyType::Secp256k1,
                    convert_scalar_libsecp256k1_to_algebra(&s.0)?.to_bytes(),
                ))
            }
        }
    }

    /// Convert from raw bytes used secp256k1 and use it with address.
    pub fn from_secp256k1_with_address(bytes: &[u8]) -> Result<Self> {
        let sk =
            Secp256k1SecretKey::parse_slice(bytes).map_err(|_| NoahError::DeserializationError)?;
        Ok(SecretKey::Secp256k1(sk))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[wasm_bindgen]
/// The keypair for confidential transfer.
pub struct KeyPair {
    /// The public key.
    pub(crate) pub_key: PublicKey,
    /// The secret key.
    pub(crate) sec_key: SecretKey,
}

impl NoahFromToBytes for KeyPair {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend_from_slice(self.sec_key.noah_to_bytes().as_slice());
        vec.extend_from_slice(self.pub_key.noah_to_bytes().as_slice());
        vec
    }

    fn noah_from_bytes(bytes: &[u8]) -> core::result::Result<Self, AlgebraError> {
        if bytes.len() == 64 {
            Ok(KeyPair {
                sec_key: SecretKey::Ed25519(
                    Ed25519SecretKey::from_bytes(&bytes[0..32])
                        .map_err(|_| AlgebraError::DeserializationError)?,
                ),
                pub_key: PublicKey(PublicKeyInner::Ed25519(
                    Ed25519PublicKey::from_bytes(&bytes[32..64])
                        .map_err(|_| AlgebraError::DeserializationError)?,
                )),
            })
        } else {
            Ok(KeyPair {
                sec_key: SecretKey::noah_from_bytes(&bytes[0..SECRET_KEY_LENGTH])?,
                pub_key: PublicKey::noah_from_bytes(&bytes[SECRET_KEY_LENGTH..])?,
            })
        }
    }
}

impl KeyPair {
    /// Default keypair
    pub fn default(address_format: AddressFormat) -> Self {
        SecretKey::default(address_format).into_keypair()
    }

    /// Change to algebra Secp256k1 keypair
    pub fn to_secp256k1(&self) -> Result<(SECP256K1Scalar, SECP256K1G1)> {
        match (&self.sec_key, &self.pub_key) {
            (SecretKey::Secp256k1(_), PublicKey(PublicKeyInner::Secp256k1(_))) => {
                Ok((self.sec_key.to_secp256k1()?, self.pub_key.to_secp256k1()?))
            }
            _ => Err(NoahError::ParameterError),
        }
    }

    /// Change to algebra Ristretto keypair
    pub fn to_ed25519(&self) -> Result<(Ed25519Scalar, Ed25519Point)> {
        match (&self.sec_key, &self.pub_key) {
            (SecretKey::Ed25519(_), PublicKey(PublicKeyInner::Ed25519(_))) => {
                Ok((self.sec_key.to_ed25519()?, self.pub_key.to_ed25519()?))
            }
            _ => Err(NoahError::ParameterError),
        }
    }

    /// Generate a random key pair.
    pub fn sample<R: CryptoRng + RngCore>(prng: &mut R, address_format: AddressFormat) -> Self {
        match address_format {
            SECP256K1 => {
                let sk = Secp256k1SecretKey::random(prng);
                let pk = Secp256k1PublicKey::from_secret_key(&sk);
                KeyPair {
                    pub_key: PublicKey(PublicKeyInner::Secp256k1(pk)),
                    sec_key: SecretKey::Secp256k1(sk),
                }
            }
            ED25519 => {
                let kp = ed25519_dalek::Keypair::generate(prng);
                KeyPair {
                    pub_key: PublicKey(PublicKeyInner::Ed25519(kp.public)),
                    sec_key: SecretKey::Ed25519(kp.secret_key()),
                }
            }
        }
    }

    /// Generate a key pair from secret key bytes.
    pub fn generate_secp256k1_from_bytes(bytes: &[u8]) -> Result<Self> {
        let sk = Secp256k1SecretKey::parse_slice(bytes).map_err(|_| NoahError::ParameterError)?;
        let pk = Secp256k1PublicKey::from_secret_key(&sk);
        Ok(KeyPair {
            pub_key: PublicKey(PublicKeyInner::Secp256k1(pk)),
            sec_key: SecretKey::Secp256k1(sk),
        })
    }

    /// Generate a Secp256k1 key pair with address.
    pub fn generate_address<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let sk = Secp256k1SecretKey::random(prng);
        let pk = Secp256k1PublicKey::from_secret_key(&sk);
        KeyPair {
            pub_key: PublicKey(PublicKeyInner::EthAddress(
                convert_libsecp256k1_public_key_to_address(&pk),
            )),
            sec_key: SecretKey::Secp256k1(sk),
        }
    }

    /// Generate a Secp256k1 key pair with address.
    pub fn sample_address<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let sk = Secp256k1SecretKey::random(prng);
        let pk = Secp256k1PublicKey::from_secret_key(&sk);
        KeyPair {
            pub_key: PublicKey(PublicKeyInner::EthAddress(
                convert_libsecp256k1_public_key_to_address(&pk),
            )),
            sec_key: SecretKey::Secp256k1(sk),
        }
    }

    /// Convert to eth address keypair.
    pub fn to_eth_address(&self) -> Result<Self> {
        Ok(Self {
            pub_key: self.pub_key.to_eth_address()?,
            sec_key: self.sec_key.clone(),
        })
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        self.sec_key.sign(msg)
    }

    #[inline(always)]
    /// Return the public key.
    pub fn get_pk(&self) -> PublicKey {
        self.pub_key
    }

    #[inline(always)]
    /// Return a reference of the public key.
    pub fn get_pk_ref(&self) -> &PublicKey {
        &self.pub_key
    }

    #[inline(always)]
    /// Return the secret key.
    pub fn get_sk(&self) -> SecretKey {
        self.sec_key.clone()
    }

    #[inline(always)]
    /// Return a reference of the secret key.
    pub fn get_sk_ref(&self) -> &SecretKey {
        &self.sec_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// The signature for confidential transfer.
pub enum Signature {
    /// Ed25519 Signature
    Ed25519(Ed25519Signature),
    /// Secp256k1 Signature with recovery.
    Secp256k1(Secp256k1Signature, RecoveryId),
}

impl NoahFromToBytes for Signature {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; SIGNATURE_LENGTH];
        match self {
            Signature::Ed25519(sign) => {
                bytes[0] = KeyType::Ed25519.to_byte();
                bytes[1..SIGNATURE_LENGTH - 1].copy_from_slice(&sign.to_bytes());
            }
            Signature::Secp256k1(sign, rec) => {
                bytes[0] = KeyType::Secp256k1.to_byte();
                bytes[1..SIGNATURE_LENGTH - 1].copy_from_slice(&sign.serialize());
                bytes[SIGNATURE_LENGTH - 1] = rec.serialize();
            }
        }
        bytes
    }

    fn noah_from_bytes(bytes: &[u8]) -> core::result::Result<Self, AlgebraError> {
        // Compatible with old data.
        if bytes.len() == 64 {
            return match Ed25519Signature::from_bytes(bytes) {
                Ok(sign) => Ok(Signature::Ed25519(sign)),
                Err(_) => Err(AlgebraError::DeserializationError),
            };
        }

        if bytes.len() != SIGNATURE_LENGTH {
            return Err(AlgebraError::DeserializationError);
        }

        let ktype = KeyType::from_byte(bytes[0]);
        match ktype {
            KeyType::Ed25519 => {
                let s_bytes = &bytes[1..SIGNATURE_LENGTH - 1];
                match Ed25519Signature::from_bytes(s_bytes) {
                    Ok(sign) => Ok(Signature::Ed25519(sign)),
                    Err(_) => Err(AlgebraError::DeserializationError),
                }
            }
            KeyType::Secp256k1 | KeyType::EthAddress => {
                let mut s_bytes = [0u8; SIGNATURE_LENGTH - 2];
                s_bytes.copy_from_slice(&bytes[1..SIGNATURE_LENGTH - 1]);
                let sign = Secp256k1Signature::parse_standard(&s_bytes)
                    .map_err(|_| AlgebraError::DeserializationError)?;
                let rec = RecoveryId::parse(bytes[SIGNATURE_LENGTH - 1])
                    .map_err(|_| AlgebraError::DeserializationError)?;
                Ok(Signature::Secp256k1(sign, rec))
            }
        }
    }
}

/// A list of signatures under each signer.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureList {
    /// The list of signatures.
    pub signatures: Vec<Signature>,
}

impl SignatureList {
    /// Sign a message under a list of key pairs.
    pub fn sign(keypairs: &[&KeyPair], message: &[u8]) -> Result<Self> {
        // sort the key pairs based on alphabetical order of their public keys
        let mut sorted = keypairs.to_owned();
        sorted.sort_unstable_by_key(|kp| kp.pub_key.noah_to_bytes());
        let mut signatures = vec![];
        for kp in sorted {
            signatures.push(kp.sign(message)?);
        }
        Ok(SignatureList { signatures })
    }

    /// Verify a list of signature.
    pub fn verify(&self, pubkeys: &[&PublicKey], message: &[u8]) -> Result<()> {
        if pubkeys.len() != self.signatures.len() {
            return Err(NoahError::SignatureError);
        }
        // sort the key pairs based on alphabetical order of their public keys
        let mut sorted = pubkeys.to_owned();
        sorted.sort_unstable_by_key(|k| k.noah_to_bytes());
        for (pk, sig) in sorted.iter().zip(self.signatures.iter()) {
            pk.verify(&message, &sig)?;
        }
        Ok(())
    }
}

/// Function helper for get recovery id from u64.
pub fn recovery_id_from_u64(v: u64) -> u8 {
    match v {
        27 => 0,
        28 => 1,
        v if v >= 35 => ((v - 1) % 2) as u8,
        _ => v as u8,
    }
}

/// Function helper for convert secp256k1 public key to address.
pub fn convert_libsecp256k1_public_key_to_address(pk: &Secp256k1PublicKey) -> [u8; 20] {
    let public_key = pk.serialize();
    debug_assert_eq!(public_key[0], 0x04);
    let mut hasher = Keccak256::new();
    hasher.update(&public_key[1..]);
    let result = hasher.finalize();
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&result[12..]);
    bytes
}

fn convert_point_libsecp256k1_to_algebra(
    pk: &Secp256k1PublicKey,
) -> core::result::Result<SECP256K1G1, AlgebraError> {
    let p: LibSecp256k1G1 = (*pk).into();
    let (mut x, mut y) = (p.x, p.y);
    x.normalize();
    y.normalize();
    let xf: FieldStorage = (x).into();
    let yf: FieldStorage = (y).into();
    let mut bytes = from_u32_slice_to_u8_slice(&xf.0).to_vec();
    bytes.extend(from_u32_slice_to_u8_slice(&yf.0));
    bytes.push(0); // fill the uncompressed size.
    SECP256K1G1::from_unchecked_bytes(&bytes)
}

fn convert_scalar_libsecp256k1_to_algebra(
    b: &[u32; 8],
) -> core::result::Result<SECP256K1Scalar, AlgebraError> {
    let bytes = from_u32_slice_to_u8_slice(b);
    SECP256K1Scalar::from_bytes(&bytes)
}

fn from_u32_slice_to_u8_slice(b: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&b[0].to_le_bytes());
    bytes[4..8].copy_from_slice(&b[1].to_le_bytes());
    bytes[8..12].copy_from_slice(&b[2].to_le_bytes());
    bytes[12..16].copy_from_slice(&b[3].to_le_bytes());
    bytes[16..20].copy_from_slice(&b[4].to_le_bytes());
    bytes[20..24].copy_from_slice(&b[5].to_le_bytes());
    bytes[24..28].copy_from_slice(&b[6].to_le_bytes());
    bytes[28..32].copy_from_slice(&b[7].to_le_bytes());
    bytes
}

fn convert_ed25519_sk_to_algebra(
    sk: &Ed25519SecretKey,
) -> core::result::Result<Ed25519Scalar, AlgebraError> {
    let esk = ExpandedSecretKey::from(sk);
    Ed25519Scalar::from_bytes(&esk.to_bytes()[..32])
}

fn convert_ed25519_pk_to_algebra(
    pk: &Ed25519PublicKey,
) -> core::result::Result<Ed25519Point, AlgebraError> {
    let y = CompressedEdwardsY(pk.to_bytes());
    let p = y.decompress().unwrap();

    let recip = p.Z.invert();
    let x = &p.X * &recip;
    let y = &p.Y * &recip;

    let mut bytes = x.to_bytes().to_vec();
    bytes.extend(y.to_bytes());
    Ed25519Point::from_unchecked_bytes(&bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::env;

    #[test]
    fn signatures() {
        env::set_var("DETERMINISTIC_TEST_RNG", "1");
        let mut prng = test_rng();

        let keypair = KeyPair::sample(&mut prng, SECP256K1);
        let message = "";

        let sig = keypair.sign(message.as_bytes()).unwrap();
        keypair.pub_key.verify("".as_bytes(), &sig).unwrap();
        //same test with secret key
        let sig = keypair.sec_key.sign(message.as_bytes()).unwrap();
        keypair.pub_key.verify("".as_bytes(), &sig).unwrap();

        //test again with fresh same key
        let mut prng = test_rng();
        let keypair = KeyPair::sample(&mut prng, SECP256K1);
        keypair.pub_key.verify("".as_bytes(), &sig).unwrap();

        env::set_var("DETERMINISTIC_TEST_RNG", "0");
        let mut prng = test_rng();
        let keypair = KeyPair::sample(&mut prng, ED25519);
        let message = [10u8; 500];
        let sig = keypair.sign(&message).unwrap();
        assert_eq!(
            dbg!(NoahError::SignatureError),
            dbg!(keypair.pub_key.verify("".as_bytes(), &sig).unwrap_err()),
            "Verifying sig on different message should have return Err(Signature Error)"
        );
        keypair.pub_key.verify(&message, &sig).unwrap();
        //test again with secret key
        let sig = keypair.sec_key.sign(&message).unwrap();
        assert_eq!(
            NoahError::SignatureError,
            keypair.pub_key.verify("".as_bytes(), &sig).unwrap_err(),
            "Verifying sig on different message should have return Err(Signature Error)"
        );
        keypair.pub_key.verify(&message, &sig).unwrap();

        // test with different keys
        let keypair = KeyPair::sample(&mut prng, ED25519);
        assert_eq!(
            NoahError::SignatureError,
            keypair.pub_key.verify(&message, &sig).unwrap_err(),
            "Verifying sig on with a different key should have return Err(Signature Error)"
        );
    }

    fn generate_keypairs<R: CryptoRng + RngCore>(prng: &mut R, n: usize) -> Vec<KeyPair> {
        let mut v = vec![];
        for _ in 0..n {
            v.push(KeyPair::sample(prng, SECP256K1));
        }
        v
    }

    #[test]
    fn secp256k1_address() {
        let sk = "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e";
        let address = "8626f6940e2eb28930efb4cef49b2d1f2c9c1199";
        let xs = SecretKey::from_secp256k1_with_address(&hex::decode(sk).unwrap()).unwrap();
        let kp = xs.into_keypair().to_eth_address().unwrap();
        match kp.get_pk() {
            PublicKey(PublicKeyInner::EthAddress(hash)) => {
                assert_eq!(hash.to_vec(), hex::decode(address).unwrap())
            }
            _ => panic!("not eth address"),
        }
        let sign = kp.sign(b"message").unwrap();
        kp.pub_key.verify(b"message", &sign).unwrap();
    }

    #[test]
    fn convert_secp256k1_key() {
        let mut prng = test_rng();
        let kp = KeyPair::sample(&mut prng, SECP256K1);
        let (s, p) = kp.to_secp256k1().unwrap();
        assert_eq!(SECP256K1G1::get_base().mul(&s), p);
    }

    #[test]
    fn convert_ed25519_key() {
        env::set_var("DETERMINISTIC_TEST_RNG", "0");
        let mut prng = test_rng();
        let kp = KeyPair::sample(&mut prng, ED25519);
        let (s, p) = kp.to_ed25519().unwrap();
        let ss = s.get_raw();

        let new_p = Ed25519Point::get_base()
            .get_raw()
            .mul_bigint(ss.into_bigint())
            .into_affine();

        assert_eq!(new_p, p.get_raw());
    }

    #[test]
    fn compatible_olddata() {
        let keypair = "54f72a37fc9166a027122034b8ac0bd68322083bf36c5bdd33037e358063577347c2e8cb4b9dc155f9cb24e436208ad5d28e9b62ceef7bfad81f3c254d623229";
        let pubkey = "47c2e8cb4b9dc155f9cb24e436208ad5d28e9b62ceef7bfad81f3c254d623229";
        let new_pk = PublicKey::noah_from_bytes(&hex::decode(&pubkey).unwrap()).unwrap();
        let new_kp = KeyPair::noah_from_bytes(&hex::decode(&keypair).unwrap()).unwrap();
        assert_eq!(new_kp.sec_key.into_keypair().pub_key, new_kp.pub_key);
        assert_eq!(new_kp.pub_key, new_pk);
    }

    #[test]
    fn multisig() {
        let mut prng = test_rng();
        let msg = b"random message here!".to_vec();
        // test with one key
        let keypairs = generate_keypairs(&mut prng, 1);
        let keypairs_refs = keypairs.iter().collect_vec();
        let pubkeys = keypairs.iter().map(|kp| &kp.pub_key).collect_vec();
        assert!(
            SignatureList::sign(&keypairs_refs, &msg)
                .unwrap()
                .verify(&pubkeys, &msg)
                .is_ok(),
            "Multisignature should have verify correctly for a single key"
        );

        // test with multiple keys
        let keypairs = generate_keypairs(&mut prng, 10);
        let keypairs_refs = keypairs.iter().collect_vec();
        let pubkeys = keypairs.iter().map(|kp| &kp.pub_key).collect_vec();
        assert!(
            SignatureList::sign(&keypairs_refs, &msg)
                .unwrap()
                .verify(&pubkeys, &msg)
                .is_ok(),
            "Multisignature should have verify correctly for 10 keys"
        );

        // test with unmatching order of keypairs
        let keypairs = generate_keypairs(&mut prng, 10);
        let keypairs_refs = keypairs.iter().collect_vec();
        let mut pubkeys = keypairs.iter().map(|kp| &kp.pub_key).collect_vec();
        pubkeys.swap(1, 3);
        pubkeys.swap(4, 9);
        assert!(
            SignatureList::sign(&keypairs_refs, &msg)
                .unwrap()
                .verify(&pubkeys, &msg)
                .is_ok(),
            "Multisignature should have verify correctly even when keylist is unordered"
        );
    }
}
