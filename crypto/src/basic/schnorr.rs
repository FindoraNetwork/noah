//! This file implements a Schnorr signature scheme and a naive implementation of a multi-signature,
//! which is a list of simple Schnorr signatures.
//!
//! At a high level the scheme works as follows:
//! * `key_gen()` => sample a random scalar `x` and compute `X=g^x` where `g` is some group generator. Return return the key pair `(x,X)`
//! * `sign(m,sk)` => sample a random scalar `r` and compute `R=g^r`. Compute scalars `c=H(X,R,m)` and `s=r+cx`. Return `(R,s)`
//! * `verify(m,pk,sig)` => parse `sig` as `(R,s)`. Compute `c=H(X,R,m)`. Check that `R.X^c == g^s`.

use merlin::Transcript;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use zei_algebra::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
/// A Schnorr signature consists of a group element R and a scalar s
pub struct Signature<G, S> {
    R: G,
    s: S,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
struct SecretKey<S>(S);

impl<S: Scalar> SecretKey<S> {
    fn randomize(&self, factor: &S) -> SecretKey<S> {
        SecretKey(self.0.mul(factor))
    }
    fn scalar(&self) -> S {
        self.0
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default, Hash, Ord, PartialOrd, Copy,
)]
pub struct PublicKey<G>(G);

impl<G: Group> PublicKey<G> {
    /// Randomize public key by `factor`
    pub fn randomize(&self, factor: &G::ScalarType) -> PublicKey<G> {
        PublicKey(self.0.mul(factor))
    }

    /// Get reference to group point representing the public key
    pub fn point_ref(&self) -> &G {
        &self.0
    }

    /// Build public key from group point
    pub fn from_point(point: G) -> PublicKey<G> {
        PublicKey(point)
    }
    /// Verify a Schnorr signature given a message and a public key
    /// * `msg` - message
    /// * `sig` - signature
    /// * `returns` - Nothing if the verification succeeds, an error otherwise
    pub fn verify(&self, msg: &[u8], sign: &Signature<G, G::ScalarType>) -> Result<()> {
        verify(self, msg, sign).c(d!())
    }
}

impl<G: Group> ZeiFromToBytes for PublicKey<G> {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.to_compressed_bytes()
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<PublicKey<G>> {
        let group_element = G::from_compressed_bytes(bytes);

        match group_element {
            Ok(g) => Ok(PublicKey(g)),
            _ => Err(eg!(ZeiError::ParameterError)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct KeyPair<G, S> {
    sec_key: SecretKey<S>,
    pub pub_key: PublicKey<G>,
}

impl<G: Group> KeyPair<G, G::ScalarType> {
    /// Generate a Schnorr keypair from `prng`
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        gen_keys(prng)
    }

    /// Return the key pair from secret value
    pub fn from_secret_scalar(secret: G::ScalarType) -> Self {
        let base = G::get_base();
        let pub_key = base.mul(&secret);

        Self {
            sec_key: SecretKey(secret),
            pub_key: PublicKey(pub_key),
        }
    }

    /// Return scalar representing secret key
    pub fn get_secret_scalar(&self) -> G::ScalarType {
        self.sec_key.scalar()
    }

    /// Compute a signature for `msg`.
    /// * `msg` - sequence of bytes to be signed
    /// * `returns` - a Schnorr signature
    pub fn sign<R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        msg: &[u8],
    ) -> Signature<G, G::ScalarType> {
        sign(prng, self, msg)
    }

    /// Randomize the keypair by `factor`
    pub fn randomize(&self, factor: &G::ScalarType) -> Self {
        KeyPair {
            pub_key: self.pub_key.randomize(factor),
            sec_key: self.sec_key.randomize(factor),
        }
    }
}

impl<G: Group> ZeiFromToBytes for KeyPair<G, G::ScalarType> {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend_from_slice(self.get_secret_scalar().to_bytes().as_slice());
        vec.extend_from_slice(self.pub_key.zei_to_bytes().as_slice());
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        let alpha = G::ScalarType::from_bytes(&bytes[0..G::ScalarType::bytes_len()]).c(d!())?;
        let u = PublicKey::zei_from_bytes(&bytes[G::ScalarType::bytes_len()..]).c(d!())?;

        Ok(KeyPair {
            sec_key: SecretKey(alpha),
            pub_key: u,
        })
    }
}

/// Transcript functions
pub trait SchnorrTranscript {
    fn update_transcript_with_sig_info<G: Group>(
        &mut self,
        msg: &[u8],
        pk: &PublicKey<G>,
        commitment: &G,
    );

    fn compute_challenge<S: Scalar>(&mut self) -> S;
}

impl SchnorrTranscript for Transcript {
    fn update_transcript_with_sig_info<G: Group>(
        &mut self,
        msg: &[u8],
        pk: &PublicKey<G>,
        commitment: &G,
    ) {
        self.append_message(b"message", msg);
        self.append_message(b"public key", &pk.zei_to_bytes());
        self.append_message(b"R", &commitment.to_compressed_bytes());
    }

    /// The challenge is computed from the transcript
    fn compute_challenge<S: Scalar>(&mut self) -> S {
        let mut c_bytes = [0_u8; 32];
        self.challenge_bytes(b"c", &mut c_bytes);
        let mut prg = ChaChaRng::from_seed(c_bytes);
        Scalar::random(&mut prg)
    }
}

#[allow(non_snake_case)]
impl<G: Group> ZeiFromToBytes for Signature<G, G::ScalarType> {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v1 = self.R.to_compressed_bytes();
        let mut v2 = self.s.to_bytes();
        v1.append(&mut v2);
        v1
    }

    fn zei_from_bytes(bytes_repr: &[u8]) -> Result<Signature<G, G::ScalarType>> {
        let R = G::from_compressed_bytes(&bytes_repr[..G::COMPRESSED_LEN]);
        if R.is_err() {
            return Err(eg!(ZeiError::ParameterError));
        }
        let R = R.unwrap(); // safe unwrap()
        let s = G::ScalarType::from_bytes(&bytes_repr[G::COMPRESSED_LEN..]);
        match s {
            Ok(s) => Ok(Signature { R, s }),
            _ => Err(eg!(ZeiError::DeserializationError)),
        }
    }
}

/// In this naive implementation a multi signature is a list
/// of  "simple" signatures.
pub struct MultiSignature<G: Group>(Vec<Signature<G, G::ScalarType>>);

/// Generates a key pair for the Schnorr signature scheme
/// * `prng` - pseudo-random generator
/// * `returns` - a key pair
fn gen_keys<R: CryptoRng + RngCore, G: Group>(prng: &mut R) -> KeyPair<G, G::ScalarType> {
    // Private key
    let alpha = G::ScalarType::random(prng);

    // Public key
    let base = G::get_base();
    let u = base.mul(&alpha);

    KeyPair {
        sec_key: SecretKey(alpha),
        pub_key: PublicKey(u),
    }
}

#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
/// Computes a signature given a key pair and a message.
/// * `signing_key` - key pair. Having both public and private key makes the signature computation more efficient
/// * `message` - sequence of bytes to be signed
/// * `returns` - a Schnorr signature
fn sign<R: CryptoRng + RngCore, G: Group>(
    prng: &mut R,
    signing_key: &KeyPair<G, G::ScalarType>,
    msg: &[u8],
) -> Signature<G, G::ScalarType> {
    let mut transcript = Transcript::new(b"schnorr_sig");

    let g = G::get_base();
    let r = G::ScalarType::random(prng);

    let R = g.mul(&r);
    let pk = &signing_key.pub_key;

    transcript.update_transcript_with_sig_info::<G>(msg, pk, &R);

    let c = transcript.compute_challenge::<G::ScalarType>();

    let private_key = &(signing_key.sec_key);
    let s: G::ScalarType = r.add(&c.mul(&private_key.0));

    Signature { R, s }
}

/// Computes a signature with key pairs sk_1, sk_2,...,sk_n on a message m
/// * `signing_keys` - list of key pairs
/// * `message` - message to be signed
pub fn multisig_sign<R: CryptoRng + RngCore, G: Group>(
    prng: &mut R,
    signing_keys: &[KeyPair<G, G::ScalarType>],
    message: &[u8],
) -> MultiSignature<G> {
    let mut signatures = vec![];

    for signing_key in signing_keys {
        let sig = sign::<R, G>(prng, signing_key, message);
        signatures.push(sig);
    }
    MultiSignature(signatures)
}

/// Verifies a Schnorr signature given a message, a public key
/// * `pk` -  public key
/// * `msg` - message
/// * `sig` - signature
/// * `returns` - Nothing if the verification succeeds, an error otherwise
#[allow(non_snake_case)]
fn verify<G: Group>(
    pk: &PublicKey<G>,
    msg: &[u8],
    sig: &Signature<G, G::ScalarType>,
) -> Result<()> {
    let mut transcript = Transcript::new(b"schnorr_sig");

    let g = G::get_base();

    transcript.update_transcript_with_sig_info(msg, pk, &sig.R);

    let c = transcript.compute_challenge::<G::ScalarType>();

    let left = sig.R.add(&pk.0.mul(&c));
    let right = g.mul(&sig.s);

    if left == right {
        Ok(())
    } else {
        Err(eg!(ZeiError::SignatureError))
    }
}

/// Verifies a multi-signature given a list of public keys and a message
/// * `public_keys` - list of public keys. Note that the order of the public keys must correspond
/// to the order of the signing keys used to produce the multi-signature
/// * `msg` - message
/// * `msig` - multi signature
/// * `returns` - Nothing if the verification succeeds, an error otherwise
pub fn multisig_verify<G: Group>(
    public_keys: &[PublicKey<G>],
    msg: &[u8],
    msig: &MultiSignature<G>,
) -> Result<()> {
    if public_keys.len() != msig.0.len() || public_keys.is_empty() {
        return Err(eg!(ZeiError::ParameterError));
    }

    for (pk, sig) in public_keys.iter().zip(msig.0.clone()) {
        verify(pk, msg, &sig).c(d!())?;
    }

    Ok(())
}

#[cfg(test)]
mod schnorr_sigs {

    mod schnorr_simple_sig {
        use crate::basic::schnorr::{KeyPair, PublicKey, Signature};
        use zei_algebra::jubjub::JubjubPoint;
        use zei_algebra::prelude::*;
        use zei_algebra::ristretto::RistrettoPoint;

        fn check_schnorr<G: Group>() {
            let seed = [0_u8; 32];
            let mut prng = rand_chacha::ChaChaRng::from_seed(seed);

            let key_pair: KeyPair<G, G::ScalarType> = KeyPair::generate(&mut prng);

            let message = b"message";

            let sig = key_pair.sign(&mut prng, message);

            let public_key = key_pair.pub_key;
            let res = public_key.verify(message, &sig);
            assert!(res.is_ok());

            let wrong_sig = Signature {
                R: G::get_identity(),
                s: G::ScalarType::one(),
            };
            let res = public_key.verify(message, &wrong_sig);
            assert!(res.is_err());

            let wrong_message = b"wrong_message";
            let res = public_key.verify(wrong_message, &sig);
            assert!(res.is_err());
        }

        #[test]
        fn schnorr_sig_over_jubjub() {
            check_schnorr::<JubjubPoint>();
        }

        #[test]
        fn schnorr_sig_over_ristretto() {
            check_schnorr::<RistrettoPoint>();
        }

        fn check_from_to_bytes<G: Group>() {
            let seed = [0_u8; 32];
            let mut prng = rand_chacha::ChaChaRng::from_seed(seed);
            let key_pair: KeyPair<G, G::ScalarType> = KeyPair::generate(&mut prng);
            let message = b"message";
            let sig = key_pair.sign(&mut prng, message);
            let public_key = key_pair.pub_key;

            // Public key
            let public_key_bytes = public_key.zei_to_bytes();
            let public_key_from_bytes = PublicKey::zei_from_bytes(&public_key_bytes).unwrap();
            assert_eq!(public_key, public_key_from_bytes);

            // Signature
            let signature_bytes = sig.zei_to_bytes();
            let signature_from_bytes = Signature::zei_from_bytes(&signature_bytes).unwrap();
            assert_eq!(sig, signature_from_bytes);
        }

        #[test]
        pub fn schnorr_from_to_bytes() {
            check_from_to_bytes::<JubjubPoint>();
        }

        #[test]
        pub fn ristretto_from_to_bytes() {
            check_from_to_bytes::<RistrettoPoint>();
        }
    }

    #[cfg(test)]
    mod schnorr_multisig {
        use crate::basic::schnorr::{
            multisig_sign, multisig_verify, KeyPair, MultiSignature, Signature,
        };
        use zei_algebra::jubjub::JubjubPoint;
        use zei_algebra::prelude::*;
        use zei_algebra::ristretto::RistrettoPoint;

        fn check_schnorr_multisig<G: Group>() {
            let seed = [0_u8; 32];
            let mut prng = rand_chacha::ChaChaRng::from_seed(seed);

            const NUMBER_OF_KEYS: usize = 3;
            let mut key_pairs = vec![];
            let mut public_keys = vec![];
            for _ in 0..NUMBER_OF_KEYS {
                let key_pair: KeyPair<G, G::ScalarType> = KeyPair::generate(&mut prng);
                let public_key = key_pair.pub_key.clone();
                key_pairs.push(key_pair);
                public_keys.push(public_key);
            }

            let message = b"message";

            let msig = multisig_sign(&mut prng, &key_pairs, message);

            let res = multisig_verify(&public_keys, message, &msig);
            assert!(res.is_ok());

            let wrong_msig: MultiSignature<G> = MultiSignature(vec![
                Signature {
                    R: G::get_identity(),
                    s: G::ScalarType::one()
                };
                3
            ]);
            let res = multisig_verify(&public_keys, message, &wrong_msig);
            assert!(res.is_err());

            let wrong_message = b"wrong_message";
            let res = multisig_verify(&public_keys, wrong_message, &msig);
            msg_eq!(ZeiError::SignatureError, res.unwrap_err());

            let too_short_multi_sig = MultiSignature(msig.0.clone()[0..2].to_vec());
            let res = multisig_verify(&public_keys, message, &too_short_multi_sig);
            msg_eq!(ZeiError::ParameterError, res.unwrap_err());

            let empty_msig: MultiSignature<G> = MultiSignature(vec![]);
            let empty_public_keys = vec![];
            let res = multisig_verify(&empty_public_keys, message, &empty_msig);
            msg_eq!(ZeiError::ParameterError, res.unwrap_err());
        }

        #[test]
        fn schnorr_multi_sig_over_jubjub() {
            check_schnorr_multisig::<JubjubPoint>();
        }

        #[test]
        fn schnorr_multi_sig_over_ristretto() {
            check_schnorr_multisig::<RistrettoPoint>();
        }
    }
}
