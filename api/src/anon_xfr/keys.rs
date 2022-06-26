use digest::crypto_common::Key;
use merlin::Transcript;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zei_algebra::bls12_381::BLSScalar;
use zei_algebra::jubjub::{JubjubPoint, JubjubScalar};
use zei_algebra::prelude::*;
use zei_crypto::basic::rescue::RescueInstance;

pub const fn get_viewing_key_domain_separator() -> BLSScalar {
    let mut hasher = Sha512::new();
    hasher.update(b"Viewing key domain separator");
    let hash = BLSScalar::from_hash(hasher);
    hash
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// A Schnorr signature consists of a group element R and a scalar s.
pub struct Signature {
    pub point_r: JubjubPoint,
    pub s: JubjubScalar,
}

/// The spending key.
pub struct SpendKey(pub BLSScalar);
/// The viewing key.
pub struct ViewKey(pub JubjubScalar);
/// The public key.
pub struct PublicKey(pub JubjubPoint);

impl PublicKey {
    /// Verify the signature.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        let mut transcript = Transcript::new(b"schnorr_sig");
        transcript.update_transcript_with_sig_info(msg, self, &sig.point_r);

        let c = transcript.compute_challenge::<JubjubScalar>();

        let g = JubjubPoint::get_base();
        let left = sig.point_r.add(&self.0.mul(&c));
        let right = g.mul(&sig.s);

        if left == right {
            Ok(())
        } else {
            Err(eg!(ZeiError::SignatureError))
        }
    }
}

impl ZeiFromToBytes for PublicKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.to_compressed_bytes()
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
        let group_element = JubjubPoint::from_compressed_bytes(bytes);
        match group_element {
            Ok(g) => Ok(PublicKey(g)),
            _ => Err(eg!(ZeiError::ParameterError)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
/// The key pair for anonymous payment.
pub struct KeyPair {
    /// The random seed that generates the secret key.
    pub spend_key: SpendKey,
    /// The secret key of Schnorr signature.
    pub view_key: ViewKey,
    /// The public key of Schnorr signature.
    pub pub_key: PublicKey,
}

impl KeyPair {
    /// Generate a Schnorr keypair from `prng`.
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        gen_keys(prng)
    }

    /// Return the key pair from the spending key.
    pub fn from_spend_key(spend_key: SpendKey) -> Self {
        let hash_instance = RescueInstance::<BLSScalar>::new();
        let viewing_key_in_bls12_381 = hash_instance.rescue(&[
            get_viewing_key_domain_separator(),
            BLSScalar::zero(),
            BLSScalar::zero(),
            spend_key.0,
        ])[0];

        // Viewing key in Jubjub = Viewing key in BLS12-381 mod Jubjub's r.
        // `from_bytes` will allow so because the number of `bytes` are the same, although it may (very likely) go beyond.
        let view_key =
            ViewKey(JubjubScalar::from_bytes(&viewing_key_in_bls12_381.to_bytes()).unwrap());

        let base = JubjubPoint::get_base();
        let pub_key = PublicKey(base.mul(&view_key.0));

        Self {
            spend_key,
            view_key,
            pub_key,
        }
    }

    /// Return the spending key.
    pub fn get_spend_key_scalar(&self) -> BLSScalar {
        self.spend_key.0
    }

    /// Return the viewing key.
    pub fn get_view_key_scalar(&self) -> JubjubScalar {
        self.view_key.0
    }

    /// Compute a signature for `msg`.
    pub fn sign<R: CryptoRng + RngCore>(&self, prng: &mut R, msg: &[u8]) -> Signature {
        sign(prng, self, msg)
    }
}

impl ZeiFromToBytes for KeyPair {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend_from_slice(self.get_spend_key_scalar().to_bytes().as_slice());
        vec.extend_from_slice(self.get_view_key_scalar().to_bytes().as_slice());
        vec.extend_from_slice(self.pub_key.zei_to_bytes().as_slice());
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len()
            != BLSScalar::bytes_len() + JubjubScalar::bytes_len() + JubjubPoint::COMPRESSED_LEN
        {
            return Err(eg!(ZeiError::DeserializationError));
        }

        let spend_key = SpendKey(BLSScalar::from_bytes(&bytes[0..BLSScalar::bytes_len()]).c(d!())?);

        let mut offset = BLSScalar::bytes_len();
        let view_key = ViewKey(
            JubjubScalar::from_bytes(&bytes[offset..offset + JubjubScalar::bytes_len()]).c(d!())?,
        );

        offset += JubjubScalar::bytes_len();
        let pub_key = PublicKey::zei_from_bytes(&bytes[offset..]).c(d!())?;

        Ok(KeyPair {
            spend_key,
            view_key,
            pub_key,
        })
    }
}

/// Transcript methods used in the Schnorr protocol.
pub trait SchnorrTranscript {
    /// Append the Schnorr response to the transcript.
    fn update_transcript_with_sig_info<G: Group>(
        &mut self,
        msg: &[u8],
        pk: &PublicKey,
        commitment: &G,
    );

    /// Compute a challenge.
    fn compute_challenge<S: Scalar>(&mut self) -> S;
}

impl SchnorrTranscript for Transcript {
    fn update_transcript_with_sig_info<G: Group>(
        &mut self,
        msg: &[u8],
        pk: &PublicKey,
        commitment: &G,
    ) {
        self.append_message(b"message", msg);
        self.append_message(b"public key", &pk.zei_to_bytes());
        self.append_message(b"R", &commitment.to_compressed_bytes());
    }

    /// The challenge is computed from the transcript.
    fn compute_challenge<S: Scalar>(&mut self) -> S {
        let mut c_bytes = [0_u8; 32];
        self.challenge_bytes(b"c", &mut c_bytes);
        let mut prg = ChaChaRng::from_seed(c_bytes);
        Scalar::random(&mut prg)
    }
}

impl ZeiFromToBytes for Signature {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v1 = self.point_r.to_compressed_bytes();
        let mut v2 = self.s.to_bytes();
        v1.append(&mut v2);
        v1
    }

    fn zei_from_bytes(bytes_repr: &[u8]) -> Result<Signature> {
        let point_r =
            JubjubPoint::from_compressed_bytes(&bytes_repr[..JubjubPoint::COMPRESSED_LEN]);
        if point_r.is_err() {
            return Err(eg!(ZeiError::ParameterError));
        }
        let point_r = point_r.unwrap(); // safe unwrap()
        let s = JubjubScalar::from_bytes(&bytes_repr[JubjubPoint::COMPRESSED_LEN..]);
        match s {
            Ok(s) => Ok(Signature { point_r, s }),
            _ => Err(eg!(ZeiError::DeserializationError)),
        }
    }
}

/// Generates a key pair.
fn gen_keys<R: CryptoRng + RngCore, G: Group>(prng: &mut R) -> KeyPair {
    let spend_key = SpendKey(BLSScalar::random(prng));
    KeyPair::from_spend_key(spend_key)
}

#[allow(clippy::many_single_char_names)]
/// Compute a signature given a key pair and a message.
fn sign<R: CryptoRng + RngCore, G: Group>(
    prng: &mut R,
    signing_key: &KeyPair,
    msg: &[u8],
) -> Signature {
    let mut transcript = Transcript::new(b"schnorr_sig");

    let g = G::get_base();
    let r = G::ScalarType::random(prng);

    let point_r = g.mul(&r);
    let pk = &signing_key.pub_key;

    transcript.update_transcript_with_sig_info::<G>(msg, pk, &point_r);

    let c = transcript.compute_challenge::<G::ScalarType>();

    let private_key = &(signing_key.view_key);
    let s: G::ScalarType = r.add(&c.mul(&private_key.0));

    Signature { point_r, s }
}

/// Verifies a signature.
#[allow(non_snake_case)]
fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<()> {
    let mut transcript = Transcript::new(b"schnorr_sig");

    let g = JubjubPoint::get_base();
    transcript.update_transcript_with_sig_info(msg, pk, &sig.point_r);

    let c = transcript.compute_challenge::<JubjubScalar>();

    let left = sig.point_r.add(&pk.0.mul(&c));
    let right = g.mul(&sig.s);

    if left == right {
        Ok(())
    } else {
        Err(eg!(ZeiError::SignatureError))
    }
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::keys::{KeyPair, PublicKey, Signature};
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
            point_r: G::get_identity(),
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
    pub(crate) fn schnorr_from_to_bytes() {
        check_from_to_bytes::<JubjubPoint>();
    }
}
