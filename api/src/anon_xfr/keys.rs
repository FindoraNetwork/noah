use digest::Digest;
use merlin::Transcript;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use wasm_bindgen::prelude::*;
use zei_algebra::{
    bls12_381::BLSScalar,
    jubjub::{JubjubPoint, JubjubScalar, JUBJUB_SCALAR_LEN},
    prelude::*,
};
use zei_crypto::basic::rescue::RescueInstance;

/// The length of the secret key for anonymous transfer.
pub const AXFR_SECRET_KEY_LENGTH: usize = JUBJUB_SCALAR_LEN;
/// The length of the public key for anonymous transfer.
pub const AXFR_PUBLIC_KEY_LENGTH: usize = JubjubPoint::COMPRESSED_LEN;
/// The length of the view key for anonymous transfer.
pub const AXFR_VIEW_KEY_LENGTH: usize = JUBJUB_SCALAR_LEN;

/// Obtain the viewing key domain separator.
// The value is 30456836461354188666588397637966466954730199316260348475646977510813971733359
pub fn get_view_key_domain_separator() -> BLSScalar {
    let mut hasher = Sha512::new();
    hasher.update(b"Viewing key domain separator");
    let hash = BLSScalar::from_hash(hasher);
    hash
}

/// The spending key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
pub struct AXfrSpendKey(pub(crate) BLSScalar);

/// The viewing key.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
pub struct AXfrViewKey(pub(crate) JubjubScalar);

/// The public key.
#[wasm_bindgen]
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, Hash,
)]
pub struct AXfrPubKey(pub(crate) JubjubPoint);

impl ZeiFromToBytes for AXfrPubKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.to_compressed_bytes()
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<AXfrPubKey> {
        if bytes.len() != AXFR_PUBLIC_KEY_LENGTH {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let group_element = JubjubPoint::from_compressed_bytes(bytes);
            match group_element {
                Ok(g) => Ok(AXfrPubKey(g)),
                _ => Err(eg!(ZeiError::ParameterError)),
            }
        }
    }
}

impl ZeiFromToBytes for AXfrViewKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<AXfrViewKey> {
        if bytes.len() != AXFR_VIEW_KEY_LENGTH {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let element = JubjubScalar::from_bytes(bytes);
            match element {
                Ok(g) => Ok(AXfrViewKey(g)),
                _ => Err(eg!(ZeiError::ParameterError)),
            }
        }
    }
}

/// Keypair associated with an Anonymous records. It is used to spending it.
#[wasm_bindgen]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
/// The key pair for anonymous payment.
pub struct AXfrKeyPair {
    /// The random seed that generates the secret key.
    pub(crate) spend_key: AXfrSpendKey,
    /// The secret key of Schnorr signature.
    pub(crate) view_key: AXfrViewKey,
    /// The public key of Schnorr signature.
    pub(crate) pub_key: AXfrPubKey,
}

impl AXfrKeyPair {
    /// Generate a Schnorr keypair from `prng`.
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let spend_key = AXfrSpendKey(BLSScalar::random(prng));
        Self::from_spend_key(spend_key)
    }

    /// Return the public key
    pub fn get_pub_key(&self) -> AXfrPubKey {
        self.pub_key.clone()
    }

    /// Return the view key
    pub fn get_view_key(&self) -> AXfrViewKey {
        self.view_key.clone()
    }

    /// Return the spend key
    pub fn get_spend_key(&self) -> AXfrSpendKey {
        self.spend_key.clone()
    }

    /// Return the key pair from the spending key.
    pub fn from_spend_key(spend_key: AXfrSpendKey) -> Self {
        let hash_instance = RescueInstance::<BLSScalar>::new();
        let viewing_key_in_bls12_381 = hash_instance.rescue(&[
            get_view_key_domain_separator(),
            spend_key.0,
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0];

        // Viewing key in Jubjub = Viewing key in BLS12-381 mod Jubjub's r.
        // `from_bytes` will allow so because the number of `bytes` are the same, although it may (very likely) go beyond.
        let view_key =
            AXfrViewKey(JubjubScalar::from_bytes(&viewing_key_in_bls12_381.to_bytes()).unwrap());

        let base = JubjubPoint::get_base();
        let pub_key = AXfrPubKey(base.mul(&view_key.0));

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
}

impl ZeiFromToBytes for AXfrKeyPair {
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

        let spend_key =
            AXfrSpendKey(BLSScalar::from_bytes(&bytes[0..BLSScalar::bytes_len()]).c(d!())?);

        let mut offset = BLSScalar::bytes_len();
        let view_key = AXfrViewKey(
            JubjubScalar::from_bytes(&bytes[offset..offset + JubjubScalar::bytes_len()]).c(d!())?,
        );

        offset += JubjubScalar::bytes_len();
        let pub_key = AXfrPubKey::zei_from_bytes(&bytes[offset..]).c(d!())?;

        Ok(AXfrKeyPair {
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
        pk: &AXfrPubKey,
        commitment: &G,
    );

    /// Compute a challenge.
    fn compute_challenge<S: Scalar>(&mut self) -> S;
}

impl SchnorrTranscript for Transcript {
    fn update_transcript_with_sig_info<G: Group>(
        &mut self,
        msg: &[u8],
        pk: &AXfrPubKey,
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

#[cfg(test)]
mod tests {
    use crate::anon_xfr::keys::{AXfrKeyPair, AXfrPubKey};
    use zei_algebra::jubjub::JubjubPoint;
    use zei_algebra::prelude::*;

    fn check_from_to_bytes<G: Group>() {
        let seed = [0_u8; 32];
        let mut prng = rand_chacha::ChaChaRng::from_seed(seed);
        let key_pair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);

        let public_key = key_pair.get_pub_key();

        // Public key
        let public_key_bytes = public_key.zei_to_bytes();
        let public_key_from_bytes = AXfrPubKey::zei_from_bytes(&public_key_bytes).unwrap();
        assert_eq!(public_key, public_key_from_bytes);
    }

    #[test]
    pub(crate) fn schnorr_from_to_bytes() {
        check_from_to_bytes::<JubjubPoint>();
    }
}
