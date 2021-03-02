use algebra::jubjub::{JubjubPoint, JubjubScalar};
use crypto::basics::signatures::schnorr;
use rand_core::{CryptoRng, RngCore};
use ruc::{err::*, *};

/// Public key used to address an Anonymous records and verify transaction spending it
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AXfrPubKey(pub(crate) schnorr::PublicKey<JubjubPoint>);

/// Keypair associated with an Anonymous records. It is used to spending it.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AXfrKeyPair(pub(crate) schnorr::KeyPair<JubjubPoint, JubjubScalar>);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AXfrSignature(pub(crate) schnorr::Signature<JubjubPoint, JubjubScalar>);

impl AXfrKeyPair {
    /// Generate a new signature key pair
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> AXfrKeyPair {
        AXfrKeyPair(schnorr::KeyPair::generate(prng))
    }

    /// Multiply the secret key scalar by `factor` producing a new "randomized" KeyPair
    pub fn randomize(&self, factor: &JubjubScalar) -> AXfrKeyPair {
        AXfrKeyPair(self.0.randomize(factor))
    }

    /// Return public key
    pub(crate) fn pub_key(&self) -> AXfrPubKey {
        AXfrPubKey(self.0.pub_key.clone())
    }

    /// Return secret key scalar value
    pub(crate) fn get_secret_scalar(&self) -> JubjubScalar {
        self.0.get_secret_scalar()
    }

    pub fn sign(&self, msg: &[u8]) -> AXfrSignature {
        AXfrSignature(self.0.sign(msg))
    }
}

impl AXfrPubKey {
    /// Implicitly multiply the associated secret key scalar by `factor` producing a new "randomized" key
    pub fn randomize(&self, factor: &JubjubScalar) -> AXfrPubKey {
        AXfrPubKey(self.0.randomize(factor))
    }
    /// return a reference to the EC group point defining the public key
    pub fn as_jubjub_point(&self) -> &JubjubPoint {
        self.0.point_ref()
    }

    pub(crate) fn from_jubjub_point(point: JubjubPoint) -> AXfrPubKey {
        AXfrPubKey(schnorr::PublicKey::from_point(point))
    }

    /// Signature verification function
    pub fn verify(&self, msg: &[u8], sig: AXfrSignature) -> Result<()> {
        self.0.verify(msg, &sig.0).c(d!())
    }
}
