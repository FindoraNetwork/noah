use algebra::jubjub::{JubjubPoint, JubjubScalar};
use crypto::basics::signatures::schnorr;
use rand_core::{CryptoRng, RngCore};

/// Public key used to address an Anonymous records and verify transaction spending it
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AXfrPubKey(pub(crate) schnorr::PublicKey<JubjubPoint>);

/// Secret key associated with an Anonymous records. It is used to spending it
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AXfrSecKey(pub(crate) schnorr::SecretKey<JubjubScalar>);

/// Keypair associated with an Anonymous records. It is used to spending it.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AXfrKeyPair {
  pub(crate) sec_key: AXfrSecKey,
  pub pub_key: AXfrPubKey,
}

impl AXfrKeyPair {
  /// Generate a new signature key pair
  pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> AXfrKeyPair {
    let (sec_key, pub_key) = schnorr::gen_keys(prng).into_pair();
    AXfrKeyPair { sec_key: AXfrSecKey(sec_key),
                  pub_key: AXfrPubKey(pub_key) }
  }

  /// Multiply the secret key scalar by `factor` producing a new "randomized" KeyPair
  pub fn randomize(&self, factor: &JubjubScalar) -> AXfrKeyPair {
    AXfrKeyPair { sec_key: self.sec_key.randomize(factor),
                  pub_key: self.pub_key.randomize(factor) }
  }

  pub(crate) fn get_secret_scalar(&self) -> JubjubScalar {
    self.sec_key.as_scalar()
  }
}

impl AXfrSecKey {
  /// Multiply the secret key scalar by `factor` producing a new "randomized" secret key
  pub(crate) fn randomize(&self, factor: &JubjubScalar) -> AXfrSecKey {
    AXfrSecKey(self.0.randomize(factor))
  }
  pub(crate) fn as_scalar(&self) -> JubjubScalar {
    self.0.scalar()
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
}
