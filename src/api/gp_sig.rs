use algebra::bls12_381::{Bls12381, BLSG1};
use crate::errors::ZeiError;
use rand_core::{CryptoRng, RngCore};

/// The public key of the group manager
pub type GroupPublicKey = crate::crypto::group_signatures::GroupPublicKey<Bls12381>;

/// The secret key of the group manager
pub type GroupSecretKey = crate::crypto::group_signatures::GroupSecretKey<Bls12381>;

/// A group signature
pub type GroupSignature = crate::crypto::group_signatures::GroupSignature<Bls12381>;

/// Generates the private and public parameters for the Group manager.
/// * `prng` - source of randomness
/// * `returns` - a group public key and a group secret key
pub fn gpsig_setup<R: CryptoRng + RngCore>(prng: &mut R) -> (GroupPublicKey, GroupSecretKey) {
  crate::crypto::group_signatures::gpsig_setup::<R, Bls12381>(prng)
}

/// Group membership certificate
pub type JoinCert = crate::crypto::group_signatures::JoinCert<Bls12381>;
pub type TagKey = crate::crypto::group_signatures::TagKey<BLSG1>;

/// Produces a join certificate for a new user.
/// Run by the Group Manager.
/// * `prng` - source of randomness
/// * `msk` - group secret key
/// * `return` join certificate
pub fn gpsig_join_cert<R: CryptoRng + RngCore>(prng: &mut R,
                                               msk: &GroupSecretKey)
                                               -> (JoinCert, TagKey) {
  crate::crypto::group_signatures::gpsig_join_cert(prng, msk)
}

/// Signature funtion run by a user to produce a group signature
/// * `prng` - source of randomness
/// * `gpk` - group public key
/// * `join_cert` - join certificate
/// * `msg` - message to be signed
/// # Example
/// ```
/// use zei::api::gp_sig::{gpsig_setup, gpsig_join_cert, gpsig_sign, gpsig_verify};
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let (gpk, msk) = gpsig_setup(&mut prng);
/// let (join_cert, _) = gpsig_join_cert(&mut prng, &msk);
/// let sig = gpsig_sign(&mut prng, &gpk, &join_cert, b"Some message");
/// assert!(gpsig_verify(&gpk, &sig, b"Some message").is_ok());
/// ```
pub fn gpsig_sign<R: CryptoRng + RngCore, B: AsRef<[u8]>>(prng: &mut R,
                                                          gpk: &GroupPublicKey,
                                                          join_cert: &JoinCert,
                                                          msg: &B)
                                                          -> GroupSignature {
  crate::crypto::group_signatures::gpsig_sign(prng, gpk, join_cert, msg.as_ref())
}

/// Group signature verification function
/// * `gpk` - group public key
/// * `sig` - group signature
/// * `msg` - message
/// # Example
/// ```
/// // See zei::api::gp_sig::gpsig_sign
/// ```
pub fn gpsig_verify<B: AsRef<[u8]>>(gpk: &GroupPublicKey,
                                    sig: &GroupSignature,
                                    msg: &B)
                                    -> Result<(), ZeiError> {
  crate::crypto::group_signatures::gpsig_verify(gpk, sig, msg.as_ref())
}

/// Signature opening function
/// This algorithm is run by the Group Manager to recover the identity tag corresponding to the signer
/// Note that the algorithm returns a group element h = g^{tag}.
/// * `sig` - signature
/// * `gp_sk` - group secret key
/// # Example
/// ```
/// use zei::api::gp_sig::{gpsig_setup, gpsig_join_cert, gpsig_sign, gpsig_open};
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// let mut prng = ChaChaRng::from_seed([0u8; 32]);
/// let (gpk, msk) = gpsig_setup(&mut prng);
/// let (join_cert, tag_key) = gpsig_join_cert(&mut prng, &msk);
/// let sig = gpsig_sign(&mut prng, &gpk, &join_cert, b"Some message");
/// let tag_group_element_recovered = gpsig_open(&sig, &msk);
/// assert_eq!(tag_key, tag_group_element_recovered, "Recovered tag key does not match")
/// ```
pub fn gpsig_open(sig: &GroupSignature, msk: &GroupSecretKey) -> TagKey {
  crate::crypto::group_signatures::gpsig_open(sig, msk)
}
