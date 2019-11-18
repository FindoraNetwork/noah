use crate::algebra::bls12_381::{BLSGt, BLSScalar, BLSG1, BLSG2};
use crate::algebra::groups::Scalar;
use crate::errors::ZeiError;
use digest::Digest;
use rand::{CryptoRng, Rng};
use sha2::Sha512;

pub type ACIssuerPublicKey = crate::crypto::anon_creds::ACIssuerPublicKey<BLSG1, BLSG2>;
pub type ACIssuerSecretKey = crate::crypto::anon_creds::ACIssuerSecretKey<BLSG1, BLSScalar>;

pub type ACSignature = crate::crypto::anon_creds::ACSignature<BLSG1>;

pub type ACUserPublicKey = crate::crypto::anon_creds::ACUserPublicKey<BLSG1>;

pub type ACUserSecretKey = crate::crypto::anon_creds::ACUserSecretKey<BLSScalar>;

pub type ACRevealSig = crate::crypto::anon_creds::ACRevealSig<BLSG1, BLSG2, BLSScalar>;

/// Generates e key pair for a credential issuer
/// # Example
/// ```
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::ac_keygen_issuer;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 10;
/// let keys = ac_keygen_issuer(&mut prng, num_attrs);
/// ```
pub fn ac_keygen_issuer<R: CryptoRng + Rng>(prng: &mut R,
                                            num_attrs: usize)
                                            -> (ACIssuerPublicKey, ACIssuerSecretKey) {
  crate::crypto::anon_creds::ac_keygen_issuer::<_, BLSGt>(prng, num_attrs)
}

/// Generates a credential user key pair for a given credential issuer
///
/// ```
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 10;
/// let (issuer_pk,_) = ac_keygen_issuer(&mut prng, num_attrs);
/// let user_keys = ac_keygen_user(&mut prng, &issuer_pk);
/// ```
pub fn ac_keygen_user<R: CryptoRng + Rng>(prng: &mut R,
                                          issuer_pk: &ACIssuerPublicKey)
                                          -> (ACUserPublicKey, ACUserSecretKey) {
  crate::crypto::anon_creds::ac_keygen_user::<_, BLSGt>(prng, issuer_pk)
}

/// Computes a credential signature for a set of attributes.
/// ```
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user, ac_sign};
/// use zei::algebra::bls12_381::BLSScalar;
/// use zei::algebra::groups::Scalar;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer(&mut prng, num_attrs);
/// let (user_pk, _) = ac_keygen_user(&mut prng, &issuer_pk);
/// let attr1 = b"attr1";
/// let attr2 = b"attr2";
/// let attributes = [attr1.as_ref(), attr2.as_ref()];
/// let signature = ac_sign(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// ```
pub fn ac_sign<R: CryptoRng + Rng>(prng: &mut R,
                                   issuer_sk: &ACIssuerSecretKey,
                                   user_pk: &ACUserPublicKey,
                                   attrs: &[&[u8]])
                                   -> ACSignature {
  let attrs_scalar: Vec<BLSScalar> = attrs.iter().map(|x| byte_slice_to_scalar(*x)).collect();
  crate::crypto::anon_creds::ac_sign::<_, BLSGt>(prng, issuer_sk, user_pk, attrs_scalar.as_slice())
}

/// Produces a AttrsRevealProof, bitmap indicates which attributes are revealed
/// # Example
/// ```
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user, ac_sign, ac_reveal};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user(&mut prng, &issuer_pk);
/// let attr1 = b"attr1";
/// let attr2 = b"attr2";
/// let attributes = [attr1.as_ref(), attr2.as_ref()];
/// let signature = ac_sign(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// let bitmap = [true,false]; // Reveal first attribute and hide the second one
/// let reveal_sig = ac_reveal(&mut prng, &user_sk, &issuer_pk, &signature, &attributes[..], &bitmap);
/// ```
pub fn ac_reveal<R: CryptoRng + Rng>(prng: &mut R,
                                     user_sk: &ACUserSecretKey,
                                     issuer_pk: &ACIssuerPublicKey,
                                     sig: &ACSignature,
                                     attrs: &[&[u8]],
                                     bitmap: &[bool] // indicates which attributes are revealed
) -> Result<ACRevealSig, ZeiError> {
  let attrs_scalar: Vec<BLSScalar> = attrs.iter().map(|x| byte_slice_to_scalar(*x)).collect();
  crate::crypto::anon_creds::ac_reveal::<_, BLSGt>(prng,
                                                   user_sk,
                                                   issuer_pk,
                                                   sig,
                                                   attrs_scalar.as_slice(),
                                                   bitmap)
}

/// Verifies an anonymous credential reveal proof.
/// # Example
/// ```
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::algebra::groups::Scalar;
/// use zei::algebra::bls12_381::{BLSScalar};
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user, ac_sign, ac_reveal, ac_verify};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user(&mut prng, &issuer_pk);
/// let attr1 = b"attr1";
/// let attr2 = b"attr2";
/// let attributes = [attr1.as_ref(), attr2.as_ref()];
/// let signature = ac_sign(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// let bitmap = [true,false]; // Reveal first attribute and hide the second one
/// let reveal_sig = ac_reveal(&mut prng, &user_sk, &issuer_pk, &signature, &attributes[..], &bitmap).unwrap();
/// let result_verification_ok = ac_verify(&issuer_pk, &attributes[..1],& bitmap, &reveal_sig);
/// assert!(result_verification_ok.is_ok());
/// let result_verification_err = ac_verify(&issuer_pk, &attributes[1..],& bitmap, &reveal_sig);
/// assert!(result_verification_err.is_err());
/// ```
pub fn ac_verify(issuer_pub_key: &ACIssuerPublicKey,
                 revealed_attrs: &[&[u8]],
                 bitmap: &[bool],
                 reveal_sig: &ACRevealSig)
                 -> Result<(), ZeiError> {
  let revealed_attrs_scalar: Vec<BLSScalar> = revealed_attrs.iter()
                                                            .map(|x| byte_slice_to_scalar(*x))
                                                            .collect();
  crate::crypto::anon_creds::ac_verify::<BLSGt>(issuer_pub_key,
                                                revealed_attrs_scalar.as_slice(),
                                                bitmap,
                                                reveal_sig)
}

fn byte_slice_to_scalar(slice: &[u8]) -> BLSScalar {
  let mut hasher = Sha512::new();
  hasher.input(slice);
  BLSScalar::from_hash(hasher)
}
