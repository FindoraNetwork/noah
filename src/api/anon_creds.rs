use crate::algebra::bls12_381::{BLSGt, BLSScalar, BLSG1, BLSG2};
use crate::errors::ZeiError;
use crate::utils::byte_slice_to_scalar;
use rand_core::{CryptoRng, RngCore};

pub type ACIssuerPublicKey = crate::crypto::anon_creds::ACIssuerPublicKey<BLSG1, BLSG2>;
pub type ACIssuerSecretKey = crate::crypto::anon_creds::ACIssuerSecretKey<BLSG1, BLSScalar>;

pub type ACSignature = crate::crypto::anon_creds::ACSignature<BLSG1>;

pub type ACUserPublicKey = crate::crypto::anon_creds::ACUserPublicKey<BLSG1>;

pub type ACUserSecretKey = crate::crypto::anon_creds::ACUserSecretKey<BLSScalar>;

pub type ACRevealSig = crate::crypto::anon_creds::ACRevealSig<BLSG1, BLSG2, BLSScalar>;

pub type ACPoK = crate::crypto::anon_creds::ACPoK<BLSG2, BLSScalar>;

/// Generates e key pair for a credential issuer
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::ac_keygen_issuer;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 10;
/// let keys = ac_keygen_issuer(&mut prng, num_attrs);
/// ```
pub fn ac_keygen_issuer<R: CryptoRng + RngCore>(prng: &mut R,
                                                num_attrs: usize)
                                                -> (ACIssuerPublicKey, ACIssuerSecretKey) {
  crate::crypto::anon_creds::ac_keygen_issuer::<_, BLSGt>(prng, num_attrs)
}

/// Generates a credential user key pair for a given credential issuer
///
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 10;
/// let (issuer_pk,_) = ac_keygen_issuer(&mut prng, num_attrs);
/// let user_keys = ac_keygen_user(&mut prng, &issuer_pk);
/// ```
pub fn ac_keygen_user<R: CryptoRng + RngCore>(prng: &mut R,
                                              issuer_pk: &ACIssuerPublicKey)
                                              -> (ACUserPublicKey, ACUserSecretKey) {
  crate::crypto::anon_creds::ac_keygen_user::<_, BLSGt>(prng, issuer_pk)
}

/// Computes a credential signature for a set of attributes.
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user, ac_sign};
/// use zei::algebra::bls12_381::BLSScalar;
/// use zei::algebra::groups::Scalar;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer(&mut prng, num_attrs);
/// let (user_pk, _) = ac_keygen_user(&mut prng, &issuer_pk);
/// let attributes = [b"attr1", b"attr2"];
/// let signature = ac_sign(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// ```
pub fn ac_sign<R: CryptoRng + RngCore, B: AsRef<[u8]>>(prng: &mut R,
                                                       issuer_sk: &ACIssuerSecretKey,
                                                       user_pk: &ACUserPublicKey,
                                                       attrs: &[B])
                                                       -> ACSignature {
  let attrs_scalar: Vec<BLSScalar> = attrs.iter()
                                          .map(|x| byte_slice_to_scalar::<BLSScalar>(x.as_ref()))
                                          .collect();
  crate::crypto::anon_creds::ac_sign::<_, BLSGt>(prng, issuer_sk, user_pk, attrs_scalar.as_slice())
}

/// Produces randomization suitable for use with ac_reveal_with_rand
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use crate::zei::algebra::groups::Scalar;
/// use zei::algebra::bls12_381::BLSScalar;
/// use zei::api::anon_creds::{ac_sample_random_factors, ac_reveal_with_rand};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let pair = ac_sample_random_factors(&mut prng);
/// ```
pub fn ac_sample_random_factors<R: CryptoRng + RngCore>(prng: &mut R) -> (BLSScalar, BLSScalar) {
  crate::crypto::anon_creds::ac_sample_random_factors::<_, BLSGt>(prng)
}

/// Produces a AttrsRevealProof, bitmap indicates which attributes are revealed
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user, ac_sign, ac_reveal};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user(&mut prng, &issuer_pk);
/// let attributes = [b"attr1", b"attr2"];
/// let signature = ac_sign(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// let bitmap = [true,false]; // Reveal first attribute and hide the second one
/// let reveal_sig = ac_reveal(&mut prng, &user_sk, &issuer_pk, &signature, &attributes[..], &bitmap);
/// ```
pub fn ac_reveal<R: CryptoRng + RngCore, B: AsRef<[u8]>>(prng: &mut R,
                                                         user_sk: &ACUserSecretKey,
                                                         issuer_pk: &ACIssuerPublicKey,
                                                         sig: &ACSignature,
                                                         attrs: &[B],
                                                         bitmap: &[bool] // indicates which attributes are revealed
) -> Result<ACRevealSig, ZeiError> {
  let attrs_scalar: Vec<BLSScalar> = attrs.iter()
                                          .map(|x| byte_slice_to_scalar::<BLSScalar>(x.as_ref()))
                                          .collect();
  crate::crypto::anon_creds::ac_reveal::<_, BLSGt>(prng,
                                                   user_sk,
                                                   issuer_pk,
                                                   sig,
                                                   attrs_scalar.as_slice(),
                                                   bitmap)
}

/// Produces a AttrsRevealProof, as with ac_reveal, but the randomization is supplied by the caller
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use crate::zei::algebra::groups::Scalar;
/// use zei::algebra::bls12_381::BLSScalar;
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user, ac_sign, ac_sample_random_factors, ac_reveal_with_rand};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user(&mut prng, &issuer_pk);
/// let attributes = [b"attr1", b"attr2"];
/// let signature = ac_sign(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// let bitmap = [true,false]; // Reveal first attribute and hide the second one
/// let pair = ac_sample_random_factors(&mut prng);
/// let reveal_sig = ac_reveal_with_rand(&mut prng, &user_sk, &issuer_pk, &signature, &attributes[..], &bitmap, pair);
/// ```
pub fn ac_reveal_with_rand<R: CryptoRng + RngCore, B: AsRef<[u8]>>(
  prng: &mut R,
  user_sk: &ACUserSecretKey,
  issuer_pk: &ACIssuerPublicKey,
  sig: &ACSignature,
  attrs: &[B],
  bitmap: &[bool],
  random_factors: (BLSScalar, BLSScalar))
  -> Result<ACRevealSig, ZeiError> {
  let attrs_scalar: Vec<BLSScalar> = attrs.iter()
                                          .map(|x| byte_slice_to_scalar::<BLSScalar>(x.as_ref()))
                                          .collect();
  crate::crypto::anon_creds::ac_reveal_with_rand::<_, BLSGt>(prng,
                                                             user_sk,
                                                             issuer_pk,
                                                             sig,
                                                             attrs_scalar.as_slice(),
                                                             bitmap,
                                                             random_factors)
}

/// Verifies an anonymous credential reveal proof.
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::algebra::groups::Scalar;
/// use zei::algebra::bls12_381::{BLSScalar};
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user, ac_sign, ac_reveal, ac_verify};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user(&mut prng, &issuer_pk);
/// let attributes = [b"attr1", b"attr2"];
/// let signature = ac_sign(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// let bitmap = [true,false]; // Reveal first attribute and hide the second one
/// let reveal_sig = ac_reveal(&mut prng, &user_sk, &issuer_pk, &signature, &attributes[..], &bitmap).unwrap();
/// let result_verification_ok = ac_verify(&issuer_pk, &attributes[..1],& bitmap, &reveal_sig.sig, &reveal_sig.pok);
/// assert!(result_verification_ok.is_ok());
/// let result_verification_err = ac_verify(&issuer_pk, &attributes[1..],& bitmap, &reveal_sig.sig, &reveal_sig.pok);
/// assert!(result_verification_err.is_err());
/// ```
pub fn ac_verify<B: AsRef<[u8]>>(issuer_pub_key: &ACIssuerPublicKey,
                                 revealed_attrs: &[B],
                                 bitmap: &[bool],
                                 ac_sig: &ACSignature,
                                 reveal_sig_pok: &ACPoK)
                                 -> Result<(), ZeiError> {
  let revealed_attrs_scalar: Vec<BLSScalar> =
    revealed_attrs.iter()
                  .map(|x| byte_slice_to_scalar::<BLSScalar>(x.as_ref()))
                  .collect();
  crate::crypto::anon_creds::ac_verify::<BLSGt>(issuer_pub_key,
                                                revealed_attrs_scalar.as_slice(),
                                                bitmap,
                                                &ac_sig,
                                                &reveal_sig_pok)
}
