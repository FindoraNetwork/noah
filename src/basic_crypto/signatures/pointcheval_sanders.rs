/* This file implements Pointcheval-Sanders randomizable signatures for a single message.
The scheme is described in Short Randomizable Signatures. David Pointcheval and Olivier Sanders. CT RSA 2015.
https://eprint.iacr.org/2015/525.pdf.

The secret key is a pair of scalar x and y. The public is a pair X,Y where X = x * G2, and Y =y * G2
for G2 being a base of one of the source groups of a bilinear map (pairing).

Signature and Verification: For a scalar m, a signature for it is the pair (s1,s2) = (H, (x+y*m) *H) for a random element H in G1.
The signature is verified by comparing e(s1, X + m*Y) =? e(s2, G2).

The signature reveals no information on the signer's public key and it is randomizable by scaling
both elements of the signature by a random factor.

The scheme can be extended to sign tuples of messages. In this case, the y/Y component of the public/secret
key is a tuple of elements rather than a single element in G2. A tuple of message can be signed as
(H, (x + \sum_i y_i * m_i) * H), and it is verified as e(s1, X + \sum m_i * Y_i) =? e(s2, G2).
(Not explicitly implemented yet, but the anon_creds file implicitly implements it).

Given the above properties, Pointcheval-Sanders signatures are suitable for anonymous credentials and group signatures.
*/

use crate::algebra::groups::{Group, GroupArithmetic, Scalar};
use crate::algebra::pairing::Pairing;
use crate::errors::ZeiError;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PSPublicKey<G2> {
  pub(crate) xx: G2,
  pub(crate) yy: G2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PSSecretKey<S> {
  pub(crate) x: S,
  pub(crate) y: S,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PSSignature<G1> {
  pub(crate) s1: G1,
  pub(crate) s2: G1,
}

/// Pointcheval-Sanders key generation algorithm
/// #Example
/// ```
///
/// use rand::rngs::{EntropyRng};
/// use zei::basic_crypto::signatures::pointcheval_sanders::ps_gen_keys;
/// use zei::algebra::bls12_381::Bls12381;
/// let mut prng = EntropyRng::new();
/// let keys = ps_gen_keys::<_,Bls12381>(&mut prng);
/// ```
pub fn ps_gen_keys<R: CryptoRng + RngCore, P: Pairing>(
  prng: &mut R)
  -> (PSPublicKey<P::G2>, PSSecretKey<P::ScalarField>) {
  let g2 = P::G2::get_base(); // TODO can I use the base or does it need to be a random element
  let x = P::ScalarField::random_scalar(prng);
  let y = P::ScalarField::random_scalar(prng);
  let xx = g2.mul(&x);
  let yy = g2.mul(&y);

  (PSPublicKey { xx, yy }, PSSecretKey { x, y })
}

/// Pointcheval-Sanders signing function for byte slices
/// #Example
/// ```
///
/// use rand::rngs::{EntropyRng};
/// use zei::basic_crypto::signatures::pointcheval_sanders::{ps_gen_keys, ps_sign_bytes};
/// use zei::algebra::bls12_381::Bls12381;
/// let mut prng = EntropyRng::new();
/// let (_, sk) = ps_gen_keys::<_,Bls12381>(&mut prng);
/// let sig = ps_sign_bytes::<_, Bls12381>(&mut prng, &sk, b"this is a message");
/// ```
pub fn ps_sign_bytes<R: CryptoRng + RngCore, P: Pairing>(prng: &mut R,
                                                         sk: &PSSecretKey<P::ScalarField>,
                                                         m: &[u8])
                                                         -> PSSignature<P::G1> {
  let m_scalar = hash_message::<P::ScalarField>(m);
  ps_sign_scalar::<_, P>(prng, sk, &m_scalar)
}

/// Pointcheval-Sanders signing function for scalars
/// #Example
/// ```
///
/// use rand::rngs::{EntropyRng};
/// use zei::algebra::bls12_381::{BLSScalar, Bls12381};
/// use zei::algebra::groups::Scalar;
/// use zei::basic_crypto::signatures::pointcheval_sanders::{ps_gen_keys, ps_sign_scalar};
/// let mut prng = EntropyRng::new();
/// let (_, sk) = ps_gen_keys::<_, Bls12381>(&mut prng);
/// let sig = ps_sign_scalar::<_, Bls12381>(&mut prng, &sk, &BLSScalar::from_u32(100u32));
/// ```
pub fn ps_sign_scalar<R: CryptoRng + RngCore, P: Pairing>(prng: &mut R,
                                                          sk: &PSSecretKey<P::ScalarField>,
                                                          m: &P::ScalarField)
                                                          -> PSSignature<P::G1> {
  let a = P::ScalarField::random_scalar(prng);
  let s1 = P::G1::get_base().mul(&a);

  let s2 = s1.mul(&sk.x.add(&sk.y.mul(&m)));
  PSSignature { s1, s2 }
}

/// Pointcheval-Sanders verification function for byte slices
/// #Example
/// ```
///
/// use rand::rngs::EntropyRng;
/// use zei::basic_crypto::signatures::pointcheval_sanders::{ps_gen_keys, ps_sign_bytes, ps_verify_sig_bytes};
/// use zei::errors::ZeiError;
/// use zei::algebra::bls12_381::Bls12381;
/// let mut prng = EntropyRng::new();
/// let (pk, sk) = ps_gen_keys::<_, Bls12381>(&mut prng);
/// let sig = ps_sign_bytes::<_, Bls12381>(&mut prng, &sk, b"this is a message");
/// assert!(ps_verify_sig_bytes::<Bls12381>(&pk, b"this is a message", &sig).is_ok());
/// assert_eq!(Some(ZeiError::SignatureError), ps_verify_sig_bytes::<Bls12381>(&pk, b"this is ANOTHER message", &sig).err());
/// ```
pub fn ps_verify_sig_bytes<P: Pairing>(pk: &PSPublicKey<P::G2>,
                                       m: &[u8],
                                       sig: &PSSignature<P::G1>)
                                       -> Result<(), ZeiError> {
  let m_scalar = hash_message::<P::ScalarField>(m);
  ps_verify_sig_scalar::<P>(pk, &m_scalar, sig)
}

/// Pointcheval-Sanders verification function for scalars
/// #Example
/// ```
///
/// use rand::rngs::EntropyRng;
/// use zei::basic_crypto::signatures::pointcheval_sanders::{ps_gen_keys, ps_sign_scalar, ps_verify_sig_scalar};
/// use zei::errors::ZeiError;
/// use zei::algebra::bls12_381::{BLSScalar, Bls12381};
/// use zei::algebra::groups::Scalar;
/// let mut prng = EntropyRng::new();
/// let (pk, sk) = ps_gen_keys::<_, Bls12381>(&mut prng);
/// let sig = ps_sign_scalar::<_, Bls12381>(&mut prng, &sk, &BLSScalar::from_u32(100));
/// assert!(ps_verify_sig_scalar::<Bls12381>(&pk, &BLSScalar::from_u32(100), &sig).is_ok());
/// assert_eq!(Some(ZeiError::SignatureError), ps_verify_sig_scalar::<Bls12381>(&pk, &BLSScalar::from_u32(333), &sig).err());
/// ```
pub fn ps_verify_sig_scalar<P: Pairing>(pk: &PSPublicKey<P::G2>,
                                        m: &P::ScalarField,
                                        sig: &PSSignature<P::G1>)
                                        -> Result<(), ZeiError> {
  let a = pk.xx.add(&pk.yy.mul(&m));
  let e1 = P::pairing(&sig.s1, &a);
  let e2 = P::pairing(&sig.s2, &P::G2::get_base());
  if e1 != e2 || sig.s1 == P::G1::get_identity() {
    return Err(ZeiError::SignatureError);
  }
  Ok(())
}

/// Pointcheval-Sanders signature randomization function
/// #Example
/// ```
/// use rand::rngs::EntropyRng;
/// use zei::basic_crypto::signatures::pointcheval_sanders::{ps_gen_keys, ps_sign_scalar, ps_verify_sig_scalar, ps_randomize_sig};
/// use zei::errors::ZeiError;
/// use zei::algebra::bls12_381::{BLSScalar, Bls12381};
/// use zei::algebra::groups::Scalar;
/// let mut prng = EntropyRng::new();
/// let (pk, sk) = ps_gen_keys::<_, Bls12381>(&mut prng);
/// let sig = ps_sign_scalar::<_, Bls12381>(&mut prng, &sk, &BLSScalar::from_u32(100));
/// let (_,rand_sig) = ps_randomize_sig::<_, Bls12381>(&mut prng, &sig);
/// assert!(ps_verify_sig_scalar::<Bls12381>(&pk, &BLSScalar::from_u32(100), &rand_sig).is_ok());
///
/// ```
pub fn ps_randomize_sig<R: RngCore + CryptoRng, P: Pairing>(
  prng: &mut R,
  sig: &PSSignature<P::G1>)
  -> (P::ScalarField, PSSignature<P::G1>) {
  let rand_factor = P::ScalarField::random_scalar(prng);
  let s1 = sig.s1.mul(&rand_factor);
  let s2 = sig.s2.mul(&rand_factor);
  (rand_factor, PSSignature { s1, s2 })
}

fn hash_message<S: Scalar>(message: &[u8]) -> S {
  let mut hasher = Sha512::new();
  hasher.input(message);
  S::from_hash(hasher)
}
