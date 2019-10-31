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

use crate::algebra::bls12_381::{BLSG2, BLSScalar, BLSG1, BLSGt};
use rand::{CryptoRng, Rng};
use crate::algebra::groups::{Scalar, Group};
use crate::algebra::pairing::PairingTargetGroup;
use crate::errors::ZeiError;
use digest::Digest;
use sha2::Sha512;

pub struct PSPublicKey{
    pub(crate) xx: BLSG2,
    pub(crate) yy: BLSG2
}

pub struct PSSecretKey{
    pub(crate) x: BLSScalar,
    pub(crate) y: BLSScalar,
}

pub struct PSSignature{
    pub(crate) s1: BLSG1,
    pub(crate) s2: BLSG1,
}

/// Pointcheval-Sanders key generation algorithm
/// #Example
/// ```
///
/// use rand::rngs::{EntropyRng};
/// use zei::basic_crypto::signatures::pointcheval_sanders::ps_gen_keys;
/// let mut prng = EntropyRng::new();
/// let keys = ps_gen_keys(&mut prng);
/// ```
pub fn ps_gen_keys<R: CryptoRng + Rng>(prng: &mut R) -> (PSPublicKey, PSSecretKey) {
    let g2 = BLSG2::get_base(); // TODO can I use the base or does it need to be a random element
    let x = BLSScalar::random_scalar(prng);
    let y = BLSScalar::random_scalar(prng);
    let xx = g2.mul(&x);
    let yy = g2.mul(&y);

    (
        PSPublicKey { xx,yy },
        PSSecretKey { x, y}
    )
}

/// Pointcheval-Sanders signing function for byte slices
/// #Example
/// ```
///
/// use rand::rngs::{EntropyRng};
/// use zei::basic_crypto::signatures::pointcheval_sanders::{ps_gen_keys, ps_sign_bytes};
/// let mut prng = EntropyRng::new();
/// let (_, sk) = ps_gen_keys(&mut prng);
/// let sig = ps_sign_bytes(&mut prng, &sk, b"this is a message");
/// ```
pub fn ps_sign_bytes<R: CryptoRng + Rng>(prng: &mut R, sk: &PSSecretKey, m: &[u8]) -> PSSignature
{
    let m_scalar = hash_message(m);
    ps_sign_scalar(prng, sk, &m_scalar)
}

/// Pointcheval-Sanders signing function for scalars
/// #Example
/// ```
///
/// use rand::rngs::{EntropyRng};
/// use zei::algebra::bls12_381::BLSScalar;
/// use zei::algebra::groups::Scalar;
/// use zei::basic_crypto::signatures::pointcheval_sanders::{ps_gen_keys, ps_sign_scalar};
/// let mut prng = EntropyRng::new();
/// let (_, sk) = ps_gen_keys(&mut prng);
/// let sig = ps_sign_scalar(&mut prng, &sk, &BLSScalar::from_u32(100u32));
/// ```
pub fn ps_sign_scalar<R: CryptoRng + Rng>(prng: &mut R, sk: &PSSecretKey, m: &BLSScalar) -> PSSignature
{
    let a = BLSScalar::random_scalar(prng);
    let s1 = BLSG1::get_base().mul(&a);

    let s2 = s1.mul(&sk.x.add(&sk.y.mul(&m)));
    PSSignature{s1,s2}
}

/// Pointcheval-Sanders verification function for byte slices
/// #Example
/// ```
///
/// use rand::rngs::{EntropyRng};
/// use zei::basic_crypto::signatures::pointcheval_sanders::{ps_gen_keys, ps_sign_bytes, ps_verify_sig_bytes};
/// use zei::errors::ZeiError;
/// let mut prng = EntropyRng::new();
/// let (pk, sk) = ps_gen_keys(&mut prng);
/// let sig = ps_sign_bytes(&mut prng, &sk, b"this is a message");
/// assert!(ps_verify_sig_bytes(&pk, b"this is a message", &sig).is_ok());
/// assert_eq!(Some(ZeiError::SignatureError), ps_verify_sig_bytes(&pk, b"this is ANOTHER message", &sig).err());
/// ```
pub fn ps_verify_sig_bytes(pk: &PSPublicKey, m: &[u8], sig: &PSSignature) -> Result<(), ZeiError>
{
    let m_scalar = hash_message(m);
    ps_verify_sig_scalar(pk, &m_scalar, sig)
}

/// Pointcheval-Sanders verification function for scalars
/// #Example
/// ```
///
/// use rand::rngs::EntropyRng;
/// use zei::basic_crypto::signatures::pointcheval_sanders::{ps_gen_keys, ps_sign_scalar, ps_verify_sig_scalar};
/// use zei::errors::ZeiError;
/// use zei::algebra::bls12_381::BLSScalar;
/// use zei::algebra::groups::Scalar;
/// let mut prng = EntropyRng::new();
/// let (pk, sk) = ps_gen_keys(&mut prng);
/// let sig = ps_sign_scalar(&mut prng, &sk, &BLSScalar::from_u32(100));
/// assert!(ps_verify_sig_scalar(&pk, &BLSScalar::from_u32(100), &sig).is_ok());
/// assert_eq!(Some(ZeiError::SignatureError), ps_verify_sig_scalar(&pk, &BLSScalar::from_u32(333), &sig).err());
/// ```
pub fn ps_verify_sig_scalar(pk: &PSPublicKey, m: &BLSScalar, sig: &PSSignature) -> Result<(), ZeiError>
{
    let a = pk.xx.add(&pk.yy.mul(&m));
    let e1 = BLSGt::pairing(&sig.s1, &a);
    let e2 = BLSGt::pairing(&sig.s2, &BLSG2::get_base());
    if e1 != e2 || sig.s1 == BLSG1::get_identity() {
        return Err(ZeiError::SignatureError);
    }
    Ok(())
}

pub fn randomize_ps_sig<R: Rng + CryptoRng>(prng: &mut R, sig: &PSSignature)
                                            -> (BLSScalar, PSSignature)
{
    let rand_factor = BLSScalar::random_scalar(prng);
    let s1 = sig.s1.mul(&rand_factor);
    let s2 = sig.s2.mul(&rand_factor);
    (
        rand_factor,
        PSSignature {
            s1,
            s2
        }
    )
}

fn hash_message(message: &[u8]) -> BLSScalar
{
    let mut hasher = Sha512::new();
    hasher.input(message);
    BLSScalar::from_hash(hasher)
}
