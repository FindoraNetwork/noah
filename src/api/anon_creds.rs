use crate::algebra::bls12_381::{BLSScalar, Bls12381, BLSG1, BLSG2};
use crate::algebra::groups::Group;
use crate::basic_crypto::elgamal::elgamal_keygen;
use crate::crypto::anon_creds::Attribute;
use crate::errors::ZeiError;
use crate::utils::byte_slice_to_scalar;
use itertools::Itertools;
use rand_core::{CryptoRng, RngCore};

type G1 = BLSG1;
type G2 = BLSG2;
type S = BLSScalar;
pub type ACIssuerPublicKey = crate::crypto::anon_creds::ACIssuerPublicKey<G1, G2>;
pub type ACIssuerSecretKey = crate::crypto::anon_creds::ACIssuerSecretKey<G1, S>;

pub type ACSignature = crate::crypto::anon_creds::ACSignature<G1>;

pub type ACUserPublicKey = crate::crypto::anon_creds::ACUserPublicKey<G1>;

pub type ACUserSecretKey = crate::crypto::anon_creds::ACUserSecretKey<S>;

pub type ACRevealSig = crate::crypto::anon_creds::ACRevealSig<G1, G2, S>;

pub type ACPoK = crate::crypto::anon_creds::ACPoK<G2, S>;

pub type ACCommitmentKey = crate::crypto::anon_creds::ACKey<S>;

pub type ACCommitment = crate::crypto::anon_creds::ACCommitment<G1>;

pub type Credential<B> = crate::crypto::anon_creds::Credential<G1, G2, B>;

pub type ACRevealProof = crate::crypto::anon_creds::ACRevealProof<G2, S>;

/// Generates e key pair for a credential issuer
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::ac_keygen_issuer;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 10;
/// let keys = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// ```
pub fn ac_keygen_issuer<R: CryptoRng + RngCore>(prng: &mut R,
                                                num_attrs: usize)
                                                -> (ACIssuerPublicKey, ACIssuerSecretKey) {
  crate::crypto::anon_creds::ac_keygen_issuer::<_, Bls12381>(prng, num_attrs)
}

/// Generates a credential user key pair for a given credential issuer
///
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 10;
/// let (issuer_pk,_) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let user_keys = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// ```
pub fn ac_keygen_user<R: CryptoRng + RngCore>(prng: &mut R,
                                              issuer_pk: &ACIssuerPublicKey)
                                              -> (ACUserPublicKey, ACUserSecretKey) {
  crate::crypto::anon_creds::ac_keygen_user::<_, Bls12381>(prng, issuer_pk)
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
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (user_pk, _) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attr1 = b"attr1";
/// let attr2 = b"attr2";
/// let attributes = vec![&attr1[..], &attr2[..]];
/// let signature = ac_sign::<ChaChaRng, &[u8]>(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// ```
pub fn ac_sign<R: CryptoRng + RngCore, B: AsRef<[u8]>>(prng: &mut R,
                                                       issuer_sk: &ACIssuerSecretKey,
                                                       user_pk: &ACUserPublicKey,
                                                       attrs: &[B])
                                                       -> ACSignature {
  let attrs_scalar: Vec<BLSScalar> = attrs.iter()
                                          .map(|x| byte_slice_to_scalar::<BLSScalar>(x.as_ref()))
                                          .collect();
  crate::crypto::anon_creds::ac_sign::<_, Bls12381>(prng,
                                                    issuer_sk,
                                                    user_pk,
                                                    attrs_scalar.as_slice())
}

/// Produces opening key for credential commitment creation and attribute opening
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_commitment};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let com_key = ac_keygen_commitment::<ChaChaRng>(&mut prng);
/// ```
pub fn ac_keygen_commitment<R: CryptoRng + RngCore>(prng: &mut R) -> ACCommitmentKey {
  crate::crypto::anon_creds::ac_gen_key::<_, Bls12381>(prng)
}

/// Compute a commitment to a credential signature with a binding message, returning the opening key.
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_commit, Credential};
/// use zei::algebra::bls12_381::BLSScalar;
/// use zei::algebra::groups::Scalar;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attr1 = b"attr1";
/// let attr2 = b"attr2";
/// let attributes = vec![&attr1[..], &attr2[..]];
/// let signature = ac_sign::<ChaChaRng, &[u8]>(&mut prng, &issuer_sk, &user_pk, attributes.as_slice());
/// let credential = Credential {
///   signature,
///   attributes,
///   issuer_pk
/// };
/// let (commitment, proof, key) = ac_commit::<ChaChaRng, &[u8]>(&mut prng, &user_sk, &credential, b"some addr").unwrap();
/// ```
pub fn ac_commit<R: CryptoRng + RngCore, A: AsRef<[u8]>>(
  prng: &mut R,
  user_sk: &ACUserSecretKey,
  credential: &Credential<A>,
  msg: &[u8])
  -> Result<(ACCommitment, ACPoK, ACCommitmentKey), ZeiError> {
  let c = Credential { signature: credential.signature.clone(),
                       attributes: credential.attributes
                                             .iter()
                                             .map(|x| byte_slice_to_scalar(x.as_ref()))
                                             .collect_vec(),
                       issuer_pk: credential.issuer_pk.clone() };
  crate::crypto::anon_creds::ac_commit::<_, Bls12381>(prng, user_sk, &c, msg)
}

/// Produces a AttrsRevealProof, bitmap indicates which attributes are revealed
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_commit, ac_keygen_commitment, ac_commit_with_key, Credential};
/// use zei::algebra::bls12_381::BLSScalar;
/// use zei::algebra::groups::Scalar;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attr1 = b"attr1";
/// let attr2 = b"attr2";
/// let attributes = vec![&attr1[..], &attr2[..]];
/// let signature = ac_sign::<ChaChaRng, &[u8]>(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// let credential = Credential::<&[u8]>{
///   signature,
///   attributes,
///   issuer_pk,
/// };
/// let ac_key = ac_keygen_commitment::<ChaChaRng>(&mut prng);
/// let addr = b"some addr";
/// let (commitment, proof) = ac_commit_with_key::<ChaChaRng, &[u8]>(&mut prng, &user_sk, &credential, &ac_key, addr).unwrap();
/// ```
pub fn ac_commit_with_key<R: CryptoRng + RngCore, A: AsRef<[u8]>>(
  prng: &mut R,
  user_sk: &ACUserSecretKey,
  credential: &Credential<A>,
  key: &ACCommitmentKey,
  msg: &[u8])
  -> Result<(ACCommitment, ACPoK), ZeiError> {
  let c = Credential { signature: credential.signature.clone(),
                       attributes: credential.attributes
                                             .iter()
                                             .map(|x| byte_slice_to_scalar(x.as_ref()))
                                             .collect_vec(),
                       issuer_pk: credential.issuer_pk.clone() };
  crate::crypto::anon_creds::ac_commit_with_key::<_, Bls12381>(prng, user_sk, &c, key, msg)
}

/// Verifies that the underlying credential is valid and that the commitment was issued using the
/// message msg in particular.
pub fn ac_verify_commitment(issuer_pub_key: &ACIssuerPublicKey,
                            sig_commitment: &ACCommitment,
                            sok: &ACPoK,
                            msg: &[u8])
                            -> Result<(), ZeiError> {
  crate::crypto::anon_creds::ac_verify_commitment::<Bls12381>(issuer_pub_key,
                                                              sig_commitment,
                                                              sok,
                                                              msg)
}

/// Produces a AttrsRevealProof for a committed credential produced using key. bitmap indicates which attributes are revealed
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_open_commitment, ac_commit, Credential};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user(&mut prng, &issuer_pk);
/// let attr1 = b"attr1";
/// let attr2 = b"attr2";
/// let attributes = vec![&attr1[..], &attr2[..]];
/// let signature = ac_sign::<ChaChaRng, &[u8]>(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// let credential = Credential {
///   signature,
///   attributes,
///   issuer_pk,
/// };
/// let (commitment, pok, key) = ac_commit::<ChaChaRng, &[u8]>(&mut prng, &user_sk, &credential, b"Some message").unwrap();
/// let attrs_map = [true, false];
/// let reveal_sig = ac_open_commitment::<ChaChaRng, &[u8]>(&mut prng, &user_sk, &credential, &key, &attrs_map).unwrap();
/// ```
pub fn ac_open_commitment<R: CryptoRng + RngCore, A: AsRef<[u8]> + Clone>(
  prng: &mut R,
  user_sk: &ACUserSecretKey,
  credential: &Credential<A>,
  key: &ACCommitmentKey,
  reveal_map: &[bool])
  -> Result<ACRevealProof, ZeiError> {
  // TODO avoid this cloning
  let c = Credential { signature: credential.signature.clone(),
                       attributes: credential.attributes
                                             .iter()
                                             .map(|a| byte_slice_to_scalar(a.as_ref()))
                                             .collect_vec(),
                       issuer_pk: credential.issuer_pk.clone() };
  crate::crypto::anon_creds::ac_open_commitment::<_, Bls12381>(prng, user_sk, &c, key, reveal_map)
}

/// Produces a ACRevealSig for a credential. ACRevealSig includes new commitment to the credential,
/// and a AttrRevealProof for the revealed attributed.
/// bitmap indicates which attributes are revealed.
/// Calling ac_reveal is analogous to calling ac_commit and then ac_open_commitment.
pub fn ac_reveal<R: CryptoRng + RngCore, A: AsRef<[u8]>>(prng: &mut R,
                                                         user_sk: &ACUserSecretKey,
                                                         credential: &Credential<A>,
                                                         reveal_bitmap: &[bool])
                                                         -> Result<ACRevealSig, ZeiError> {
  let c = Credential { signature: credential.signature.clone(),
                       attributes: credential.attributes
                                             .iter()
                                             .map(|a| byte_slice_to_scalar(a.as_ref()))
                                             .collect_vec(),
                       issuer_pk: credential.issuer_pk.clone() };
  crate::crypto::anon_creds::ac_reveal::<_, Bls12381>(prng, user_sk, &c, reveal_bitmap)
}
/// Verifies an anonymous credential reveal proof.
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::algebra::groups::Scalar;
/// use zei::algebra::bls12_381::BLSScalar;
/// use zei::api::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_open_commitment, ac_verify, ac_reveal, Credential};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attr1 = b"attr1";
/// let attr2 = b"attr2";
/// let attributes = vec![&attr1[..], &attr2[..]];
/// let signature = ac_sign::<ChaChaRng, &[u8]>(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// let credential = Credential{
///   signature,
///   attributes,
///   issuer_pk: issuer_pk.clone(),
/// };
/// let bitmap = [true,false]; // Reveal first attribute and hide the second one
/// let reveal_sig = ac_reveal::<ChaChaRng, &[u8]>(&mut prng, &user_sk, &credential, &bitmap).unwrap();
/// let attr_map = [Some(&attr1[..]), None];
/// let result_verification_ok = ac_verify::<&[u8]>(&issuer_pk, &attr_map, &reveal_sig.sig_commitment, &reveal_sig.pok);
/// assert!(result_verification_ok.is_ok());
/// let attr_map = [None, Some(&attr2[..])];
/// let result_verification_err = ac_verify::<&[u8]>(&issuer_pk, &attr_map, &reveal_sig.sig_commitment, &reveal_sig.pok);
/// assert!(result_verification_err.is_err());
/// ```
pub fn ac_verify<B: AsRef<[u8]> + Clone>(issuer_pub_key: &ACIssuerPublicKey,
                                         attrs: &[Option<B>],
                                         ac_sig: &ACSignature,
                                         reveal_proof: &ACRevealProof)
                                         -> Result<(), ZeiError> {
  let attrs_scalar: Vec<Attribute<S>> =
    attrs.iter()
         .map(|attr| match attr {
           Some(x) => Attribute::Revealed(byte_slice_to_scalar::<S>(x.as_ref())),
           None => Attribute::Hidden(None),
         })
         .collect();

  crate::crypto::anon_creds::ac_verify::<Bls12381>(issuer_pub_key,
                                                   attrs_scalar.as_slice(),
                                                   &ac_sig,
                                                   &reveal_proof)
}

pub type ElGamalPublicKey = crate::basic_crypto::elgamal::ElGamalPublicKey<G1>;
pub type ElGamalSecretKey = crate::basic_crypto::elgamal::ElGamalSecretKey<S>;
pub type ElGamalCiphertext = crate::basic_crypto::elgamal::ElGamalCiphertext<G1>;

pub type ConfidentialAC = crate::crypto::conf_cred_reveal::ConfidentialAC<G1, G2, S>;

/// Produced a Confidential Anonymous Credential Reveal Proof for a single instance of a confidential anonymous reveal. Proof asserts
/// that a list of attributes can be decrypted from a list of ciphertexts under recv_enc_pub_key,
/// and that these attributed verify an anonymous credential reveal proof.
/// * `prng` - randomness source
/// * `cred_issuer_pk` - (signing) public key of the credential issuer
/// * `enc_key` - encryption public key of the receiver
/// * `attrs` - attributes to prove knowledge of
/// * `reveal_map` - indicates position of each attribute to prove
/// * `ac_reveal_sig` - proof that the issuer has signed some attributes
/// * `returns` - proof that the ciphertexts contains the attributes that have been signed by some issuer for the user.
/// # Example
/// ```
/// use zei::api::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_commit};
/// use zei::api::anon_creds::{ac_confidential_open_commitment, ac_confidential_verify, ac_confidential_gen_encryption_keys};
/// use rand_chacha::ChaChaRng;
/// use rand_core::SeedableRng;
/// use zei::algebra::bls12_381::{BLSScalar, BLSG1};
/// use zei::algebra::groups::Group;
/// use zei::api::anon_creds::Credential;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, 3);
/// let (user_pk, user_sk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let (_, enc_key) = ac_confidential_gen_encryption_keys::<ChaChaRng>(&mut prng);
/// let attr1 = b"attr1";
/// let attr2 = b"attr2";
/// let attr3 = b"attr3";
/// let attrs = vec![&attr1[..], &attr2[..], &attr3[..]];
/// let bitmap = [false, true, false];
/// let ac_sig = ac_sign::<ChaChaRng, &[u8]>(&mut prng, &issuer_sk, &user_pk, &attrs[..]);
/// let credential = Credential {
///   signature: ac_sig,
///   attributes: attrs,
///   issuer_pk: issuer_pk.clone(),
/// };
/// let (sig_commitment,_,key) = ac_commit::<ChaChaRng, &[u8]>(&mut prng, &user_sk, &credential, b"Address").unwrap();
/// let conf_reveal_proof = ac_confidential_open_commitment::<ChaChaRng, &[u8]>(&mut prng, &user_sk, &credential, &key, &enc_key, &bitmap[..], b"Some Message").unwrap();
/// assert!(ac_confidential_verify(&issuer_pk, &enc_key, &bitmap[..], &sig_commitment, &conf_reveal_proof, b"Some Message").is_ok())
/// ```
pub fn ac_confidential_open_commitment<R: CryptoRng + RngCore, B: AsRef<[u8]>>(
  prng: &mut R,
  user_sk: &ACUserSecretKey,
  credential: &Credential<B>,
  key: &ACCommitmentKey,
  enc_key: &ElGamalPublicKey,
  reveal_map: &[bool],
  msg: &[u8])
  -> Result<ConfidentialAC, ZeiError> {
  let attrs_scalar = credential.attributes
                               .iter()
                               .map(|x| byte_slice_to_scalar::<S>(x.as_ref()))
                               .collect_vec();
  let c = Credential { signature: credential.signature.clone(),
                       attributes: attrs_scalar,
                       issuer_pk: credential.issuer_pk.clone() };
  crate::crypto::conf_cred_reveal::ac_confidential_open_commitment::<R, Bls12381>(prng, user_sk,
                                                                                  &c, key,
                                                                                  reveal_map,
                                                                                  enc_key, msg)
}

/// Verifies a Confidential Anonymous Credential reveal proof. Proof asserts
/// that a list of ciphertexts encodes attributes under `enc_key` such that
/// these verify an anonymous credential reveal proof.
/// * `prng` - randomness source
/// * `issuer_pk` - (signing) public key of the credential issuer
/// * `enc_key` - encryption public key of the receiver
/// * `reveal_map` - indicates position of each attribute to prove
/// * `cac` - List of ciphertext and the corresponding proof
/// # Example
/// ```
///  // see zei::api::anon_creds::ac_confidential_open_commitment;
/// ```
pub fn ac_confidential_verify(issuer_pk: &ACIssuerPublicKey,
                              enc_key: &ElGamalPublicKey,
                              reveal_map: &[bool],
                              sig_commitment: &ACCommitment,
                              cac: &ConfidentialAC,
                              msg: &[u8])
                              -> Result<(), ZeiError> {
  crate::crypto::conf_cred_reveal::ac_confidential_open_verify::<Bls12381>(issuer_pk,
                                                                           enc_key,
                                                                           reveal_map,
                                                                           sig_commitment,
                                                                           cac,
                                                                           msg)
}

pub fn ac_confidential_gen_encryption_keys<R: CryptoRng + RngCore>(
  prng: &mut R)
  -> (ElGamalSecretKey, ElGamalPublicKey) {
  elgamal_keygen::<_, S, G1>(prng, &G1::get_base())
}
