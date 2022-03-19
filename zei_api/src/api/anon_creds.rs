use algebra::bls12_381::{BLSPairingEngine, BLSScalar, BLSG1, BLSG2};
use algebra::traits::Group;
use crypto::anon_creds::{ACCommitOutput, Attribute};
use crypto::basics::elgamal::elgamal_key_gen;
use itertools::Itertools;
use rand_core::{CryptoRng, RngCore};
use ruc::*;

type G1 = BLSG1;
type G2 = BLSG2;
type S = BLSScalar;
pub type ACIssuerPublicKey = crypto::anon_creds::ACIssuerPublicKey<G1, G2>;
pub type ACIssuerSecretKey = crypto::anon_creds::ACIssuerSecretKey<G1, S>;

pub type ACSignature = crypto::anon_creds::ACSignature<G1>;

pub type ACUserPublicKey = crypto::anon_creds::ACUserPublicKey<G1>;

pub type ACUserSecretKey = crypto::anon_creds::ACUserSecretKey<S>;

pub type ACRevealSig = crypto::anon_creds::ACRevealSig<G1, G2, S>;

pub type ACPoK = crypto::anon_creds::ACPoK<G2, S>;

pub type ACCommitmentKey = crypto::anon_creds::ACKey<S>;

pub type ACCommitment = crypto::anon_creds::ACCommitment<G1>;

pub type Credential = crypto::anon_creds::Credential<G1, G2, Attr>;

pub type ACRevealProof = crypto::anon_creds::ACRevealProof<G2, S>;

pub type ACConfidentialRevealProof = crypto::conf_cred_reveal::CACPoK<G1, G2, S>;

pub type Attr = u32;

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
pub fn ac_keygen_issuer<R: CryptoRng + RngCore>(
    prng: &mut R,
    num_attrs: usize,
) -> (ACIssuerPublicKey, ACIssuerSecretKey) {
    crypto::anon_creds::ac_keygen_issuer::<_, BLSPairingEngine>(prng, num_attrs)
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
pub fn ac_keygen_user<R: CryptoRng + RngCore>(
    prng: &mut R,
    issuer_pk: &ACIssuerPublicKey,
) -> (ACUserPublicKey, ACUserSecretKey) {
    crypto::anon_creds::ac_user_key_gen::<_, BLSPairingEngine>(prng, issuer_pk)
}

/// Computes a credential signature for a set of attributes.
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer,ac_keygen_user, ac_sign};
/// use algebra::bls12_381::BLSScalar;
/// use algebra::traits::Scalar;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (user_pk, _) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attributes = vec![1u32, 2];
/// let signature = ac_sign::<ChaChaRng>(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// ```
pub fn ac_sign<R: CryptoRng + RngCore>(
    prng: &mut R,
    issuer_sk: &ACIssuerSecretKey,
    user_pk: &ACUserPublicKey,
    attrs: &[Attr],
) -> Result<ACSignature> {
    let attrs_scalar: Vec<BLSScalar> = attrs.iter().map(|x| BLSScalar::from(*x)).collect();
    crypto::anon_creds::ac_sign::<_, BLSPairingEngine>(
        prng,
        issuer_sk,
        user_pk,
        attrs_scalar.as_slice(),
    )
    .c(d!())
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
    crypto::anon_creds::ac_commitment_key_gen::<_, BLSPairingEngine>(prng)
}

/// Compute a commitment to a credential signature with a binding message, returning the opening key.
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_commit, Credential};
/// use algebra::bls12_381::BLSScalar;
/// use algebra::traits::Scalar;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attr1 = 10;
/// let attr2 = 20;
/// let attributes = vec![attr1, attr2];
/// let signature = ac_sign::<ChaChaRng>(&mut prng, &issuer_sk, &user_pk, attributes.as_slice()).unwrap();
/// let credential = Credential {
///   signature,
///   attributes,
///   issuer_pub_key:issuer_pk
/// };
/// let (_,_,_) = ac_commit::<ChaChaRng>(&mut prng, &user_sk, &credential, b"some addr").unwrap();
/// ```
pub fn ac_commit<R: CryptoRng + RngCore>(
    prng: &mut R,
    user_sk: &ACUserSecretKey,
    credential: &Credential,
    msg: &[u8],
) -> Result<ACCommitOutput<BLSPairingEngine>> {
    let c = crypto::anon_creds::Credential {
        signature: credential.signature.clone(),
        attributes: credential
            .attributes
            .iter()
            .map(|x| BLSScalar::from(*x))
            .collect_vec(),
        issuer_pub_key: credential.issuer_pub_key.clone(),
    };
    crypto::anon_creds::ac_commit::<_, BLSPairingEngine>(prng, user_sk, &c, msg).c(d!())
}

/// Produces a AttrsRevealProof, bitmap indicates which attributes are revealed
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use zei::api::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_commit, ac_keygen_commitment, ac_commit_with_key, Credential};
/// use algebra::bls12_381::BLSScalar;
/// use algebra::traits::Scalar;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attributes = vec![10u32, 20u32];
/// let signature = ac_sign::<ChaChaRng, >(&mut prng, &issuer_sk, &user_pk, &attributes[..]).unwrap();
/// let credential = Credential{
///   signature,
///   attributes,
///   issuer_pub_key:issuer_pk,
/// };
/// let ac_key = ac_keygen_commitment::<ChaChaRng>(&mut prng);
/// let addr = b"some addr";
/// let output = ac_commit_with_key::<ChaChaRng>(&mut prng, &user_sk, &credential, &ac_key, addr).unwrap();
/// ```
pub fn ac_commit_with_key<R: CryptoRng + RngCore>(
    prng: &mut R,
    user_sk: &ACUserSecretKey,
    credential: &Credential,
    key: &ACCommitmentKey,
    msg: &[u8],
) -> Result<ACCommitOutput<BLSPairingEngine>> {
    let c = crypto::anon_creds::Credential {
        signature: credential.signature.clone(),
        attributes: credential
            .attributes
            .iter()
            .map(|x| BLSScalar::from(*x))
            .collect_vec(),
        issuer_pub_key: credential.issuer_pub_key.clone(),
    };
    crypto::anon_creds::ac_commit_with_key::<_, BLSPairingEngine>(prng, user_sk, &c, key, msg)
        .c(d!())
}

/// Verifies that the underlying credential is valid and that the commitment was issued using the
/// message msg in particular.
pub fn ac_verify_commitment(
    issuer_pub_key: &ACIssuerPublicKey,
    sig_commitment: &ACCommitment,
    sok: &ACPoK,
    msg: &[u8],
) -> Result<()> {
    crypto::anon_creds::ac_verify_commitment::<BLSPairingEngine>(
        issuer_pub_key,
        sig_commitment,
        sok,
        msg,
    )
    .c(d!())
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
/// let attributes = vec![10, 20];
/// let signature = ac_sign::<ChaChaRng>(&mut prng, &issuer_sk, &user_pk, &attributes[..]).unwrap();
/// let credential = Credential {
///   signature,
///   attributes,
///   issuer_pub_key:issuer_pk,
/// };
/// let (commitment,pok,key) = ac_commit::<ChaChaRng>(&mut prng, &user_sk, &credential, b"Some message").unwrap();
/// let attrs_map = [true, false];
/// let reveal_sig = ac_open_commitment::<ChaChaRng>(&mut prng, &user_sk, &credential, &key.unwrap(), &attrs_map).unwrap();
/// ```
pub fn ac_open_commitment<R: CryptoRng + RngCore>(
    prng: &mut R,
    user_sk: &ACUserSecretKey,
    credential: &Credential,
    key: &ACCommitmentKey,
    reveal_map: &[bool],
) -> Result<ACRevealProof> {
    let c = crypto::anon_creds::Credential {
        signature: credential.signature.clone(),
        attributes: credential
            .attributes
            .iter()
            .map(|a| BLSScalar::from(*a))
            .collect_vec(),
        issuer_pub_key: credential.issuer_pub_key.clone(),
    };
    crypto::anon_creds::ac_open_commitment::<_, BLSPairingEngine>(
        prng, user_sk, &c, key, reveal_map,
    )
    .c(d!())
}

/// Produces a ACRevealSig for a credential. ACRevealSig includes new commitment to the credential,
/// and a AttrRevealProof for the revealed attributed.
/// bitmap indicates which attributes are revealed.
/// Calling ac_reveal is analogous to calling ac_commit and then ac_open_commitment.
pub fn ac_reveal<R: CryptoRng + RngCore>(
    prng: &mut R,
    user_sk: &ACUserSecretKey,
    credential: &Credential,
    reveal_bitmap: &[bool],
) -> Result<ACRevealSig> {
    let c = crypto::anon_creds::Credential {
        signature: credential.signature.clone(),
        attributes: credential
            .attributes
            .iter()
            .map(|a| BLSScalar::from(*a))
            .collect_vec(),
        issuer_pub_key: credential.issuer_pub_key.clone(),
    };
    crypto::anon_creds::ac_reveal::<_, BLSPairingEngine>(prng, user_sk, &c, reveal_bitmap).c(d!())
}
/// Verifies an anonymous credential reveal proof.
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use algebra::traits::Scalar;
/// use algebra::bls12_381::BLSScalar;
/// use zei::api::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_open_commitment, ac_verify, ac_reveal, Credential};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (user_pk, user_sk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attributes = vec![10u32, 20];
/// let signature = ac_sign::<ChaChaRng>(&mut prng, &issuer_sk, &user_pk, &attributes[..]).unwrap();
/// let credential = Credential{
///   signature,
///   attributes,
///   issuer_pub_key: issuer_pk.clone(),
/// };
/// let bitmap = [true,false]; // Reveal first attribute and hide the second one
/// let reveal_sig = ac_reveal::<ChaChaRng>(&mut prng, &user_sk, &credential, &bitmap).unwrap();
/// let attr_map = [Some(10u32), None];
/// let result_verification_ok = ac_verify(&issuer_pk, &attr_map, &reveal_sig.sig_commitment, &reveal_sig.pok);
/// assert!(result_verification_ok.is_ok());
/// let attr_map = [None, Some(20)];
/// let result_verification_err = ac_verify(&issuer_pk, &attr_map, &reveal_sig.sig_commitment, &reveal_sig.pok);
/// assert!(result_verification_err.is_err());
/// ```
pub fn ac_verify(
    issuer_pub_key: &ACIssuerPublicKey,
    attrs: &[Option<Attr>],
    sig_commitment: &ACCommitment,
    reveal_proof: &ACRevealProof,
) -> Result<()> {
    let attrs_scalar: Vec<Attribute<S>> = attrs
        .iter()
        .map(|attr| match attr {
            Some(x) => Attribute::Revealed(BLSScalar::from(*x)),
            None => Attribute::Hidden(None),
        })
        .collect();

    crypto::anon_creds::ac_verify::<BLSPairingEngine>(
        issuer_pub_key,
        attrs_scalar.as_slice(),
        &sig_commitment,
        &reveal_proof,
    )
    .c(d!())
}

pub type AttributeEncKey = crypto::basics::elgamal::ElGamalEncKey<G1>;
pub type AttributeDecKey = crypto::basics::elgamal::ElGamalDecKey<S>;
pub type AttributeCiphertext = crypto::basics::elgamal::ElGamalCiphertext<G1>;

pub type ConfidentialAC = crypto::conf_cred_reveal::ConfidentialAC<G1, G2, S>;

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
/// use algebra::bls12_381::{BLSScalar, BLSG1};
/// use algebra::traits::Group;
/// use zei::api::anon_creds::Credential;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let (issuer_pk, issuer_sk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, 3);
/// let (user_pk, user_sk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let (_, enc_key) = ac_confidential_gen_encryption_keys::<ChaChaRng>(&mut prng);
/// let attrs = vec![10, 20, 30];
/// let bitmap = [false, true, false];
/// let ac_sig = ac_sign::<ChaChaRng>(&mut prng, &issuer_sk, &user_pk, &attrs[..]).unwrap();
/// let credential = Credential {
///   signature: ac_sig,
///   attributes: attrs,
///   issuer_pub_key: issuer_pk.clone(),
/// };
/// let (sig_commitment,_,key) = ac_commit::<ChaChaRng>(&mut prng, &user_sk, &credential, b"Address").unwrap();
/// let conf_reveal_proof = ac_confidential_open_commitment::<ChaChaRng>(&mut prng, &user_sk, &credential, &key.unwrap(), &enc_key, &bitmap[..], b"Some Message").unwrap();
/// assert!(ac_confidential_verify(&issuer_pk, &enc_key, &bitmap[..], &sig_commitment, &conf_reveal_proof.ctexts, &conf_reveal_proof.pok, b"Some Message").is_ok())
/// ```
pub fn ac_confidential_open_commitment<R: CryptoRng + RngCore>(
    prng: &mut R,
    user_sk: &ACUserSecretKey,
    credential: &Credential,
    key: &ACCommitmentKey,
    enc_key: &AttributeEncKey,
    reveal_map: &[bool],
    msg: &[u8],
) -> Result<ConfidentialAC> {
    let attrs_scalar = credential
        .attributes
        .iter()
        .map(|x| BLSScalar::from(*x))
        .collect_vec();
    let c = crypto::anon_creds::Credential {
        signature: credential.signature.clone(),
        attributes: attrs_scalar,
        issuer_pub_key: credential.issuer_pub_key.clone(),
    };
    crypto::conf_cred_reveal::ac_confidential_open_commitment::<R, BLSPairingEngine>(
        prng, user_sk, &c, key, reveal_map, enc_key, msg,
    )
    .c(d!())
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
/// see zei::api::anon_creds::ac_confidential_open_commitment;
pub fn ac_confidential_verify(
    issuer_pk: &ACIssuerPublicKey,
    enc_key: &AttributeEncKey,
    reveal_map: &[bool],
    sig_commitment: &ACCommitment,
    attr_ctext: &[AttributeCiphertext],
    cac_proof: &ACConfidentialRevealProof,
    msg: &[u8],
) -> Result<()> {
    crypto::conf_cred_reveal::ac_confidential_open_verify::<BLSPairingEngine>(
        issuer_pk,
        enc_key,
        reveal_map,
        sig_commitment,
        attr_ctext,
        cac_proof,
        msg,
    )
    .c(d!())
}

pub fn ac_confidential_gen_encryption_keys<R: CryptoRng + RngCore>(
    prng: &mut R,
) -> (AttributeDecKey, AttributeEncKey) {
    elgamal_key_gen::<_, G1>(prng, &G1::get_base())
}
