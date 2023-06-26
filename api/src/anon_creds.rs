use crate::errors::Result;
use noah_algebra::bn254::BN254PairingEngine;
use noah_algebra::bn254::BN254G2;
use noah_algebra::{
    bn254::{BN254Scalar, BN254G1},
    prelude::*,
    traits::Pairing,
};
use noah_crypto::{
    anon_creds::{Attribute, CommOutput},
    elgamal::elgamal_key_gen,
};

type G1 = BN254G1;
type G2 = BN254G2;
type S = BN254Scalar;

/// The isssuer's public key.
pub type ACIssuerPublicKey = noah_crypto::anon_creds::CredentialIssuerPK<G1, G2>;
/// The isssuer's secret key.
pub type ACIssuerSecretKey = noah_crypto::anon_creds::CredentialIssuerSK<G1, S>;
/// The signature.
pub type ACSignature = noah_crypto::anon_creds::CredentialSig<G1>;
/// The user's public key.
pub type ACUserPublicKey = noah_crypto::anon_creds::CredentialUserPK<G1>;
/// The user's secret key.
pub type ACUserSecretKey = noah_crypto::anon_creds::CredentialUserSK<S>;
/// The signature opening proof.
pub type ACRevealSig = noah_crypto::anon_creds::CredentialSigOpenProof<G1, G2, S>;
/// The proof of knowledge.
pub type ACPoK = noah_crypto::anon_creds::CredentialPoK<G2, S>;
/// The commitment randomizer.
pub type ACCommitmentKey = noah_crypto::anon_creds::CredentialCommRandomizer<S>;
/// The commitment.
pub type ACCommitment = noah_crypto::anon_creds::CredentialComm<G1>;
/// The credential.
pub type Credential = noah_crypto::anon_creds::Credential<G1, G2, Attr>;
/// The commitment opening proof.
pub type ACRevealProof = noah_crypto::anon_creds::CredentialCommOpenProof<G2, S>;
/// The confidential opening proof.
pub type ACConfidentialRevealProof = noah_crypto::confidential_anon_creds::CACPoK<G1, G2, S>;
/// The attribute types.
pub type Attr = u32;

/// Generate e key pair for a credential issuer.
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use noah::anon_creds::ac_keygen_issuer;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 10;
/// let keys = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// ```
pub fn ac_keygen_issuer<R: CryptoRng + RngCore>(
    prng: &mut R,
    num_attrs: usize,
) -> (ACIssuerSecretKey, ACIssuerPublicKey) {
    noah_crypto::anon_creds::issuer_keygen::<_, BN254PairingEngine>(prng, num_attrs)
}

/// Generate a credential user key pair for a given credential issuer.
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use noah::anon_creds::{ac_keygen_issuer,ac_keygen_user};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 10;
/// let (_, issuer_pk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let user_keys = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// ```
pub fn ac_keygen_user<R: CryptoRng + RngCore>(
    prng: &mut R,
    issuer_pk: &ACIssuerPublicKey,
) -> (ACUserSecretKey, ACUserPublicKey) {
    noah_crypto::anon_creds::user_keygen::<_, BN254PairingEngine>(prng, issuer_pk)
}

/// Compute a credential signature for a set of attributes.
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use noah::anon_creds::{ac_keygen_issuer,ac_keygen_user, ac_sign};
/// use noah_algebra::bn254::BN254Scalar;
/// use noah_algebra::traits::Scalar;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_sk, issuer_pk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (_, user_pk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attributes = vec![1u32, 2];
/// let signature = ac_sign::<ChaChaRng>(&mut prng, &issuer_sk, &user_pk, &attributes[..]);
/// ```
pub fn ac_sign<R: CryptoRng + RngCore>(
    prng: &mut R,
    issuer_sk: &ACIssuerSecretKey,
    user_pk: &ACUserPublicKey,
    attrs: &[Attr],
) -> Result<ACSignature> {
    let attrs_scalar: Vec<BN254Scalar> = attrs.iter().map(|x| BN254Scalar::from(*x)).collect();
    Ok(noah_crypto::anon_creds::grant_credential::<
        _,
        BN254PairingEngine,
    >(prng, issuer_sk, user_pk, attrs_scalar.as_slice())?)
}

/// Produce an opening key for credential commitment creation and attribute opening
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use noah::anon_creds::{ac_keygen_commitment};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let com_key = ac_keygen_commitment::<ChaChaRng>(&mut prng);
/// ```
pub fn ac_keygen_commitment<R: CryptoRng + RngCore>(prng: &mut R) -> ACCommitmentKey {
    noah_crypto::anon_creds::randomizer_gen::<_, BN254PairingEngine>(prng)
}

/// Compute a commitment to a credential signature with a binding message, returning the opening key.
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use noah::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_commit, Credential};
/// use noah_algebra::bn254::BN254Scalar;
/// use noah_algebra::traits::Scalar;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_sk, issuer_pk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (user_sk, user_pk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attr1 = 10;
/// let attr2 = 20;
/// let attributes = vec![attr1, attr2];
/// let signature = ac_sign::<ChaChaRng>(&mut prng, &issuer_sk, &user_pk, attributes.as_slice()).unwrap();
/// let credential = Credential {
///   sig:signature,
///   attrs:attributes,
///   ipk:issuer_pk
/// };
/// let (_,_,_) = ac_commit::<ChaChaRng>(&mut prng, &user_sk, &credential, b"some addr").unwrap();
/// ```
pub fn ac_commit<R: CryptoRng + RngCore>(
    prng: &mut R,
    user_sk: &ACUserSecretKey,
    credential: &Credential,
    msg: &[u8],
) -> Result<
    CommOutput<
        <BN254PairingEngine as Pairing>::G1,
        <BN254PairingEngine as Pairing>::G2,
        <BN254PairingEngine as Pairing>::ScalarField,
    >,
> {
    let c = noah_crypto::anon_creds::Credential {
        sig: credential.sig.clone(),
        attrs: credential
            .attrs
            .iter()
            .map(|x| BN254Scalar::from(*x))
            .collect_vec(),
        ipk: credential.ipk.clone(),
    };
    Ok(noah_crypto::anon_creds::commit_without_randomizer::<
        _,
        BN254PairingEngine,
    >(prng, user_sk, &c, msg)?)
}

/// Produce an AttrsRevealProof, bitmap indicates which attributes are revealed
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use noah::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_commit, ac_keygen_commitment, ac_commit_with_key, Credential};
/// use noah_algebra::bn254::BN254Scalar;
/// use noah_algebra::traits::Scalar;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_sk, issuer_pk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (user_sk, user_pk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attributes = vec![10u32, 20u32];
/// let signature = ac_sign::<ChaChaRng, >(&mut prng, &issuer_sk, &user_pk, &attributes[..]).unwrap();
/// let credential = Credential{
///   sig:signature,
///   attrs:attributes,
///   ipk:issuer_pk,
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
) -> Result<
    CommOutput<
        <BN254PairingEngine as Pairing>::G1,
        <BN254PairingEngine as Pairing>::G2,
        <BN254PairingEngine as Pairing>::ScalarField,
    >,
> {
    let c = noah_crypto::anon_creds::Credential {
        sig: credential.sig.clone(),
        attrs: credential
            .attrs
            .iter()
            .map(|x| BN254Scalar::from(*x))
            .collect_vec(),
        ipk: credential.ipk.clone(),
    };
    Ok(noah_crypto::anon_creds::commit::<_, BN254PairingEngine>(
        prng, user_sk, &c, key, msg,
    )?)
}

/// Verify that the underlying credential is valid and that the commitment was issued using the
/// message msg in particular.
pub fn ac_verify_commitment(
    issuer_pub_key: &ACIssuerPublicKey,
    sig_commitment: &ACCommitment,
    sok: &ACPoK,
    msg: &[u8],
) -> Result<()> {
    Ok(noah_crypto::anon_creds::check_comm::<BN254PairingEngine>(
        issuer_pub_key,
        sig_commitment,
        sok,
        msg,
    )?)
}

/// Produce an AttrsRevealProof for a committed credential produced using key.
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use noah::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_open_commitment, ac_commit, Credential};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_sk, issuer_pk) = ac_keygen_issuer(&mut prng, num_attrs);
/// let (user_sk, user_pk) = ac_keygen_user(&mut prng, &issuer_pk);
/// let attributes = vec![10, 20];
/// let signature = ac_sign::<ChaChaRng>(&mut prng, &issuer_sk, &user_pk, &attributes[..]).unwrap();
/// let credential = Credential {
///   sig:signature,
///   attrs:attributes,
///   ipk:issuer_pk,
/// };
/// let (commitment,pok,key) = ac_commit::<ChaChaRng>(&mut prng, &user_sk, &credential, b"Some message").unwrap();
/// let attrs_map = [true, false];
/// let reveal_sig = ac_open_commitment::<ChaChaRng>(&mut prng, &user_sk, &credential, &key.unwrap(), &attrs_map).unwrap();
/// ```
pub fn ac_open_commitment<R: CryptoRng + RngCore>(
    prng: &mut R,
    usk: &ACUserSecretKey,
    credential: &Credential,
    rand: &ACCommitmentKey,
    reveal_map: &[bool],
) -> Result<ACRevealProof> {
    let c = noah_crypto::anon_creds::Credential {
        sig: credential.sig.clone(),
        attrs: credential
            .attrs
            .iter()
            .map(|a| BN254Scalar::from(*a))
            .collect_vec(),
        ipk: credential.ipk.clone(),
    };

    let cm = ACCommitment::new(&credential.sig, &rand);

    Ok(noah_crypto::anon_creds::open_comm::<_, BN254PairingEngine>(
        prng, usk, &c, &cm, &rand, reveal_map,
    )?)
}

/// Produce a ACRevealSig for a credential.
pub fn ac_reveal<R: CryptoRng + RngCore>(
    prng: &mut R,
    user_sk: &ACUserSecretKey,
    credential: &Credential,
    reveal_bitmap: &[bool],
) -> Result<ACRevealSig> {
    let c = noah_crypto::anon_creds::Credential {
        sig: credential.sig.clone(),
        attrs: credential
            .attrs
            .iter()
            .map(|a| BN254Scalar::from(*a))
            .collect_vec(),
        ipk: credential.ipk.clone(),
    };
    Ok(noah_crypto::anon_creds::open_credential::<
        _,
        BN254PairingEngine,
    >(prng, user_sk, &c, reveal_bitmap)?)
}
/// Verifies an anonymous credential reveal proof.
/// # Example
/// ```
/// use rand_core::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// use noah_algebra::traits::Scalar;
/// use noah_algebra::bn254::BN254Scalar;
/// use noah::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_open_commitment, ac_verify, ac_reveal, Credential};
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let num_attrs = 2;
/// let (issuer_sk, issuer_pk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, num_attrs);
/// let (user_sk, user_pk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let attributes = vec![10u32, 20];
/// let signature = ac_sign::<ChaChaRng>(&mut prng, &issuer_sk, &user_pk, &attributes[..]).unwrap();
/// let credential = Credential{
///   sig:signature,
///   attrs:attributes,
///   ipk: issuer_pk.clone(),
/// };
/// let bitmap = [true,false]; // Reveal first attribute and hide the second one
/// let reveal_sig = ac_reveal::<ChaChaRng>(&mut prng, &user_sk, &credential, &bitmap).unwrap();
/// let attr_map = [Some(10u32), None];
/// let result_verification_ok = ac_verify(&issuer_pk, &attr_map, &reveal_sig.cm, &reveal_sig.proof_open);
/// assert!(result_verification_ok.is_ok());
/// let attr_map = [None, Some(20)];
/// let result_verification_err = ac_verify(&issuer_pk, &attr_map, &reveal_sig.cm, &reveal_sig.proof_open);
/// assert!(result_verification_err.is_err());
/// ```
pub fn ac_verify(
    issuer_pub_key: &ACIssuerPublicKey,
    attrs: &[Option<Attr>],
    cm: &ACCommitment,
    proof_open: &ACRevealProof,
) -> Result<()> {
    let attrs_scalar: Vec<Attribute<S>> = attrs
        .iter()
        .map(|attr| match attr {
            Some(x) => Attribute::Revealed(BN254Scalar::from(*x)),
            None => Attribute::Hidden(None),
        })
        .collect();

    Ok(noah_crypto::anon_creds::verify_open::<BN254PairingEngine>(
        issuer_pub_key,
        &cm,
        &proof_open,
        attrs_scalar.as_slice(),
    )?)
}

/// The attribute encryption key.
pub type AttributeEncKey = noah_crypto::elgamal::ElGamalEncKey<G1>;
/// The attribute decryption key.
pub type AttributeDecKey = noah_crypto::elgamal::ElGamalDecKey<S>;
/// The ciphertext of an attribute.
pub type AttributeCiphertext = noah_crypto::elgamal::ElGamalCiphertext<G1>;

/// Confidential anonymous credential
pub type ConfidentialAC = noah_crypto::confidential_anon_creds::ConfidentialAC<G1, G2, S>;

/// Produce a confidential anonymous credential revealing proof.
/// # Example
/// ```
/// use noah::anon_creds::{ac_keygen_issuer, ac_keygen_user, ac_sign, ac_commit};
/// use noah::anon_creds::{ac_confidential_open_commitment, ac_confidential_verify, ac_confidential_gen_encryption_keys};
/// use rand_chacha::ChaChaRng;
/// use rand_core::SeedableRng;
/// use noah_algebra::bn254::BN254Scalar;
/// use noah_algebra::traits::Group;
/// use noah::anon_creds::Credential;
/// let mut prng = ChaChaRng::from_seed([0u8;32]);
/// let (issuer_sk, issuer_pk) = ac_keygen_issuer::<ChaChaRng>(&mut prng, 3);
/// let (user_sk, user_pk) = ac_keygen_user::<ChaChaRng>(&mut prng, &issuer_pk);
/// let (_, enc_key) = ac_confidential_gen_encryption_keys::<ChaChaRng>(&mut prng);
/// let attrs = vec![10, 20, 30];
/// let bitmap = [false, true, false];
/// let ac_sig = ac_sign::<ChaChaRng>(&mut prng, &issuer_sk, &user_pk, &attrs[..]).unwrap();
/// let credential = Credential {
///   sig: ac_sig,
///   attrs: attrs,
///   ipk: issuer_pk.clone(),
/// };
/// let (sig_commitment,_,key) = ac_commit::<ChaChaRng>(&mut prng, &user_sk, &credential, b"Address").unwrap();
/// let conf_reveal_proof = ac_confidential_open_commitment::<ChaChaRng>(&mut prng, &user_sk, &credential, &key.unwrap(), &enc_key, &bitmap[..], b"Some Message").unwrap();
/// assert!(ac_confidential_verify(&issuer_pk, &enc_key, &bitmap[..], &sig_commitment, &conf_reveal_proof.cts, &conf_reveal_proof.pok, b"Some Message").is_ok())
/// ```
pub fn ac_confidential_open_commitment<R: CryptoRng + RngCore>(
    prng: &mut R,
    usk: &ACUserSecretKey,
    credential: &Credential,
    rand: &ACCommitmentKey,
    enc_key: &AttributeEncKey,
    reveal_map: &[bool],
    msg: &[u8],
) -> Result<ConfidentialAC> {
    let attrs_scalar = credential
        .attrs
        .iter()
        .map(|x| BN254Scalar::from(*x))
        .collect_vec();
    let c = noah_crypto::anon_creds::Credential {
        sig: credential.sig.clone(),
        attrs: attrs_scalar,
        ipk: credential.ipk.clone(),
    };
    let cm = ACCommitment::new(&credential.sig, &rand);
    Ok(
        noah_crypto::confidential_anon_creds::confidential_open_comm::<R, BN254PairingEngine>(
            prng, usk, &c, &cm, rand, reveal_map, enc_key, msg,
        )?,
    )
}

/// Verify a confidential anonymous credential reveal proof.
pub fn ac_confidential_verify(
    issuer_pk: &ACIssuerPublicKey,
    enc_key: &AttributeEncKey,
    reveal_map: &[bool],
    sig_commitment: &ACCommitment,
    attr_ctext: &[AttributeCiphertext],
    cac_proof: &ACConfidentialRevealProof,
    msg: &[u8],
) -> Result<()> {
    Ok(
        noah_crypto::confidential_anon_creds::confidential_verify_open::<BN254PairingEngine>(
            issuer_pk,
            enc_key,
            reveal_map,
            sig_commitment,
            attr_ctext,
            cac_proof,
            msg,
        )?,
    )
}

/// Generate encryptiion key for confidential anonymous credentials.
pub fn ac_confidential_gen_encryption_keys<R: CryptoRng + RngCore>(
    prng: &mut R,
) -> (AttributeDecKey, AttributeEncKey) {
    elgamal_key_gen::<_, G1>(prng)
}
