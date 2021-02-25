/*
This file implements anonymous credentials based on the signature scheme of
David Pointcheval and Olivier Sanders. Short Randomizable Signatures. CT RSA 2015.
https://eprint.iacr.org/2015/525.pdf. Details are described below:

Credential issuers can issue credentials for a set of n attributes by providing a signature
on this attributes for a given user.

Given a credential signature, users can selectively reveal a subset of attributes that are signed
in the credentials by
 a) Randomizing the signature (provide unlinkability between reveals)
 b) Revealing a subset of attributes
 c) Provide a zero knowledge proof of knowledge of the user secret key and hidden attributes for
 the credential signature

 Specifications:
 Let G1, G2,Gt be groups of prime order and a bilinear map e: G1 x G2 -> Gt. In what follows,
 additive notation is used.
 Issuer secret key:
     - G1 // random generator of group 1
     - x // random scalar
     - {y_i} one y_i per attribute // random scalars

 Issuer public key:
     - G2  // random generator of group 2
     - X2 = x * G2
     - Z1 = z * G1 //for a random scalar z
     - Z2 = z * G2
     - {Y2_i} = {y_i * G2} // one y_i per attribute

 User secret key: sk // random scalar
 User public key: sk * Z2


 + Signature over attributes {attr_i} for user public key user_pub_key = user_sec_key * Z1:
   - Sample random scalar u
   - Compute C = (issuer_sec_key.x + \sum attr_i * y_i) * issuer_sec_key.G1
   - sigma1 = u * issuer_sec_key.G1 // u * G1
   - sigma2 = u * (C + user_pub_key) // u* (x + \sum attr_i * y_i + user_sec_key * z) * G1
   - output (sigma1, sigma2)

 + Signature Verification for a set of attributes {attr_i} for user public key user_pub_key over
   - compare e(sigma1, \sum attr_i * Y2_i + user_pk + X2) =? e(sigma2, G2)
      // Left hand side: e(G1, G2) * u * (\sum attr_i * y_i + user_sec_key * z + x)
      // Right hand side e(G1, G2) * u * (x + \sum attr_i * y_i + user_sec_key * z)

 + Selective revealing: prove that a signature verify against a set of attributes,
 some of which are hidden to the verifier. Strategy:
    a) Randomize the signature to provide unlinkability (and hence anonymity ) different reveals
    of the same underlying signature.
    b) provide a proof of knowledge of user's secret key,
      hidden attributes and scalar used to randomize the signature.

   Reveal Algorithm:
    a) signature randomization
      i) sigma1' = r * sigma1
      ii) sigma2' = r* (sigma2 + t * sigma1)
    b) NI proof of knowledge
        i) Produce blinding scalar b_t, b_sk, {b_attr_i: one for each attributes to hide}
       ii) Compute an aggregated proof commitment C = b_t * G2 + b_sk * Z2 + \sum b_attr_i * Y2_i
            (sum over attrs to hide)
      iii) Compute challenge c as Hash("ZeiACReveal", IssuerPubKey, sigma1', sigma2', {attrs_j}, C)
           where j ranges for the hidden attributes subset.
       iv) Compute challenge responses
           r_t = c * t + r_t,
           r_sk = c * sk + b_sk, and
           {r_attr_i = c* attr_i + b_attr_i} for each hidden attribute attr_i
    c) Output (sigma1', sigma2', C, r_t, r_sk, {r_attri})

  + Selective reveal verification:
   (Input: (sigma1', sigma2', C, r_t, r_sk, {r_attr_i}), revealed attributes: {attr_j}, issuer_pk)
     i) Compute challenge c as Hash("ZeiACReveal", IssuerPubKey, sigma1', sigma2', {attrs_j}, C)
    ii) Compute P = c * (X2 + \sum Y2_j attr_j) + r_t * G2 + r_sk * Z2 + \sum r_attr_i * Y2_i - C
        (where i ranges for all hidden attributes and j ranges for all revealed attributes)
   iii) Compare e(sigma1, P) =? e(sigma2, c * G2) (output 1 if equals, 0 otherwise)
        (e(sigma1',P) = e(r * u * G1, c * (X2 + \sum attr_i * Y2_j + t * G2 + sk * Z2) )
                      = e(G1,G2) * r * u * c( x + \sum attr_i * y_i + t + sk * z), and
         e(sigma2', c * G2) = e(G1,G2) * r * c * u * (x + \sum attr_i * y_i + t + sk * x)
*/

use crate::sigma::{SigmaTranscript, SigmaTranscriptPairing};
use algebra::groups::{Group, GroupArithmetic, Scalar, ScalarArithmetic};
use algebra::multi_exp::MultiExp;
use algebra::pairing::Pairing;
use itertools::Itertools;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use ruc::{err::*, *};
use utils::errors::ZeiError;

pub(crate) const AC_REVEAL_PROOF_DOMAIN: &[u8] = b"AC Reveal PoK";
pub(crate) const AC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE: &[u8] =
    b"AC Reveal PoK Instance";
pub(crate) const AC_COMMIT_NEW_TRANSCRIPT_INSTANCE: &[u8] = b"AC Commit SoK Instance";
pub(crate) const SOK_LABEL: &[u8] = b"Signature Message";

/// I contain Credentials' Issuer Public key fields
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACIssuerPublicKey<G1, G2> {
    pub gen2: G2,     //random generator for G2
    pub xx2: G2,      //gen2^x, x in CredIssuerSecretKey
    pub zz1: G1,      //gen1^z, z random scalar, gen1 in CredIssuerSecretKey
    pub zz2: G2,      //gen2^z, same z as above
    pub yy2: Vec<G2>, //gen2^{y_i}, y_i in CredIssuerSecretKey
}

impl<G1, G2> ACIssuerPublicKey<G1, G2> {
    pub fn num_attrs(&self) -> usize {
        self.yy2.len()
    }
}
/// I contain the Credentials' Issuer Secret key fields
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACIssuerSecretKey<G1, S> {
    pub gen1: G1, //random generator for G1
    pub x: S,
    pub y: Vec<S>,
}

/// I'm a signature for a set of attributes produced by issuer for a user
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACSignature<G1> {
    pub sigma1: G1,
    pub sigma2: G1,
}

impl<G: Group> Default for ACSignature<G> {
    fn default() -> ACSignature<G> {
        ACSignature {
            sigma1: G::get_identity(),
            sigma2: G::get_identity(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential<G1, G2, B> {
    pub signature: ACSignature<G1>, // original signature from Issuer
    pub attributes: Vec<B>,         // set of attributes in credential
    pub issuer_pub_key: ACIssuerPublicKey<G1, G2>,
}

impl<G1, G2, B: Copy> Credential<G1, G2, B> {
    pub fn get_revealed_attributes(&self, bitmap_policy: &[bool]) -> Result<Vec<B>> {
        if bitmap_policy.len() != self.attributes.len() {
            return Err(eg!(ZeiError::ParameterError));
        }
        Ok(self
            .attributes
            .iter()
            .zip(bitmap_policy)
            .filter(|(_, b)| *(*b))
            .map(|(a, _)| *a)
            .collect())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACCommitment<G1>(pub(crate) ACSignature<G1>);

impl<G: Group> Default for ACCommitment<G> {
    fn default() -> ACCommitment<G> {
        let sig = ACSignature::<G>::default();
        ACCommitment::<G> { 0: sig }
    }
}

///I'm a user public key used to request a signature for a set of attributes (credential)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACUserPublicKey<G1>(pub(crate) G1);

///I'm a user's secret key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACUserSecretKey<S>(pub(crate) S);

/// I'm a proof computed by the UserSecretKey holder that an Issuer has signed certain
/// attributes for the corresponding UserPublicKey
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACRevealSig<G1, G2, S> {
    pub sig_commitment: ACCommitment<G1>,
    pub pok: ACRevealProof<G2, S>,
}

/// Proof that revealed attributes verify a credential commitment signature
pub type ACRevealProof<G2, S> = ACPoK<G2, S>;

/// Proof of knowledge for t, sk (UserSecretKey), and hidden attributes that satisfy a
/// certain relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACPoK<G2, S> {
    pub(crate) commitment: G2, // r_t*G2 + r_sk*Z2 + sum_{a_i in hidden attrs} r_{a_i}*Y2_i
    pub(crate) response_t: S,  // c*t + r_t
    pub(crate) response_sk: S, // c*sk + r_sk
    pub(crate) response_attrs: Vec<S>, // {c*a_i + r_{a_i}; a_i in hidden}
}

#[derive(Clone)]
pub enum Attribute<S> {
    Revealed(S),
    Hidden(Option<S>),
}

/// Secret AC Commitment opening parameters. Used to create ac reveal proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACKey<S> {
    // a credential signature (s1,s2) is committed as (r*s1, r*(s2 + t*s1))
    pub r: S,
    pub t: S,
}

#[allow(type_alias_bounds)]
pub type ACCommitOutput<P: Pairing> = (
    ACCommitment<P::G1>,
    ACPoK<P::G2, P::ScalarField>,
    Option<ACKey<P::ScalarField>>,
);

/// I generate e key pair for a credential issuer
#[allow(clippy::type_complexity)]
pub fn ac_keygen_issuer<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    num_attrs: usize,
) -> (
    ACIssuerPublicKey<P::G1, P::G2>,
    ACIssuerSecretKey<P::G1, P::ScalarField>,
) {
    let x = P::ScalarField::random(prng);
    let z = P::ScalarField::random(prng);
    let gen1: P::G1 = P::G1::get_random_base(prng);
    let gen2 = P::G2::get_random_base(prng);
    let mut y = vec![];
    let mut yy2 = vec![];
    for _ in 0..num_attrs {
        let yi = P::ScalarField::random(prng);
        yy2.push(gen2.mul(&yi));
        y.push(yi);
    }
    let xx2 = gen2.mul(&x);
    let zz1 = gen1.mul(&z);
    let zz2 = gen2.mul(&z);
    (
        ACIssuerPublicKey {
            gen2,
            xx2,
            zz1,
            zz2,
            yy2,
        },
        ACIssuerSecretKey { gen1, x, y },
    )
}

/// I generate a credential user key pair for a given credential issuer
pub fn ac_user_key_gen<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
) -> (ACUserPublicKey<P::G1>, ACUserSecretKey<P::ScalarField>) {
    let secret = P::ScalarField::random(prng);
    let pk = issuer_pk.zz1.mul(&secret);
    (ACUserPublicKey(pk), ACUserSecretKey(secret))
}

/// I Compute a credential signature for a set of attributes. User can represent Null attributes by
/// a fixes scalar (e.g. 0)
pub fn ac_sign<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    issuer_sk: &ACIssuerSecretKey<P::G1, P::ScalarField>,
    user_pk: &ACUserPublicKey<P::G1>,
    attrs: &[P::ScalarField],
) -> Result<ACSignature<P::G1>> {
    let number_attributes_from_issuer_sk = issuer_sk.y.len();
    let n = attrs.len();
    if number_attributes_from_issuer_sk != n {
        return Err(eg!(ZeiError::AnonymousCredentialSignError));
    }

    let u = P::ScalarField::random(prng);
    let mut exponent = issuer_sk.x;
    for (attr, yi) in attrs.iter().zip(issuer_sk.y.iter()) {
        exponent = exponent.add(&attr.mul(yi));
    }
    let cc = issuer_sk.gen1.mul(&exponent);
    Ok(ACSignature::<P::G1> {
        sigma1: issuer_sk.gen1.mul(&u),
        sigma2: user_pk.0.add(&cc).mul(&u),
    })
}

/// Sample an  AC commitment key
pub fn ac_commitment_key_gen<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
) -> ACKey<P::ScalarField> {
    ACKey {
        r: P::ScalarField::random(prng),
        t: P::ScalarField::random(prng),
    }
}

/// Credential commitment to a message
pub fn ac_commit<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    user_sk: &ACUserSecretKey<P::ScalarField>,
    credential: &Credential<P::G1, P::G2, P::ScalarField>,
    msg: &[u8],
) -> Result<ACCommitOutput<P>> {
    let key = ac_commitment_key_gen::<_, P>(prng);
    let output =
        ac_commit_with_key::<_, P>(prng, user_sk, credential, &key, msg).c(d!())?;
    let commitment = output.0;
    let sok = output.1;

    Ok((commitment, sok, Some(key)))
}

pub fn ac_commit_with_key<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    user_sk: &ACUserSecretKey<P::ScalarField>,
    credential: &Credential<P::G1, P::G2, P::ScalarField>,
    key: &ACKey<P::ScalarField>,
    msg: &[u8],
) -> Result<ACCommitOutput<P>> {
    let hidden_attrs = credential
        .attributes
        .iter()
        .map(|attr| Attribute::Hidden(Some(attr)))
        .collect_vec(); // all hidden

    let sig_commitment = ac_randomize::<P>(&credential.signature, key); // compute commitment
    let mut transcript = Transcript::new(AC_COMMIT_NEW_TRANSCRIPT_INSTANCE);
    ac_init_transcript::<P>(
        &mut transcript,
        &credential.issuer_pub_key,
        &sig_commitment,
    ); // public parameters
    transcript.append_message(SOK_LABEL, msg); // SoK on message msg
    let sok = prove_pok::<_, P>(
        &mut transcript,
        prng,
        user_sk,
        &credential.issuer_pub_key,
        &key.t,
        hidden_attrs.as_slice(),
    )
    .c(d!())?;

    Ok((sig_commitment, sok, None))
}

/// Produces a credential commitment by randomizing the credential signature
pub fn ac_randomize<P: Pairing>(
    sig: &ACSignature<P::G1>,
    key: &ACKey<P::ScalarField>,
) -> ACCommitment<P::G1> {
    let sigma1_r = sig.sigma1.mul(&key.r);
    let sigma1_t = sig.sigma1.mul(&key.t);
    let sigma2_aux = sig.sigma2.add(&sigma1_t);
    let sigma2_r = sigma2_aux.mul(&key.r);
    let commitment = ACSignature::<P::G1> {
        sigma1: sigma1_r,
        sigma2: sigma2_r, //sigma2: r*(sigma2 + t*sigma1)
    };
    ACCommitment(commitment)
}

pub fn ac_verify_commitment<P: Pairing>(
    issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
    sig_commitment: &ACCommitment<P::G1>,
    sok: &ACPoK<P::G2, P::ScalarField>,
    msg: &[u8],
) -> Result<()> {
    let mut transcript = Transcript::new(AC_COMMIT_NEW_TRANSCRIPT_INSTANCE);
    ac_init_transcript::<P>(&mut transcript, issuer_pub_key, &sig_commitment); // public parameters
    transcript.append_message(SOK_LABEL, msg); // SoK proof on message msg

    let attributes: Vec<Attribute<P::ScalarField>> =
        vec![Attribute::Hidden(None); issuer_pub_key.num_attrs()];

    pok_verify::<P>(
        &mut transcript,
        issuer_pub_key,
        sig_commitment,
        sok,
        attributes.as_slice(),
    )
}

pub(crate) fn pok_verify<P: Pairing>(
    transcript: &mut Transcript,
    issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
    sig_commitment: &ACCommitment<P::G1>,
    sok: &ACPoK<P::G2, P::ScalarField>,
    attributes: &[Attribute<P::ScalarField>],
) -> Result<()> {
    transcript.append_proof_commitment(&sok.commitment); // proof object
    let challenge = transcript.get_challenge::<P::ScalarField>();
    ac_do_challenge_check_commitment::<P>(
        issuer_pub_key,
        sig_commitment,
        sok,
        attributes,
        &challenge,
    )
    // do checkings
}

pub(crate) fn ac_do_challenge_check_commitment<P: Pairing>(
    issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
    sig_commitment: &ACCommitment<P::G1>,
    pok: &ACPoK<P::G2, P::ScalarField>,
    attributes: &[Attribute<P::ScalarField>],
    challenge: &P::ScalarField,
) -> Result<()> {
    // p = X_2*c - proof_commitment + &G2 * r_t + Z2 * r_sk + \sum r_attr_i * Y2_i;

    let minus_one: P::ScalarField = P::ScalarField::from_u32(1).neg();
    let mut scalars = vec![
        &pok.response_t,  // G2
        challenge,        //X2
        &pok.response_sk, //Z2
        &minus_one,       //Commitment
    ];

    let mut resp_attr_iter = pok.response_attrs.iter();

    let attributes = attributes
        .iter()
        .map(|attr| match attr {
            Attribute::Revealed(attr) => Some(attr.mul(challenge)),
            _ => None,
        })
        .collect_vec();
    for attr in attributes.iter() {
        match attr {
            Some(a) => {
                scalars.push(a);
            }
            None => {
                let response = resp_attr_iter.next().c(d!(ZeiError::ParameterError))?;
                scalars.push(response);
            }
        }
    }
    let mut elems = vec![
        &issuer_pub_key.gen2,
        &issuer_pub_key.xx2,
        &issuer_pub_key.zz2,
        &pok.commitment,
    ];

    for y in issuer_pub_key.yy2.iter() {
        elems.push(y);
    }
    let p = P::G2::vartime_multi_exp(scalars.as_slice(), elems.as_slice());
    ac_verify_final_check::<P>(sig_commitment, &challenge, &issuer_pub_key.gen2, &p)
}
/// Produce a AttrsRevealProof, attributes that are not Revealed(attr) and secret parameters
/// are proved in ZeroKnowledge.
#[allow(clippy::type_complexity)]
pub fn ac_open_commitment<
    R: CryptoRng + RngCore,
    P: Pairing<ScalarField = algebra::bls12_381::BLSScalar>,
>(
    prng: &mut R,
    user_sk: &ACUserSecretKey<P::ScalarField>,
    credential: &Credential<P::G1, P::G2, P::ScalarField>,
    key: &ACKey<P::ScalarField>,
    reveal_map: &[bool],
) -> Result<ACRevealProof<P::G2, P::ScalarField>> {
    let sig_commitment = ac_randomize::<P>(&credential.signature, key);

    let revealed_attributes = credential
        .attributes
        .iter()
        .zip(reveal_map.iter())
        .map(|(attr, b)| {
            if *b {
                Attribute::Revealed(attr)
            } else {
                Attribute::Hidden(Some(attr))
            }
        })
        .collect_vec();
    let mut transcript = Transcript::new(AC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
    ac_init_transcript::<P>(
        &mut transcript,
        &credential.issuer_pub_key,
        &sig_commitment,
    ); // public parameters
    let pok = prove_pok::<_, P>(
        &mut transcript,
        prng,
        user_sk,
        &credential.issuer_pub_key,
        &key.t,
        revealed_attributes.as_slice(),
    )
    .c(d!())?;

    Ok(pok)
}

/// Produce a AttrsRevealProof, attributes that are not Revealed(attr) and secret parameters
/// are proved in ZeroKnowledge.
#[allow(clippy::type_complexity)]
pub fn ac_reveal<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    user_sk: &ACUserSecretKey<P::ScalarField>,
    credential: &Credential<P::G1, P::G2, P::ScalarField>,
    reveal_bitmap: &[bool],
) -> Result<ACRevealSig<P::G1, P::G2, P::ScalarField>> {
    if credential.attributes.len() != reveal_bitmap.len() {
        return Err(eg!(ZeiError::ParameterError));
    }
    let attributes = credential
        .attributes
        .iter()
        .zip(reveal_bitmap.iter())
        .map(|(attr, b)| {
            if *b {
                Attribute::Revealed(attr)
            } else {
                Attribute::Hidden(Some(attr))
            }
        })
        .collect_vec();

    let key = ac_commitment_key_gen::<_, P>(prng);
    let sig_commitment = ac_randomize::<P>(&credential.signature, &key);
    let mut transcript = Transcript::new(AC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
    ac_init_transcript::<P>(
        &mut transcript,
        &credential.issuer_pub_key,
        &sig_commitment,
    );
    let pok = prove_pok::<_, P>(
        &mut transcript,
        prng,
        user_sk,
        &credential.issuer_pub_key,
        &key.t,
        attributes.as_slice(),
    )
    .c(d!())?;

    Ok(ACRevealSig {
        sig_commitment,
        pok,
    })
}

/// Given a list of revealed attributes_{k}, and a credential structure composed by a signature
/// (sigma1,sigma2) and a proof of
/// knowledge of t, sk and some hidden attributes, I verify that
/// e(sigma1,X2) + e(sigma1, g_2^t) + e(sigma1, Z2^sk) + e(sigma1, \\sum Y2_i^attr_i)
/// equals e(sigma2, g_2)
/// Revealed attributes attr corresponds to the positions where the bitmap is true
/// I return Ok() in case signatures and proofs are correct.
/// Otherwise, I return Err(ZeiError:SignatureError)
/// Algorithm:
/// 1. Compute challenge c as hash of proof_commitment
/// 2. Compute p \= -proof_commitment + c*X2 + proof_response\_t*g\_2 + proof\_response\_sk*Z2 +
///  sum_{i\in hidden} proof_response_attr_i * Y2_i + sum_{i\in revealed} c*attr_i * Y2_i
/// 3. Compare e(sigma1, p) against e(sigma2, c*g2)
pub fn ac_verify<P: Pairing>(
    issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
    attrs: &[Attribute<P::ScalarField>],
    sig_commitment: &ACCommitment<P::G1>,
    reveal_proof: &ACRevealProof<P::G2, P::ScalarField>,
) -> Result<()> {
    let mut transcript = Transcript::new(AC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
    ac_init_transcript::<P>(&mut transcript, issuer_pub_key, &sig_commitment);
    pok_verify::<P>(
        &mut transcript,
        issuer_pub_key,
        sig_commitment,
        reveal_proof,
        attrs,
    )
}

pub(super) fn ac_init_transcript<P: Pairing>(
    transcript: &mut Transcript,
    issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
    commitment: &ACCommitment<P::G1>,
) {
    let g1 = P::G1::get_base();
    let g2 = P::G2::get_base();
    let g1_elems = vec![
        &g1,
        &issuer_pk.zz1,
        &commitment.0.sigma1,
        &commitment.0.sigma2,
    ];
    let mut g2_elems = vec![&g2, &issuer_pk.gen2, &issuer_pk.xx2, &issuer_pk.zz2];
    for e in issuer_pk.yy2.iter() {
        g2_elems.push(e);
    }
    transcript.init_sigma_pairing::<P>(
        AC_REVEAL_PROOF_DOMAIN,
        &[],
        &g1_elems[..],
        g2_elems.as_slice(),
        &[],
    );
}
/// I produce selective attribute disclose proof of knowledge
/// Algorithm:
///     1. Sample beta1, beta2 and {gamma_j} (One for each hidden attribute)
///     2. Compute a sigma proof commitment for the values in 1:
///        beta1*g2 + beta2*Z2 + \sum gamma_j Y2_{j_i} for each j_i s.t revealed_itmap[j_i] = false
///     3. Sample the challenge as a hash of the commitment.
///     4. Compute challenge's responses  c*t + \beta1, c*sk + beta2, {c*y_i + gamma_i}
///     5. Return proof commitment and responses
#[allow(clippy::too_many_arguments)]
fn prove_pok<R: CryptoRng + RngCore, P: Pairing>(
    transcript: &mut Transcript,
    prng: &mut R,
    user_sk: &ACUserSecretKey<P::ScalarField>,
    issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
    t: &P::ScalarField,
    attrs: &[Attribute<&P::ScalarField>],
) -> Result<ACPoK<P::G2, P::ScalarField>> {
    let beta1 = P::ScalarField::random(prng);
    let beta2 = P::ScalarField::random(prng);
    let mut gamma = vec![];
    let mut commitment = issuer_pk.gen2.mul(&beta1).add(&issuer_pk.zz2.mul(&beta2));
    for (yy2i, attr) in issuer_pk.yy2.iter().zip(attrs) {
        match attr {
            Attribute::Hidden(Some(_)) => {
                let gamma_i = P::ScalarField::random(prng);
                let elem = yy2i.mul(&gamma_i);
                commitment = commitment.add(&elem);
                gamma.push(gamma_i);
            }
            Attribute::Hidden(None) => {
                return Err(eg!(ZeiError::ParameterError));
            }
            _ => {}
        }
    }
    transcript.append_proof_commitment(&commitment);
    let challenge = transcript.get_challenge::<P::ScalarField>();
    let response_t = challenge.mul(t).add(&beta1); // challente*t + beta1
    let response_sk = challenge.mul(&user_sk.0).add(&beta2);
    let mut response_attrs = vec![];
    let mut gamma_iter = gamma.iter();
    for attr_enum in attrs {
        if let Attribute::Hidden(Some(attr)) = attr_enum {
            let gamma = gamma_iter.next().unwrap(); // safe unwrap()
            let resp_attr_i = challenge.mul(attr).add(gamma);
            response_attrs.push(resp_attr_i);
        }
    }
    Ok(ACPoK {
        commitment,
        response_t,
        response_sk,
        response_attrs,
    })
}

#[allow(non_snake_case)]
fn ac_verify_final_check<P: Pairing>(
    sig_commitment: &ACCommitment<P::G1>,
    challenge: &P::ScalarField,
    G2: &P::G2,
    p: &P::G2,
) -> Result<()> {
    let lhs = P::pairing(&sig_commitment.0.sigma1, p);
    let rhs = P::pairing(&sig_commitment.0.sigma2.mul(challenge), G2);

    if lhs == rhs {
        Ok(())
    } else {
        Err(eg!(ZeiError::IdentityRevealVerifyError))
    }
}

#[cfg(test)]
pub(crate) mod credentials_tests {
    use super::*;
    use algebra::bls12_381::Bls12381;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use rmp_serde::Deserializer;
    use serde::{Deserialize, Serialize};
    extern crate typenum;
    use typenum::U8;

    fn check_ac_sign<P: Pairing>(bitmap: &[bool]) {
        let n = bitmap.len();
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let issuer_keypair = super::ac_keygen_issuer::<_, P>(&mut prng, n);
        let issuer_pk = &issuer_keypair.0;
        let issuer_sk = &issuer_keypair.1;
        let (user_pk, _user_sk) = super::ac_user_key_gen::<_, P>(&mut prng, issuer_pk);

        let mut attrs = vec![];

        for _ in bitmap.iter() {
            attrs.push(P::ScalarField::random(&mut prng));
        }

        let sig = super::ac_sign::<_, P>(&mut prng, &issuer_sk, &user_pk, &attrs);
        assert!(sig.is_ok());

        if n > 1 {
            let sig_error =
                super::ac_sign::<_, P>(&mut prng, &issuer_sk, &user_pk, &attrs[0..0]);
            assert!(sig_error.is_err());
        }
    }

    fn do_test_keygen_issuer<P: Pairing>() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);

        let _ = super::ac_keygen_issuer::<_, P>(&mut prng, 5);
        let _ = super::ac_keygen_issuer::<_, P>(&mut prng, 0);
    }

    #[test]
    fn test_key_gen_issuer() {
        do_test_keygen_issuer::<Bls12381>();
    }

    #[test]
    fn test_ac_sign() {
        for i in 0..16i32 {
            let bit_array = bit_array::BitArray::<u32, U8>::from_bytes(&i.to_be_bytes());

            let mut bool_vector = vec![];
            for i in 0..bit_array.len() {
                bool_vector.push(bit_array.get(i).unwrap());
            }

            check_ac_sign::<Bls12381>(bool_vector.as_slice());
        }
    }

    fn reveal<P: Pairing>(bitmap: &[bool]) {
        let n = bitmap.len();
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let issuer_keypair = super::ac_keygen_issuer::<_, P>(&mut prng, n);
        let issuer_pk = &issuer_keypair.0;
        let issuer_sk = &issuer_keypair.1;
        let (user_pk, user_sk) = super::ac_user_key_gen::<_, P>(&mut prng, issuer_pk);

        let mut attrs = vec![];

        for _ in bitmap.iter() {
            attrs.push(P::ScalarField::random(&mut prng));
        }

        let sig =
            super::ac_sign::<_, P>(&mut prng, &issuer_sk, &user_pk, attrs.as_slice())
                .unwrap();

        let credential = Credential {
            signature: sig,
            attributes: attrs,
            issuer_pub_key: issuer_pk.clone(),
        };

        let reveal_sig =
            super::ac_reveal::<_, P>(&mut prng, &user_sk, &credential, bitmap).unwrap();

        let revealed_attributes = credential
            .attributes
            .iter()
            .zip(bitmap.iter())
            .map(|(a, b)| {
                if *b {
                    Attribute::Revealed(a.clone())
                } else {
                    Attribute::Hidden(None)
                }
            })
            .collect_vec();
        assert_eq!(
            true,
            ac_verify::<P>(
                &issuer_pk,
                revealed_attributes.as_slice(),
                &reveal_sig.sig_commitment,
                &reveal_sig.pok
            )
            .is_ok()
        )
    }

    pub fn no_attributes<P: Pairing>() {
        reveal::<P>(&[]);
    }

    pub fn single_attribute<P: Pairing>() {
        reveal::<P>(&[false]);
        reveal::<P>(&[true]);
    }

    pub fn two_attributes<P: Pairing>() {
        reveal::<P>(&[false, false]);
        reveal::<P>(&[true, false]);
        reveal::<P>(&[false, true]);
        reveal::<P>(&[true, true]);
    }

    pub fn ten_attributes<P: Pairing>() {
        reveal::<P>(&[false; 10]);
        reveal::<P>(&[
            true, false, true, false, true, false, true, false, true, false,
        ]);
        reveal::<P>(&[
            false, true, false, true, false, true, false, true, false, true,
        ]);
        reveal::<P>(&[true; 10]);
    }

    #[test]
    pub fn test_attributes() {
        no_attributes::<Bls12381>();
        single_attribute::<Bls12381>();
        two_attributes::<Bls12381>();
        ten_attributes::<Bls12381>();
    }

    pub fn to_json_credential_structures<P: Pairing>() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);

        let num_attributes = 10;

        //issuer keys
        let issuer_keys = ac_keygen_issuer::<_, P>(&mut prng, num_attributes);
        let json_str = serde_json::to_string(&issuer_keys.0).unwrap();
        let issuer_pub_key_de: ACIssuerPublicKey<P::G1, P::G2> =
            serde_json::from_str(&json_str).unwrap();
        assert_eq!(issuer_keys.0, issuer_pub_key_de);

        let json_str = serde_json::to_string(&issuer_keys.1).unwrap();
        let issuer_sec_key_de: ACIssuerSecretKey<P::G1, P::ScalarField> =
            serde_json::from_str(&json_str).unwrap();
        assert_eq!(issuer_keys.1, issuer_sec_key_de);

        //user keys
        let user_keys = super::ac_user_key_gen::<_, P>(&mut prng, &issuer_keys.0);
        let json_str = serde_json::to_string(&user_keys.0).unwrap();
        let user_pub_key_de: ACUserPublicKey<P::G1> =
            serde_json::from_str(&json_str).unwrap();
        assert_eq!(user_keys.0, user_pub_key_de);

        let json_str = serde_json::to_string(&user_keys.1).unwrap();
        let user_sec_key_de: ACUserSecretKey<P::ScalarField> =
            serde_json::from_str(&json_str).unwrap();
        assert_eq!(user_keys.1, user_sec_key_de);

        // reveal proof containing signature and pok
        let attrs = vec![P::ScalarField::from_u32(10); num_attributes];
        let sig = super::ac_sign::<_, P>(
            &mut prng,
            &issuer_keys.1,
            &user_keys.0,
            attrs.as_slice(),
        )
        .unwrap();
        let credential = Credential {
            signature: sig,
            attributes: attrs,
            issuer_pub_key: issuer_keys.0,
        };
        let reveal_sig = super::ac_reveal::<_, P>(
            &mut prng,
            &user_keys.1,
            &credential,
            &[
                true, false, true, false, true, false, true, false, true, false,
            ],
        )
        .unwrap();
        let json_str = serde_json::to_string(&reveal_sig).unwrap();
        let reveal_sig_de: ACRevealSig<P::G1, P::G2, P::ScalarField> =
            serde_json::from_str(&json_str).unwrap();
        assert_eq!(reveal_sig, reveal_sig_de);
    }

    #[test]
    fn test_to_json_credential_structures() {
        to_json_credential_structures::<Bls12381>();
    }

    pub fn to_msg_pack_credential_structures<P: Pairing>() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);

        let num_attributes = 10;
        //issuer keys
        let issuer_keys = ac_keygen_issuer::<_, P>(&mut prng, num_attributes);
        let mut vec = vec![];
        issuer_keys
            .0
            .serialize(&mut rmp_serde::Serializer::new(&mut vec))
            .unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let issuer_pub_key_de: ACIssuerPublicKey<P::G1, P::G2> =
            Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(issuer_keys.0, issuer_pub_key_de);

        let mut vec = vec![];
        issuer_keys
            .1
            .serialize(&mut rmp_serde::Serializer::new(&mut vec))
            .unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let issuer_priv_key_de: ACIssuerSecretKey<P::G1, P::ScalarField> =
            Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(issuer_keys.1, issuer_priv_key_de);

        //user keys
        let user_keys = super::ac_user_key_gen::<_, P>(&mut prng, &issuer_keys.0);
        let mut vec = vec![];
        user_keys
            .0
            .serialize(&mut rmp_serde::Serializer::new(&mut vec))
            .unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let user_pub_key_de: ACUserPublicKey<P::G1> =
            Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(user_keys.0, user_pub_key_de);

        let mut vec = vec![];
        user_keys
            .1
            .serialize(&mut rmp_serde::Serializer::new(&mut vec))
            .unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let user_priv_key_de: ACUserSecretKey<P::ScalarField> =
            Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(user_keys.1, user_priv_key_de);

        // reveal proof containing signature and pok
        let attrs = vec![P::ScalarField::from_u32(10); num_attributes];
        let sig = super::ac_sign::<_, P>(
            &mut prng,
            &issuer_keys.1,
            &user_keys.0,
            attrs.as_slice(),
        )
        .unwrap();
        let credential = Credential {
            signature: sig,
            attributes: attrs,
            issuer_pub_key: issuer_keys.0,
        };
        let reveal_sig = super::ac_reveal::<_, P>(
            &mut prng,
            &user_keys.1,
            &credential,
            &[
                true, false, true, false, true, false, true, false, true, false,
            ],
        )
        .unwrap();

        let mut vec = vec![];
        reveal_sig
            .serialize(&mut rmp_serde::Serializer::new(&mut vec))
            .unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let reveal_sig_de: ACRevealSig<P::G1, P::G2, P::ScalarField> =
            Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(reveal_sig, reveal_sig_de);
    }

    #[test]
    fn test_to_msg_pack_credential_structures() {
        to_msg_pack_credential_structures::<Bls12381>();
    }
}
