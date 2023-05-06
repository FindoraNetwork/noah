//! Anonymous credentials enable a credential issuer to issue a credential (with some attributes)
//! to a user, and the user can later, with anonymity, selectively disclose some attributes.

use crate::{confidential_anon_creds::CACTranscript, matrix_sigma::SigmaTranscript};
use merlin::Transcript;
use noah_algebra::{prelude::*, traits::Pairing};
use serde_derive::{Deserialize, Serialize};

pub(crate) const REVEAL_PROOF_DOMAIN: &[u8] = b"AC Reveal PoK";
pub(crate) const REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE: &[u8] = b"AC Reveal PoK Instance";
pub(crate) const COMMIT_NEW_TRANSCRIPT_INSTANCE: &[u8] = b"AC Commit SoK Instance";
pub(crate) const POK_LABEL: &[u8] = b"Signature Message";

/// Credential issuer public key (`ipk`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIssuerPK<G1, G2> {
    /// The public generator in `G2`.
    pub gen2: G2,
    /// The public parameter `x G2`.
    pub xx2: G2,
    /// The public parameter `z G1`.
    pub zz1: G1,
    /// The public parameter `x G2`.
    pub zz2: G2,
    /// The public parameter for each attribute, `y[i] G2`.
    pub yy2: Vec<G2>,
}

impl<G1: Group, G2: Group> CredentialIssuerPK<G1, G2> {
    /// Return the number of attributes supported by this credential issuer's public key.
    pub fn num_attrs(&self) -> usize {
        self.yy2.len()
    }
}

/// Credential issue secret key (`isk`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIssuerSK<G1, S> {
    /// The secret generator in `G1`.
    pub gen1: G1,
    /// The secret value `x`.
    pub x: S,
    /// The secret key for individual attributes.
    pub y: Vec<S>,
}

/// Credential signature (`\sigma`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSig<G1> {
    /// First element of the signature.
    pub sigma1: G1,
    /// Second element of the signature.
    pub sigma2: G1,
}

impl<G: Group> Default for CredentialSig<G> {
    fn default() -> CredentialSig<G> {
        CredentialSig {
            sigma1: G::get_identity(),
            sigma2: G::get_identity(),
        }
    }
}

/// Credential data structure: credential signature, attribute, and the issuer public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential<G1, G2, AttrType> {
    /// The credential signature.
    pub sig: CredentialSig<G1>,
    /// The list of all attributes.
    pub attrs: Vec<AttrType>,
    /// The issuer public key.
    pub ipk: CredentialIssuerPK<G1, G2>,
}

impl<G1: Group, G2: Group, AttrType: Copy> Credential<G1, G2, AttrType> {
    /// Apply the reveal map to get revealed attributes.
    pub fn get_revealed_attributes(&self, reveal_map: &[bool]) -> Result<Vec<AttrType>> {
        if reveal_map.len() != self.attrs.len() {
            return Err(eg!(NoahError::ParameterError));
        }
        Ok(self
            .attrs
            .iter()
            .zip(reveal_map)
            .filter(|(_, b)| *(*b))
            .map(|(a, _)| *a)
            .collect())
    }
}

/// Credential commitment attached to specific data (`cm`),
/// which is a randomized version of the signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialComm<G1>(pub(crate) CredentialSig<G1>);

impl<G1: Group> Default for CredentialComm<G1> {
    fn default() -> Self {
        Self(CredentialSig::<G1>::default())
    }
}

impl<G1: Group> CredentialComm<G1> {
    /// Derive the commitment from the credential signature and the randomizer.
    pub fn new(sig: &CredentialSig<G1>, rand: &CredentialCommRandomizer<G1::ScalarType>) -> Self {
        let sigma1_r = sig.sigma1.mul(&rand.r);
        let sigma2_r = sig.sigma2.add(&sig.sigma1.mul(&rand.t)).mul(&rand.r);
        // sigma2: r * (sigma2 + t * sigma1)

        Self(CredentialSig::<G1> {
            sigma1: sigma1_r,
            sigma2: sigma2_r,
        })
    }
}

/// User public key (`upk`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialUserPK<G1>(pub(crate) G1);

/// User secret key (`usk`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialUserSK<S>(pub(crate) S);

/// Proof of selective disclosure of the attributes inside a signature `\sigma`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSigOpenProof<G1, G2, S> {
    /// The credential commitment.
    pub cm: CredentialComm<G1>,
    /// The opening proof.
    pub proof_open: CredentialPoK<G2, S>,
}

/// Proof that revealed attributes verify a credential commitment signature.
pub type CredentialCommOpenProof<G2, S> = CredentialPoK<G2, S>;

/// Proof of knowledge for t, sk (UserSecretKey), and hidden attributes that satisfy a
/// certain relation..
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPoK<G2, S> {
    pub(crate) blinding: G2, // r_t * G2 + r_sk * Z2 + sum_{a_i in hidden attrs} r_{a_i} * Y2_i
    pub(crate) response_t: S, // c * t + r_t
    pub(crate) response_sk: S, // c * sk + r_sk
    pub(crate) response_attrs: Vec<S>, // {c * a_i + r_{a_i}; a_i in hidden}
}

#[derive(Clone)]
/// An attribute in the anonymous credential scheme.
pub enum Attribute<AttrType: Copy> {
    /// A revealed attribute.
    Revealed(AttrType),
    /// A hidden attribute.
    /// The prover must provide the attribute value, but the verifier does not.
    Hidden(Option<AttrType>),
}

/// Randomizer used in the commitment scheme for credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialCommRandomizer<S> {
    /// The first randomizer value.
    pub r: S,
    /// The second randomizer value.
    pub t: S,
}

/// The commitment scheme output.
pub type CommOutput<G1, G2, S> = (
    CredentialComm<G1>,
    CredentialPoK<G2, S>,
    Option<CredentialCommRandomizer<S>>,
);

/// Each credential issuer can generate a pair of keys, where the issuer secret key `isk` is used to
/// issue attributes to a specific user, and the issuer public key `ipk` is used by the public to
/// verify the issued attributes of a given user.
pub fn issuer_keygen<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    num_attrs: usize,
) -> (
    CredentialIssuerSK<P::G1, P::ScalarField>,
    CredentialIssuerPK<P::G1, P::G2>,
) {
    let x = P::ScalarField::random(prng);
    let z = P::ScalarField::random(prng);
    let gen1: P::G1 = P::G1::random(prng);
    let gen2 = P::G2::random(prng);
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
        CredentialIssuerSK { gen1, x, y },
        CredentialIssuerPK {
            gen2,
            xx2,
            zz1,
            zz2,
            yy2,
        },
    )
}

/// Each user can create a pair of keys `(usk, upk)` under a specific issuer. The user secret key
/// `usk` is used to claim ownership of an issued credential. The user public key `upk` is used by
/// the public to verify such a claim.
pub fn user_keygen<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    ipk: &CredentialIssuerPK<P::G1, P::G2>,
) -> (CredentialUserSK<P::ScalarField>, CredentialUserPK<P::G1>) {
    let sk = P::ScalarField::random(prng);
    let pk = ipk.zz1.mul(&sk);
    (CredentialUserSK(sk), CredentialUserPK(pk))
}

/// The credential issuer can use the issuer secret key `isk` to grant a number of attributes (the
/// contents of the attributes are described in `\vec{attrs}` to a user, given this user's public
/// key `upk`.
pub fn grant_credential<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    isk: &CredentialIssuerSK<P::G1, P::ScalarField>,
    upk: &CredentialUserPK<P::G1>,
    attrs: &[P::ScalarField],
) -> Result<CredentialSig<P::G1>> {
    let number_attributes_from_issuer_sk = isk.y.len();
    let n = attrs.len();
    if number_attributes_from_issuer_sk != n {
        return Err(eg!(NoahError::AnonymousCredentialSignError));
    }

    let u = P::ScalarField::random(prng);
    let mut exponent = isk.x;
    for (attr, yi) in attrs.iter().zip(isk.y.iter()) {
        exponent = exponent.add(&attr.mul(yi));
    }
    let cc = isk.gen1.mul(&exponent);
    Ok(CredentialSig::<P::G1> {
        sigma1: isk.gen1.mul(&u),
        sigma2: upk.0.add(&cc).mul(&u),
    })
}

/// Selectively reveal the attributes within the credential that is granted by the credential issuer
/// with public key `ipk`.
pub fn open_credential<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    usk: &CredentialUserSK<P::ScalarField>,
    credential: &Credential<P::G1, P::G2, P::ScalarField>,
    reveal_map: &[bool],
) -> Result<CredentialSigOpenProof<P::G1, P::G2, P::ScalarField>> {
    let rand = randomizer_gen::<_, P>(prng);
    let cm = CredentialComm::<P::G1>::new(&credential.sig, &rand);

    let proof_open = open_comm::<_, P>(prng, usk, credential, &cm, &rand, reveal_map)?;

    Ok(CredentialSigOpenProof { cm, proof_open })
}

/// Sample a randomizer used to generate a commitment from the signature.
pub fn randomizer_gen<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
) -> CredentialCommRandomizer<P::ScalarField> {
    CredentialCommRandomizer {
        r: P::ScalarField::random(prng),
        t: P::ScalarField::random(prng),
    }
}

/// Credential commitment associated with a message.
pub fn commit_without_randomizer<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    usk: &CredentialUserSK<P::ScalarField>,
    credential: &Credential<P::G1, P::G2, P::ScalarField>,
    m: &[u8],
) -> Result<CommOutput<P::G1, P::G2, P::ScalarField>> {
    let rand = randomizer_gen::<_, P>(prng);
    let output = commit::<_, P>(prng, usk, credential, &rand, m).c(d!())?;
    let cm = output.0;
    let proof_valid = output.1;

    Ok((cm, proof_valid, Some(rand)))
}

/// Commit a credential over a message `m` under the credential `\sigma`, the user secret key `usk`,
/// and randomizer `rand`. The signature `\sigma` corresponds to the attributes in `\vec{attrs}`,
/// granted by the credential issuer with public key `ipk`. The output is a commitment `cm` and a
/// validity proof `\pi_{valid}`.
pub fn commit<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    usk: &CredentialUserSK<P::ScalarField>,
    credential: &Credential<P::G1, P::G2, P::ScalarField>,
    rand: &CredentialCommRandomizer<P::ScalarField>,
    m: &[u8],
) -> Result<CommOutput<P::G1, P::G2, P::ScalarField>> {
    let hidden_attrs = credential
        .attrs
        .iter()
        .map(|attr| Attribute::Hidden(Some(*attr)))
        .collect_vec(); // all hidden

    let cm = CredentialComm::<P::G1>::new(&credential.sig, rand);
    let mut transcript = Transcript::new(COMMIT_NEW_TRANSCRIPT_INSTANCE);
    init_pok_transcript::<P>(&mut transcript, &credential.ipk, &cm);
    transcript.append_message(POK_LABEL, m);
    let proof_valid = prove_pok::<_, P>(
        &mut transcript,
        prng,
        usk,
        &credential.ipk,
        &rand.t,
        hidden_attrs.as_slice(),
    )
    .c(d!())?;

    Ok((cm, proof_valid, None))
}

/// Check if a commitment is valid; that is, if it commits to a credential issued by `ipk`.
pub fn check_comm<P: Pairing>(
    ipk: &CredentialIssuerPK<P::G1, P::G2>,
    cm: &CredentialComm<P::G1>,
    proof_valid: &CredentialPoK<P::G2, P::ScalarField>,
    m: &[u8],
) -> Result<()> {
    let mut transcript = Transcript::new(COMMIT_NEW_TRANSCRIPT_INSTANCE);
    init_pok_transcript::<P>(&mut transcript, ipk, cm);
    transcript.append_message(POK_LABEL, m);

    transcript.append_proof_commitment(&proof_valid.blinding);
    let challenge = transcript.get_challenge::<P::ScalarField>();

    let attrs: Vec<Attribute<P::ScalarField>> = vec![Attribute::Hidden(None); ipk.num_attrs()];

    verify_pok::<P>(ipk, cm, proof_valid, attrs.as_slice(), &challenge)
}

/// Selectively reveal some attributes of the credential previously committed, where `\sigma` is
/// the signature of attributes signed by the credential provider, `rand` is the randomizer,
/// `\vec{attrs}` represents the user's attributes, and `\vec{reveal_map}` is the binary vector
/// indicating whether or not an attribute is revealed.
pub fn open_comm<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    usk: &CredentialUserSK<P::ScalarField>,
    credential: &Credential<P::G1, P::G2, P::ScalarField>,
    cm: &CredentialComm<P::G1>,
    rand: &CredentialCommRandomizer<P::ScalarField>,
    reveal_map: &[bool],
) -> Result<CredentialCommOpenProof<P::G2, P::ScalarField>> {
    if credential.attrs.len() != reveal_map.len() {
        return Err(eg!(NoahError::ParameterError));
    }

    let revealed_attrs = credential
        .attrs
        .iter()
        .zip(reveal_map.iter())
        .map(|(attr, b)| {
            if *b {
                Attribute::Revealed(*attr)
            } else {
                Attribute::Hidden(Some(*attr))
            }
        })
        .collect_vec();

    let mut transcript = Transcript::new(REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
    init_pok_transcript::<P>(&mut transcript, &credential.ipk, &cm); // public parameters
    let pok = prove_pok::<_, P>(
        &mut transcript,
        prng,
        usk,
        &credential.ipk,
        &rand.t,
        revealed_attrs.as_slice(),
    )
    .c(d!())?;

    Ok(pok)
}

/// Given a commitment `cm`, the message `m`, the revealing proof `\pi`, the claimed attributes
/// `\vec{attrs}`, and a vector indicating revealed attributes `\vec{reveal_map}`, this function
/// checks if the claimed attributes are indeed signed by the credential issuer (with the public
/// key `ipk`) over the credential committed in `cm`.
pub fn verify_open<P: Pairing>(
    ipk: &CredentialIssuerPK<P::G1, P::G2>,
    cm: &CredentialComm<P::G1>,
    proof_open: &CredentialCommOpenProof<P::G2, P::ScalarField>,
    attrs: &[Attribute<P::ScalarField>],
) -> Result<()> {
    let mut transcript = Transcript::new(REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
    init_pok_transcript::<P>(&mut transcript, ipk, cm);

    transcript.append_proof_commitment(&proof_open.blinding);
    let challenge = transcript.get_challenge::<P::ScalarField>();

    verify_pok::<P>(ipk, cm, proof_open, attrs, &challenge)
}

pub(super) fn init_pok_transcript<P: Pairing>(
    transcript: &mut Transcript,
    ipk: &CredentialIssuerPK<P::G1, P::G2>,
    cm: &CredentialComm<P::G1>,
) {
    let g1 = P::G1::get_base();
    let g2 = P::G2::get_base();
    let g1_elems = vec![&g1, &ipk.zz1, &cm.0.sigma1, &cm.0.sigma2];
    let mut g2_elems = vec![&g2, &ipk.gen2, &ipk.xx2, &ipk.zz2];
    for e in ipk.yy2.iter() {
        g2_elems.push(e);
    }
    transcript.init_sigma_pairing::<P>(REVEAL_PROOF_DOMAIN, &g1_elems[..], g2_elems.as_slice());
}

/// Internal function for generating a proof of knowledge.
fn prove_pok<R: CryptoRng + RngCore, P: Pairing>(
    transcript: &mut Transcript,
    prng: &mut R,
    usk: &CredentialUserSK<P::ScalarField>,
    ipk: &CredentialIssuerPK<P::G1, P::G2>,
    t: &P::ScalarField,
    attrs: &[Attribute<P::ScalarField>],
) -> Result<CredentialPoK<P::G2, P::ScalarField>> {
    let beta1 = P::ScalarField::random(prng);
    let beta2 = P::ScalarField::random(prng);
    let mut gamma = vec![];
    let mut blinding = ipk.gen2.mul(&beta1).add(&ipk.zz2.mul(&beta2));
    for (yy2i, attr) in ipk.yy2.iter().zip(attrs) {
        match attr {
            Attribute::Hidden(Some(_)) => {
                let gamma_i = P::ScalarField::random(prng);
                let elem = yy2i.mul(&gamma_i);
                blinding = blinding.add(&elem);
                gamma.push(gamma_i);
            }
            Attribute::Hidden(None) => {
                return Err(eg!(NoahError::ParameterError));
            }
            _ => {}
        }
    }
    transcript.append_proof_commitment(&blinding);
    let challenge = transcript.get_challenge::<P::ScalarField>();
    let response_t = challenge.mul(t).add(&beta1); // challenge*t + beta1
    let response_sk = challenge.mul(&usk.0).add(&beta2);
    let mut response_attrs = vec![];
    let mut gamma_iter = gamma.iter();
    for attr_enum in attrs {
        if let Attribute::Hidden(Some(attr)) = attr_enum {
            let gamma = gamma_iter.next().unwrap(); // safe unwrap()
            let resp_attr_i = challenge.mul(*attr).add(gamma);
            response_attrs.push(resp_attr_i);
        }
    }
    Ok(CredentialPoK {
        blinding,
        response_t,
        response_sk,
        response_attrs,
    })
}

/// Internal function for verify a proof of knowledge.
pub(crate) fn verify_pok<P: Pairing>(
    ipk: &CredentialIssuerPK<P::G1, P::G2>,
    cm: &CredentialComm<P::G1>,
    proof_open: &CredentialPoK<P::G2, P::ScalarField>,
    attrs: &[Attribute<P::ScalarField>],
    challenge: &P::ScalarField,
) -> Result<()> {
    // p = X_2*c - proof_blinding + &G2 * r_t + Z2 * r_sk + \sum r_attr_i * Y2_i;
    let minus_one: P::ScalarField = P::ScalarField::one().neg();
    let mut scalars = vec![
        &proof_open.response_t,  // G2
        challenge,               // X2
        &proof_open.response_sk, // Z2
        &minus_one,              // Commitment
    ];

    let mut resp_attr_iter = proof_open.response_attrs.iter();

    let attrs_times_challenge = attrs
        .iter()
        .map(|attr| match attr {
            Attribute::Revealed(attr) => Some(attr.mul(challenge)),
            _ => None,
        })
        .collect_vec();
    for attr in attrs_times_challenge.iter() {
        match attr {
            Some(a) => {
                scalars.push(a);
            }
            None => {
                let response = resp_attr_iter.next().c(d!(NoahError::ParameterError))?;
                scalars.push(response);
            }
        }
    }
    let mut elems = vec![&ipk.gen2, &ipk.xx2, &ipk.zz2, &proof_open.blinding];

    for y in ipk.yy2.iter() {
        elems.push(y);
    }
    let p = P::G2::multi_exp(scalars.as_slice(), elems.as_slice());

    let lhs = P::pairing(&cm.0.sigma1, &p);
    let rhs = P::pairing(&cm.0.sigma2.mul(challenge), &ipk.gen2);

    if lhs == rhs {
        Ok(())
    } else {
        Err(eg!(NoahError::IdentityRevealVerifyError))
    }
}

#[cfg(test)]
pub(crate) mod credentials_tests {
    use super::*;
    use crate::anon_creds::Attribute::{Hidden, Revealed};
    use noah_algebra::bls12_381::BLSPairingEngine;

    fn check_signatures<P: Pairing>(n: usize) {
        let mut prng = test_rng();

        let ikeypair = issuer_keygen::<_, P>(&mut prng, n);
        let isk = &ikeypair.0;
        let ipk = &ikeypair.1;
        let (_, upk) = user_keygen::<_, P>(&mut prng, ipk);

        let mut attrs = vec![];
        for _ in 0..n {
            attrs.push(P::ScalarField::random(&mut prng));
        }

        let sig = grant_credential::<_, P>(&mut prng, &isk, &upk, &attrs);
        assert!(sig.is_ok());

        if n > 1 {
            let error = grant_credential::<_, P>(&mut prng, &isk, &upk, &attrs[0..0]);
            assert!(error.is_err());
        }
    }

    #[test]
    fn test_issuer_keygen() {
        let mut prng = test_rng();

        let _ = issuer_keygen::<_, BLSPairingEngine>(&mut prng, 5);
        let _ = issuer_keygen::<_, BLSPairingEngine>(&mut prng, 0);
    }

    #[test]
    fn test_signing() {
        for n in 0..16 {
            check_signatures::<BLSPairingEngine>(n);
        }
    }

    fn reveal(reveal_map: &[bool]) {
        type P = BLSPairingEngine;
        let n = reveal_map.len();
        let mut prng = test_rng();

        let ikeypair = issuer_keygen::<_, P>(&mut prng, n);
        let isk = &ikeypair.0;
        let ipk = &ikeypair.1;
        let (usk, upk) = user_keygen::<_, P>(&mut prng, ipk);

        let mut attrs = vec![];
        for _ in reveal_map.iter() {
            attrs.push(<P as Pairing>::ScalarField::random(&mut prng));
        }

        let sig = grant_credential::<_, P>(&mut prng, &isk, &upk, attrs.as_slice()).unwrap();

        let credential = Credential {
            sig,
            attrs,
            ipk: ipk.clone(),
        };

        let reveal_sig = open_credential::<_, P>(&mut prng, &usk, &credential, reveal_map).unwrap();

        let revealed_attrs = credential
            .attrs
            .iter()
            .zip(reveal_map.iter())
            .map(|(a, b)| if *b { Revealed(*a) } else { Hidden(None) })
            .collect_vec();

        assert_eq!(
            true,
            verify_open::<P>(
                &ipk,
                &reveal_sig.cm,
                &reveal_sig.proof_open,
                revealed_attrs.as_slice()
            )
            .is_ok()
        )
    }

    pub(crate) fn no_attributes() {
        reveal(&[]);
    }

    pub(crate) fn single_attribute() {
        reveal(&[false]);
        reveal(&[true]);
    }

    pub(crate) fn two_attributes() {
        reveal(&[false, false]);
        reveal(&[true, false]);
        reveal(&[false, true]);
        reveal(&[true, true]);
    }

    pub(crate) fn ten_attributes() {
        reveal(&[false; 10]);
        reveal(&[
            true, false, true, false, true, false, true, false, true, false,
        ]);
        reveal(&[
            false, true, false, true, false, true, false, true, false, true,
        ]);
        reveal(&[true; 10]);
    }

    #[test]
    pub(crate) fn test_attributes() {
        no_attributes();
        single_attribute();
        two_attributes();
        ten_attributes();
    }
}
