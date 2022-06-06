use crate::anon_creds::{
    verify_pok, Attribute,
    Attribute::{Hidden, Revealed},
    Credential, CredentialComm, CredentialCommRandomizer, CredentialIssuerPK, CredentialPoK,
    CredentialUserSK, POK_LABEL,
};
use crate::basic::{
    elgamal::{elgamal_encrypt, ElGamalCiphertext, ElGamalEncKey},
    matrix_sigma::SigmaTranscript,
};
use merlin::Transcript;
use zei_algebra::{prelude::*, traits::Pairing};

const CAC_REVEAL_PROOF_DOMAIN: &[u8] = b"Confidential AC Reveal PoK";
const CAC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE: &[u8] = b"Confidential AC Reveal PoK New Instance";

/// The transcript methods used in confidential anonymous credentials.
pub trait CACTranscript {
    /// Append the public parameters for EC pairing.
    fn init_sigma_pairing<P: Pairing>(
        &mut self,
        instance_name: &'static [u8],
        g1: &[&P::G1],
        g2: &[&P::G2],
    );
    /// Append the information for the confidential anonymous credentials.
    fn cac_init<P: Pairing>(
        &mut self,
        ipk: &CredentialIssuerPK<P::G1, P::G2>,
        ek: &ElGamalEncKey<P::G1>,
        cm: &CredentialComm<P::G1>,
        ct: &[ElGamalCiphertext<P::G1>],
    );
    /// Append the issuer PK to the transcript.
    fn append_issuer_pk<P: Pairing>(&mut self, ipk: &CredentialIssuerPK<P::G1, P::G2>);
    /// Append an ElGamal encryption key to the transcript.
    fn append_encryption_key<P: Pairing>(&mut self, ek: &ElGamalEncKey<P::G1>);
    /// Append an ElGamal ciphertext to the transcript.
    fn append_ciphertext<P: Pairing>(&mut self, ct: &ElGamalCiphertext<P::G1>);
    /// Append a commitment to the transcript.
    fn append_commitment<P: Pairing>(&mut self, cm: &CredentialComm<P::G1>);
}

impl CACTranscript for Transcript {
    fn init_sigma_pairing<P: Pairing>(
        &mut self,
        instance_name: &'static [u8],
        g1: &[&P::G1],
        g2: &[&P::G2],
    ) {
        self.append_message(
            b"Sigma Protocol domain",
            b"Sigma protocol with pairings elements",
        );
        self.append_message(b"Sigma Protocol instance", instance_name);
        for elem in g1 {
            self.append_message(b"public elem g1", elem.to_compressed_bytes().as_slice())
        }
        for elem in g2 {
            self.append_message(b"public elem g2", elem.to_compressed_bytes().as_slice())
        }
    }
    fn cac_init<P: Pairing>(
        &mut self,
        ipk: &CredentialIssuerPK<P::G1, P::G2>,
        ek: &ElGamalEncKey<P::G1>,
        cm: &CredentialComm<P::G1>,
        cts: &[ElGamalCiphertext<P::G1>],
    ) {
        self.append_message(b"New Domain", CAC_REVEAL_PROOF_DOMAIN);
        self.append_group_element(b"G1", &P::G1::get_base());
        self.append_group_element(b"G2", &P::G2::get_base());
        self.append_issuer_pk::<P>(ipk);
        self.append_encryption_key::<P>(ek);
        self.append_commitment::<P>(cm);
        for ctext in cts.iter() {
            self.append_ciphertext::<P>(ctext);
        }
    }
    fn append_issuer_pk<P: Pairing>(&mut self, ipk: &CredentialIssuerPK<P::G1, P::G2>) {
        self.append_group_element(b"ipk.G2", &ipk.gen2);
        self.append_group_element(b"ipk.Z1", &ipk.zz1);
        self.append_group_element(b"ipk.Z2", &ipk.zz2);
        self.append_group_element(b"ipk.X2", &ipk.xx2);
        for y2 in ipk.yy2.iter() {
            self.append_group_element(b"ipk.Y2", y2);
        }
    }
    fn append_encryption_key<P: Pairing>(&mut self, ek: &ElGamalEncKey<P::G1>) {
        self.append_group_element(b"encryption key", &ek.0);
    }
    fn append_ciphertext<P: Pairing>(&mut self, ct: &ElGamalCiphertext<P::G1>) {
        self.append_group_element(b"ct.e1", &ct.e1);
        self.append_group_element(b"ct.e2", &ct.e2);
    }
    fn append_commitment<P: Pairing>(&mut self, cm: &CredentialComm<P::G1>) {
        self.append_group_element(b"sigma1", &cm.0.sigma1);
        self.append_group_element(b"sigma2", &cm.0.sigma2);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Confidential anonymous credential reveal proof
pub struct CACPoK<G1, G2, S> {
    /// The proof of knowledge.
    pub pok: CredentialPoK<G2, S>,
    /// The randomizers for the individual attributes.
    pub cm_ct: Vec<ElGamalCiphertext<G1>>,
    /// The responses for individual attributes.
    pub response_rands: Vec<S>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Confidential anonymous credentials (attributes and a proof).
pub struct ConfidentialAC<G1, G2, S> {
    /// The ciphertexts of the revealed attributes.
    pub cts: Vec<ElGamalCiphertext<G1>>,
    /// The proof of knowledge.
    pub pok: CACPoK<G1, G2, S>,
}

impl<G1: Group, G2: Group, S: Scalar> ConfidentialAC<G1, G2, S> {
    /// Obtain the field elements
    pub fn get_fields(self) -> (Vec<ElGamalCiphertext<G1>>, CACPoK<G1, G2, S>) {
        (self.cts, self.pok)
    }
}

/// Selectively open some attributes committed in `cm` to ciphertexts, where `\vec{attrs}` lists
/// the attributes, `cm` is the commitment, `rand` is the randomizer used in the commitment,
/// `\vec{reveal_map}` describes whether an attribute should be revealed or not, `ek` is the
/// encryption key, and `m`is the message committed along with the commitment. It outputs the
/// ciphertexts `\vec{ct}` and an opening proof `\pi_{open}`$`.
pub fn confidential_open_comm<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    usk: &CredentialUserSK<P::ScalarField>,
    credential: &Credential<P::G1, P::G2, P::ScalarField>,
    cm: &CredentialComm<P::G1>,
    rand: &CredentialCommRandomizer<P::ScalarField>,
    reveal_map: &[bool],
    ek: &ElGamalEncKey<P::G1>,
    m: &[u8],
) -> Result<ConfidentialAC<P::G1, P::G2, P::ScalarField>> {
    // 1. create ciphertext for all revealed attributes
    let mut cts = vec![];
    let mut ct_rands = vec![];
    let mut revealed_attrs = vec![];
    if credential.attrs.len() != reveal_map.len() {
        return Err(eg!(ZeiError::ParameterError));
    }
    for (attr, b) in credential.attrs.iter().zip(reveal_map.iter()) {
        if *b {
            let r = P::ScalarField::random(prng);
            let ct = elgamal_encrypt::<P::G1>(attr, &r, ek);
            ct_rands.push(r);
            cts.push(ct);
            revealed_attrs.push(*attr);
        }
    }
    // 2. Do PoK
    let mut attributes = vec![];
    for (attr, b) in credential.attrs.iter().zip(reveal_map.iter()) {
        if *b {
            attributes.push(Revealed(attr));
        } else {
            attributes.push(Hidden(Some(attr)));
        }
    }
    let mut transcript = Transcript::new(CAC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
    let pok = confidential_prove_pok::<_, P>(
        &mut transcript,
        prng,
        usk,
        &credential.ipk,
        &rand,
        attributes.as_slice(),
        &cm,
        ek,
        cts.as_slice(),
        ct_rands.as_slice(),
        m,
    );

    Ok(ConfidentialAC { cts, pok })
}

/// Verify a confidential selective opening, that is, the ElGamal ciphertexts `\vec{ct}` correctly
/// encrypt the attributes that are being committed in `cm` and specified in `\vec{reveal_map}`.
pub fn confidential_verify_open<P: Pairing>(
    ipk: &CredentialIssuerPK<P::G1, P::G2>,
    ek: &ElGamalEncKey<P::G1>,
    reveal_map: &[bool],
    cm: &CredentialComm<P::G1>,
    cts: &[ElGamalCiphertext<P::G1>],
    pok: &CACPoK<P::G1, P::G2, P::ScalarField>,
    m: &[u8],
) -> Result<()> {
    let n = cts.len();
    let revealed_count = reveal_map
        .iter()
        .fold(0, |sum, b| if *b { sum + 1 } else { sum });
    if reveal_map.len() != ipk.num_attrs() {
        return Err(eg!(ZeiError::ParameterError));
    }
    if n > ipk.num_attrs()
        || n != pok.cm_ct.len()
        || n != pok.response_rands.len()
        || n != revealed_count
    {
        return Err(eg!(ZeiError::IdentityRevealVerifyError));
    }

    let mut transcript = Transcript::new(CAC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);

    confidential_verify_pok::<P>(&mut transcript, ipk, ek, cm, cts, pok, reveal_map, m).c(d!())
}

pub(crate) fn confidential_prove_pok<R: CryptoRng + RngCore, P: Pairing>(
    transcript: &mut Transcript,
    prng: &mut R,
    usk: &CredentialUserSK<P::ScalarField>,
    ipk: &CredentialIssuerPK<P::G1, P::G2>,
    rand: &CredentialCommRandomizer<P::ScalarField>,
    attrs: &[Attribute<&P::ScalarField>],
    cm: &CredentialComm<P::G1>,
    ek: &ElGamalEncKey<P::G1>,
    cts: &[ElGamalCiphertext<P::G1>],
    ct_rands: &[P::ScalarField],
    m: &[u8],
) -> CACPoK<P::G1, P::G2, P::ScalarField> {
    transcript.cac_init::<P>(ipk, ek, cm, cts);
    transcript.append_message(POK_LABEL, m); // SoK
    let r_t = P::ScalarField::random(prng);
    let r_sk = P::ScalarField::random(prng);
    let mut r_attrs = vec![];
    let mut r_rands = vec![];
    let mut blinding = ipk.gen2.mul(&r_t).add(&ipk.zz2.mul(&r_sk));
    let mut cm_cts = vec![];
    for (y2_i, attr) in ipk.yy2.iter().zip(attrs.iter()) {
        let r_attr = P::ScalarField::random(prng);
        let elem = y2_i.mul(&r_attr);
        blinding = blinding.add(&elem);
        if let Revealed(_) = attr {
            let r_rand = P::ScalarField::random(prng);
            let ct_cm = elgamal_encrypt(&r_attr, &r_rand, ek);
            transcript.append_proof_commitment(&ct_cm.e1);
            transcript.append_proof_commitment(&ct_cm.e2);
            cm_cts.push(ct_cm);
            r_rands.push(r_rand);
        };
        r_attrs.push(r_attr);
    }
    transcript.append_proof_commitment(&blinding);
    let challenge = transcript.get_challenge::<P::ScalarField>();
    let response_t = challenge.mul(rand.t).add(&r_t);
    let response_sk = challenge.mul(&usk.0).add(&r_sk);
    let mut response_attrs = vec![];
    for (attr_enum, r_attr) in attrs.iter().zip(r_attrs.iter()) {
        match attr_enum {
            Hidden(Some(attr)) => {
                let response_attr = challenge.mul(*attr).add(r_attr);
                response_attrs.push(response_attr);
            }
            Revealed(attr) => {
                let response_attr = challenge.mul(*attr).add(r_attr);
                response_attrs.push(response_attr);
            }
            _ => {}
        }
    }
    let mut response_rands = vec![];
    for (ct_rand, r_rand) in ct_rands.iter().zip(r_rands.iter()) {
        let response_rand = challenge.mul(ct_rand).add(r_rand);
        response_rands.push(response_rand);
    }
    CACPoK {
        pok: CredentialPoK {
            blinding,
            response_t,
            response_sk,
            response_attrs,
        },
        cm_ct: cm_cts,
        response_rands,
    }
}

#[allow(clippy::too_many_arguments)]
fn confidential_verify_pok<P: Pairing>(
    transcript: &mut Transcript,
    ipk: &CredentialIssuerPK<P::G1, P::G2>,
    ek: &ElGamalEncKey<P::G1>,
    cm: &CredentialComm<P::G1>,
    cts: &[ElGamalCiphertext<P::G1>],
    pok: &CACPoK<P::G1, P::G2, P::ScalarField>,
    reveal_map: &[bool],
    m: &[u8],
) -> Result<()> {
    transcript.cac_init::<P>(ipk, ek, cm, cts);
    transcript.append_message(POK_LABEL, m);

    for ct in pok.cm_ct.iter() {
        transcript.append_proof_commitment(&ct.e1);
        transcript.append_proof_commitment(&ct.e2);
    }
    transcript.append_proof_commitment(&pok.pok.blinding);

    let challenge = transcript.get_challenge::<P::ScalarField>();

    let mut attr_resps = vec![];
    for (z_attr, b) in pok.pok.response_attrs.iter().zip(reveal_map.iter()) {
        if *b {
            attr_resps.push(z_attr);
        }
    }

    verify_ciphertext::<P>(
        &challenge,
        cts,
        pok.cm_ct.as_slice(),
        attr_resps.as_slice(),
        pok.response_rands.as_slice(),
        ek,
    )
    .c(d!())?;

    // 3. verify credential proof
    let hidden_attrs = vec![Hidden(None); ipk.num_attrs()];
    verify_pok::<P>(ipk, cm, &pok.pok, hidden_attrs.as_slice(), &challenge).c(d!())
}

fn verify_ciphertext<P: Pairing>(
    challenge: &P::ScalarField,
    cts: &[ElGamalCiphertext<P::G1>],
    ct_cms: &[ElGamalCiphertext<P::G1>],
    attrs: &[&P::ScalarField],
    rands: &[P::ScalarField],
    ek: &ElGamalEncKey<P::G1>,
) -> Result<()> {
    for (ct, ct_cm, attr, rand) in izip!(cts.iter(), ct_cms.iter(), attrs.iter(), rands.iter()) {
        let enc = elgamal_encrypt::<P::G1>(attr, rand, ek);
        if enc.e1 != ct.e1.mul(challenge).add(&ct_cm.e1) {
            return Err(eg!(ZeiError::IdentityRevealVerifyError));
        }
        if enc.e2 != ct.e2.mul(challenge).add(&ct_cm.e2) {
            return Err(eg!(ZeiError::IdentityRevealVerifyError));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_helper {
    use crate::anon_creds::{
        check_comm, commit_without_randomizer, grant_credential, issuer_keygen, user_keygen,
        Credential,
    };
    use crate::basic::elgamal::elgamal_key_gen;
    use crate::confidential_anon_creds::{confidential_open_comm, confidential_verify_open};
    use rand_chacha::ChaChaRng;
    use zei_algebra::prelude::*;
    use zei_algebra::traits::Pairing;

    pub(super) fn byte_slice_to_scalar<S: Scalar>(slice: &[u8]) -> S {
        use digest::Digest;
        use sha2::Sha512;
        let mut hasher = Sha512::new();
        hasher.update(slice);
        S::from_hash(hasher)
    }

    pub(crate) fn test_confidential_ac_reveal<P: Pairing>(reveal_map: &[bool]) {
        let proof_msg = b"Some message";
        let credential_addr = b"Some address";
        let num_attr = reveal_map.len();
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let (isk, ipk) = issuer_keygen::<_, P>(&mut prng, num_attr);
        let (usk, upk) = user_keygen::<_, P>(&mut prng, &ipk);
        let (_, ek) = elgamal_key_gen::<_, P::G1>(&mut prng);

        let mut attrs = Vec::new();
        for i in 0..num_attr {
            attrs.push(byte_slice_to_scalar(format!("attr{}!", i).as_bytes()));
        }

        let sig = grant_credential::<_, P>(&mut prng, &isk, &upk, &attrs[..]).unwrap();
        let credential = Credential {
            sig,
            attrs,
            ipk: ipk.clone(),
        };
        let output =
            commit_without_randomizer::<_, P>(&mut prng, &usk, &credential, credential_addr)
                .unwrap();

        let cm = output.0;
        let pok = output.1;
        let rand = output.2.unwrap(); // safe unwrap()

        // 1. Verify commitment
        assert!(check_comm::<P>(&ipk, &cm, &pok, credential_addr).is_ok());
        let conf_reveal_proof = confidential_open_comm::<_, P>(
            &mut prng,
            &usk,
            &credential,
            &cm,
            &rand,
            reveal_map,
            &ek,
            proof_msg,
        )
        .unwrap();
        assert!(confidential_verify_open::<P>(
            &credential.ipk,
            &ek,
            reveal_map,
            &cm,
            &conf_reveal_proof.cts,
            &conf_reveal_proof.pok,
            proof_msg,
        )
        .is_ok());

        // Error cases

        // Inconsistent bitmap
        let mut tampered_bitmap = vec![];
        tampered_bitmap.extend_from_slice(reveal_map);

        let b = reveal_map.get(0).unwrap();

        tampered_bitmap[0] = !(*b);

        let res = confidential_verify_open::<P>(
            &ipk,
            &ek,
            &tampered_bitmap[..],
            &cm,
            &conf_reveal_proof.cts,
            &conf_reveal_proof.pok,
            proof_msg,
        );
        msg_eq!(
            ZeiError::IdentityRevealVerifyError,
            res.unwrap_err(),
            "proof should fail, reveal map doesn't match"
        );

        // Empty bitmap
        let empty_bitmap = vec![];
        let res = confidential_verify_open::<P>(
            &ipk,
            &ek,
            &empty_bitmap[..],
            &cm,
            &conf_reveal_proof.cts,
            &conf_reveal_proof.pok,
            proof_msg,
        );
        msg_eq!(
            ZeiError::ParameterError,
            res.unwrap_err(),
            "proof should fail, bitmap length does not match number of attributes"
        );

        // Wrong issuer public key
        let (_, ipk2) = issuer_keygen::<_, P>(&mut prng, num_attr);
        let res = confidential_verify_open::<P>(
            &ipk2,
            &ek,
            &reveal_map,
            &cm,
            &conf_reveal_proof.cts,
            &conf_reveal_proof.pok,
            proof_msg,
        );
        msg_eq!(
            ZeiError::IdentityRevealVerifyError,
            res.unwrap_err(),
            "proof should fail, inconsistent issuer public key"
        );

        // Wrong encryption key
        let (_, ek2) = elgamal_key_gen::<_, P::G1>(&mut prng);
        let res = confidential_verify_open::<P>(
            &ipk,
            &ek2,
            &reveal_map,
            &cm,
            &conf_reveal_proof.cts,
            &conf_reveal_proof.pok,
            proof_msg,
        );
        msg_eq!(
            ZeiError::IdentityRevealVerifyError,
            res.unwrap_err(),
            "proof should fail, inconsistent encryption key"
        );

        // Wrong message
        let wrong_message = b"Some other message";
        let res = confidential_verify_open::<P>(
            &ipk,
            &ek,
            &reveal_map,
            &cm,
            &conf_reveal_proof.cts,
            &conf_reveal_proof.pok,
            wrong_message,
        );
        msg_eq!(
            ZeiError::IdentityRevealVerifyError,
            res.unwrap_err(),
            "proof should fail, bad sok message"
        );
    }
}

#[cfg(test)]
mod test_bls12_381 {
    use crate::confidential_anon_creds::test_helper::test_confidential_ac_reveal;
    use zei_algebra::bls12_381::BLSPairingEngine;

    #[test]
    fn confidential_reveal_one_attr_hidden() {
        test_confidential_ac_reveal::<BLSPairingEngine>(&[false]);
    }

    #[test]
    fn confidential_reveal_one_attr_revealed() {
        test_confidential_ac_reveal::<BLSPairingEngine>(&[true]);
    }

    #[test]
    fn confidential_reveal_two_attr_hidden_first() {
        test_confidential_ac_reveal::<BLSPairingEngine>(&[false, false]);
        test_confidential_ac_reveal::<BLSPairingEngine>(&[false, true]);
    }

    #[test]
    fn confidential_reveal_two_attr_revealed_first() {
        test_confidential_ac_reveal::<BLSPairingEngine>(&[true, false]);
        test_confidential_ac_reveal::<BLSPairingEngine>(&[true, true]);
    }

    #[test]
    fn confidential_reveal_ten_attr_all_hidden() {
        test_confidential_ac_reveal::<BLSPairingEngine>(&[false; 10]);
    }

    #[test]
    fn confidential_reveal_ten_attr_all_revealed() {
        test_confidential_ac_reveal::<BLSPairingEngine>(&[true; 10]);
    }

    #[test]
    fn confidential_reveal_ten_attr_half_revealed() {
        test_confidential_ac_reveal::<BLSPairingEngine>(&[
            true, false, true, false, true, false, true, false, true, false,
        ]);
        test_confidential_ac_reveal::<BLSPairingEngine>(&[
            false, true, false, true, false, true, false, true, false, true,
        ]);
    }
}
