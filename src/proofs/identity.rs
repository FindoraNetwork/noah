use rand::{CryptoRng, Rng};
use crate::credentials::{IssuerPublicKey, compute_challenge, AttrsRevealProof};
use crate::errors::ZeiError;
use crate::algebra::pairing::Pairing;
use crate::algebra::groups::{Group, Scalar};
use sha2::{Sha512, Digest};
use crate::basic_crypto::elgamal::{ElGamalCiphertext, ElGamalPublicKey, elgamal_encrypt};
use crate::algebra::bls12_381::{BLSG1, BLSGt, BLSScalar, BLSG2};

// BLS12_381 implementation of confidential identity reveal protocol
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfIdReveal{
    ctexts: Vec<ElGamalCiphertext<BLSG1>>,
    attr_reveal_proof: AttrsRevealProof<BLSG1, BLSG2, BLSScalar>,
    pok_attrs: PoKAttrs<BLSG1, BLSG2, BLSScalar>,
}

pub fn create_conf_id_reveal<R: Rng + CryptoRng>(
    prng: &mut R,
    attrs: &[BLSScalar],
    attr_reveal_proof: &AttrsRevealProof<BLSG1, BLSG2, BLSScalar>,
    cred_issuer_public_key: &IssuerPublicKey<BLSG1, BLSG2>,
    asset_issuer_public_key: &ElGamalPublicKey<BLSG1>,
    bitmap: &[bool], // this is the policy. It indicates which attributes should be revealed
)
 -> Result<ConfIdReveal, ZeiError>
{
    let mut ctexts = vec![];
    let mut rands = vec![];
    let base = BLSG1::get_base();
    for attr in attrs{
        let r = BLSScalar::random_scalar(prng);
        let ctext = elgamal_encrypt(&base, attr, &r, asset_issuer_public_key);
        rands.push(r);
        ctexts.push(ctext);
    }

    let pok_attrs_proof = pok_attrs_prove::<_,BLSGt>(
        prng,
        attrs,
        cred_issuer_public_key,
        asset_issuer_public_key,
        rands.as_slice(),
        bitmap,
    )?;

    Ok(ConfIdReveal{
        ctexts: ctexts,
        attr_reveal_proof:attr_reveal_proof.clone(),
        pok_attrs: pok_attrs_proof,
    })

}

pub fn verify_conf_id_reveal(
    conf_id_reveal: &ConfIdReveal,
    cred_issuer_public_key: &IssuerPublicKey<BLSG1, BLSG2>,
    asset_issuer_public_key: &ElGamalPublicKey<BLSG1>,
    bitmap: &[bool], // this is the policy. It indicates which attributes should be revealed
) -> Result<(), ZeiError>
{
    pok_attrs_verify::<BLSGt>(
        &conf_id_reveal.attr_reveal_proof,
        &conf_id_reveal.ctexts,
        &conf_id_reveal.pok_attrs,
        cred_issuer_public_key,
        asset_issuer_public_key,
        bitmap,
    )
}


// Generic functions for confidential identity reveal features
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PoKAttrs<G1, G2, S>{
    attr_blind_cred_commitment: G2, // sum blind_{a_i} * Y2_i for a_i in encrypted attributes
    attr_commitments: Vec<G1>, // blind_{a_i} * G1 for a_i in encrypted attributes
    rand_commitments: Vec<(G1, G1)>, // (blind_{r_i} * G, blind_{r_i} * PK)
    attr_responses: Vec<S>, // {c*a_i + blind_{a_i}}
    rand_responses: Vec<S>, // {c*r_i + blind_{r_i}}
}

/// I compute a proof of knowledge of identity attributes to be verified against ciphertext of these
/// and a anoymouns credential proof
fn pok_attrs_prove<R, Gt>(
    prng: &mut R,
    attrs: &[Gt::ScalarType], // attributes to prove knowledge of
    cred_issuer_pk: &IssuerPublicKey<Gt::G1, Gt::G2>,
    asset_issuer_pk: &ElGamalPublicKey<Gt::G1>,
    ctexts_rand: &[Gt::ScalarType], // randomness used to encrypt attrs
    bitmap: &[bool], // indicates position of each attribute to prove

) -> Result<PoKAttrs<Gt::G1, Gt::G2, Gt::ScalarType>, ZeiError>
    where R: CryptoRng + Rng, Gt: Pairing
{
    let m = attrs.len();
    let mut attr_commitments = Vec::with_capacity(m);
    let mut attr_blind = Vec::with_capacity(m);
    let mut rand_commitments =
        Vec::with_capacity(m);
    let mut rand_blind = Vec::with_capacity(m);
    let mut attr_blind_cred_commitment = Gt::G2::get_identity();
    for (yy2i, shown) in cred_issuer_pk.yy2.iter().zip(
        bitmap.iter()){
        if *shown {
            let r: Gt::ScalarType = Gt::ScalarType::random_scalar(prng);
            let com_y2i = Gt::g2_mul_scalar(yy2i, &r);
            let com_g = Gt::g1_mul_scalar(&Gt::G1::get_base(), &r);
            attr_blind.push(r);
            attr_commitments.push(com_g);
            attr_blind_cred_commitment = attr_blind_cred_commitment.add(&com_y2i);

            let r: Gt::ScalarType = Gt::ScalarType::random_scalar(prng);
            let com_g = Gt::g1_mul_scalar(&Gt::G1::get_base(), &r);
            let com_pk = Gt::g1_mul_scalar(&asset_issuer_pk.0, &r);
            rand_blind.push(r);
            rand_commitments.push((com_g, com_pk));
        }
    }

    if m != rand_blind.len(){
        return Err(ZeiError::ParameterError);
    }

    let c = pok_attrs_challenge::<Gt>(
        attr_commitments.as_slice(),
        rand_commitments.as_slice());

    let mut attr_responses = Vec::with_capacity(m);
    for (attr, blind) in attrs.iter().
        zip(attr_blind.iter()){
        attr_responses.push(attr.mul(&c).add(&blind));
    }
    let mut rand_responses = Vec::with_capacity(m);
    for (rand, blind) in ctexts_rand.iter().
        zip(rand_blind.iter()){
        rand_responses.push(rand.mul(&c).add(&blind));
    }

    Ok(PoKAttrs{
        attr_blind_cred_commitment,
        attr_commitments,
        attr_responses,
        rand_commitments,
        rand_responses
    })
}

/// I compute the challenge in a proof of knowledge of identity attributes
fn pok_attrs_challenge<Gt: Pairing>(
    attr_coms: &[Gt::G1],
    rand_coms: &[(Gt::G1, Gt::G1)]
) -> Gt::ScalarType
{
    let mut hash = Sha512::new();
    for com in attr_coms.iter(){
        hash.input(com.to_compressed_bytes());
    }
    for com in rand_coms.iter(){
        hash.input(com.0.to_compressed_bytes());
        hash.input(com.1.to_compressed_bytes());
    }
    Gt::ScalarType::from_hash(hash)
}

/// I verify a proof of knowledge of attributes that satisfy a confidential identity proof
fn pok_attrs_verify<Gt: Pairing>(
    reveal_proof: &AttrsRevealProof<Gt::G1, Gt::G2, Gt::ScalarType>,
    ctexts: &[ElGamalCiphertext<Gt::G1>],
    pok_attrs: &PoKAttrs<Gt::G1, Gt::G2, Gt::ScalarType>,
    cred_issuer_public_key: &IssuerPublicKey<Gt::G1, Gt::G2>,
    asset_issuer_public_key: &ElGamalPublicKey<Gt::G1>,
    bitmap: &[bool], // indicates which attributes should be revealed to the asset issuer
) -> Result<(), ZeiError>
{
    // 1. compute challenge
    let challenge = pok_attrs_challenge::<Gt>(
        pok_attrs.attr_commitments.as_slice(),
        pok_attrs.rand_commitments.as_slice());
    // 2. do ciphertexts verification
    verify_ciphertext::<Gt>(&challenge, ctexts, pok_attrs, asset_issuer_public_key)?;
    // 3. do credential verification
    verify_credential::<Gt>(&challenge, reveal_proof, pok_attrs, cred_issuer_public_key, bitmap)
}

/// I verify a proof of knowledge of a set of ElGamal encrypted messages
fn verify_ciphertext<Gt: Pairing>(
    challenge: &Gt::ScalarType,
    ctexts: &[ElGamalCiphertext<Gt::G1>],
    pok_attrs: &PoKAttrs<Gt::G1, Gt::G2, Gt::ScalarType>,
    asset_issuer_public_key: &ElGamalPublicKey<Gt::G1>
) -> Result<(), ZeiError>
{
    let commitments = pok_attrs.rand_commitments.iter().
        zip(pok_attrs.attr_commitments.iter());
    let responses = pok_attrs.rand_responses.iter().
        zip(pok_attrs.attr_responses.iter());
    for (
        ctext,
        (
            (
                (
                    rand_com_g,
                    rand_com_pk
                ),
                attr_com
            ),
            (
                rand_response,
                attr_response
            )
        )
    )
        in ctexts.iter().zip(commitments.zip(responses)){
        let e1 = &ctext.e1;
        let e2 = &ctext.e2;

        let verify_e1 =
            Gt::g1_mul_scalar(e1, &challenge).add(rand_com_g) ==
                Gt::g1_mul_scalar(&Gt::G1::get_base(), rand_response);
        let verify_e2 =
            Gt::g1_mul_scalar(e2, &challenge).add(rand_com_pk).add(attr_com) ==
                Gt::g1_mul_scalar(&Gt::G1::get_base(), attr_response).add(
                    &Gt::g1_mul_scalar(&asset_issuer_public_key.0, rand_response));
        if !(verify_e1 && verify_e2) {
            return Err(ZeiError::IdentityRevealVerificationError);
        }
    }
    Ok(())
}

/// I verify a proof of knowledge of a set of identity attributes that verify an identity
/// credential proof
fn verify_credential<Gt: Pairing>(
    challenge: &Gt::ScalarType,
    reveal_proof: &AttrsRevealProof<Gt::G1, Gt::G2, Gt::ScalarType>,
    pok_attrs: &PoKAttrs<Gt::G1, Gt::G2, Gt::ScalarType>,
    cred_issuer_public_key: &IssuerPublicKey<Gt::G1, Gt::G2>,
    bitmap: &[bool], //policy, indicates which attributes needs to be revealed to the asset issuer
) -> Result<(), ZeiError>
{
    //compute credential proof constants and multiply them by challenge
    let cred_challenge =
        compute_challenge::<Gt>(&reveal_proof.pok.commitment); //c
    // lhs constant c*X2 + - pf.com + r_t*G2 + r_sk * Z2 + sum a_i + Y2i (a_i in hidden)
    let cred_lhs_constant =
        constant_terms_addition::<Gt>(&cred_challenge, reveal_proof, cred_issuer_public_key, bitmap);
    let cred_rhs_constant = Gt::g2_mul_scalar(
        &cred_issuer_public_key.gen2,
        &cred_challenge); //c*G2

    // c' * (c*X2 + - pf.com + r_t*G2 + r_sk * Z2 + sum a_i + Y2i (a_i in hidden))
    let lhs_constant = Gt::g2_mul_scalar(&cred_lhs_constant, challenge);


    //add pok response terms to left hand side
    // c * sum r_{a_i}*Y2_i (ai in revealed) = c * sum r_{a_i}*Y2_i (ai in revealed)
    let mut blinded_attr_sum = Gt::G2::get_identity();
    let mut attrs_responses_iter = pok_attrs.attr_responses.iter();
    for (b, yy2i) in bitmap.iter().
        zip(cred_issuer_public_key.yy2.iter()) {
        if *b {
            let response = attrs_responses_iter.next().unwrap();
            blinded_attr_sum = blinded_attr_sum.add(&Gt::g2_mul_scalar(yy2i, response));
        }
    }
    // subtract commitment scaled by cred_challenge: c*pok_aattrs.attr_commitment = c*\sum b_i* Y2i
    blinded_attr_sum = blinded_attr_sum.sub(&pok_attrs.attr_blind_cred_commitment);
    blinded_attr_sum = Gt::g2_mul_scalar(&blinded_attr_sum, &cred_challenge);
    let lhs = lhs_constant.add(&blinded_attr_sum);
    let rhs = Gt::g2_mul_scalar(&cred_rhs_constant, challenge);
    let a = Gt::pairing(&reveal_proof.sig.sigma1, &lhs);
    let b = Gt::pairing(&reveal_proof.sig.sigma2, &rhs); // e(s2, c' * c * G2)
    match a == b {
        true => Ok(()),
        false => Err(ZeiError::IdentityRevealVerificationError),
    }
}

fn constant_terms_addition<Gt: Pairing>(
    challenge: &Gt::ScalarType,
    reveal_proof: &AttrsRevealProof<Gt::G1, Gt::G2, Gt::ScalarType>,
    cred_issuer_public_key: &IssuerPublicKey<Gt::G1, Gt::G2>,
    bitmap: &[bool],
) -> Gt::G2
{
    //compute X_2*challenge - commitment + &G2 * &response_t + &PK.Z2 * response_sk +
    // sum response_attr_i * PK.Y2_i
    let mut q = Gt::g2_mul_scalar(
        &cred_issuer_public_key.xx2,
        &challenge).sub(&reveal_proof.pok.commitment); //X_2*challente - proof.commitment

    q = q.add(&Gt::g2_mul_scalar(&cred_issuer_public_key.gen2, &reveal_proof.pok.response_t));
    q = q.add(&Gt::g2_mul_scalar(&cred_issuer_public_key.zz2, &reveal_proof.pok.response_sk));

    let mut resp_attr_iter = reveal_proof.pok.response_attrs.iter();
    for (b, yy2i)  in bitmap.iter().
        zip(cred_issuer_public_key.yy2.iter()){
        if !b {
            let response = resp_attr_iter.next().unwrap();
            q = q.add(&Gt::g2_mul_scalar(&yy2i, response));
        }
    }
    q
}

#[cfg(test)]
mod test_bn{
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use crate::credentials::{gen_user_keys, reveal_attrs, issuer_sign, gen_issuer_keys};
    use crate::algebra::bn::{BNScalar, BNGt, BNG1};
    use crate::algebra::groups::{Group, Scalar};
    use crate::proofs::identity::{pok_attrs_prove, pok_attrs_verify};
    use crate::basic_crypto::elgamal::{elgamal_generate_secret_key,
                                       elgamal_derive_public_key, elgamal_encrypt};

    #[test]
    fn one_confidential_reveal(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let cred_issuer_keypair =
            gen_issuer_keys::<_, BNGt>(&mut prng, 3);
        let cred_issuer_pk = &cred_issuer_keypair.0;
        let cred_issuer_sk = &cred_issuer_keypair.1;

        let asset_issuer_secret_key =
            elgamal_generate_secret_key::<_,BNG1>(&mut prng);
        let asset_issuer_public_key =
            elgamal_derive_public_key(&BNG1::get_base(), &asset_issuer_secret_key);

        let (user_pk, user_sk) =
            gen_user_keys::<_, BNGt>(&mut prng, cred_issuer_pk);

        let attr1 = BNScalar::random_scalar(&mut prng);
        let attr2 = BNScalar::random_scalar(&mut prng);
        let attr3 = BNScalar::random_scalar(&mut prng);

        let signature = issuer_sign::<_, BNGt>(
            &mut prng, &cred_issuer_sk, &user_pk,
            vec![attr1.clone(), attr2.clone(), attr3.clone()]);

        let proof = reveal_attrs::<_, BNGt>(
            &mut prng,
            &user_sk,
            cred_issuer_pk,
            &signature,
            &[attr1.clone(), attr2.clone(), attr3.clone()],
            &[false, true, false],
        );

        let rand = BNScalar::random_scalar(&mut prng);
        let ctext = elgamal_encrypt(
            &BNG1::get_base(), &attr2, &rand, &asset_issuer_public_key);
        let pok_attr = pok_attrs_prove::<_, BNGt>(
            &mut prng,
            &[attr2.clone()],
            cred_issuer_pk,
            &asset_issuer_public_key,
            &[rand],
            &[false, true, false]).unwrap();

        let vrfy = pok_attrs_verify::<BNGt>(
            &proof,
            &[ctext],
            &pok_attr,
            cred_issuer_pk,
            &asset_issuer_public_key,
            &[false, true, false]);
        assert_eq!(Ok(()), vrfy);
    }
}



#[cfg(test)]
mod test_bls12_381{
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use crate::credentials::{gen_user_keys, reveal_attrs, issuer_sign, gen_issuer_keys};
    use crate::algebra::groups::{Group, Scalar};
    use crate::proofs::identity::{pok_attrs_prove, pok_attrs_verify};
    use crate::basic_crypto::elgamal::{elgamal_generate_secret_key,
                                       elgamal_derive_public_key, elgamal_encrypt};
    use crate::algebra::bls12_381::{BLSGt, BLSG1, BLSScalar};

    #[test]
    fn one_confidential_reveal(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let cred_issuer_keypair =
            gen_issuer_keys::<_, BLSGt>(&mut prng, 3);
        let cred_issuer_pk = &cred_issuer_keypair.0;
        let cred_issuer_sk = &cred_issuer_keypair.1;

        let asset_issuer_secret_key =
            elgamal_generate_secret_key::<_,BLSG1>(&mut prng);
        let asset_issuer_public_key =
            elgamal_derive_public_key(&BLSG1::get_base(), &asset_issuer_secret_key);

        let (user_pk, user_sk) =
            gen_user_keys::<_, BLSGt>(&mut prng, cred_issuer_pk);

        let attr1 = BLSScalar::random_scalar(&mut prng);
        let attr2 = BLSScalar::random_scalar(&mut prng);
        let attr3 = BLSScalar::random_scalar(&mut prng);

        let signature = issuer_sign::<_, BLSGt>(
            &mut prng, &cred_issuer_sk, &user_pk,
            vec![attr1.clone(), attr2.clone(), attr3.clone()]);

        let proof = reveal_attrs::<_, BLSGt>(
            &mut prng,
            &user_sk,
            cred_issuer_pk,
            &signature,
            &[attr1.clone(), attr2.clone(), attr3.clone()],
            &[false, true, false],
        );

        let rand = BLSScalar::random_scalar(&mut prng);
        let ctext = elgamal_encrypt(
            &BLSG1::get_base(), &attr2, &rand, &asset_issuer_public_key);
        let pok_attr = pok_attrs_prove::<_, BLSGt>(
            &mut prng,
            &[attr2.clone()],
            cred_issuer_pk,
            &asset_issuer_public_key,
            &[rand],
            &[false, true, false]).unwrap();

        let vrfy = pok_attrs_verify::<BLSGt>(
            &proof,
            &[ctext],
            &pok_attr,
            cred_issuer_pk,
            &asset_issuer_public_key,
            &[false, true, false]);
        assert_eq!(Ok(()), vrfy);
    }
}
