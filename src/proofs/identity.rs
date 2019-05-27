use rand::{CryptoRng, Rng};
use crate::credentials::{IssuerPublicKey, compute_challenge, AttrsRevealProof};
use crate::errors::ZeiError;
use crate::algebra::pairing::Pairing;
use crate::algebra::groups::{Group, Scalar};
use sha2::{Sha512, Digest};
use crate::basic_crypto::elgamal::{ElGamalCiphertext, ElGamalPublicKey};


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
pub(crate) fn pok_attrs_prove<R, S, P>(
    prng: &mut R,
    attrs: &[S], // attributes to prove knowledge of
    cred_issuer_pub_key: &IssuerPublicKey<P::G1, P::G2>,
    asset_issuer_pub_key: &ElGamalPublicKey<P::G1>,
    ctexts_rand: &[S], // randomness used to encrypt attrs
    bitmap: &[bool], // indicates position of each attribute to prove

) -> Result<PoKAttrs<P::G1, P::G2, S>, ZeiError>
    where R: CryptoRng + Rng, S: Scalar, P: Pairing<S>
{
    let m = attrs.len();
    let mut attr_commitments = Vec::with_capacity(m);
    let mut attr_blind = Vec::with_capacity(m);
    let mut rand_commitments =
        Vec::with_capacity(m);
    let mut rand_blind = Vec::with_capacity(m);
    let mut attr_blind_cred_commitment = P::G2::get_identity();
    for (yy2i, shown) in cred_issuer_pub_key.yy2.iter().zip(
        bitmap.iter()){
        if *shown {
            let r: S = S::random_scalar(prng);
            let com_y2i = P::g2_mul_scalar(yy2i, &r);
            let com_g = P::g1_mul_scalar(&P::G1::get_base(), &r);
            attr_blind.push(r);
            attr_commitments.push(com_g);
            attr_blind_cred_commitment = attr_blind_cred_commitment.add(&com_y2i);

            let r = S::random_scalar(prng);
            let com_g = P::g1_mul_scalar(&P::G1::get_base(), &r);
            let com_pk = P::g1_mul_scalar(&asset_issuer_pub_key.0, &r);
            rand_blind.push(r);
            rand_commitments.push((com_g, com_pk));
        }
    }

    if m != rand_blind.len(){
        return Err(ZeiError::ParameterError);
    }

    let c = pok_attrs_challenge::<S,P>(
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
fn pok_attrs_challenge<S: Scalar, P: Pairing<S>>(
    attr_coms: &[P::G1],
    rand_coms: &[(P::G1, P::G1)]
) -> S
{
    let mut hash = Sha512::new();
    for com in attr_coms.iter(){
        hash.input(com.to_compressed_bytes());
    }
    for com in rand_coms.iter(){
        hash.input(com.0.to_compressed_bytes());
        hash.input(com.1.to_compressed_bytes());
    }
    S::from_hash(hash)
}

/// I verify a proof of knowledge of attributes that satisfy a confidential identity proof
pub(crate) fn pok_attrs_verify<S: Scalar, P: Pairing<S>>(
    reveal_proof: &AttrsRevealProof<P::G1, P::G2, S>,
    ctexts: &[ElGamalCiphertext<P::G1>],
    pok_attrs: &PoKAttrs<P::G1, P::G2, S>,
    asset_issuer_public_key: &ElGamalPublicKey<P::G1>,
    cred_issuer_pub_key: &IssuerPublicKey<P::G1, P::G2>,
    bitmap: &[bool], // indicates which attributes should be revealed to the asset issuer
) -> Result<(), ZeiError>
{
    // 1. compute challenge
    let challenge = pok_attrs_challenge::<S,P>(
        pok_attrs.attr_commitments.as_slice(),
        pok_attrs.rand_commitments.as_slice());
    // 2. do ciphertexts verification
    verify_ciphertext::<S,P>(&challenge, ctexts, pok_attrs, asset_issuer_public_key)?;
    // 3. do credential verification
    verify_credential::<S,P>(&challenge, reveal_proof, pok_attrs, cred_issuer_pub_key, bitmap)
}

/// I verify a proof of knowledge of a set of ElGamal encrypted messages
fn verify_ciphertext<S: Scalar, P: Pairing<S>>(
    challenge: &S,
    ctexts: &[ElGamalCiphertext<P::G1>],
    pok_attrs: &PoKAttrs<P::G1, P::G2, S>,
    asset_issuer_public_key: &ElGamalPublicKey<P::G1>
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
            P::g1_mul_scalar(e1, &challenge).add(rand_com_g) ==
                P::g1_mul_scalar(&P::G1::get_base(), rand_response);
        let verify_e2 =
            P::g1_mul_scalar(e2, &challenge).add(rand_com_pk).add(attr_com) ==
                P::g1_mul_scalar(&P::G1::get_base(), attr_response).add(
                    &P::g1_mul_scalar(&asset_issuer_public_key.0, rand_response));
        if !(verify_e1 && verify_e2) {
            return Err(ZeiError::IdentityRevealVerifyError);
        }
    }
    Ok(())
}

/// I verify a proof of knowledge of a set of identity attributes that verify an identity
/// credential proof
fn verify_credential<S: Scalar, P: Pairing<S>>(
    challenge: &S,
    reveal_proof: &AttrsRevealProof<P::G1, P::G2, S>,
    pok_attrs: &PoKAttrs<P::G1, P::G2, S>,
    cred_issuer_public_key: &IssuerPublicKey<P::G1, P::G2>,
    bitmap: &[bool], //policy, indicates which attributes needs to be revealed to the asset issuer
) -> Result<(), ZeiError>
{
    //compute credential proof constants and multiply them by challenge
    let cred_challenge =
        compute_challenge::<S,P>(&reveal_proof.pok.commitment); //c
    // lhs constant c*X2 + - pf.com + r_t*G2 + r_sk * Z2 + sum a_i + Y2i (a_i in hidden)
    let cred_lhs_constant =
        constant_terms_addition::<S,P>(&cred_challenge, reveal_proof, cred_issuer_public_key, bitmap).map_err(|_| ZeiError::IdentityRevealVerifyError)?;
    let cred_rhs_constant = P::g2_mul_scalar(
        &cred_issuer_public_key.gen2,
        &cred_challenge); //c*G2

    // c' * (c*X2 + - pf.com + r_t*G2 + r_sk * Z2 + sum a_i + Y2i (a_i in hidden))
    let lhs_constant = P::g2_mul_scalar(&cred_lhs_constant, challenge);


    //add pok response terms to left hand side
    // c * sum r_{a_i}*Y2_i (ai in revealed) = c * sum r_{a_i}*Y2_i (ai in revealed)
    let mut blinded_attr_sum = P::G2::get_identity();
    let mut attrs_responses_iter = pok_attrs.attr_responses.iter();
    for (b, yy2i) in bitmap.iter().
        zip(cred_issuer_public_key.yy2.iter()) {
        if *b {
            let response = attrs_responses_iter.next().ok_or(ZeiError::IdentityRevealVerifyError)?;
            blinded_attr_sum = blinded_attr_sum.add(&P::g2_mul_scalar(yy2i, response));
        }
    }
    // subtract commitment scaled by cred_challenge: c*pok_aattrs.attr_commitment = c*\sum b_i* Y2i
    blinded_attr_sum = blinded_attr_sum.sub(&pok_attrs.attr_blind_cred_commitment);
    blinded_attr_sum = P::g2_mul_scalar(&blinded_attr_sum, &cred_challenge);
    let lhs = lhs_constant.add(&blinded_attr_sum);
    let rhs = P::g2_mul_scalar(&cred_rhs_constant, challenge);
    let a = P::pairing(&reveal_proof.sig.sigma1, &lhs);
    let b = P::pairing(&reveal_proof.sig.sigma2, &rhs); // e(s2, c' * c * G2)
    match a == b {
        true => Ok(()),
        false => {Err(ZeiError::IdentityRevealVerifyError)},
    }
}

fn constant_terms_addition<S:Scalar, P: Pairing<S>>(
    challenge: &S,
    reveal_proof: &AttrsRevealProof<P::G1, P::G2, S>,
    cred_issuer_public_key: &IssuerPublicKey<P::G1, P::G2>,
    bitmap: &[bool],
) -> Result<P::G2, ZeiError>
{
    //compute X_2*challenge - commitment + &G2 * &response_t + &PK.Z2 * response_sk +
    // sum response_attr_i * PK.Y2_i
    let mut q = P::g2_mul_scalar(
        &cred_issuer_public_key.xx2,
        &challenge).sub(&reveal_proof.pok.commitment); //X_2*challente - proof.commitment

    q = q.add(&P::g2_mul_scalar(&cred_issuer_public_key.gen2, &reveal_proof.pok.response_t));
    q = q.add(&P::g2_mul_scalar(&cred_issuer_public_key.zz2, &reveal_proof.pok.response_sk));

    let mut resp_attr_iter = reveal_proof.pok.response_attrs.iter();
    for (b, yy2i)  in bitmap.iter().
        zip(cred_issuer_public_key.yy2.iter()){
        if !b {
            let response = resp_attr_iter.next().ok_or(ZeiError::ParameterError)?;
            q = q.add(&P::g2_mul_scalar(&yy2i, response));
        }
    }
    Ok(q)
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
            gen_issuer_keys::<_, BNScalar, BNGt>(&mut prng, 3);
        let cred_issuer_pub_key = &cred_issuer_keypair.0;
        let cred_issuer_sk = &cred_issuer_keypair.1;

        let asset_issuer_secret_key =
            elgamal_generate_secret_key::<_,BNScalar>(&mut prng);
        let asset_issuer_public_key =
            elgamal_derive_public_key(&BNG1::get_base(), &asset_issuer_secret_key);

        let (user_pk, user_sk) =
            gen_user_keys::<_, BNScalar,BNGt>(&mut prng, cred_issuer_pub_key);

        let attr1 = BNScalar::random_scalar(&mut prng);
        let attr2 = BNScalar::random_scalar(&mut prng);
        let attr3 = BNScalar::random_scalar(&mut prng);

        let signature = issuer_sign::<_, BNScalar,BNGt>(
            &mut prng, &cred_issuer_sk, &user_pk,
            &[attr1.clone(), attr2.clone(), attr3.clone()]);

        let proof = reveal_attrs::<_, BNScalar, BNGt>(
            &mut prng,
            &user_sk,
            cred_issuer_pub_key,
            &signature,
            &[attr1.clone(), attr2.clone(), attr3.clone()],
            &[false, true, false],
        );

        let rand = BNScalar::random_scalar(&mut prng);
        let ctext = elgamal_encrypt(
            &BNG1::get_base(), &attr2, &rand, &asset_issuer_public_key);
        let pok_attr = pok_attrs_prove::<_, BNScalar,BNGt>(
            &mut prng,
            &[attr2.clone()],
            cred_issuer_pub_key,
            &asset_issuer_public_key,
            &[rand],
            &[false, true, false]).unwrap();

        let vrfy = pok_attrs_verify::<BNScalar,BNGt>(
            &proof,
            &[ctext],
            &pok_attr,
            &asset_issuer_public_key,
            cred_issuer_pub_key,

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
    use crate::errors::ZeiError;

    fn confidential_reveal(reveal_bitmap: &[bool]){
        let num_attr = reveal_bitmap.len();
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let cred_issuer_keypair =
            gen_issuer_keys::<_, BLSScalar,BLSGt>(&mut prng, num_attr);

        let cred_issuer_pub_key = &cred_issuer_keypair.0;
        let cred_issuer_sk = &cred_issuer_keypair.1;

        let asset_issuer_secret_key =
            elgamal_generate_secret_key::<_,BLSScalar>(&mut prng);
        let asset_issuer_public_key =
            elgamal_derive_public_key(&BLSG1::get_base(), &asset_issuer_secret_key);

        let (user_pk, user_sk) =
            gen_user_keys::<_, BLSScalar,BLSGt>(&mut prng, cred_issuer_pub_key);

        let mut attrs = vec![];

        for _ in 0..num_attr{
            attrs.push(BLSScalar::random_scalar(&mut prng));
        }

        let signature = issuer_sign::<_, BLSScalar, BLSGt>(
            &mut prng, &cred_issuer_sk, &user_pk,
            attrs.as_slice());

        let proof = reveal_attrs::<_, BLSScalar, BLSGt>(
            &mut prng,
            &user_sk,
            cred_issuer_pub_key,
            &signature,
            &attrs,
            reveal_bitmap,
        );

        let mut ctext_rands = vec![];
        let mut ctexts = vec![];
        let mut revealed_attrs = vec![];
        for (attr, reveal) in attrs.iter().zip(reveal_bitmap){
            if *reveal {
                let rand = BLSScalar::random_scalar(&mut prng);
                let ctext = elgamal_encrypt(
                    &BLSG1::get_base(), attr, &rand, &asset_issuer_public_key);

                ctext_rands.push(rand);
                ctexts.push(ctext);
                revealed_attrs.push(attr.clone());
            }
        }

        let pok_attrs = pok_attrs_prove::<_, BLSScalar, BLSGt>(
            &mut prng,
            revealed_attrs.as_slice(),
            cred_issuer_pub_key,
            &asset_issuer_public_key,
            ctext_rands.as_slice(),
            reveal_bitmap).unwrap();

        let vrfy = pok_attrs_verify::<BLSScalar,BLSGt>(
            &proof,
            ctexts.as_slice(),
            &pok_attrs,
            &asset_issuer_public_key,
            cred_issuer_pub_key,
            reveal_bitmap);

        assert_eq!(Ok(()), vrfy);


        let mut tampered_bitmap = vec![];
        tampered_bitmap.extend_from_slice(reveal_bitmap);

        let b = reveal_bitmap.get(0).unwrap();

        tampered_bitmap[0] = !(*b);
        if *b {
            ctexts.remove(0);
        }


        let vrfy = pok_attrs_verify::<BLSScalar,BLSGt>(
            &proof,
            ctexts.as_slice(),
            &pok_attrs,
            &asset_issuer_public_key,
            cred_issuer_pub_key,
            tampered_bitmap.as_slice());


        assert_eq!(Err(ZeiError::IdentityRevealVerifyError), vrfy);

    }

    #[test]
    fn confidential_reveal_one_attr_hidden(){
        confidential_reveal(&[false]);
    }

    #[test]
    fn confidential_reveal_one_attr_revealed(){
        confidential_reveal(&[true]);
    }

    #[test]
    fn confidential_reveal_two_attr_hidden_first(){
        confidential_reveal(&[false, false]);
        confidential_reveal(&[false, true]);
    }

    #[test]
    fn confidential_reveal_two_attr_revealed_first(){
        confidential_reveal(&[true, false]);
        confidential_reveal(&[true, true]);
    }

    #[test]
    fn confidential_reveal_ten_attr_all_hidden(){
        confidential_reveal(&[false;10]);
    }

    #[test]
    fn confidential_reveal_ten_attr_all_revealed(){
        confidential_reveal(&[true;10]);
    }

    #[test]
    fn confidential_reveal_ten_attr_half_revealed(){
        confidential_reveal(&[true,false,true,false,true,false,true,false,true,false]);
        confidential_reveal(&[false,true,false,true,false,true,false,true,false,true]);
    }
}

#[cfg(test)]
mod test_serialization{
    use crate::algebra::bls12_381::{BLSG1, BLSG2, BLSScalar};
    use crate::proofs::identity::PoKAttrs;
    use serde::{Deserialize, Serialize};
    use rmp_serde::Deserializer;
    use crate::algebra::groups::{Group, Scalar};
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;

    fn to_json<G1: Group<S>, G2: Group<S>, S: Scalar>(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let pokattrs = PoKAttrs{
            attr_blind_cred_commitment: G2::get_base(),
            attr_commitments: vec![G1::get_identity()],
            rand_commitments: vec![(G1::get_base(), G1::get_identity()), ((G1::get_base(), G1::get_identity()))], // (blind_{r_i} * G, blind_{r_i} * PK)
            attr_responses: vec![S::from_u32(0), S::random_scalar(&mut prng)],
            rand_responses: vec![S::from_u32(0), S::from_u32(0), S::from_u32(0), S::from_u32(0)],
        };

        let json_str = serde_json::to_string(&pokattrs).unwrap();
        let pokattrs_de: PoKAttrs<G1, G2, S> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(pokattrs, pokattrs_de);
    }

    fn to_msg_pack<G1: Group<S>, G2: Group<S>, S: Scalar>(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let pokattrs = PoKAttrs{
            attr_blind_cred_commitment: G2::get_base(),
            attr_commitments: vec![G1::get_identity()],
            rand_commitments: vec![(G1::get_base(), G1::get_identity()), ((G1::get_base(), G1::get_identity()))], // (blind_{r_i} * G, blind_{r_i} * PK)
            attr_responses: vec![S::from_u32(0), S::random_scalar(&mut prng)],
            rand_responses: vec![S::from_u32(0), S::from_u32(0), S::from_u32(0), S::from_u32(0)],
        };
        //keys serialization
        let mut vec = vec![];
        pokattrs.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let pokattrs_de: PoKAttrs<G1, G2, S> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(pokattrs, pokattrs_de);
    }

    #[test]
    fn to_json_bls12_381(){
        to_json::<BLSG1, BLSG2, BLSScalar>();
    }

    #[test]
    fn to_msg_pack_bls12_381(){
        to_msg_pack::<BLSG1, BLSG2, BLSScalar>();
    }
}
