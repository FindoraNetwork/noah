use rand::{CryptoRng, Rng};
use crate::credentials::{IssuerPublicKey, compute_challenge, AttrsRevealProof};
use crate::errors::ZeiError;
use crate::algebra::pairing::Pairing;
use crate::algebra::groups::{Group, Scalar};
use sha2::{Sha512, Digest};
use crate::basic_crypto::elgamal::{ElGamalCiphertext, ElGamalPublicKey};
use crate::algebra::utils::{scalar_linear_combination_rows, group_linear_combination_rows};
use serde::ser::Serialize;

// Generic functions for confidential identity reveal features
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoKAttrs<G1, G2, S>{
    attr_cred_com: G2, // sum blind_{a_i} * Y2_i for a_i in encrypted attributes
    attr_enc_coms: Vec<G1>, // blind_{a_i} * G1 for a_i in encrypted attributes
    attr_resps: Vec<S>, // {c*a_i + blind_{a_i}}
    rand_coms_g: Vec<G1>, // (blind_{r_i} * G1
    rand_coms_pk: Vec<G1>, // blind_{r_i} * PK
    rand_resps: Vec<S>, // {c*r_i + blind_{r_i}}
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggPoKAttrs<G1, G2, S>{
    pub attr_cred_com_vec: Vec<G2>, // sum blind_{a_i} * Y2_i for a_i in encrypted attributes for each instance j. Cannot be aggregated
    pub agg_attr_coms: Vec<G1>, // \sum_j x_j* blind_{a_i} * G1 for a_i in encrypted attributes
    pub attr_resps_vecs: Vec<Vec<S>>, // {{c*a_i + blind_{a_i}}_i}_j for each instance j, Cannot be aggregated
    pub agg_rand_coms_g: Vec<G1>, // \sum_j x_j * blind_{r_i} * G
    pub agg_rand_coms_pk: Vec<G1>, // \sum_j x_j  * blind_{r_i} * PK)
    pub agg_rand_resps: Vec<S>, // {\sum_j x_j (c*r_i + blind_{r_i})}
}


pub fn pok_attrs_aggregate_prove<R,S,P>(
    prng: &mut R,
    cred_issuer_pub_key: &IssuerPublicKey<P::G1, P::G2>,
    asset_issuer_pub_key: &ElGamalPublicKey<P::G1>,
    attrs: &[&[S]],
    ctexts_rand: &[&[S]],
    bitmap: &[bool],
    ctexts: &[&[ElGamalCiphertext<P::G1>]],
    cred_sigs: &[AttrsRevealProof<P::G1, P::G2, S>]
)-> Result<AggPoKAttrs<P::G1, P::G2, S>, ZeiError>
    where R: CryptoRng + Rng, S: Scalar, P: Pairing<S>
{
    //0: santity check on vector length
    let n_instances = attrs.len();
    if n_instances != ctexts_rand.len() || n_instances != ctexts.len() || n_instances != cred_sigs.len(){
        return Err(ZeiError::ParameterError);
    }
    let n_attrs = bitmap.iter().filter(|x| **x).count();
    if n_attrs > bitmap.len(){
        return Err(ZeiError::ParameterError);
    }

    //1: compute proof commitments. That is, sample bliding factor for each secret value and "commit to them"
    let mut cred_attrs_coms = vec![];
    let mut enc_attrs_coms = vec![];
    let mut enc_rands_coms_g = vec![];
    let mut enc_rands_coms_pk = vec![];
    let mut enc_attrs_rands_blinds = vec![];
    for attrs_i in attrs.iter(){
        if n_attrs != (*attrs_i).len() {
            return Err(ZeiError::ParameterError);
        }
        let (cred_com,
            coms,
            blinds
        ) = compute_proof_commitments::<_, S, P>(prng, cred_issuer_pub_key, asset_issuer_pub_key, bitmap, n_attrs);
        cred_attrs_coms.push(cred_com);
        enc_attrs_coms.push(coms.0);
        enc_rands_coms_g.push(coms.1);
        enc_rands_coms_pk.push(coms.2);
        enc_attrs_rands_blinds.push(blinds);
    }
    //2: sample linear combination scalars
    let lc_scalars = compute_linear_combination_scalars::<S,P>(ctexts, cred_sigs);

    //3: aggregate attributes blinding commitments under G
    let agg_enc_attr_coms = group_linear_combination_rows(
        lc_scalars.as_slice(),
        enc_attrs_coms.as_slice());
    let agg_enc_rand_coms_g = group_linear_combination_rows(
        lc_scalars.as_slice(),
        enc_rands_coms_g.as_slice());
    let agg_enc_rand_coms_pk = group_linear_combination_rows(
        lc_scalars.as_slice(),
        enc_rands_coms_pk.as_slice());

    //4: Compute challenge for the proof and scalars for linear combination
    let challenge = compute_challenge_aggregate::<S,P>(
        cred_attrs_coms.as_slice(),
        agg_enc_attr_coms.as_slice(),
        agg_enc_rand_coms_g.as_slice(),
        agg_enc_rand_coms_pk.as_slice()
    );

    //3: compute proof responses
    let mut attrs_resp = vec![];
    let mut rands_resp = vec![];
    for (attrs_i, rands_i, blinds_i) in izip!(attrs, ctexts_rand, enc_attrs_rands_blinds){
        let pf_resp_i = compute_proof_responses::<S>(
            &challenge,
            *attrs_i,
            blinds_i.0.as_slice(),
            *rands_i,
            blinds_i.1.as_slice());

        attrs_resp.push(pf_resp_i.0);
        rands_resp.push(pf_resp_i.1);
    }

    //4: aggregate rand responses
    let agg_rand_resp = scalar_linear_combination_rows(lc_scalars.as_slice(), rands_resp.as_slice());

    //5: build struct and return
    Ok(AggPoKAttrs{
        attr_cred_com_vec: cred_attrs_coms,
        agg_attr_coms: agg_enc_attr_coms,
        agg_rand_coms_g: agg_enc_rand_coms_g,
        agg_rand_coms_pk: agg_enc_rand_coms_pk,
        attr_resps_vecs: attrs_resp,
        agg_rand_resps: agg_rand_resp,
    })

}


/*
/// I aggregate a set of PoKAttrs using a linear combination of the struct fields
fn aggregate_proofs<G1, G2, S>(
    scalars: &[S],
    cred_attrs_coms: &[G2],
    enc_attrs_coms: &[Vec<G1>],
    enc_rands_coms: &[Vec<(G1, G1)>],
    attrs_resp: &[Vec<S>],
    rands_resp: &[Vec<S>],
) -> AggPoKAttrs<G1, G2, S>
where G1: Group<S>, G2: Group<S>, S:Scalar
{
    // 1: append all Cred_Attrs_coms
    let mut attr_cred_com_vec = vec![];
    attr_cred_com_vec.extend_from_slice(cred_attrs_coms);

    //2 append all attrs_responses
    let mut attr_resps_vecs = vec![];
    attr_resps_vecs.extend_from_slice(attrs_resp);


    let n_attrs = attrs_resp.len();
    let mut agg_attr_coms = vec![G1::get_identity(); n_attrs];
    let mut agg_rand_coms = vec![(G1::get_identity(), G1::get_identity()); n_attrs];
    let mut agg_rand_resps = vec![S::from_u32(0u32); n_attrs];

    for (xi, enc_attrs_coms_i, enc_rand_coms_i, rand_resp_i)
        in izip!(
        scalars.iter(),
        enc_attrs_coms.iter(),
        enc_rands_coms.iter(),
        rands_resp.iter()){


        for j  in 0 ..n_attrs{
            agg_attr_coms[j] = agg_attr_coms[j].add(&enc_attrs_coms_i[j].mul(xi));
            agg_rand_resps[j] = agg_rand_resps[j].add(&rand_resp_i[j].mul(xi));

            let (agg_g, agg_pk) = &agg_rand_coms[j];
            let (g, pk) = &enc_rand_coms_i[j];
            let agg_rand_com_g_j = agg_g.add(&g.mul(xi));
            let agg_rand_com_pk_j = agg_pk.add(&pk.mul(xi));
            agg_rand_coms[j] = (agg_rand_com_g_j, agg_rand_com_pk_j);
        }
    }

    AggPoKAttrs{
        attr_cred_com_vec,
        agg_attr_coms,
        agg_rand_coms,
        attr_resps_vecs,
        agg_rand_resps
    }

}
*/

fn compute_linear_combination_scalars<S:Scalar, P: Pairing<S>> (
    ctexts: &[&[ElGamalCiphertext<P::G1>]],
    cred_sigs: &[AttrsRevealProof<P::G1, P::G2, S>]
) -> Vec<S>
{
    let mut hash = Sha512::new();
    let mut cred_sig_vec = vec![];
    cred_sigs.serialize(&mut rmp_serde::Serializer::new(&mut cred_sig_vec)).unwrap();
    hash.input(cred_sig_vec.as_slice());

    for ctext_vec in ctexts.iter(){
        for ctext in *ctext_vec{
            hash.input(ctext.e1.to_compressed_bytes());
            hash.input(ctext.e1.to_compressed_bytes());
        }
    }
    let mut x = vec![];
    let mut xi = S::from_hash(hash);
    for _ in 1..ctexts.len(){
        let mut hash = Sha512::new();
        hash.input(xi.to_bytes());
        let new_xi = S::from_hash(hash);
        x.push(xi);
        xi = new_xi;
    }

    x.push(xi);
    x
}

fn compute_challenge_aggregate<S: Scalar, P: Pairing<S>> (
    cred_coms: &[P::G2],
    agg_proof_coms_attrs: &[P::G1],
    agg_proof_coms_rands_g: &[P::G1],
    agg_proof_coms_rands_pk: &[P::G1]
) -> S
{
    let mut hash = Sha512::new();
    for cred_com in cred_coms{
        hash.input(cred_com.to_compressed_bytes());
    }
    for (a_g, r_g, r_pk)
        in izip!(agg_proof_coms_attrs, agg_proof_coms_rands_g, agg_proof_coms_rands_pk){
            hash.input(a_g.to_compressed_bytes());
            hash.input(r_g.to_compressed_bytes());
            hash.input(r_pk.to_compressed_bytes());
    }
    S::from_hash(hash)
}


pub(crate) fn pok_attrs_verify_aggregate<S: Scalar, P: Pairing<S>>(
    cred_issuer_pub_key: &IssuerPublicKey<P::G1, P::G2>,
    asset_issuer_public_key: &ElGamalPublicKey<P::G1>,
    reveal_proofs: &[AttrsRevealProof<P::G1, P::G2, S>],
    ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
    agg_pok_attrs: AggPoKAttrs<P::G1, P::G2, S>,
    bitmap: &[bool], // indicates which attributes should be revealed to the asset issuer
) -> Result<(), ZeiError>
{
    let n_attrs = ctexts_vecs[0].len();

    // 1. compute scalars
    let lc_scalars = compute_linear_combination_scalars::<S,P>(
        ctexts_vecs, reveal_proofs);


    // 2. aggregate ctexts and attribute responses
    let mut ctexts_agg = vec![
        ElGamalCiphertext{
            e1: P::G1::get_identity(),e2: P::G1::get_identity()
        }; n_attrs];
    let mut agg_attr_resps = vec![S::from_u32(0u32); n_attrs];

    for (xi, ctexts_vec, attr_resp_vec) in izip!(lc_scalars.iter(), ctexts_vecs.iter(), agg_pok_attrs.attr_resps_vecs.iter()) {
        for j in 0..n_attrs {
            let ctext_attr = &ctexts_vec[j];
            let ctext_attr_agg = &ctexts_agg[j];
            ctexts_agg[j] = ElGamalCiphertext {
                e1: ctext_attr_agg.e1.add(&ctext_attr.e1.mul(xi)),
                e2: ctext_attr_agg.e2.add(&ctext_attr.e2.mul(xi))
            };
            agg_attr_resps[j] = agg_attr_resps[j].add(&attr_resp_vec[j].mul(xi));
        }

    }

    // 3. verify
    // 3.1 compute challenge
    let challenge = compute_challenge_aggregate::<S,P>(
        agg_pok_attrs.attr_cred_com_vec.as_slice(),
        agg_pok_attrs.agg_attr_coms.as_slice(),
        agg_pok_attrs.agg_rand_coms_g.as_slice(),
        agg_pok_attrs.agg_rand_coms_pk.as_slice());

    // 3.2 verify ciphertexts
    verify_ciphertext::<S,P>(
        &challenge,
        ctexts_agg.as_slice(),
        agg_pok_attrs.agg_attr_coms.as_slice(),
        agg_pok_attrs.agg_rand_coms_g.as_slice(),
        agg_pok_attrs.agg_rand_coms_pk.as_slice(),
        agg_attr_resps.as_slice(),
        agg_pok_attrs.agg_rand_resps.as_slice(),
        asset_issuer_public_key)?;

    // 4. verify credentials
    verify_credential_agg::<S,P>(
        &challenge,
        lc_scalars.as_slice(),
        reveal_proofs,
        agg_pok_attrs.attr_cred_com_vec.as_slice(),
        agg_pok_attrs.attr_resps_vecs.as_slice(),
        cred_issuer_pub_key,
        bitmap)?;
    Ok(())
}

fn verify_credential_agg<S: Scalar, P: Pairing<S>>(
    challenge: &S,
    lc_scalars: &[S],
    reveal_proofs: &[AttrsRevealProof<P::G1, P::G2, S>],
    cred_coms: &[P::G2],
    attr_resps: &[Vec<S>],
    cred_issuer_public_key: &IssuerPublicKey<P::G1, P::G2>,
    bitmap: &[bool], //policy, indicates which attributes needs to be revealed to the asset issuer
) -> Result<(), ZeiError>
{
    // 1. For each credential instance k compute challenge c_k
    // 2. For each credential instance k compute P_k = challenge * A_k + challenges_k * B_k where
    //  A is credential proof constant values
    //  and B correspond to the credential proof "revealed" attributes
    // 3. Aggregate signatures for the righ-hand-side of the pairing:
    //    \sigma2 = challenge * \sum_k x_k * challenges_k * sigma2_k
    let mut pp = vec![];
    let mut agg_sigma2 = P::G1::get_identity();
    for (reveal_proof, cred_com, attr_resp, lc_scalar)
        in izip!(reveal_proofs, cred_coms, attr_resps, lc_scalars) {

        let c_k = compute_challenge::<S, P>(&reveal_proof.pok.commitment);
        let aa_k = constant_terms_addition::<S,P>(&c_k, reveal_proof, cred_issuer_public_key, bitmap)?;

        let mut bb_k = P::G2::get_identity();
        let mut resp_iter = attr_resp.iter();
        for (bi, yi) in bitmap.iter().zip(cred_issuer_public_key.yy2.iter()){
            if *bi {
                let resp = resp_iter.next().ok_or(ZeiError::ParameterError)?;
                bb_k = bb_k.add(&yi.mul(resp));
            }
        }
        bb_k.sub(cred_com);
        let c = c_k.mul(lc_scalar);
        let pp_k = aa_k.mul(challenge).add(&bb_k.mul(&c));
        pp.push(pp_k);

        agg_sigma2 = agg_sigma2.add(&reveal_proof.sig.sigma2.mul(&c));
    }
    agg_sigma2 = agg_sigma2.mul(challenge);

    //3. Compute right hand side pairing: e(sigma2, G2)
    let rhs = P::pairing(&agg_sigma2, &cred_issuer_public_key.gen2);

    //4. Compute left hans side as \prod_k e(sigma1_k, P_k)
    let mut lhs = P::get_identity();
    for (proof, pp_k) in reveal_proofs.iter().zip(pp){
        let lhs_i= P::pairing(&proof.sig.sigma1, &pp_k);
        lhs = lhs.add(&lhs_i)
    }

    //5. return Ok if LHS = RHS
    match lhs == rhs {
        true => Ok(()),
        false => {Err(ZeiError::IdentityRevealVerifyError)},
    }
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
    let (attr_blind_cred_commitment,
    (attr_commitments,rand_commitments_g, rand_commitments_pk),
    (attr_blind,rand_blind)) =
    compute_proof_commitments::<_, S, P>(prng, cred_issuer_pub_key, asset_issuer_pub_key, bitmap, m);

    let challenge = pok_attrs_challenge::<S, P>(
        attr_commitments.as_slice(),
        rand_commitments_g.as_slice(),
        rand_commitments_pk.as_slice()
    );

    let (attr_responses, rand_responses) =
        compute_proof_responses::<S>(&challenge, attrs, attr_blind.as_slice(), ctexts_rand, rand_blind.as_slice());

    Ok(PoKAttrs{
        attr_cred_com: attr_blind_cred_commitment,
        attr_enc_coms: attr_commitments,
        attr_resps: attr_responses,
        rand_coms_g: rand_commitments_g,
        rand_coms_pk: rand_commitments_pk,
        rand_resps: rand_responses
    })
}

fn compute_proof_commitments<R,S, P>(
    prng: &mut R,
    cred_issuer_pub_key: &IssuerPublicKey<P::G1, P::G2>,
    asset_issuer_pub_key: &ElGamalPublicKey<P::G1>,
    bitmap: &[bool], m: usize) -> (P::G2, (Vec<P::G1>, Vec<P::G1>, Vec<P::G1>), (Vec<S>,  Vec<S>))
where R: CryptoRng + Rng, S: Scalar, P: Pairing<S>
{
    let mut attr_commitments = Vec::with_capacity(m);
    let mut attr_blind = Vec::with_capacity(m);
    let mut rand_commitments_g =
        Vec::with_capacity(m);
    let mut rand_commitments_pk =
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
            rand_commitments_g.push(com_g);
            rand_commitments_pk.push(com_pk);
        }
    }

    (attr_blind_cred_commitment, (attr_commitments, rand_commitments_g, rand_commitments_pk), (attr_blind, rand_blind))
}

fn compute_proof_responses<S: Scalar>(
    challenge: &S,
    attrs: &[S],
    attr_blind: &[S],
    ctexts_rand: &[S],
    rand_blind: &[S]
) -> (Vec<S>, Vec<S>)
{
    let m = attr_blind.len();
    let mut attr_responses = Vec::with_capacity(m);
    for (attr, blind) in attrs.iter().
        zip(attr_blind.iter()){
        attr_responses.push(attr.mul(&challenge).add(&blind));
    }
    let mut rand_responses = Vec::with_capacity(m);
    for (rand, blind) in ctexts_rand.iter().
        zip(rand_blind.iter()){
        rand_responses.push(rand.mul(&challenge).add(&blind));
    }

    (attr_responses, rand_responses)
}


/// I compute the challenge in a proof of knowledge of identity attributes
fn pok_attrs_challenge<S: Scalar, P: Pairing<S>>(
    attr_coms: &[P::G1],
    rand_coms_g: &[P::G1],
    rand_coms_pk: &[P::G1]
) -> S
{
    let mut hash = Sha512::new();
    for (a_g, r_g, r_pk) in izip!(attr_coms, rand_coms_g, rand_coms_pk){
        hash.input(a_g.to_compressed_bytes());
        hash.input(r_g.to_compressed_bytes());
        hash.input(r_pk.to_compressed_bytes());
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
        pok_attrs.attr_enc_coms.as_slice(),
        pok_attrs.rand_coms_g.as_slice(),
        pok_attrs.rand_coms_pk.as_slice());
    // 2. do ciphertexts verification
    verify_ciphertext::<S,P>(
        &challenge,
        ctexts,
        pok_attrs.attr_enc_coms.as_slice(),
        pok_attrs.rand_coms_g.as_slice(),
        pok_attrs.rand_coms_pk.as_slice(),
        pok_attrs.attr_resps.as_slice(),
        pok_attrs.rand_resps.as_slice(),
        asset_issuer_public_key)?;
    // 3. do credential verification
    verify_credential::<S,P>(&challenge, reveal_proof, pok_attrs, cred_issuer_pub_key, bitmap)
}

/// I verify a proof of knowledge of a set of ElGamal encrypted messages
fn verify_ciphertext<S: Scalar, P: Pairing<S>>(
    challenge: &S,
    ctexts: &[ElGamalCiphertext<P::G1>],
    attr_commitments: &[P::G1],
    rand_commitments_g: &[P::G1],
    rand_commitments_pk: &[P::G1],
    attr_responses: &[S],
    rand_responses: &[S],
    asset_issuer_public_key: &ElGamalPublicKey<P::G1>
) -> Result<(), ZeiError>
{

    for (ctext, attr_com, rand_coms_g, rand_coms_pk, attr_response, rand_response)
        in izip!(ctexts, attr_commitments, rand_commitments_g, rand_commitments_pk, attr_responses, rand_responses){
        let e1 = &ctext.e1;
        let e2 = &ctext.e2;

        let verify_e1 =
            P::g1_mul_scalar(e1, &challenge).add(rand_coms_g) ==
                P::g1_mul_scalar(&P::G1::get_base(), rand_response);
        let verify_e2 =
            P::g1_mul_scalar(e2, &challenge).add(rand_coms_pk).add(attr_com) ==
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
    // lhs constant: c*X2 + - pf.com + r_t*G2 + r_sk * Z2 + sum a_i*Y2i (a_i in hidden)
    let cred_lhs_constant =
        constant_terms_addition::<S,P>(
            &cred_challenge,
            reveal_proof,
            cred_issuer_public_key, bitmap).
            map_err(|_| ZeiError::IdentityRevealVerifyError)?;

    let cred_rhs_constant = P::g2_mul_scalar(
        &cred_issuer_public_key.gen2,
        &cred_challenge); //c*G2

    // c' * (c*X2 + - pf.com + r_t*G2 + r_sk * Z2 + sum a_i + Y2i (a_i in hidden))
    let lhs_constant = P::g2_mul_scalar(&cred_lhs_constant, challenge);


    //add pok response terms to left hand side
    // c * sum r_{a_i}*Y2_i (ai in revealed) = c * sum r_{a_i}*Y2_i (ai in revealed)
    let mut blinded_attr_sum = P::G2::get_identity();
    let mut attrs_responses_iter = pok_attrs.attr_resps.iter();
    for (b, yy2i) in bitmap.iter().
        zip(cred_issuer_public_key.yy2.iter()) {
        if *b {
            let response = attrs_responses_iter.next().ok_or(ZeiError::IdentityRevealVerifyError)?;
            blinded_attr_sum = blinded_attr_sum.add(&P::g2_mul_scalar(yy2i, response));
        }
    }
    // subtract commitment scaled by cred_challenge: c*pok_aattrs.attr_commitment = c*\sum b_i* Y2i
    blinded_attr_sum = blinded_attr_sum.sub(&pok_attrs.attr_cred_com);
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

fn constant_terms_addition<S: Scalar, P: Pairing<S>>(
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
            attr_cred_com: G2::get_base(),
            attr_enc_coms: vec![G1::get_identity()],
            rand_coms: vec![(G1::get_base(), G1::get_identity()), ((G1::get_base(), G1::get_identity()))], // (blind_{r_i} * G, blind_{r_i} * PK)
            attr_resps: vec![S::from_u32(0), S::random_scalar(&mut prng)],
            rand_resps: vec![S::from_u32(0), S::from_u32(0), S::from_u32(0), S::from_u32(0)],
        };

        let json_str = serde_json::to_string(&pokattrs).unwrap();
        let pokattrs_de: PoKAttrs<G1, G2, S> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(pokattrs, pokattrs_de);
    }

    fn to_msg_pack<G1: Group<S>, G2: Group<S>, S: Scalar>(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let pokattrs = PoKAttrs{
            attr_cred_com: G2::get_base(),
            attr_enc_coms: vec![G1::get_identity()],
            rand_coms: vec![(G1::get_base(), G1::get_identity()), ((G1::get_base(), G1::get_identity()))], // (blind_{r_i} * G, blind_{r_i} * PK)
            attr_resps: vec![S::from_u32(0), S::random_scalar(&mut prng)],
            rand_resps: vec![S::from_u32(0), S::from_u32(0), S::from_u32(0), S::from_u32(0)],
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
