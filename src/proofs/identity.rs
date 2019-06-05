use crate::algebra::groups::{Group, Scalar};
use crate::algebra::pairing::Pairing;
use crate::algebra::utils::{scalar_linear_combination_rows, group_linear_combination_rows};
use crate::basic_crypto::elgamal::{ElGamalCiphertext, ElGamalPublicKey};
use crate::credentials::{IssuerPublicKey, compute_challenge, AttrsRevealProof};
use crate::errors::ZeiError;
use rand::{CryptoRng, Rng};
use serde::ser::Serialize;
use sha2::{Sha512, Digest};


/// Aggregated proof of knowledge of revealed attributes for an anonymous credetial reveal proof
/// that are encrypted under ElGamal
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggPoKAttrs<G1, G2, S>{
    pub attr_sum_com_yy2: Vec<G2>, // {sum blind_{attr_{j,k}} * Y2_j }_k for attr_{j,k} in encrypted attributes for each instance k. Cannot be aggregated
    pub agg_attrs_coms_g: Vec<G1>, // \sum_k x_k* blind_{a_{j,k}} * G1 for attr_{j,k} in encrypted attributes
    pub attrs_resps: Vec<Vec<S>>, // {{c*attr_{j,k} + blind_{attr_{j,k}} }_j}_k for each instance k, Cannot be aggregated
    pub agg_rands_coms_g: Vec<G1>, // {\sum_k x_k * blind_{r_{j,k}} * G}_j
    pub agg_rands_coms_pk: Vec<G1>, // {\sum_k x_k  * blind_{r_{j,k}} * PK }_j
    pub agg_rands_resps: Vec<S>, //  {\sum_k x_k (c*r_{j,k} + blind_{r_{i,k}})}_j
}

/// I compute a proof of knowledge of identity attributes to be verified against encryption of these
/// and a anonymous credential reveal proof
pub fn pok_attrs_prove<R, S, P>(
    prng: &mut R,
    cred_issuer_pub_key: &IssuerPublicKey<P::G1, P::G2>,
    asset_issuer_pub_key: &ElGamalPublicKey<P::G1>,
    attrs: &[S], // attributes to prove knowledge of
    ctexts_rand: &[S], // randomness used to encrypt attrs
    bitmap: &[bool], // indicates position of each attribute to prove
    ctexts: &[ElGamalCiphertext<P::G1>],
    cred_sig: &AttrsRevealProof<P::G1, P::G2, S>,
) -> Result<AggPoKAttrs<P::G1, P::G2, S>, ZeiError>
    where R: CryptoRng + Rng, S: Scalar, P: Pairing<S>
{
    agg_pok_attrs_prove::<R,S,P>(
        prng,
        cred_issuer_pub_key,
        asset_issuer_pub_key,
        &[attrs],
        &[ctexts_rand],
        bitmap,
        &[ctexts],
        &[cred_sig]
    )
}

/// I verify a proof of knowledge of attributes that
/// a) satisfy a single anonymous credential reveal proof
/// b) are encrypted under ctexts (ElGamal encryptions)
pub(crate) fn pok_attrs_verify<S: Scalar, P: Pairing<S>>(
    cred_issuer_pub_key: &IssuerPublicKey<P::G1, P::G2>,
    asset_issuer_public_key: &ElGamalPublicKey<P::G1>,
    reveal_proof: &AttrsRevealProof<P::G1, P::G2, S>,
    ctexts: &[ElGamalCiphertext<P::G1>],
    pok_attrs: &AggPoKAttrs<P::G1, P::G2, S>,
    bitmap: &[bool], // indicates which attributes should be revealed to the asset issuer
) -> Result<(), ZeiError>
{
    agg_pok_attrs_verify::<S, P>(
        cred_issuer_pub_key,
        asset_issuer_public_key,
        &[reveal_proof],
        &[ctexts],
        pok_attrs,
        bitmap
    )
}

/// I compute an aggregated proof of knowledge of identity attribute sets to be verified against
/// encryption of these and a set of anonymous credential reveal proofs
pub fn agg_pok_attrs_prove<R,S,P>(
    prng: &mut R,
    cred_issuer_pub_key: &IssuerPublicKey<P::G1, P::G2>,
    asset_issuer_pub_key: &ElGamalPublicKey<P::G1>,
    attrs: &[&[S]],
    ctexts_rand: &[&[S]],
    bitmap: &[bool],
    ctexts: &[&[ElGamalCiphertext<P::G1>]],
    cred_sigs: &[&AttrsRevealProof<P::G1, P::G2, S>]
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

    //1: sample secrets' blinds and compute proof commitments.
    let (attr_sum_com_yy2,
        (attrs_coms_g, rands_coms_g, rands_coms_pk),
        (attrs_blinds, rands_blinds)) =
        sample_blinds_compute_commitments::<_, S, P>(
            prng,
            cred_issuer_pub_key,
            asset_issuer_pub_key,
            bitmap,
            n_attrs,
            n_instances)?;

    //2: sample linear combination scalars
    let lc_scalars = compute_linear_combination_scalars::<S,P>(ctexts, cred_sigs);

    //3: aggregate attributes blinding commitments under G and PK
    let agg_attrs_coms_g = group_linear_combination_rows(
        lc_scalars.as_slice(),
        attrs_coms_g.as_slice());
    let agg_rands_coms_g = group_linear_combination_rows(
        lc_scalars.as_slice(),
        rands_coms_g.as_slice());
    let agg_rands_coms_pk = group_linear_combination_rows(
        lc_scalars.as_slice(),
        rands_coms_pk.as_slice());

    //4: Compute challenge for the proof and scalars for linear combination
    let challenge = compute_challenge_aggregate::<S,P>(
        attr_sum_com_yy2.as_slice(),
        agg_attrs_coms_g.as_slice(),
        agg_rands_coms_g.as_slice(),
        agg_rands_coms_pk.as_slice()
    );

    //3: compute proof responses
    let mut attrs_resps = vec![];
    let mut rands_resps = vec![];
    for (attrs_k, rands_k, attrs_blinds_k, rands_blinds_k) in izip!(attrs, ctexts_rand, attrs_blinds, rands_blinds){
        let (attrs_resps_k,rands_resps_k) = compute_proof_responses::<S>(
            &challenge,
            *attrs_k,
            attrs_blinds_k.as_slice(),
            *rands_k,
            rands_blinds_k.as_slice()
            );

        attrs_resps.push(attrs_resps_k);
        rands_resps.push(rands_resps_k);
    }

    //4: aggregate rand responses
    let agg_rands_resps = scalar_linear_combination_rows(
        lc_scalars.as_slice(),
        rands_resps.as_slice());

    //5: build struct and return
    Ok(AggPoKAttrs{
        attr_sum_com_yy2,
        agg_attrs_coms_g,
        agg_rands_coms_g,
        agg_rands_coms_pk,
        attrs_resps,
        agg_rands_resps,
    })

}

pub(crate) fn agg_pok_attrs_verify<S: Scalar, P: Pairing<S>>(
    cred_issuer_pub_key: &IssuerPublicKey<P::G1, P::G2>,
    asset_issuer_public_key: &ElGamalPublicKey<P::G1>,
    reveal_proofs: &[&AttrsRevealProof<P::G1, P::G2, S>],
    ctexts_vecs: &[&[ElGamalCiphertext<P::G1>]],
    agg_pok_attrs: &AggPoKAttrs<P::G1, P::G2, S>,
    bitmap: &[bool], // indicates which attributes should be revealed to the asset issuer
) -> Result<(), ZeiError>
{
    let n_attrs = ctexts_vecs[0].len();

    // 1. compute linear combination scalars
    let lc_scalars = compute_linear_combination_scalars::<S,P>(
        ctexts_vecs, reveal_proofs);


    // 2. aggregate ctexts and attribute responses
    let mut ctexts_agg = vec![
        ElGamalCiphertext{
            e1: P::G1::get_identity(),e2: P::G1::get_identity()
        }; n_attrs];
    let mut agg_attr_resps = vec![S::from_u32(0u32); n_attrs];

    for (x_k, ctexts_vec, attr_resp_vec) in izip!(lc_scalars.iter(), ctexts_vecs.iter(), agg_pok_attrs.attrs_resps.iter()) {
        for j in 0..n_attrs {
            let ctext_attr = &ctexts_vec[j];
            let ctext_attr_agg = &ctexts_agg[j];
            ctexts_agg[j] = ElGamalCiphertext {
                e1: ctext_attr_agg.e1.add(&ctext_attr.e1.mul(x_k)),
                e2: ctext_attr_agg.e2.add(&ctext_attr.e2.mul(x_k))
            };
            agg_attr_resps[j] = agg_attr_resps[j].add(&attr_resp_vec[j].mul(x_k));
        }

    }

    // 3. verify
    // 3.1 compute challenge
    let challenge = compute_challenge_aggregate::<S,P>(
        agg_pok_attrs.attr_sum_com_yy2.as_slice(),
        agg_pok_attrs.agg_attrs_coms_g.as_slice(),
        agg_pok_attrs.agg_rands_coms_g.as_slice(),
        agg_pok_attrs.agg_rands_coms_pk.as_slice());

    // 3.2 verify ciphertexts
    verify_ciphertext::<S,P>(
        &challenge,
        ctexts_agg.as_slice(),
        agg_pok_attrs.agg_attrs_coms_g.as_slice(),
        agg_pok_attrs.agg_rands_coms_g.as_slice(),
        agg_pok_attrs.agg_rands_coms_pk.as_slice(),
        agg_attr_resps.as_slice(),
        agg_pok_attrs.agg_rands_resps.as_slice(),
        asset_issuer_public_key)?;

    // 4. verify credentials
    verify_credential_agg::<S,P>(
        &challenge,
        lc_scalars.as_slice(),
        reveal_proofs,
        agg_pok_attrs.attr_sum_com_yy2.as_slice(),
        agg_pok_attrs.attrs_resps.as_slice(),
        cred_issuer_pub_key,
        bitmap)?;
    Ok(())
}

/// I hash the parameters to sample a set of scalars used to aggregate proofs,
/// one scalar per instance. First scalar is 1.
fn compute_linear_combination_scalars<S:Scalar, P: Pairing<S>> (
    ctexts: &[&[ElGamalCiphertext<P::G1>]],
    cred_sigs: &[&AttrsRevealProof<P::G1, P::G2, S>]
) -> Vec<S>
{
    if ctexts.len() == 0 {
        return vec![];
    }

    let mut scalars = vec![S::from_u32(1)];
    if ctexts.len() == 1 {
        return scalars;
    }

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
    let mut xi = S::from_hash(hash);
    for _ in 2..ctexts.len(){
        let mut hash = Sha512::new();
        hash.input(xi.to_bytes());
        let new_xi = S::from_hash(hash);
        scalars.push(xi);
        xi = new_xi;
    }

    scalars.push(xi);
    scalars
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

    //TODO Use multi-exponentiation, then aggregate
    for (ctext, attr_com, rand_coms_g, rand_coms_pk, attr_response, rand_response)
        in izip!(ctexts, attr_commitments, rand_commitments_g, rand_commitments_pk, attr_responses, rand_responses){
        let e1 = &ctext.e1;
        let e2 = &ctext.e2;

        let verify_e1 =
            e1.mul(challenge).add(rand_coms_g) == P::G1::get_base().mul(rand_response);
        let verify_e2 =
            e2.mul(&challenge).add(rand_coms_pk).add(attr_com) ==
                P::G1::get_base().mul(attr_response).add( &asset_issuer_public_key.0.mul(rand_response));
        if !(verify_e1 && verify_e2) {
            return Err(ZeiError::IdentityRevealVerifyError);
        }
    }

    Ok(())
}

/// I verify a proof of knowledge of attributed that verify an anonymous credential reveal proof.
fn verify_credential_agg<S: Scalar, P: Pairing<S>>(
    challenge: &S,
    lc_scalars: &[S],
    reveal_proofs: &[&AttrsRevealProof<P::G1, P::G2, S>],
    attr_sum_com_yy2: &[P::G2],
    attr_resps: &[Vec<S>],
    cred_issuer_public_key: &IssuerPublicKey<P::G1, P::G2>,
    bitmap: &[bool], //policy, indicates which attributes needs to be revealed to the asset issuer
) -> Result<(), ZeiError>
{
    // 1. For each credential instance k compute challenge c_k
    // 2. For each credential instance k compute P_k = challenge * H_k + challenges_k * R_k where
    //  A is credential proof terms for x, t, sk, Hidden attributes
    //  and R_k correspond to the credential proof "revealed" attributes
    // 3. Aggregate signatures for the righ-hand-side of the pairing:
    //    \sigma2 = challenge * \sum_k x_k * challenges_k * sigma2_k
    let mut pp = vec![];
    let mut agg_sigma2 = P::G1::get_identity();
    for (lc_scalar_k, reveal_proof_k, attr_sum_com_k, attr_resp_k)
        in izip!(lc_scalars, reveal_proofs, attr_sum_com_yy2, attr_resps) {

        let c_k = compute_challenge::<S, P>(&reveal_proof_k.pok.commitment);

        let hidden_k = credential_hidden_terms_addition::<S,P>(
            &c_k,
            reveal_proof_k,
            cred_issuer_public_key, bitmap)?;

        let revealed_k = crendential_zk_revealed_terms_addition::<S,P>(
            cred_issuer_public_key,
            attr_sum_com_k,
            attr_resp_k,
            bitmap,
        )?;

        let pp_k = hidden_k.mul(challenge).add(&revealed_k.mul(&c_k));
        pp.push(pp_k);
        agg_sigma2 = agg_sigma2.add(&reveal_proof_k.sig.sigma2.mul(&c_k.mul(lc_scalar_k)));
    }
    agg_sigma2 = agg_sigma2.mul(challenge);

    //3. Compute right hand side pairing: e(sigma2, G2)
    let rhs = P::pairing(&agg_sigma2, &cred_issuer_public_key.gen2);

    //4. Compute left hand side as \sum_k e(sigma1_k, P_k)
    let mut lhs = P::get_identity();
    for (lc_scalar_k, reveal_proof_k, pp_k) in izip!(lc_scalars, reveal_proofs, pp){
        let lhs_i= P::pairing(&reveal_proof_k.sig.sigma1.mul(lc_scalar_k), &pp_k);
        lhs = lhs.add(&lhs_i);
    }
    //5. return Ok if LHS = RHS
    match lhs == rhs {
        true => Ok(()),
        false => {Err(ZeiError::IdentityRevealVerifyError)},
    }
}

/// For each secret value,
/// a) sample a blinding scalar,
/// b) compute proof commitments of this scalars to be used in a PoK of the secret values that
/// verify an anonymous credential reveal proof and matched ElGamal encryptions
fn sample_blinds_compute_commitments<R,S, P>(
    prng: &mut R,
    cred_issuer_pub_key: &IssuerPublicKey<P::G1, P::G2>,
    asset_issuer_pub_key: &ElGamalPublicKey<P::G1>,
    bitmap: &[bool], n_attrs: usize, n_instances: usize
) -> Result<
    (Vec<P::G2>, (Vec<Vec<P::G1>>, Vec<Vec<P::G1>>, Vec<Vec<P::G1>>), (Vec<Vec<S>>,  Vec<Vec<S>>)),
    ZeiError>
    where R: CryptoRng + Rng, S: Scalar, P: Pairing<S>
{
    let mut attr_sum_com_yy2 =  Vec::with_capacity(n_instances);
    let mut attrs_coms_g: Vec<Vec<P::G1>> = Vec::with_capacity(n_instances);
    let mut rands_coms_g = Vec::with_capacity(n_instances);
    let mut rands_coms_pk = Vec::with_capacity(n_instances);

    let (attrs_blinds, rands_blinds) = sample_blinds::<R,S>(prng, n_attrs, 1);

    for k in 0..n_instances {
        attr_sum_com_yy2.push(compute_attr_sum_yy2::<S,P>(
            cred_issuer_pub_key,
            attrs_blinds.get(0).ok_or(ZeiError::ParameterError)?,
            bitmap)?);
        attrs_coms_g.push(Vec::with_capacity(n_attrs));
        rands_coms_g.push(Vec::with_capacity(n_attrs));
        rands_coms_pk.push(Vec::with_capacity(n_attrs));
        for (attr_blind, rand_blind) in izip!(attrs_blinds.get(k).unwrap(), rands_blinds.get(k).unwrap()) {
            attrs_coms_g[k].push(P::G1::get_base().mul(&attr_blind));
            rands_coms_g[k].push(P::G1::get_base().mul(&rand_blind));
            rands_coms_pk[k].push(asset_issuer_pub_key.0.mul(&rand_blind));
        }
    }
    
    Ok((attr_sum_com_yy2, (attrs_coms_g, rands_coms_g, rands_coms_pk), (attrs_blinds, rands_blinds)))
}

fn compute_attr_sum_yy2<S: Scalar, P: Pairing<S>>(
    cred_issuer_pub_key: &IssuerPublicKey<P::G1, P::G2>,
    attr_blinds: &Vec<S>,
    bitmap: &[bool],
) -> Result<P::G2, ZeiError>
{
    let mut attr_sum_com_yy2 = P::G2::get_identity();
    let mut blind_iter = attr_blinds.iter();
    for (yy2j, shown) in cred_issuer_pub_key.yy2.iter().zip(bitmap.iter()){
        if *shown {
            let attr_com_y2j = yy2j.mul(blind_iter.next().ok_or(ZeiError::ParameterError)?);
            attr_sum_com_yy2 = attr_sum_com_yy2.add(&attr_com_y2j);
        }
    }
    Ok(attr_sum_com_yy2)
}

/// I sample proof blindings for every attribute and encryption randomness for every instance
fn sample_blinds<R,S>(
    prng: &mut R,
    n_attrs: usize,
    n_instances: usize, ) -> (Vec<Vec<S>>, Vec<Vec<S>>)    where R: CryptoRng + Rng, S: Scalar
{
    let mut attr_blinds = vec![];
    let mut rand_blinds = vec![];
    for j in 0..n_instances {
        attr_blinds.push(vec![]);
        rand_blinds.push(vec![]);
        for _ in 0..n_attrs {
            attr_blinds[j].push(S::random_scalar(prng));
            rand_blinds[j].push(S::random_scalar(prng));
        }
    }
    (attr_blinds, rand_blinds)
}

/// I compute a challenge for the PoK of knowledge protocol for confidential attribute reveal
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

/// Using a challenge, secret values and their blindings, I compute the proof responses of a PoK
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
    let mut rand_responses = Vec::with_capacity(m);

    for (attr, blind) in attrs.iter().zip(attr_blind.iter()){
        attr_responses.push(attr.mul(&challenge).add(&blind));
    }
    for (rand, blind) in ctexts_rand.iter().zip(rand_blind.iter()){
        rand_responses.push(rand.mul(&challenge).add(&blind));
    }

    (attr_responses, rand_responses)
}

/// Helper function that compute the term of an anonymous credential verification
/// that do not include the revealed attributes. That is:
/// c * X2 + b_t * G1  + b_sk * Z2 + sum_{i\in Hidden} b_{attr_i} * Y2_i - reveal_proof.COM
/// = c( x + t + sk * z + sum_{i\in Hidden} attr_i * y2_i) * G2
fn credential_hidden_terms_addition<S: Scalar, P: Pairing<S>>(
    challenge: &S,
    reveal_proof: &AttrsRevealProof<P::G1, P::G2, S>,
    cred_issuer_public_key: &IssuerPublicKey<P::G1, P::G2>,
    bitmap: &[bool],
) -> Result<P::G2, ZeiError>
{
    //compute X_2 * challenge - commitment + G2 * &response_t + PK.Z2 * response_sk +
    // sum PK.Y2_i * response_attr_i
    let mut q = cred_issuer_public_key.xx2.mul(&challenge).sub(&reveal_proof.pok.commitment); //X_2*challenge - proof.commitment

    q = q.add(&cred_issuer_public_key.gen2.mul(&reveal_proof.pok.response_t));
    q = q.add(&cred_issuer_public_key.zz2.mul(&reveal_proof.pok.response_sk));

    let mut resp_attr_iter = reveal_proof.pok.response_attrs.iter();
    for (b, yy2i)  in bitmap.iter().
        zip(cred_issuer_public_key.yy2.iter()){
        if !b {
            let response = resp_attr_iter.next().ok_or(ZeiError::ParameterError)?;
            q = q.add(&yy2i.mul(response));
        }
    }
    Ok(q)
}

/// Helper function that compute the term of an anonymous credential verification
/// that DO include the revealed attributes, using the proof of knowledge of these attributes
/// rather than the plain attributes. That is:
/// sum_{j\in Revealed} b'_{attr_j} * Y2_j - PoK.attr_sum_com_yy2
///  = c' * sum_{j\in Revealed} attr_j * y_j * G2
fn crendential_zk_revealed_terms_addition<S: Scalar, P: Pairing<S>>(
    cred_issuer_public_key: &IssuerPublicKey<P::G1, P::G2>,
    attr_sum_com: &P::G2,
    attr_resps: &[S],
    bitmap: &[bool]
) -> Result<P::G2, ZeiError>
{
    let mut addition = P::G2::get_identity();
    let mut attr_resp_iter = attr_resps.iter();
    for (bj, yy2_j) in bitmap.iter().zip(cred_issuer_public_key.yy2.iter()){
        if *bj {
            let attr_resp = attr_resp_iter.next().ok_or(ZeiError::ParameterError)?;
            addition = addition.add(&yy2_j.mul(attr_resp));
        }
    }
    addition = addition.sub(attr_sum_com);
    Ok(addition)
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

        let ctexts = [ctext];
        let pok_attr = pok_attrs_prove::<_, BNScalar,BNGt>(
            &mut prng,
            cred_issuer_pub_key,
            &asset_issuer_public_key,
            &[attr2.clone()],
            &[rand],
            &[false, true, false],
            &ctexts,
            &proof,
        ).unwrap();

        let vrfy = pok_attrs_verify::<BNScalar,BNGt>(
            cred_issuer_pub_key,
            &asset_issuer_public_key,
            &proof,
            &ctexts,
            &pok_attr,
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

        let mut proof = reveal_attrs::<_, BLSScalar, BLSGt>(
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

        let mut pok_attrs = pok_attrs_prove::<_, BLSScalar, BLSGt>(
            &mut prng,
            cred_issuer_pub_key,
            &asset_issuer_public_key,
            &revealed_attrs.as_slice(),
            &ctext_rands.as_slice(),
            reveal_bitmap,
            &ctexts.as_slice(),
            &proof
        ).unwrap();

        let vrfy = pok_attrs_verify::<BLSScalar,BLSGt>(
            cred_issuer_pub_key,
            &asset_issuer_public_key,
            &proof,
            ctexts.as_slice(),
            &pok_attrs,
            reveal_bitmap);

        assert_eq!(Ok(()), vrfy);

        let mut tampered_bitmap = vec![];
        tampered_bitmap.extend_from_slice(reveal_bitmap);

        let b = reveal_bitmap.get(0).unwrap();

        tampered_bitmap[0] = !(*b);
        if *b {
            ctexts.remove(0);
            pok_attrs.agg_rands_coms_g.remove(0);
            pok_attrs.agg_rands_coms_pk.remove(0);
            pok_attrs.agg_attrs_coms_g.remove(0);
            pok_attrs.attrs_resps[0].remove(0);
            proof.pok.response_attrs.push(BLSScalar::from_u32(0));

        }
        else{
            ctexts.push(elgamal_encrypt(
                &BLSG1::get_base(), &BLSScalar::from_u32(0), &BLSScalar::from_u32(0), &asset_issuer_public_key));
            pok_attrs.agg_rands_coms_g.push(BLSG1::get_identity());
            pok_attrs.agg_rands_coms_pk.push(BLSG1::get_identity());
            pok_attrs.agg_attrs_coms_g.push(BLSG1::get_identity());
            if pok_attrs.attrs_resps.len() > 0{
                pok_attrs.attrs_resps[0].push(BLSScalar::from_u32(0u32));
            }
            else{
                pok_attrs.attrs_resps.push(vec![BLSScalar::from_u32(0u32)]);
            }
            proof.pok.response_attrs.remove(0);
        }

        let vrfy = pok_attrs_verify::<BLSScalar,BLSGt>(
            cred_issuer_pub_key,
            &asset_issuer_public_key,
            &proof,
            ctexts.as_slice(),
            &pok_attrs,
            tampered_bitmap.as_slice());

        assert_eq!(Err(ZeiError::IdentityRevealVerifyError), vrfy, "proof should fail");
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
    use crate::proofs::identity::AggPoKAttrs;
    use serde::{Deserialize, Serialize};
    use rmp_serde::Deserializer;
    use crate::algebra::groups::{Group, Scalar};
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;

    fn to_json<G1: Group<S>, G2: Group<S>, S: Scalar>(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let pokattrs = AggPoKAttrs{ //2 instances 3 attributes
            attr_sum_com_yy2: vec![G2::get_base(), G2::get_base()],
            agg_attrs_coms_g: vec![G1::get_identity(), G1::get_identity(), G1::get_identity()],
            agg_rands_coms_g: vec![G1::get_base(), G1::get_identity(), G1::get_identity()],
            agg_rands_coms_pk: vec![G1::get_identity(), G1::get_base(), G1::get_identity()],
            attrs_resps: vec![
                vec![S::from_u32(0), S::random_scalar(&mut prng), S::from_u32(10)],
                vec![S::from_u32(1), S::random_scalar(&mut prng), S::from_u32(20)],
            ],
            agg_rands_resps: vec![S::from_u32(60), S::from_u32(40), S::from_u32(20)],
        };

        let json_str = serde_json::to_string(&pokattrs).unwrap();
        let pokattrs_de: AggPoKAttrs<G1, G2, S> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(pokattrs, pokattrs_de);
    }

    fn to_msg_pack<G1: Group<S>, G2: Group<S>, S: Scalar>(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let pokattrs = AggPoKAttrs{ //2 instances 3 attributes
            attr_sum_com_yy2: vec![G2::get_base(), G2::get_base()],
            agg_attrs_coms_g: vec![G1::get_identity(), G1::get_identity(), G1::get_identity()],
            agg_rands_coms_g: vec![G1::get_base(), G1::get_identity(), G1::get_identity()],
            agg_rands_coms_pk: vec![G1::get_identity(), G1::get_base(), G1::get_identity()],
            attrs_resps: vec![
                vec![S::from_u32(0), S::random_scalar(&mut prng), S::from_u32(10)],
                vec![S::from_u32(1), S::random_scalar(&mut prng), S::from_u32(20)],
            ],
            agg_rands_resps: vec![S::from_u32(60), S::from_u32(40), S::from_u32(20)],
        };
        //keys serialization
        let mut vec = vec![];
        pokattrs.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let pokattrs_de: AggPoKAttrs<G1, G2, S> = Deserialize::deserialize(&mut de).unwrap();
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
