
/*
 This file implements anonymous credentials as described below:

 Credential issuers can issue credentials for a set of n attributes by providing a signature
 on this attributes for a given user.

 Users can selectively reveal a subset of attributes that are signed in the credentials by
  a) Randomizing the signature (provide unlinkability between reveals)
  b) Revealing a subset of attributes
  c) Provide a zero knowledge proof of knowledge of user secret key and hidden attributes for the
     credential signature

  Specifications:
  Issuer secret key:
      - G1 // random generator of group 1
      - x // random scalar
      - y // random scalar

  Issuer public key:
      - G2  // random generator of group 2
      - X2 = x * G2
      - Z1 = z * G1 //for a random scalar z
      - Z2 = z * G2
      - {Y2_i} = {y_i * G2} // one y_i per attribute

  User secret key: sk // random scalar
  User public key: sk * Z2


  + Signature over a set of attributes {attr_i} for user public key user_pk = sk * Z1:
    - Sample random exponent u
    - Compute e = issuer_sk.x + \sum attr_i*y_i
    - C = e * issuer_sk.G1
    - sigma1 = u * issuer_sk.G1 // u * G1
    - sigma2 = u * (C + user_pk) // u* (x + sum attr_i * y_i + sk * z) * G1
    - output (sigma1, sigma2)

  + Signature Verification for a set of attributes {attr_i} for user public key user_pk over
    - compare e(sigma1, \sum attr_i * Y2 + user_pk + X2) =? e(sigma2, G2)

  + Selective revealing: prove that a signature signs a subset of attributes that are revealed while
    hiddidng the rest of the attributes and the user public key. Strategy:
     a) randomize the signature to provide unlinkability.
     b) provide a proof of knowledge of user's secret key,
       hidden attributed and scalar used to randomize the signature.

    Reveal Algorithm:
     a) signature randomization
       i) sigma1' = r * sigma1
       ii) sigma2' = r* (sigma2 + t * sigma1)
     b) NI proof of knowledge
       i) produce blinding scalar  b_t, b_sk, {b_attri: one for each attributes to hide}
       ii) Compute a proof commitment C = b_t * G2 + b_s * Z2 + sum b_attri * Y2_i
           (sum over attrs to hide)
       iii) Compute challenge c as Hash(C)
       iv) Compute challenge responses r_t = c * t + r_t, r_sk = c * sk + b_sk, and
                                      {r_attri = c* attr_i + b_attri}
     c) Output (sigma1', sigma2', C, r_t, r_sk, {r_attri})

   + Revealed attributes verify (Input: (sigma1', sigma2', C, r_t, r_sk, {r_attri}),
    revealed attributes: {attrj}, issuer_pk)
     - Compute challenge c = Hash(C)
     - compute P = c * X2 + c*\sum Y2_j attr_j + r_t * G2 + r_sk * Z2 + \sum r_attr_i * Y2_i - C
        (where i ranges for all hidden attributes and j ranges for all revealed attributes)
     - compare e(sigma1, P) =? e(sigma2, c * G2)
 */

use crate::errors::ZeiError;
use sha2::{Sha512, Digest};
use crate::algebra::groups::{Group, Scalar};
use crate::algebra::pairing::Pairing;
use rand::{CryptoRng, Rng};

/// I contain Credentials' Issuer Public key fields
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerPublicKey<G1, G2>{
    pub(crate) gen2: G2, //random generator for G2
    pub(crate) xx2: G2,  //gen2^x, x in CredIssuerSecretKey
    pub(crate) zz1: G1,  //gen1^z, z random scalar, gen1 in CredIssuerSecretKey
    pub(crate) zz2: G2,  //gen2^z, same z as above
    pub(crate) yy2: Vec<G2>, //gen2^{y_i}, y_i in CredIssuerSecretKey
}

/// I contain the Credentials' Issuer Secret key fields
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerSecretKey<G1, S> {
    gen1: G1, //random generator for G1
    x: S,
    y: Vec<S>,

}

/// I'm a signature for a set of attributes produced by issuer for a user
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttrsSignature<G1>{
    pub(crate) sigma1: G1,
    pub(crate) sigma2: G1,
}

///I'm a user public key used to request a signature for a set of attributes (credential)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPublicKey<G1>(pub(crate) G1);

///I'm a user's secret key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSecretKey<S> (pub(crate) S);

/// I'm a proof computed by the UserSecretKey holder that an Issuer has signed certain
/// attributes for the corresponding UserPublicKey
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttrsRevealProof<G1, G2, S> {
    pub(crate) sig: AttrsSignature<G1>,
    pub(crate) pok: PoKCred<G2, S>,

}

/// I'm a proof of knowledge for t, sk (UserSecretKey), and hidden attributes that satisfy a
/// certain relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PoKCred<G2, S>{
    pub(crate) commitment: G2, // r_t*G2 + r_sk*Z2 + sum_{a_i in hidden attrs} r_{a_i}*Y2_i
    pub(crate) response_t: S, // c*t + r_t
    pub(crate) response_sk: S, // c*sk + r_sk
    pub(crate) response_attrs: Vec<S>,  // {c*a_i + r_{a_i}; a_i in hidden}
}

/// I generate e key pair for a credential issuer
pub fn gen_issuer_keys<R: CryptoRng + Rng, S: Scalar,P : Pairing<S>>(
    prng: &mut R,
    num_attrs: usize,
) -> (IssuerPublicKey<P::G1, P::G2>, IssuerSecretKey<P::G1, S>)
{
    let x = S::random_scalar(prng);
    let z = S::random_scalar(prng);
    //TODO check that G1 and G2 are of prime order so that every element is generator
    let gen1 = P::g1_mul_scalar(
        &P::G1::get_base(),
        &S::random_scalar(prng));
    let gen2 = P::g2_mul_scalar(
        &P::G2::get_base(),
        &S::random_scalar(prng));
    let mut y = vec![];
    let mut yy2 = vec![];
    for _ in 0..num_attrs {
        let yi = S::random_scalar(prng);
        yy2.push(P::g2_mul_scalar(&gen2, &yi));
        y.push(yi);
    }
    let xx2 = P::g2_mul_scalar(&gen2, &x);
    let zz1 = P::g1_mul_scalar(&gen1, &z);
    let zz2 = P::g2_mul_scalar( &gen2, &z);
    (
     IssuerPublicKey {
            gen2,
            xx2,
            zz1,
            zz2,
            yy2,
        },
     IssuerSecretKey {
            gen1: gen1,
            x,
            y,
        }
    )
}

/// I generate a credential user key pair for a given credential issuer
pub fn gen_user_keys<R: CryptoRng + Rng, S: Scalar, P: Pairing<S>>(
    prng: &mut R,
    issuer_pk: &IssuerPublicKey<P::G1, P::G2>,
) -> (UserPublicKey<P::G1>, UserSecretKey<S>)
{
    let secret = S::random_scalar(prng);
    let pk = P::g1_mul_scalar(&issuer_pk.zz1, &secret);
    (UserPublicKey(pk), UserSecretKey(secret))
}

/// I Compute a credential signature for a set of attributes. User can represent Null attributes by
/// a fixes scalar (e.g. 0)
pub fn issuer_sign<R: CryptoRng + Rng, S:Scalar, P: Pairing<S>>(
    prng: &mut R,
    issuer_sk: &IssuerSecretKey<P::G1, S>,
    user_pk: &UserPublicKey<P::G1>,
    attrs: &[S],
) -> AttrsSignature<P::G1>
{
    let u = S::random_scalar(prng);
    let mut exponent = issuer_sk.x.clone();
    for (attr ,yi) in attrs.iter().
        zip(issuer_sk.y.iter()){
        exponent = exponent.add(&attr.mul(yi));
    }
    let cc = P::g1_mul_scalar(&issuer_sk.gen1, &exponent);
    AttrsSignature::<P::G1>{
        sigma1: P::g1_mul_scalar(&issuer_sk.gen1, &u),
        sigma2: P::g1_mul_scalar(&user_pk.0.add(&cc), &u),
    }
}

/// I produce a AttrsRevealProof, bitmap indicates which attributes are revealed
pub fn reveal_attrs<R: CryptoRng + Rng,S:Scalar, P: Pairing<S>>(
    prng: &mut R,
    user_sk: &UserSecretKey<S>,
    issuer_pk: &IssuerPublicKey<P::G1, P::G2>,
    sig: &AttrsSignature<P::G1>,
    attrs: &[S],
    bitmap: &[bool], // indicates which attributes are revealed
) -> AttrsRevealProof<P::G1, P::G2, S>
{
    let r = S::random_scalar(prng);
    let t = S::random_scalar(prng);
    let sigma1_r = P::g1_mul_scalar(&sig.sigma1, &r);
    let sigma1_t = P::g1_mul_scalar(&sig.sigma1,&t);
    let sigma2_aux = sig.sigma2.add(&sigma1_t);
    let sigma2_r = P::g1_mul_scalar(&sigma2_aux, &r);
    let rand_sig = AttrsSignature::<P::G1>{
        sigma1: sigma1_r,
        sigma2: sigma2_r, //sigma2: r*(sigma2 + t*sigma1)
    };

    let mut hidden_attrs = vec![];
    for (attr, revealed) in attrs.iter().zip(bitmap){
        if !(*revealed) {
            hidden_attrs.push(attr.clone());
        }
    }
    let proof = prove_pok::<_,S,P>(
        prng,
        user_sk,
        issuer_pk,
        &t,
        hidden_attrs.as_slice(),
        bitmap);

    AttrsRevealProof {
        sig: rand_sig,
        pok: proof,

    }
}

/// I produce selective attribute disclose proof of knowledge
/// Algorithm:
///     1. Sample beta1, beta2 and {gamma_j} (One for each hidden attribute)
///     2. Compute a sigma proof commitment for the values in 1:
///        beta1*g2 + beta2*Z2 + \sum gamma_j Y2_{j_i} for each j_i s.t revealed_itmap[j_i] = false
///     3. Sample the challenge as a hash of the commitment.
///     4. Compute challenge's responses  c*t + \beta1, c*sk + beta2, {c*y_i + gamma_i}
///     5. Return proof commitment and responses
fn prove_pok<R: CryptoRng + Rng, S: Scalar, P: Pairing<S>>(
    prng: &mut R,
    user_sk: &UserSecretKey<S>,
    issuer_pk: &IssuerPublicKey<P::G1, P::G2>,
    t: &S,
    hidden_attrs: &[S],
    bitmap: &[bool], // indicates reveales attributed
) -> PoKCred<P::G2, S>
{
    let beta1 = S::random_scalar(prng);
    let beta2 = S::random_scalar(prng);
    let mut gamma = vec![];
    for _ in 0..hidden_attrs.len(){
        gamma.push(S::random_scalar(prng));
    }
    let mut commitment = P::g2_mul_scalar(&issuer_pk.gen2,&beta1).
        add(&P::g2_mul_scalar(&issuer_pk.zz2, &beta2));
    let mut gamma_iter = gamma.iter();
    for (yy2i,x) in issuer_pk.yy2.iter().zip(bitmap){
        if !(*x) {
            let gammai = gamma_iter.next().unwrap();
            let elem = P::g2_mul_scalar(&yy2i,gammai);
            commitment = commitment.add(&elem);
        }
    }
    let challenge: S = compute_challenge::<S,P>(&commitment);
    let response_t = challenge.mul(t).add(&beta1); // challente*t + beta1
    let response_sk = challenge.mul(&user_sk.0).add(&beta2);
    let mut response_attrs = vec![];
    let mut gamma_iter = gamma.iter();
    let mut attr_iter = hidden_attrs.iter();
    for y in bitmap{
        if (*y) == false {
            let gamma = gamma_iter.next().unwrap();
            let attr = attr_iter.next().unwrap();
            let resp_attr_i = challenge.mul(attr).add(gamma);
            response_attrs.push(resp_attr_i);
        }
    }
    PoKCred {
        commitment,
        response_t,
        response_sk,
        response_attrs,
    }

}

/// I compute proof of knowledge challenge for selective attribute disclosure proof
pub(crate) fn compute_challenge<S: Scalar, P: Pairing<S>>(commitment: &P::G2) -> S{
    let c = commitment.to_compressed_bytes();
    let mut hasher = Sha512::new();
    hasher.input(c.as_slice());

    S::from_hash(hasher)
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
pub fn verify<S: Scalar, P: Pairing<S>>(
    issuer_pk: &IssuerPublicKey<P::G1, P::G2>,
    revealed_attrs: &[S],
    bitmap: &[bool],
    reveal_proof: &AttrsRevealProof<P::G1, P::G2, S>,
) -> Result<(), ZeiError>
{
    let proof_commitment = &reveal_proof.pok.commitment;
    let proof_resp_attrs = &reveal_proof.pok.response_attrs;
    let challenge = compute_challenge::<S,P>(proof_commitment);
    //q = X_2*c - proof_commitment + &G2 * r_t + Z2 * r_sk;
    let mut q = P::g2_mul_scalar(&issuer_pk.xx2, &challenge).sub(proof_commitment);

    let a = P::g2_mul_scalar(&issuer_pk.gen2, &reveal_proof.pok.response_t);
    let b = P::g2_mul_scalar(&issuer_pk.zz2, &reveal_proof.pok.response_sk);
    let c = a.add(&b);
    q = q.add(&c);

    let mut y_shown_attr = P::G2::get_identity(); //sum (challenge * attr_i)*Y2
    let mut y_hidden_attr = P::G2::get_identity(); //sum gamma_i*Y2
    let mut attr_iter = revealed_attrs.iter();
    let mut response_attr_iter = proof_resp_attrs.iter();
    let mut yy2_iter = issuer_pk.yy2.iter();

    for b in bitmap.iter(){
        let yy2i = yy2_iter.next().unwrap();
        if *b {
            let attribute = attr_iter.next().unwrap();
            let scalar = challenge.mul(&attribute);
            y_shown_attr = y_shown_attr.add(&P::g2_mul_scalar(&yy2i, &scalar));
        }
        else {
            let response_attr = response_attr_iter.next().unwrap();
            y_hidden_attr = y_hidden_attr.add(&P::g2_mul_scalar(&yy2i, response_attr));
        }
    }
    let shown_plus_hidden = y_shown_attr.add(&y_hidden_attr);
    q = q.add(&shown_plus_hidden);

    let a = P::pairing(&reveal_proof.sig.sigma1, &q);
    let b = P::pairing(
        &reveal_proof.sig.sigma2,
        &P::g2_mul_scalar(&issuer_pk.gen2, &challenge)
    );

    match a == b {
        true => Ok(()),
        false => Err(ZeiError::SignatureError),
    }

}

#[cfg(test)]
pub(crate) mod credentials_tests {
    use super::*;
    use rand::{SeedableRng};
    use rand_chacha::ChaChaRng;
    use serde::{Serialize, Deserialize};
    use rmp_serde::Deserializer;

    fn reveal<S: Scalar, P: Pairing<S>>(bitmap: &[bool]){
        let n = bitmap.len();
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let issuer_keypair =
            super::gen_issuer_keys::<_,S, P>(&mut prng, n);
        let issuer_pk = &issuer_keypair.0;
        let issuer_sk = &issuer_keypair.1;
        let (user_pk, user_sk) =
            super::gen_user_keys::<_, S, P>(&mut prng, issuer_pk);

        let mut attrs = vec![];

        for _ in bitmap {
            attrs.push(S::random_scalar(&mut prng));
        }

        let sig =
            super::issuer_sign::<_, S,P>(&mut prng, &issuer_sk, &user_pk, attrs.as_slice());

        let reveal_proof = super::reveal_attrs::<_, S,P>(
            &mut prng,
            &user_sk,
            issuer_pk,
            &sig,
            attrs.as_slice(),
            bitmap,
        );

        let mut revealed_attrs = vec![];

        for (attr, b) in attrs.iter().zip(bitmap){
            if *b {
                revealed_attrs.push(attr.clone());
            }
        }

        assert_eq!(true, verify::<S,P>(
            &issuer_pk,
            revealed_attrs.as_slice(),
            bitmap,
            &reveal_proof,
        ).is_ok())
    }

    pub fn single_attribute<S:Scalar, P: Pairing<S>>(){
        reveal::<S,P>(&[false]);
        reveal::<S,P>(&[true]);
    }

    pub fn two_attributes<S:Scalar, P: Pairing<S>>(){
        reveal::<S,P>(&[false, false]);
        reveal::<S,P>(&[true, false]);
        reveal::<S,P>(&[false, true]);
        reveal::<S,P>(&[true, true]);
    }

    pub fn ten_attributes<S: Scalar, P: Pairing<S>>(){
        reveal::<S,P>(&[false;10]);
        reveal::<S,P>(&[true, false, true, false, true, false, true, false,  true, false]);
        reveal::<S,P>(&[false, true, false, true, false, true, false, true, false,  true]);
        reveal::<S,P>(&[true; 10]);
    }

    pub fn to_json_credential_structures<S:Scalar, P: Pairing<S>>(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        //issuer keys
        let issuer_keys = gen_issuer_keys::<_, S,P>(&mut prng, 10);
        let json_str = serde_json::to_string(&issuer_keys.0).unwrap();
        let issuer_pub_key_de: IssuerPublicKey<P::G1, P::G2> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(issuer_keys.0, issuer_pub_key_de);

        let json_str = serde_json::to_string(&issuer_keys.1).unwrap();
        let issuer_sec_key_de: IssuerSecretKey<P::G1, S> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(issuer_keys.1, issuer_sec_key_de);

        //user keys
        let user_keys = super::gen_user_keys::<_, S, P>(&mut prng, &issuer_keys.0);
        let json_str = serde_json::to_string(&user_keys.0).unwrap();
        let user_pub_key_de: UserPublicKey<P::G1> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(user_keys.0, user_pub_key_de);

        let json_str = serde_json::to_string(&user_keys.1).unwrap();
        let user_sec_key_de: UserSecretKey<S> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(user_keys.1, user_sec_key_de);


        // reveal proof containing signature and pok
        let attrs = [S::from_u32(10), S::from_u32(10)];
        let credential =
            super::issuer_sign::<_, S,P>(&mut prng, &issuer_keys.1, &user_keys.0, &attrs);
        let reveal_proof = super::reveal_attrs::<_, S,P>(
            &mut prng,
            &user_keys.1,
            &issuer_keys.0,
            &credential,
            &attrs,
            &[true, false],
        );
        let json_str = serde_json::to_string(&reveal_proof).unwrap();
        let reveal_proof_de: AttrsRevealProof<P::G1, P::G2, S> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(reveal_proof, reveal_proof_de);
    }

    pub fn to_msg_pack_credential_structures<S: Scalar, P: Pairing<S>>(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        //issuer keys
        let issuer_keys = gen_issuer_keys::<_, S,P>(&mut prng, 10);
        let mut vec = vec![];
        issuer_keys.0.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let issuer_pub_key_de: IssuerPublicKey<P::G1, P::G2> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(issuer_keys.0, issuer_pub_key_de);

        let mut vec = vec![];
        issuer_keys.1.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let issuer_priv_key_de: IssuerSecretKey<P::G1, S> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(issuer_keys.1, issuer_priv_key_de);

        //user keys
        let user_keys = super::gen_user_keys::<_, S,P>(&mut prng, &issuer_keys.0);
        let mut vec = vec![];
        user_keys.0.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let user_pub_key_de: UserPublicKey<P::G1> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(user_keys.0, user_pub_key_de);

        let mut vec = vec![];
        user_keys.1.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let user_priv_key_de: UserSecretKey<S> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(user_keys.1, user_priv_key_de);


        // reveal proof containing signature and pok
        let attrs = [S::from_u32(10), S::from_u32(10)];
        let credential =
            super::issuer_sign::<_, S,P>(&mut prng, &issuer_keys.1, &user_keys.0, &attrs);
        let reveal_proof = super::reveal_attrs::<_, S,P>(
            &mut prng,
            &user_keys.1,
            &issuer_keys.0,
            &credential,
            &attrs,
            &[true, false],
        );

        let mut vec = vec![];
        reveal_proof.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let reveal_proof_de: AttrsRevealProof<P::G1, P::G2, S> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(reveal_proof, reveal_proof_de);
    }
}
