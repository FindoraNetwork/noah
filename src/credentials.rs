
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
pub struct IssuerPublicKey<Gt: Pairing>{
    pub(crate) gen2: Gt::G2, //random generator for G2
    pub(crate) xx2: Gt::G2,  //gen2^x, x in CredIssuerSecretKey
    pub(crate) zz1: Gt::G1,  //gen1^z, z random scalar, gen1 in CredIssuerSecretKey
    pub(crate) zz2: Gt::G2,  //gen2^z, same z as above
    pub(crate) yy2: Vec<Gt::G2>, //gen2^{y_i}, y_i in CredIssuerSecretKey
}

/// I contain the Credentials' Issuer Secret key fields
pub struct IssuerSecretKey<Gt: Pairing> {
    gen1: Gt::G1, //random generator for G1
    x: Gt::ScalarType,
    y: Vec<Gt::ScalarType>,

}

/// I'm a signature for a set of attributes produced by issuer for a user
#[derive(Clone)]
pub struct AttrsSignature<Gt: Pairing>{
    pub(crate) sigma1: Gt::G1,
    pub(crate) sigma2: Gt::G1,
}

///I'm a user public key used to request a signature for a set of attributes (credential)
pub struct UserPublicKey<Gt: Pairing>(pub(crate) Gt::G1);

///I'm a user's secret key
pub struct UserSecretKey<Gt: Pairing> (pub(crate) Gt::ScalarType);

/// I'm a proof computed by the UserSecretKey holder that an Issuer has signed certain
/// attributes for the corresponding UserPublicKey
#[derive(Clone)]
pub struct AttrsRevealProof<Gt: Pairing> {
    pub(crate) sig: AttrsSignature<Gt>,
    pub(crate) pok: PoKCred<Gt>,

}

/// I'm a proof of knowledge for t, sk (UserSecretKey), and hidden attributes that satisfy a
/// certain relation.
#[derive(Clone)]
pub(crate) struct PoKCred<Gt: Pairing>{
    pub(crate) commitment: Gt::G2, // r_t*G2 + r_sk*Z2 + sum_{a_i in hidden attrs} r_{a_i}*Y2_i
    pub(crate) response_t: Gt::ScalarType, // c*t + r_t
    pub(crate) response_sk: Gt::ScalarType, // c*sk + r_sk
    pub(crate) response_attrs: Vec<Gt::ScalarType>,  // {c*a_i + r_{a_i}; a_i in hidden}
}

/// I generate e key pair for a credential issuer
pub fn gen_issuer_keys<R: CryptoRng + Rng, Gt: Pairing>(
    prng: &mut R,
    num_attrs: usize,
) -> (IssuerPublicKey<Gt>, IssuerSecretKey<Gt>)
{
    let x = Gt::ScalarType::random_scalar(prng);
    let z = Gt::ScalarType::random_scalar(prng);
    //TODO check that G1 and G2 are of prime order so that every element is generator
    let gen1 = Gt::g1_mul_scalar(
        &Gt::G1::get_base(),
        &Gt::ScalarType::random_scalar(prng));
    let gen2 = Gt::g2_mul_scalar(
        &Gt::G2::get_base(),
        &Gt::ScalarType::random_scalar(prng));
    let mut y = vec![];
    let mut yy2 = vec![];
    for _ in 0..num_attrs {
        let yi = Gt::ScalarType::random_scalar(prng);
        yy2.push(Gt::g2_mul_scalar(&gen2, &yi));
        y.push(yi);
    }
    let xx2 = Gt::g2_mul_scalar(&gen2, &x);
    let zz1 = Gt::g1_mul_scalar(&gen1, &z);
    let zz2 = Gt::g2_mul_scalar( &gen2, &z);
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
pub fn gen_user_keys<R: CryptoRng + Rng, Gt: Pairing>(
    prng: &mut R,
    issuer_pk: &IssuerPublicKey<Gt>,
) -> (UserPublicKey<Gt>, UserSecretKey<Gt>)
{
    let secret = Gt::ScalarType::random_scalar(prng);
    let pk = Gt::g1_mul_scalar(&issuer_pk.zz1, &secret);
    (UserPublicKey(pk), UserSecretKey(secret))
}

/// I Compute a credential signature for a set of attributes. User can represent Null attributes by
/// a fixes scalar (e.g. 0)
pub fn issuer_sign<R: CryptoRng + Rng, Gt: Pairing>(
    prng: &mut R,
    issuer_sk: &IssuerSecretKey<Gt>,
    user_pk: &UserPublicKey<Gt>,
    attrs: Vec<Gt::ScalarType>,
) -> AttrsSignature<Gt>
{
    let u = Gt::ScalarType::random_scalar(prng);
    let mut exponent = issuer_sk.x.clone();
    for (attr ,yi) in attrs.iter().
        zip(issuer_sk.y.iter()){
        exponent = exponent.add(&attr.mul(yi));
    }
    let cc = Gt::g1_mul_scalar(&issuer_sk.gen1, &exponent);
    AttrsSignature::<Gt>{
        sigma1: Gt::g1_mul_scalar(&issuer_sk.gen1, &u),
        sigma2: Gt::g1_mul_scalar(&user_pk.0.add(&cc), &u),
    }
}

/// I produce a AttrsRevealProof, bitmap indicates which attributes are revealed
pub fn reveal_attrs<R: CryptoRng + Rng, Gt: Pairing>(
    prng: &mut R,
    user_sk: &UserSecretKey<Gt>,
    issuer_pk: &IssuerPublicKey<Gt>,
    sig: &AttrsSignature<Gt>,
    attrs: &[Gt::ScalarType],
    bitmap: &[bool], // indicates which attributes are revealed
) -> AttrsRevealProof<Gt>
{
    let r = Gt::ScalarType::random_scalar(prng);
    let t = Gt::ScalarType::random_scalar(prng);
    let sigma1_r = Gt::g1_mul_scalar(&sig.sigma1, &r);
    let sigma1_t = Gt::g1_mul_scalar(&sig.sigma1,&t);
    let sigma2_aux = sig.sigma2.add(&sigma1_t);
    let sigma2_r = Gt::g1_mul_scalar(&sigma2_aux, &r);
    let rand_sig = AttrsSignature::<Gt>{
        sigma1: sigma1_r,
        sigma2: sigma2_r, //sigma2: r*(sigma2 + t*sigma1)
    };

    let mut hidden_attrs = vec![];
    for (attr, revealed) in attrs.iter().zip(bitmap){
        if !(*revealed) {
            hidden_attrs.push(attr.clone());
        }
    }
    let proof = prove_pok(
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
fn prove_pok<R: CryptoRng + Rng, Gt: Pairing>(
    prng: &mut R,
    user_sk: &UserSecretKey<Gt>,
    issuer_pk: &IssuerPublicKey<Gt>,
    t: &Gt::ScalarType,
    hidden_attrs: &[Gt::ScalarType],
    bitmap: &[bool], // indicates reveales attributed
) -> PoKCred<Gt>
{
    let beta1 = Gt::ScalarType::random_scalar(prng);
    let beta2 = Gt::ScalarType::random_scalar(prng);
    let mut gamma = vec![];
    for _ in 0..hidden_attrs.len(){
        gamma.push(Gt::ScalarType::random_scalar(prng));
    }
    let mut commitment = Gt::g2_mul_scalar(&issuer_pk.gen2,&beta1).
        add(&Gt::g2_mul_scalar(&issuer_pk.zz2, &beta2));
    let mut gamma_iter = gamma.iter();
    for (yy2i,x) in issuer_pk.yy2.iter().zip(bitmap){
        if !(*x) {
            let gammai = gamma_iter.next().unwrap();
            let elem = Gt::g2_mul_scalar(&yy2i,gammai);
            commitment = commitment.add(&elem);
        }
    }
    let challenge: Gt::ScalarType = compute_challenge::<Gt>(&commitment);
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
pub(crate) fn compute_challenge<Gt: Pairing>(commitment: &Gt::G2) -> Gt::ScalarType{
    let c = commitment.to_compressed_bytes();
    let mut hasher = Sha512::new();
    hasher.input(c.as_slice());

    Gt::ScalarType::from_hash(hasher)
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
/// 2. Compute p \= -proof_commitment c*X2 + proof_response\_t*g\_2 + proof\_response\_sk*Z2 +
///  sum_{i\in hidden} proof_response_attr_i * Y2_i + sum_{i\in revealed} c*attr_i * Y2_i
/// 3. Compare e(sigma1, p) against e(sigma2, c*g2)
pub fn verify<Gt: Pairing>(
    issuer_pk: &IssuerPublicKey<Gt>,
    revealed_attrs: &[Gt::ScalarType],
    bitmap: &[bool],
    reveal_proof: &AttrsRevealProof<Gt>,
) -> Result<(), ZeiError>
{
    let proof_commitment = &reveal_proof.pok.commitment;
    let proof_resp_attrs = &reveal_proof.pok.response_attrs;
    let challenge = compute_challenge::<Gt>(proof_commitment);
    //q = X_2*c - proof_commitment + &G2 * r_t + Z2 * r_sk;
    let mut q = Gt::g2_mul_scalar(&issuer_pk.xx2, &challenge).sub(proof_commitment);

    let a = Gt::g2_mul_scalar(&issuer_pk.gen2, &reveal_proof.pok.response_t);
    let b = Gt::g2_mul_scalar(&issuer_pk.zz2, &reveal_proof.pok.response_sk);
    let c = a.add(&b);
    q = q.add(&c);

    let mut y_shown_attr = Gt::G2::get_identity(); //sum (challenge * attr_i)*Y2
    let mut y_hidden_attr = Gt::G2::get_identity(); //sum gamma_i*Y2
    let mut attr_iter = revealed_attrs.iter();
    let mut response_attr_iter = proof_resp_attrs.iter();
    let mut yy2_iter = issuer_pk.yy2.iter();

    for b in bitmap.iter(){
        let yy2i = yy2_iter.next().unwrap();
        if *b {
            let attribute = attr_iter.next().unwrap();
            let scalar = challenge.mul(&attribute);
            y_shown_attr = y_shown_attr.add(&Gt::g2_mul_scalar(&yy2i, &scalar));
        }
        else {
            let response_attr = response_attr_iter.next().unwrap();
            y_hidden_attr = y_hidden_attr.add(&Gt::g2_mul_scalar(&yy2i, response_attr));
        }
    }
    let shown_plus_hidden = y_shown_attr.add(&y_hidden_attr);
    q = q.add(&shown_plus_hidden);

    let a = Gt::pairing(&reveal_proof.sig.sigma1, &q);
    let b = Gt::pairing(
        &reveal_proof.sig.sigma2,
        &Gt::g2_mul_scalar(&issuer_pk.gen2, &challenge)
    );

    match a == b {
        true => Ok(()),
        false => Err(ZeiError::SignatureError),
    }

}

pub mod credentials_tests {
    use super::*;
    use rand::{SeedableRng};
    use rand_chacha::ChaChaRng;

    pub fn single_attribute<Gt: Pairing>(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let issuer_keypair =
            super::gen_issuer_keys::<_,Gt>(&mut prng, 1);
        let issuer_pk = &issuer_keypair.0;
        let issuer_sk = &issuer_keypair.1;
        let (user_pk, user_sk) =
            super::gen_user_keys(&mut prng, issuer_pk);
        let attr = Gt::ScalarType::random_scalar(&mut prng);

        let signature =
            super::issuer_sign(&mut prng, &issuer_sk, &user_pk, vec![attr.clone()]);

        let proof = super::reveal_attrs(
            &mut prng,
            &user_sk,
            issuer_pk,
            &signature,
            &[attr.clone()],
            &[true],
        );

        assert_eq!(true, verify(&issuer_pk,
            &[attr.clone()],
            &[true],
            &proof,
        ).is_ok())
    }

    pub fn two_attributes<Gt: Pairing>(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let issuer_keypair =
            super::gen_issuer_keys::<_,Gt>(&mut prng, 2);
        let issuer_pk = &issuer_keypair.0;
        let issuer_sk = &issuer_keypair.1;

        let (user_pk, user_sk) =
            super::gen_user_keys(&mut prng, issuer_pk);

        let attr1 = Gt::ScalarType::random_scalar(&mut prng);
        let attr2 = Gt::ScalarType::random_scalar(&mut prng);

        let signature = super::issuer_sign(
            &mut prng, &issuer_sk, &user_pk, vec![attr1.clone(), attr2.clone()]);

        let proof = reveal_attrs(
            &mut prng,
            &user_sk,
            issuer_pk,
            &signature,
            &[attr1.clone(), attr2.clone()],
            &[true, false],
        );

        assert_eq!(true, verify(
            &issuer_pk,
            &[attr1.clone()],
            &[true, false],
            &proof,
        ).is_ok(), "Revealing first attribute");

        let proof = reveal_attrs(
            &mut prng,
            &user_sk,
            issuer_pk,
            &signature,
            &[attr1.clone(), attr2.clone()],
            &[false, true]
        );

        assert_eq!(true, verify(
            &issuer_pk,
            &[attr2.clone()],
            &[false, true],
            &proof,
        ).is_ok(), "Revealing second attribute");

        let proof = reveal_attrs(
            &mut prng,
            &user_sk,
            issuer_pk,
            &signature,
            &[attr1.clone(), attr2.clone()],
            &[false, false],
        );

        assert_eq!(true, verify(
            &issuer_pk,
            vec![].as_slice(),
            &[false, false],
            &proof,
        ).is_ok(), "Error revealing no attribute");

        let proof = reveal_attrs(
            &mut prng,
            &user_sk,
            issuer_pk,
            &signature,
            &[attr1.clone(), attr2.clone()],
            &[true, true],
        );

        assert_eq!(true, verify(
            &issuer_pk,
            &[attr1.clone(), attr2.clone()],
            &[true, true],
            &proof,
        ).is_ok(), "Error revealing both attributes")
    }
}
