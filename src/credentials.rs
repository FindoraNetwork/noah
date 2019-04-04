use crate::errors::ZeiError;
use sha2::{Sha512, Digest};
use crate::algebra::groups::{Group, Scalar};
use crate::algebra::pairing::Pairing;
use rand::{CryptoRng, Rng};

/// I represent the Credentials' Issuer Public key
pub struct CredIssuerPublicKey<Gt: Pairing>{
    pub(crate) gen2: Gt::G2, //random generator for G2
    pub(crate) xx2: Gt::G2,  //gen2^x, x in CredIssuerSecretKey
    pub(crate) zz1: Gt::G1,  //gen1^z, z random scalar, gen1 in CredIssuerSecretKey
    pub(crate) zz2: Gt::G2,  //gen2^z, same z as above
    pub(crate) yy2: Vec<Gt::G2>, //gen2^{y_i}, y_i in CredIssuerSecretKey
}

/// I represent the Credentials' Issuer Secret key
pub struct CredIssuerSecretKey<Gt: Pairing> {
    gen1: Gt::G1, //random generator for G1
    x: Gt::ScalarType,
    y: Vec<Gt::ScalarType>,

}

/// I represent the Credentials' Issuer Key pair
pub struct CredIssuerKeyPair<Gt: Pairing> {
    public: CredIssuerPublicKey<Gt>,
    secret: CredIssuerSecretKey<Gt>,
}

impl<Gt: Pairing> CredIssuerKeyPair<Gt> {
    pub fn public_key_ref(&self) -> &CredIssuerPublicKey<Gt> {
        &self.public
    }

    pub fn secret_key_ref(&self) -> &CredIssuerSecretKey<Gt> {
        &self.secret
    }
}

/// I represent a credential signature produce by credential issuer and used by
/// user to selectively disclose signed attributed
#[derive(Clone)]
pub struct CredSignature<Gt: Pairing>{
    pub(crate) sigma1: Gt::G1,
    pub(crate) sigma2: Gt::G1,
}

///I represent a credential user public key used to request credentials to a credential issuer
pub struct CredUserPublicKey<Gt: Pairing>(pub(crate) Gt::G1);

///I represent a credential user secret key used to selectively reveals attributed of my credential
pub struct CredUserSecretKey<Gt: Pairing>{
    secret: Gt::ScalarType,
    public: CredUserPublicKey<Gt>,
}

impl<Gt: Pairing> CredUserSecretKey<Gt> {
    pub fn get_public_key_ref(&self) -> &CredUserPublicKey<Gt> {
        &self.public
    }
}
/// I'm a proof computed by the CredUserSecretKey holder that an Issuer has signed certain
/// attributes for the corresponding CredUserPublicKey
#[derive(Clone)]
pub struct CredRevealProof<Gt: Pairing> {
    pub(crate) signature: CredSignature<Gt>,
    pub(crate) pok: PoKCred<Gt>,

}

/// I'm a proof of knowledge for t, sk (CredUserSecretKey), and hidden attributes that satisfy a
/// certain relation.
#[derive(Clone)]
pub(crate) struct PoKCred<Gt: Pairing>{
    pub(crate) commitment: Gt::G2, // r_t*G2 + r_sk*Z2 + sum_{a_i in hidden attrs} r_{a_i}*Y2_i
    pub(crate) response_t: Gt::ScalarType, // c*t + r_t
    pub(crate) response_sk: Gt::ScalarType, // c*sk + r_sk
    pub(crate) response_attrs: Vec<Gt::ScalarType>,  // {c*a_i + r_{a_i}; a_i in hidden}
}

/// I generate e key pair for a credential issuer
pub fn generate_cred_issuer_keys<R: CryptoRng + Rng, Gt: Pairing>(
    prng: &mut R,
    num_attrs: usize,
) -> CredIssuerKeyPair<Gt>
{
    let x = Gt::ScalarType::random_scalar(prng);
    let z = Gt::ScalarType::random_scalar(prng);
    let gen1 = Gt::g1_mul_scalar(&Gt::G1::get_base(), &Gt::ScalarType::random_scalar(prng)); //TODO check that G1 is of prime order so that every element is generator
    let gen2 = Gt::g2_mul_scalar(&Gt::G2::get_base(), &Gt::ScalarType::random_scalar(prng)); //TODO check that G2 is of prime order so that every element is generator
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
    CredIssuerKeyPair{
        public: CredIssuerPublicKey {
            gen2,
            xx2,
            zz1,
            zz2,
            yy2,
        },
        secret: CredIssuerSecretKey {
            gen1: gen1,
            x,
            y,
        },
    }
}

/// I generate a credential user key pair for a given credential issuer
pub fn generate_cred_user_keys<R: CryptoRng + Rng, Gt: Pairing>(
    prng: &mut R,
    issuer_public_key: &CredIssuerPublicKey<Gt>,
)  -> CredUserSecretKey<Gt>
{
    let secret = Gt::ScalarType::random_scalar(prng);
    let pk = Gt::g1_mul_scalar(&issuer_public_key.zz1, &secret);
    let public = CredUserPublicKey(pk);
    CredUserSecretKey {
        secret,
        public,
    }
}

pub fn reveal<R: CryptoRng + Rng, Gt: Pairing>(
    user_secret_key: &CredUserSecretKey<Gt>,
    prng: &mut R,
    issuer_public_key: &CredIssuerPublicKey<Gt>,
    issuer_signature: &CredSignature<Gt>,
    attributes: &[Gt::ScalarType],
    bitmap_reveal: &[bool],
) -> CredRevealProof<Gt>
{
    let r = Gt::ScalarType::random_scalar(prng);
    let t = Gt::ScalarType::random_scalar(prng);
    let sigma1_r = Gt::g1_mul_scalar(&issuer_signature.sigma1, &r);
    let sigma1_t = Gt::g1_mul_scalar(&issuer_signature.sigma1,&t);
    let sigma2_aux = issuer_signature.sigma2.add(&sigma1_t);
    let sigma2_r = Gt::g1_mul_scalar(&sigma2_aux, &r);
    let randomized_signature = CredSignature::<Gt>{
        sigma1: sigma1_r,
        sigma2: sigma2_r, //sigma2: issuer_signature.sigma2.add( Gt::g1_mul_scalar(&issuer_signature.sigma1,&t)).mul(&r),
    };

    let mut hidden_attributes = vec![];
    for (attr, revealed) in attributes.iter().zip(bitmap_reveal){
        if !(*revealed) {
            hidden_attributes.push(attr.clone());
        }
    }
    let proof = prove_pok(user_secret_key, prng, issuer_public_key, &t, hidden_attributes.as_slice(), bitmap_reveal);

    CredRevealProof{
        signature: randomized_signature,
        pok: proof,

    }
}

fn prove_pok<R: CryptoRng + Rng, Gt: Pairing>(
    user_secret_key: &CredUserSecretKey<Gt>,
    prng: &mut R,
    issuer_public_key: &CredIssuerPublicKey<Gt>,
    t: &Gt::ScalarType,
    hidden_attributes: &[Gt::ScalarType],
    revealed_bitmap: &[bool],
) -> PoKCred<Gt>
{
    /*! I compute a proof of knowledge of t, sk, and hidden attributes such that
     * some relation on them holds.
     * Algorithm:
     * 1. Sample beta1, beta2 and {gamma_j} (One for each hidden attribute)
     * 2. Compute a sigma proof commitment for the values in 1:
     *    beta1*g2 + beta2*Z2 + \sum gamma_j Y2_{j_i} for each j_i s.t revealed_itmap[j_i] = false
     * 3. Sample the challenge as a hash of the commitment.
     * 4. Compute challenge's responses  c*t + \beta1, c*sk + beta2, {c*y_i + gamma_i}
     * 5. Return proof commitment and responses
    */
    let beta1 = Gt::ScalarType::random_scalar(prng);
    let beta2 = Gt::ScalarType::random_scalar(prng);
    let mut gamma = vec![];
    for _ in 0..hidden_attributes.len(){
        gamma.push(Gt::ScalarType::random_scalar(prng));
    }
    let mut commitment = Gt::g2_mul_scalar(&issuer_public_key.gen2,&beta1).add(&Gt::g2_mul_scalar(&issuer_public_key.zz2, &beta2));
    let mut gamma_iter = gamma.iter();
    //let mut attr_commitment = vec![];
    for (yy2i,x) in issuer_public_key.yy2.iter().zip(revealed_bitmap){
        if !(*x) {
            let gammai = gamma_iter.next().unwrap();
            let elem = Gt::g2_mul_scalar(&yy2i,gammai);
            commitment = commitment.add(&elem);
            //attr_commitment.push(elem);
        }
    }
    let challenge: Gt::ScalarType = compute_challenge::<Gt>(&commitment);
    let response_t = challenge.mul(t).add(&beta1); // challente*t + beta1
    let response_sk = challenge.mul(&user_secret_key.secret).add(&beta2);
    let mut response_attrs = vec![];
    let mut gamma_iter = gamma.iter();
    let mut attr_iter = hidden_attributes.iter();
    for y in revealed_bitmap{
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

pub(crate) fn compute_challenge<Gt: Pairing>(proof_commitment: &Gt::G2) -> Gt::ScalarType{
    /*! In a sigma protocol, I compute a hash of the proof commitment*/
    let c = proof_commitment.to_compressed_bytes();
    let mut hasher = Sha512::new();
    hasher.input(c.as_slice());

    Gt::ScalarType::from_hash(hasher)
}

/// I Compute a credential signature for a set of attributes. User can represent Null attributes by
/// a fixes scalar (e.g. 0)
pub fn issuer_sign<R: CryptoRng + Rng, Gt: Pairing>(
    prng: &mut R,
    issuer_secret_key: &CredIssuerSecretKey<Gt>,
    user_public_key: &CredUserPublicKey<Gt>,
    attributes: Vec<Gt::ScalarType>,
) -> CredSignature<Gt>
{
    let u = Gt::ScalarType::random_scalar(prng);
    let mut exponent = issuer_secret_key.x.clone();
    for (attr ,yi) in attributes.iter().zip(issuer_secret_key.y.iter()){
        exponent = exponent.add(&attr.mul(yi));
    }
    let cc = Gt::g1_mul_scalar(&issuer_secret_key.gen1, &exponent);
    CredSignature::<Gt>{
        sigma1: Gt::g1_mul_scalar(&issuer_secret_key.gen1, &u),
        sigma2: Gt::g1_mul_scalar(&user_public_key.0.add(&cc), &u),
    }
}

/// Given a list of revealed attributes_{k}, and a credential structure composed by a signature
/// (sigma1,sigma2) and a proof of
/// knowledge of t, sk and some hidden attributes, I verify that
/// e(sigma1,X2) + e(sigma1, g_2^t) + e(sigma1, Z2^sk) + e(sigma1, \\sum Y2_i^attr_i)
/// equals e(sigma2, g_2)
/// Revealed attributes attr corresponds to the positions where the bitmap is true
/// I return Ok() in case signatures and proofs are correct. Otherwise, I return Err(ZeiError:SignatureError)
/// Algorithm:
/// 1. Compute challenge c as hash of proof_commitment
/// 2. Compute p \= -proof_commitment c*X2 + proof_response\_t*g\_2 + proof\_response\_sk*Z2 +
///  sum_{i\in hidden} proof_response_attr_i * Y2_i + sum_{i\in revealed} c*attr_i * Y2_i
/// 3. Compare e(sigma1, p) against e(sigma2, c*g2)

pub fn verify<Gt: Pairing>(
    issuer_public_key: &CredIssuerPublicKey<Gt>,
    revealed_attrs: &[Gt::ScalarType],
    bitmap: &[bool],
    credential: &CredRevealProof<Gt>,
) -> Result<(), ZeiError>
{
    let challenge = compute_challenge::<Gt>(&credential.pok.commitment);
    //q = X_2*challenge - proof_commitment + &self.gen2 * &credential.pok.response_t + &self.zz2 * &credential.pok.response_sk;
    let mut q = Gt::g2_mul_scalar(&issuer_public_key.xx2, &challenge).sub(&credential.pok.commitment); //X_2*challente + proof.commitment

    let a = Gt::g2_mul_scalar(&issuer_public_key.gen2, &credential.pok.response_t);
    let b = Gt::g2_mul_scalar(&issuer_public_key.zz2, &credential.pok.response_sk);
    let c = a.add(&b);
    q = q.add(&c);

    let mut y_shown_attr = Gt::G2::get_identity(); //sum (challenge * attr_i)*Y2
    let mut y_hidden_attr = Gt::G2::get_identity(); //sum gamma_i*Y2
    let mut attr_iter = revealed_attrs.iter();
    let mut response_attr_iter = credential.pok.response_attrs.iter();
    let mut yy2_iter = issuer_public_key.yy2.iter();

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

    let a = Gt::pairing(&credential.signature.sigma1, &q);
    let b = Gt::pairing(&credential.signature.sigma2, &Gt::g2_mul_scalar(&issuer_public_key.gen2, &challenge));
    if a != b {
        return Err(ZeiError::SignatureError);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{SeedableRng};
    use rand_chacha::ChaChaRng;
    use crate::algebra::bn::{BNGt, BNScalar};

    #[test]
    fn test_single_attribute(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let issuer_keypair = super::generate_cred_issuer_keys::<_,BNGt>(&mut prng, 1);
        let issuer_pk = issuer_keypair.public_key_ref();
        let issuer_sk = issuer_keypair.secret_key_ref();
        let user_key = super::generate_cred_user_keys(&mut prng, &issuer_keypair.public);
        let attr = BNScalar::random_scalar(&mut prng);

        let signature = super::issuer_sign(&mut prng, &issuer_sk, &user_key.public, vec![attr.clone()]);

        let proof = super::reveal(
            &user_key,
            &mut prng,
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

    #[test]
    fn test_two_attributes(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let issuer_keypair = super::generate_cred_issuer_keys::<_,BNGt>(&mut prng, 2);
        let issuer_pk = issuer_keypair.public_key_ref();
        let issuer_sk = issuer_keypair.secret_key_ref();

        let user_key = super::generate_cred_user_keys(&mut prng, issuer_pk);

        let attr1 = BNScalar::random_scalar(&mut prng);
        let attr2 = BNScalar::random_scalar(&mut prng);

        let signature = super::issuer_sign(
            &mut prng, &issuer_sk, &user_key.get_public_key_ref(), vec![attr1.clone(),attr2.clone()]);

        let proof = reveal(
            &user_key,
            &mut prng,
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
        ).is_ok(), "Revaling first attribute");

        let proof = reveal(
            &user_key,
            &mut prng,
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

        let proof = reveal(
            &user_key,
            &mut prng,
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

        let proof = reveal(
            &user_key,
            &mut prng,
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
