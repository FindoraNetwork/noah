use crate::errors::ZeiError;
use sha2::{Sha512, Digest};
use crate::algebra::groups::Group;
use crate::algebra::pairing::Pairing;
use rand::{CryptoRng, Rng};

/// I represent the Credentials' Issuer Public key
pub struct CredIssuerPublicKey<G1: Group, G2: Group>{
    gen2: G2, //random generator for G2
    xx2: G2,  //gen2^x, x in CredIssuerSecretKey
    zz1: G1,  //gen1^z, z random scalar, gen1 in CredIssuerSecretKey
    zz2: G2,  //gen2^z, same z as above
    yy2: Vec<G2>, //gen2^{y_i}, y_i in CredIssuerSecretKey
}

/// I represent the Credentials' Issuer Secret key
pub struct CredIssuerSecretKey<G1: Group> {
    gen1: G1, //random generator for G1
    x: G1::ScalarType,
    y: Vec<G1::ScalarType>,

}

/// I represent the Credentials' Issuer Key pair
pub struct CredIssuerKeyPair<G1: Group, G2: Group> {
    public: CredIssuerPublicKey<G1, G2>,
    secret: CredIssuerSecretKey<G1>,
}

///I represent a credential signature produce by credential issuer and used by
/// user to selectively disclose signed attributed
pub struct CredSignature<G1: Group>{
    sigma1: G1,
    sigma2: G1,
}

///I represent a credential user public key used to request credentials to a credential issuer
pub struct CredUserPublicKey<G1: Group>(pub(crate) G1);

///I represent a credential user secret key used to selectively reveals attributed of my credential
pub struct CredUserSecretKey<G1: Group>{
    secret: G1::ScalarType, //same as G2
    public: CredUserPublicKey<G1>,
}

/// I'm a proof computed by the CredUserSecretKey holder that an Issuer has signed certain
/// attributes for the corresponding CredUserPublicKey
pub struct CredRevealProof<G1: Group, G2: Group> {
    signature: CredSignature<G1>,
    pok: ProofOfKnowledgeCredentials<G2>,

}

/// I'm a proof of knowledge for t, sk (CredUserSecretKey), and hidden attributes that satisfy a
/// certain relation.
pub(crate) struct ProofOfKnowledgeCredentials<G2: Group>{
    commitment: G2,
    response_t: G2::ScalarType,
    response_sk: G2::ScalarType,
    response_attrs: Vec<G2::ScalarType>,
}

impl<G1: Group> CredUserSecretKey<G1>{
    pub fn generate<R: CryptoRng + Rng, G2: Group>(prng: &mut R, issuer_public_key: &CredIssuerPublicKey<G1,G2>) -> CredUserSecretKey<G1>{
        /*! given the issuer public key, I compute a CredUserSecretKet and correspondig
         *  CredUserPublicKey
         */
        let secret = G1::random_scalar(prng);
        let public = CredUserPublicKey((&issuer_public_key.zz1).mul_by_scalar(&secret));
        CredUserSecretKey {
            secret,
            public,
        }
    }
    pub fn get_public_key_ref(&self) -> &CredUserPublicKey<G1>{
        &self.public
    }

    /// I compute a proof that a credential provider with pk issuer_public_key has giving me
    /// credentials for certain attributes. The attributes to reveal are the ones indicated
    /// by the bitmap. The rest of attributed remain hidden.
    /// Algorithm:
    ///  1. sample random scalars r and t.
    ///  2. Randomize the signature (sigma1, sigma2) as (r*sigma1, r*(sigma2 + t*sigma1)
    ///  3. Compute a proof of knowledge for t, sk (self), and hidden attributes such that
    ///   e(r*sigma1,X2) + e(r*sigma1, g_2^t) + e(r*sigma1, Z2^sk) + e(r*sigma1, \\sum Y2_i^attr_i)
    ///     = e(r*(\sigma2 + r + (t*sigma1), g_2)
    ///     Where X2, Z2, Y2 belongs to the issuer's public key and e is bilinear map.
    ///  4. Return randomized_signature, and the proof of knowledge
    pub fn reveal<R: CryptoRng + Rng, G2: Group>(
        &self, prng: &mut R,
        issuer_public_key: &CredIssuerPublicKey<G1, G2>,
        issuer_signature: &CredSignature<G1>,
        attributes: Vec<G1::ScalarType>,
        bitmap_reveal: Vec<bool>
    ) -> CredRevealProof<G1, G2> {
        let r = G1::random_scalar(prng);
        let t = G1::random_scalar(prng);
        let randomized_signature = CredSignature::<G1>{
            sigma1: issuer_signature.sigma1.mul_by_scalar(&r),
            sigma2: issuer_signature.sigma2.add(&issuer_signature.sigma1.mul_by_scalar(&t)).mul_by_scalar(&r),
        };

        let mut hidden_attributes = vec![];
        for (attr, revealed) in attributes.iter().zip(&bitmap_reveal){
            if !(*revealed) {
                hidden_attributes.push(attr.clone());
            }
        }
        let proof = self.prove_pok::<_,G2>(prng, issuer_public_key, &t,
                                   hidden_attributes, &bitmap_reveal);

        CredRevealProof{
            signature: randomized_signature,
            pok: proof,

        }
    }

    fn prove_pok<R: CryptoRng + Rng, G2: Group>(
        &self, prng:
        &mut R,
        issuer_public_key: &CredIssuerPublicKey<G1, G2>,
        t: &G1::ScalarType,
        hidden_attributes: Vec<G1::ScalarType>,
        revealed_bitmap: &Vec<bool>) -> ProofOfKnowledgeCredentials<G2>
    {
        /*! I compute a proof of knowledge of t, sk (self), and hidden attributes such that
         * some relation on them holds.
         * Algorithm:
         * 1. Sample beta1, beta2 and {gamma_j} (One for each hidden attribute)
         * 2. Compute a sigma proof commitment for the values in 1:
         *    beta1*g2 + beta2*Z2 + \sum gamma_j Y2_{j_i} for each j_i s.t revealed_itmap[j_i] = false
         * 3. Sample the challenge as a hash of the commitment.
         * 4. Compute challenge's responses  c*t + \beta1, c*sk + beta2, {c*y_i + gamma_i}
         * 5. Return proof commitment and responses
        */
        let beta1 = G2::random_scalar(prng);
        let beta2 = G2::random_scalar(prng);
        let mut gamma = vec![];
        for _ in 0..hidden_attributes.len(){
            gamma.push(G2::random_scalar(prng));
        }
        let mut commitment = issuer_public_key.gen2.mul_by_scalar(&beta1).add(&issuer_public_key.zz2.mul_by_scalar(&beta2));
        let mut gamma_iter = gamma.iter();
        for (yy2i,x) in issuer_public_key.yy2.iter().zip(revealed_bitmap){
            if !(*x) {
                let gammai = gamma_iter.next().unwrap();
                let elem = yy2i.mul_by_scalar(gammai);
                commitment = commitment.add(&elem);
            }
        }
        let challenge = compute_challenge(&commitment);
        let response_t = G2::scalar_add(&G2::scalar_mul(&challenge,t as &G2::ScalarType), &beta1); // challente*t + beta1
        let response_sk = G2::scalar_add(&G2::scalar_mul(&challenge, &(self.secret as G2::ScalarType)), &beta2);
        let mut response_attrs = vec![];
        let mut gamma_iter = gamma.iter();
        let mut attr_iter = hidden_attributes.iter();
        for y in revealed_bitmap{
            if (*y) == false {
                let gamma = gamma_iter.next().unwrap();
                let attr = attr_iter.next().unwrap();
                let resp_attr_i = G2::scalar_add(&G2::scalar_mul(&challenge, attr as &G2::ScalarType), gamma);
                response_attrs.push(resp_attr_i);
            }
        }
        ProofOfKnowledgeCredentials{
            commitment,
            response_t,
            response_sk,
            response_attrs,
        }

    }
}

fn compute_challenge<G2: Group>(proof_commitment: &G2) -> G2::ScalarType{
    /*! In a sigma protocol, I compute a hash of the proof commitment */
    let c = proof_commitment.to_compressed_bytes();
    let mut hasher = Sha512::new();
    hasher.input(c.as_slice());

    let result = hasher.result();
    /*
    let mut seed =  [0u32;8];

    seed[0] = u8_bigendian_slice_to_u32(&result.as_slice()[..4]);
    seed[1] = u8_bigendian_slice_to_u32(&result.as_slice()[4..8]);
    seed[2] = u8_bigendian_slice_to_u32(&result.as_slice()[8..12]);
    seed[3] = u8_bigendian_slice_to_u32(&result.as_slice()[12..16]);
    seed[4] = u8_bigendian_slice_to_u32(&result.as_slice()[16..20]);
    seed[5] = u8_bigendian_slice_to_u32(&result.as_slice()[20..24]);
    seed[6] = u8_bigendian_slice_to_u32(&result.as_slice()[24..28]);
    seed[7] = u8_bigendian_slice_to_u32(&result.as_slice()[28..32]);


    let mut prg = rand_04::ChaChaRng::from_seed(&seed[..]);
    */
    G2::scalar_from_hash(hasher)
}

impl<G1: Group> CredIssuerSecretKey<G1> {
    pub fn sign<R: CryptoRng + Rng>(
        &self,
        prng: &mut R,
        user_public_key: &CredUserPublicKey<G1>,
        attributes: Vec<G1::ScalarType>) -> CredSignature<G1>{
        /*! I Compute a credential signature for a set of attributes */

        let u = G1::random_scalar(prng);
        let mut exponent = self.x.clone();
        for (attr       ,yi) in attributes.iter().zip(self.y.iter()){
            exponent = G1::scalar_add(&exponent, &G1::scalar_mul(attr,yi));
        }
        let cc = self.gen1.mul_by_scalar(&exponent);
        CredSignature::<G1>{
            sigma1: self.gen1.mul_by_scalar(&u),
            sigma2: user_public_key.0.add(&cc).mul_by_scalar(&u),
        }
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
impl<G1: Group, G2: Group> CredIssuerPublicKey<G1, G2> {
    pub fn verify<Gt: Group + Pairing>(
        &self,
        revealed_attrs: Vec<G1::ScalarType>,
        bitmap: Vec<bool>,
        credential: &CredRevealProof<G1, G2>) -> Result<(), ZeiError>{
        let challenge = compute_challenge(&credential.pok.commitment);

        //q = X_2*challenge - proof_commitment + &self.gen2 * &credential.pok.response_t + &self.zz2 * &credential.pok.response_sk;
        let mut q = self.xx2.mul_by_scalar(&challenge).sub(&credential.pok.commitment); //X_2*challente + proof.commitment

        let a = self.gen2.mul_by_scalar(&credential.pok.response_t);
        let b = self.zz2.mul_by_scalar(&credential.pok.response_sk);
        let c = a.add(&b);
        q = q.add(&c);

        let mut y_shown_attr = G2::get_identity(); //sum (challenge * attr_i)*Y2
        let mut y_hidden_attr = G2::get_identity(); //sum gamma_i*Y2
        let mut attr_iter = revealed_attrs.iter();
        let mut response_attr_iter = credential.pok.response_attrs.iter();
        let mut yy2_iter = self.yy2.iter();

        for b in bitmap{
            let yy2i = yy2_iter.next().unwrap();
            if b {
                let attribute = attr_iter.next().unwrap();
                let scalar = G2::scalar_mul(&challenge, &attribute);
                y_shown_attr = y_shown_attr.add(&yy2i.mul_by_scalar(&scalar));
            }
            else {
                let response_attr = response_attr_iter.next().unwrap();
                y_hidden_attr = y_hidden_attr.add(&yy2i.mul_by_scalar(response_attr));
            }
        }
        let shown_plus_hidden = y_shown_attr.add(&y_hidden_attr);
        q = q.add(&shown_plus_hidden);

        let a = Gt::pairing(&credential.signature.sigma1, &q);
        let b = Gt::pairing(&credential.signature.sigma2, &self.gen2.mul_by_scalar(&challenge));
        if a != b {
            return Err(ZeiError::SignatureError);
        }

        Ok(())

    }
}

impl<G1: Group, G2: Group> CredIssuerKeyPair<G1, G2> {
    pub fn generate<R>(prng: &mut R, num_attributes: u32) -> Self
        where R: CryptoRng + Rng,
    {
        /*! I generate e key pair for a credential issuer */
        let x = G2::random_scalar(prng);
        let z = G1::random_scalar(prng);
        let gen1 = G1::get_base().mul_by_scalar(&G1::random_scalar(prng)); //TODO check that G1 is of prime order so that every element is generator
        let gen2 = G2::get_base().mul_by_scalar(&G2::random_scalar(prng)); //TODO check that G2 is of prime order so that every element is generator
        let mut y = vec![];
        let mut yy2 = vec![];
        for _ in 0..num_attributes {
            let yi = G1::random_scalar(prng);
            yy2.push(gen2.mul_by_scalar(&yi));
            y.push(yi);
        }
        let xx2 = gen2.mul_by_scalar(&x);
        let zz1 = gen1.mul_by_scalar(&z);
        let zz2 = gen2.mul_by_scalar(&z);
        Self{
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

    pub fn public_key_ref(&self) -> &CredIssuerPublicKey<G1, G2> {
        &self.public
    }

    pub fn secret_key_ref(&self) -> &CredIssuerSecretKey<G1> {
        &self.secret
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_04::{SeedableRng, ChaChaRng};
    use crate::algebra::bn::{BNG1, BNG2};

    #[test]
    fn test_single_attribute(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed(&[032; 8]);
        let issuer_keypair = CredIssuerKeyPair::<BNG1, BNG2>::generate(&mut prng, 1);
        let issuer_pk = issuer_keypair.public_key_ref();
        let issuer_sk = issuer_keypair.secret_key_ref();
        let user_key = CredUserSecretKey::generate(&mut prng, &issuer_keypair.public);
        let attr = BNG1::random_scalar(&mut prng);

        let signature = issuer_sk.sign(&mut prng, &user_key.public, vec![attr.clone()]);

        let proof = user_key.reveal(
            &mut prng,
            issuer_pk,
            &signature,
            vec![attr.clone()],
            vec![true]);

        assert_eq!(true, issuer_pk.verify(
            vec![attr.clone()],
            vec![true],
            &proof,
        ).is_ok())
    }

    #[test]
    fn test_two_attributes(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed(&[032; 8]);
        let issuer_keypair = CredIssuerKeyPair::<BNG1,BNG2>::generate(&mut prng, 2);
        let issuer_pk = issuer_keypair.public_key_ref();
        let issuer_sk = issuer_keypair.secret_key_ref();

        let user_key = CredUserSecretKey::generate(&mut prng, issuer_pk);

        let attr1 = BNG1::random_scalar(&mut prng);
        let attr2 = BNG1::random_scalar(&mut prng);

        let signature = issuer_sk.sign(
            &mut prng, &user_key.get_public_key_ref(), vec![attr1.clone(),attr2.clone()]);

        let proof = user_key.reveal(
            &mut prng,
            issuer_pk,
            &signature,
            vec![attr1.clone(), attr2.clone()],
            vec![true, false]);

        assert_eq!(true, issuer_pk.verify(
            vec![attr1.clone()],
            vec![true, false],
            &proof,
        ).is_ok(), "Revaling first attribute");

        let proof = user_key.reveal(
            &mut prng,
            issuer_pk,
            &signature,
            vec![attr1.clone(), attr2.clone()],
            vec![false, true]);

        assert_eq!(true, issuer_pk.verify(
            vec![attr2.clone()],
            vec![false, true],
            &proof,
        ).is_ok(), "Revealing second attribute");

        let proof = user_key.reveal(
            &mut prng,
            issuer_pk,
            &signature,
            vec![attr1.clone(), attr2.clone()],
            vec![false, false]);

        assert_eq!(true, issuer_pk.verify(
            vec![],
            vec![false, false],
            &proof,
        ).is_ok(), "Error revealing no attribute");

        let proof = user_key.reveal(
            &mut prng,
            issuer_pk,
            &signature,
            vec![attr1.clone(), attr2.clone()],
            vec![true, true]);

        assert_eq!(true, issuer_pk.verify(
            vec![attr1.clone(), attr2.clone()],
            vec![true, true],
            &proof,
        ).is_ok(), "Error revealing both attributes")
    }
}