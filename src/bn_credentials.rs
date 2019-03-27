use rand_04::{Rng, SeedableRng};
use crate::bn_pairing::{PairingScalar, G1Elem, G2Elem, pairing};
use blake2::{Blake2b, Digest};
use crate::errors::ZeiError;
use crate::utils::u8_bigendian_slice_to_u32;

/// I represent the Credentials' Issuer Public key
pub struct CredIssuerPublicKey{
    gen2: G2Elem, //random generator for G2
    xx2: G2Elem,  //gen2^x, x in CredIssuerSecretKey
    zz1: G1Elem,  //gen1^z, z random scalar, gen1 in CredIssuerSecretKey
    zz2: G2Elem,  //gen2^z, same z as above
    yy2: Vec<G2Elem>, //gen2^{y_i}, y_i in CredIssuerSecretKey
}

/// I represent the Credentials' Issuer Secret key
pub struct CredIssuerSecretKey {
    gen1: G1Elem, //random generator for G1
    x: PairingScalar,
    y: Vec<PairingScalar>,

}

/// I represent the Credentials' Issuer Key pair
pub struct CredIssuerKeyPair {
    public: CredIssuerPublicKey,
    secret: CredIssuerSecretKey,
}

///I represent a credential signature produce by credential issuer and used by
/// user to selectively disclose signed attributed
pub struct CredSignature{
    sigma1: G1Elem,
    sigma2: G1Elem,
}

///I represent a credential user public key used to request credentials to a credential issuer
pub struct CredUserPublicKey(G1Elem);

///I represent a credential user secret key used to selectively reveals attributed of my credential
pub struct CredUserSecretKey{
    secret: PairingScalar,
    public: CredUserPublicKey,
}

/// I'm a proof computed by the CredUserSecretKey holder that an Issuer has signed certain
/// attributes for the corresponding CredUserPublicKey
pub struct CredRevealProof {
    signature: CredSignature,
    pok: ProofOfKnowledgeCredentials,

}

/// I'm a proof of knowledge for t, sk (CredUserSecretKey), and hidden attributes that satisfy a
/// certain relation.
pub(crate) struct ProofOfKnowledgeCredentials{
    commitment: G2Elem,
    response_t: PairingScalar,
    response_sk: PairingScalar,
    response_attrs: Vec<PairingScalar>,
}

impl CredUserSecretKey{
    pub fn generate<R: Rng>(prng: &mut R, issuer_public_key: &CredIssuerPublicKey) -> CredUserSecretKey{
        /*! given the issuer public key, I compute a CredUserSecretKet and correspondig
         *  CredUserPublicKey
         */
        let secret = PairingScalar::random(prng);
        let public = CredUserPublicKey((&issuer_public_key.zz1) * &secret);
        CredUserSecretKey {
            secret,
            public,
        }
    }
     pub fn get_public_key_ref(&self) -> &CredUserPublicKey{
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
    pub fn reveal<R: Rng>(
        &self, prng: &mut R,
        issuer_public_key: &CredIssuerPublicKey,
        issuer_signature: &CredSignature,
        attributes: Vec<PairingScalar>,
        bitmap_reveal: Vec<bool>
    ) -> CredRevealProof {
        let r = PairingScalar::random(prng);
        let t = PairingScalar::random(prng);
        let randomized_signature = CredSignature{
            sigma1: &issuer_signature.sigma1 * &r,
            sigma2: &(&issuer_signature.sigma2 + &(&issuer_signature.sigma1 * &t)) * &r,
        };

        let mut hidden_attributes = vec![];
        for (attr, revealed) in attributes.iter().zip(&bitmap_reveal){
            if !(*revealed) {
                hidden_attributes.push(attr.clone());
            }
        }
        let proof = self.prove_pok(prng, issuer_public_key, &t,
                                       hidden_attributes, &bitmap_reveal);

        CredRevealProof{
            signature: randomized_signature,
            pok: proof,

        }
    }

    fn prove_pok<R: Rng>(
        &self, prng:
        &mut R,
        issuer_public_key: &CredIssuerPublicKey,
        t: &PairingScalar,
        hidden_attributes: Vec<PairingScalar>,
        revealed_bitmap: &Vec<bool>) -> ProofOfKnowledgeCredentials
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
        let beta1 = PairingScalar::random(prng);
        let beta2 = PairingScalar::random(prng);
        let mut gamma = vec![];
        for _ in 0..hidden_attributes.len(){
            gamma.push(PairingScalar::random(prng));
        }
        let mut commitment = &issuer_public_key.gen2 * &beta1 + &issuer_public_key.zz2 * &beta2;
        let mut gamma_iter = gamma.iter();
        for (yy2i,x) in issuer_public_key.yy2.iter().zip(revealed_bitmap){
            if !(*x) {
                let gammai = gamma_iter.next().unwrap();
                let elem = yy2i * gammai;
                commitment = commitment + elem;
            }
        }
        let challenge = compute_challenge(&commitment);
        let response_t = &challenge * t + beta1;
        let response_sk = (&challenge * &self.secret) + beta2;
        let mut response_attrs = vec![];
        let mut gamma_iter = gamma.iter();
        let mut attr_iter = hidden_attributes.iter();
        for y in revealed_bitmap{
            if (*y) == false {
                let gamma = gamma_iter.next().unwrap();
                let attr = attr_iter.next().unwrap();
                let resp_attr_i = &(&challenge * attr) + gamma;
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

fn compute_challenge(proof_commitment: &G2Elem) -> PairingScalar{
    /*! In a sigma protocol, I compute a hash of the proof commitment */
    let c = proof_commitment.to_str();
    let mut hasher = Blake2b::new();
    hasher.input(c.as_bytes());

    let result = hasher.result();
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
    PairingScalar::random(&mut prg)
}

impl CredIssuerSecretKey {
    pub fn sign<R: Rng>(
        &self,
        prng: &mut R,
        user_public_key: &CredUserPublicKey,
        attributes: Vec<PairingScalar>) -> CredSignature{
        /*! I Compute a credential signature for a set of attributes */

        let u = PairingScalar::random(prng);
        let mut exponent = self.x.clone();
        for (attr       ,yi) in attributes.iter().zip(self.y.iter()){
            exponent = exponent + attr * yi;
        }
        let cc = &self.gen1 * &exponent;
        CredSignature{
            sigma1: &self.gen1 * &u,
            sigma2: &(&user_public_key.0 + &cc) * &u,
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
impl CredIssuerPublicKey {
    pub fn verify(
        &self,
        revealed_attrs: Vec<PairingScalar>,
        bitmap: Vec<bool>,
        credential: &CredRevealProof) -> Result<(), ZeiError>{
        let challenge = compute_challenge(&credential.pok.commitment);

        let mut q = &self.xx2 * &challenge - &credential.pok.commitment;
        q = q + &self.gen2 * &credential.pok.response_t + &self.zz2 * &credential.pok.response_sk;
        let mut y_shown_attr = G2Elem::zero(); //sum (challenge * attr_i)*Y2
        let mut y_hidden_attr = G2Elem::zero(); //sum gamma_i*Y2
        let mut attr_iter = revealed_attrs.iter();
        let mut response_attr_iter = credential.pok.response_attrs.iter();
        let mut yy2_iter = self.yy2.iter();

        for b in bitmap{
            let yy2i = yy2_iter.next().unwrap();
            if b {
                let attribute = attr_iter.next().unwrap();
                y_shown_attr = y_shown_attr + &(yy2i * &challenge) * attribute;
            }
            else {
                let response_attr = response_attr_iter.next().unwrap();
                y_hidden_attr = y_hidden_attr + yy2i * response_attr;

            }
        }
        q = q + y_shown_attr + y_hidden_attr;
        let a = pairing(&credential.signature.sigma1, &q);
        let b = pairing(&credential.signature.sigma2, &(&self.gen2 * &challenge));
        if a != b {
            return Err(ZeiError::SignatureError);
        }

        Ok(())

    }
}

impl CredIssuerKeyPair {
    pub fn generate<R>(prng: &mut R, num_attributes: u32) -> Self
    where R: Rng,
    {
        /*! I generate e key pair for a credential issuer */
        let x = PairingScalar::random(prng);
        let z = PairingScalar::random(prng);
        let gen1 = G1Elem::random(prng);
        let gen2 = G2Elem::random(prng);
        let mut y = vec![];
        let mut yy2 = vec![];
        for _ in 0..num_attributes {
            let yi = PairingScalar::random(prng);
            yy2.push(&gen2 * &yi);
            y.push(yi);
        }
        let xx2 = &gen2 *&x;
        let zz1 = &gen1 *&z;
        let zz2 = &gen2 *&z;
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

    pub fn public_key_ref(&self) -> &CredIssuerPublicKey {
        &self.public
    }

    pub fn secret_key_ref(&self) -> &CredIssuerSecretKey {
        &self.secret
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_04::{SeedableRng, ChaChaRng};

    #[test]
    fn test_single_attribute(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed(&[032; 8]);
        let issuer_keypair = CredIssuerKeyPair::generate(&mut prng, 1);
        let issuer_pk = issuer_keypair.public_key_ref();
        let issuer_sk = issuer_keypair.secret_key_ref();
        let user_key = CredUserSecretKey::generate(&mut prng, &issuer_keypair.public);
        let attr = PairingScalar::random(&mut prng);

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
        let issuer_keypair = CredIssuerKeyPair::generate(&mut prng, 2);
        let issuer_pk = issuer_keypair.public_key_ref();
        let issuer_sk = issuer_keypair.secret_key_ref();

        let user_key = CredUserSecretKey::generate(&mut prng, issuer_pk);

        let attr1 = PairingScalar::random(&mut prng);
        let attr2 = PairingScalar::random(&mut prng);

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