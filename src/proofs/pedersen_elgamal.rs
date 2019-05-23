use curve25519_dalek::traits::{Identity, MultiscalarMul};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use crate::basic_crypto::elgamal::{ElGamalCiphertext, elgamal_encrypt, ElGamalPublicKey};
use rand::{CryptoRng, Rng};
use bulletproofs::PedersenGens;
use crate::errors::ZeiError;
use crate::proofs::{compute_challenge_ref};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de::{Visitor, SeqAccess};
use crate::serialization::ZeiFromToBytes;
use sha2::{Sha512, Digest};

/*
 * This file implements a Chaum-Pedersen proof of equality of
 * a commitment C = m*G + r*H, and ciphertext E = (r*G, m*G + r*PK)

 * Proof algorithm:
   a) Sample random scalars r1, r2
   b) Compute commitment on r1 using r2 as randomness: C1 = r1*G + r2*H
   c) Compute encryption of r1 using r2 as randomness: E1 = (r2*G, r1*G + r2*PK)
   d) Compute challenge c = HASH(C, E, C1, E1)
   e) Compute response z1 = cm + r1, z2 = cr + r2
   f) Output proof = C1,E1,z1,z2

 * Verify algorithm:
   a) Compute challenge c = HASH(C, E, C, E)
   b) Output Ok iff C1 + c * C == z1 * G + z2 * H
          and       E1 + c * E == (z2 * G, z1 * pc_gens.B + z2 * PK)
 */
const ELGAMAL_CTEXT_LEN: usize = 64;
pub const PEDERSEN_ELGAMAL_EQ_PROOF_LEN: usize = 96 + ELGAMAL_CTEXT_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenElGamalEqProof{
    z1: Scalar, // c*m + r_1
    z2: Scalar, // c*r + r_2
    e1: ElGamalCiphertext<RistrettoPoint>, // (r_2*G, r1*g + r2*PK)
    c1: RistrettoPoint, // r_1*g + r_2*H
}

impl ZeiFromToBytes for PedersenElGamalEqProof{
    fn zei_to_bytes(&self) -> Vec<u8>{
        let mut v = vec![];
        v.extend_from_slice(self.z1.as_bytes());
        v.extend_from_slice(self.z2.as_bytes());
        let mut e1_vec = self.e1.zei_to_bytes();
        v.append(&mut e1_vec);
        v.extend_from_slice(self.c1.compress().as_bytes());
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Self{
        let mut array = [0u8;32];
        array.copy_from_slice(&bytes[..32]);
        let z1 = Scalar::from_bits(array);
        array.copy_from_slice(&bytes[32..64]);
        let z2 = Scalar::from_bits(array);
        let e1 = ElGamalCiphertext::zei_from_bytes(&bytes[64..64 + ELGAMAL_CTEXT_LEN]);
        let c1 = CompressedRistretto::from_slice(&bytes[64 + ELGAMAL_CTEXT_LEN..]).decompress().unwrap();

        PedersenElGamalEqProof{ z1,z2,e1,c1}
    }
}

impl Serialize for PedersenElGamalEqProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer
    {
        serializer.serialize_bytes(self.zei_to_bytes().as_slice())
    }
}

impl<'de> Deserialize<'de> for PedersenElGamalEqProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>
    {
        struct ProofVisitor;

        impl<'de> Visitor<'de> for ProofVisitor {
            type Value = PedersenElGamalEqProof;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a encoded PedersenElGamal proof")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<PedersenElGamalEqProof, E>
                where E: serde::de::Error
            {
                Ok(PedersenElGamalEqProof::zei_from_bytes(v))
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<PedersenElGamalEqProof, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut vec: Vec<u8> = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    vec.push(x);
                }
                Ok(PedersenElGamalEqProof::zei_from_bytes(vec.as_slice()))
            }
        }
        deserializer.deserialize_bytes(ProofVisitor)
    }
}


/// I compute a proof that ctext and commitment encrypts/holds m under same randomness r.
pub fn pedersen_elgamal_eq_prove<R: CryptoRng + Rng>(
    prng: &mut R,
    m: &Scalar,
    r: &Scalar,
    public_key: &ElGamalPublicKey<RistrettoPoint>,
    ctext: &ElGamalCiphertext<RistrettoPoint>,
    commitment: &RistrettoPoint
) -> PedersenElGamalEqProof
{
    let r1 = Scalar::random(prng);
    let r2 = Scalar::random(prng);
    let pc_gens = PedersenGens::default();
    let com = pc_gens.commit(r1, r2);
    let enc = elgamal_encrypt(&pc_gens.B, &r1, &r2, public_key);
    let c = compute_challenge_ref::<RistrettoPoint>(&[&ctext.e1, &ctext.e2, commitment, &enc.e1, &enc.e2, &com]);
    let z1 = c * m + r1;
    let z2 = c * r + r2;

    PedersenElGamalEqProof{
      z1,z2, e1:enc, c1:com,
    }
}

/// I verify perdersen/elgamal equality proof againts ctext and commitment.
pub fn pedersen_elgamal_eq_verify(
    public_key: &ElGamalPublicKey<RistrettoPoint>,
    ctext: &ElGamalCiphertext<RistrettoPoint>,
    commitment: &RistrettoPoint,
    proof: &PedersenElGamalEqProof,
) -> Result<(), ZeiError>
{
    let pc_gens = PedersenGens::default();
    let c = compute_challenge_ref::<RistrettoPoint>(&[&ctext.e1, &ctext.e2, commitment, &proof.e1.e1, &proof.e1.e2, &proof.c1]);

    let proof_enc_e1 = &proof.e1.e1;
    let proof_enc_e2 = &proof.e1.e2;

    if proof.c1 + c * commitment == proof.z1 * pc_gens.B + proof.z2 * pc_gens.B_blinding {
        if proof_enc_e1 + c * ctext.e1 == proof.z2 * pc_gens.B &&
            proof_enc_e2 + c * ctext.e2 == proof.z1 * pc_gens.B + proof.z2 * public_key.0 {
            return Ok(());
        }
    }
    Err(ZeiError::VerifyPedersenElGamalEqError)
}

/// verify a pedersen/elgamal equality proof against ctext and commitment using aggregation
/// technique and a single multiexponentiation check.
pub fn pedersen_elgamal_eq_verify_fast<R: CryptoRng + Rng>(
    prng: &mut R,
    public_key: &ElGamalPublicKey<RistrettoPoint>,
    ctext: &ElGamalCiphertext<RistrettoPoint>,
    commitment: &RistrettoPoint,
    proof: &PedersenElGamalEqProof,
) -> Result<(), ZeiError>
{
    let pc_gens = PedersenGens::default();
    let c = compute_challenge_ref::<RistrettoPoint>(&[&ctext.e1, &ctext.e2, commitment, &proof.e1.e1, &proof.e1.e2, &proof.c1]);

    let proof_enc_e1 = proof.e1.e1;
    let proof_enc_e2 = proof.e1.e2;

    let a1 = Scalar::random(prng);
    let a2 = Scalar::random(prng);

    let ver = RistrettoPoint::multiscalar_mul(
        &[-a1,     -c*a1,       proof.z1*(a1+Scalar::one()) + proof.z2*a2, proof.z2*a1,        -a2,         -c*a2,     -Scalar::one(), -c,       proof.z2],
        &[proof.c1, *commitment, pc_gens.B,                                 pc_gens.B_blinding, proof_enc_e1, ctext.e1, proof_enc_e2,   ctext.e2, public_key.0]);

    if ver != RistrettoPoint::identity() {
        return Err(ZeiError::VerifyPedersenElGamalEqError);
    }

    Ok(())
}

fn compute_linear_combination_scalar_vector(
    commitments: &[RistrettoPoint],
    ctexts: &[ElGamalCiphertext<RistrettoPoint>],
    public_key: &ElGamalPublicKey<RistrettoPoint>
) -> Vec<Scalar>
{
    let mut input = vec![];
    for c in commitments.iter(){
        input.push(c);
    }
    input.push(&public_key.0);
    for ct in ctexts {
        input.push(&ct.e1);
        input.push(&ct.e2);
    }
    let mut x = vec![];
    let mut xi = compute_challenge_ref(input.as_slice());
    for _ in 1..commitments.len(){
        let mut hash = Sha512::new();
        hash.input(xi.to_bytes());
        let new_x = Scalar::from_hash(hash);
        x.push(xi);
        xi = new_x;
    }
    x.push(xi);
    x
}
pub fn pedersen_elgamal_aggragate_eq_proof<R: CryptoRng + Rng>(
    prng: &mut R,
    m: &[Scalar],
    r: &[Scalar],
    public_key: &ElGamalPublicKey<RistrettoPoint>,
    ctexts: &[ElGamalCiphertext<RistrettoPoint>],
    commitments: &[RistrettoPoint]
) -> PedersenElGamalEqProof
{
    let pc_gens = PedersenGens::default();

    // 1. compute x vector
    let x = compute_linear_combination_scalar_vector(commitments, ctexts, public_key);
    // 2. sampling blinding vector r1 and r2
    let mut r1_vec = vec![];
    let mut r2_vec = vec![];
    for _ in 0..m.len(){
        r1_vec.push(Scalar::random(prng));
        r2_vec.push(Scalar::random(prng));
    }

    // 3. commpute proof commitment vector
    let mut com_vec = vec![];
    let mut enc_vec = vec![];
    for (r1,r2) in r1_vec.iter().zip(r2_vec.iter()){
        com_vec.push(pc_gens.commit(*r1, *r2));
        enc_vec.push(elgamal_encrypt(&pc_gens.B, &r1, &r2, public_key));
    }
    //4. aggregate vectors
    let mut com = RistrettoPoint::identity();
    for (x_i, com_i) in x.iter().zip(commitments.iter()){
        com = com + com_i*x_i
    }
    let mut enc1 = RistrettoPoint::identity();
    let mut enc2 = RistrettoPoint::identity();
    for (x_i, enc_i) in x.iter().zip(ctexts.iter()){
        enc1 = enc1 + enc_i.e1*x_i;
        enc2 = enc2 + enc_i.e2*x_i;
    }

    let mut proof_enc1 = RistrettoPoint::identity();
    let mut proof_enc2 = RistrettoPoint::identity();
    for (x_i, enc_i) in x.iter().zip(enc_vec.iter()){
        proof_enc1 = proof_enc1 + enc_i.e1*x_i;
        proof_enc2 = proof_enc2 + enc_i.e2*x_i;
    }
    let mut proof_com = RistrettoPoint::identity();
    for (x_i, com_i) in x.iter().zip(com_vec.iter()){
        proof_com = proof_com + com_i*x_i
    }
    //5. compute challenge
    let c = compute_challenge_ref::<RistrettoPoint>(&[&pc_gens.B, &pc_gens.B_blinding, &public_key.0, &enc1, &enc2, &com, &proof_enc1,&proof_enc2, &proof_com]);

    //6. compute challenge responses
    let mut z1 = Scalar::zero();
    for ((m_i,r1_i),x_i) in m.iter().zip(r1_vec.iter()).zip(x.iter()){
        z1 = z1 + (m_i*c + r1_i)*x_i;
    }
    let mut z2 = Scalar::zero();
    for ((r_i,r2_i),x_i) in r.iter().zip(r2_vec.iter()).zip(x.iter()){
        z2 = z2 + (r_i*c + r2_i)*x_i;
    }

    let proof_enc = ElGamalCiphertext{
        e1: proof_enc1,
        e2: proof_enc2
    };
    PedersenElGamalEqProof{
        z1,z2, e1:proof_enc, c1:proof_com,
    }
}

pub fn pedersen_elgamal_eq_aggregate_verify_fast<R: CryptoRng + Rng>(
    prng: &mut R,
    public_key: &ElGamalPublicKey<RistrettoPoint>,
    ctexts: &[ElGamalCiphertext<RistrettoPoint>],
    commitments: &[RistrettoPoint],
    proof: &PedersenElGamalEqProof,
) -> Result<(), ZeiError>
{
    // 1. compute x vector
    let x = compute_linear_combination_scalar_vector(commitments, ctexts, public_key);

    // 2. aggragate commitments and ciphertexts
    let mut com = RistrettoPoint::identity();
    for (x_i, com_i) in x.iter().zip(commitments.iter()){
        com = com + com_i*x_i
    }
    let mut enc1 = RistrettoPoint::identity();
    let mut enc2 = RistrettoPoint::identity();
    for (x_i, enc_i) in x.iter().zip(ctexts.iter()){
        enc1 = enc1 + enc_i.e1*x_i;
        enc2 = enc2 + enc_i.e2*x_i;
    }

    let pc_gens = PedersenGens::default();
    let c = compute_challenge_ref::<RistrettoPoint>(&[&pc_gens.B, &pc_gens.B_blinding, &public_key.0, &enc1, &enc2, &com, &proof.e1.e1,&proof.e1.e2, &proof.c1]);

    let proof_enc_e1 = proof.e1.e1;
    let proof_enc_e2 = proof.e1.e2;

    let a1 = Scalar::random(prng);
    let a2 = Scalar::random(prng);

    let ver = RistrettoPoint::multiscalar_mul(
        &[-a1,     -c*a1, proof.z1*(a1+Scalar::one()) + proof.z2*a2, proof.z2*a1,        -a2,          -c*a2, -Scalar::one(), -c,   proof.z2],
        &[proof.c1, com,   pc_gens.B,                                 pc_gens.B_blinding, proof_enc_e1, enc1,  proof_enc_e2,   enc2, public_key.0]);

    if ver != RistrettoPoint::identity() {
        return Err(ZeiError::VerifyPedersenElGamalEqError);
    }

    Ok(())
}


#[cfg(test)]
mod test{
    use crate::errors::ZeiError;
    use crate::basic_crypto::elgamal::{elgamal_generate_secret_key, elgamal_derive_public_key, elgamal_encrypt};
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use bulletproofs::PedersenGens;
    use curve25519_dalek::scalar::Scalar;
    use serde::ser::Serialize;
    use serde::de::Deserialize;
    use rmp_serde::Deserializer;
    use crate::proofs::pedersen_elgamal::PedersenElGamalEqProof;
    use curve25519_dalek::ristretto::RistrettoPoint;

    #[test]
    fn good_proof_verify(){
        let m = Scalar::from(10u8);
        let r = Scalar::from(7657u32);
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let pc_gens = PedersenGens::default();

        let sk = elgamal_generate_secret_key::<_,RistrettoPoint>(&mut prng);
        let pk = elgamal_derive_public_key(&pc_gens.B, &sk);
        let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk);
        let commitment = pc_gens.commit(m,r);

        let proof = super::pedersen_elgamal_eq_prove(&mut prng, &m, &r, &pk, &ctext, &commitment);
        let verify = super::pedersen_elgamal_eq_verify(&pk, &ctext, &commitment, &proof);
        assert_eq!(true, verify.is_ok());

        let verify = super::pedersen_elgamal_eq_verify_fast(&mut prng,&pk, &ctext, &commitment, &proof);
        assert_eq!(true, verify.is_ok());
    }

    #[test]
    fn bad_proof_verify(){
        let m = Scalar::from(10u8);
        let m2 = Scalar::from(11u8);
        let r = Scalar::from(7657u32);
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let pc_gens = PedersenGens::default();

        let sk = elgamal_generate_secret_key::<_, RistrettoPoint>(&mut prng);
        let pk = elgamal_derive_public_key(&pc_gens.B, &sk);
        let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk);
        let commitment = pc_gens.commit(m2,r);

        let proof = super::pedersen_elgamal_eq_prove(&mut prng, &m, &r, &pk, &ctext, &commitment);
        let verify = super::pedersen_elgamal_eq_verify(&pk, &ctext, &commitment, &proof);
        assert_eq!(true, verify.is_err());
        assert_eq!(ZeiError::VerifyPedersenElGamalEqError, verify.err().unwrap());
        let verify = super::pedersen_elgamal_eq_verify_fast(&mut prng, &pk, &ctext, &commitment, &proof);
        assert_eq!(true, verify.is_err());
        assert_eq!(ZeiError::VerifyPedersenElGamalEqError, verify.err().unwrap());
    }

    #[test]
    fn proof_aggregate(){
        let m1 = Scalar::from(11u8);
        let r1 = Scalar::from(7657u32);
        let m2 = Scalar::from(12u8);
        let r2 = Scalar::from(7658u32);
        let m3 = Scalar::from(13u8);
        let r3 = Scalar::from(7659u32);
        let m4 = Scalar::from(14u8);
        let r4 = Scalar::from(7660u32);
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let pc_gens = PedersenGens::default();

        let sk = elgamal_generate_secret_key::<_,RistrettoPoint>(&mut prng);
        let pk = elgamal_derive_public_key(&pc_gens.B, &sk);
        let ctext1 = elgamal_encrypt(&pc_gens.B, &m1, &r1, &pk);
        let commitment1 = pc_gens.commit(m1,r1);
        let ctext2 = elgamal_encrypt(&pc_gens.B, &m2, &r2, &pk);
        let commitment2 = pc_gens.commit(m2,r2);
        let ctext3 = elgamal_encrypt(&pc_gens.B, &m3, &r3, &pk);
        let commitment3 = pc_gens.commit(m3,r3);
        let ctext4 = elgamal_encrypt(&pc_gens.B, &m4, &r4, &pk);
        let commitment4 = pc_gens.commit(m4,r4);

        let ctexts = [ctext1, ctext2, ctext3, ctext4];
        let commitments = [commitment1, commitment2, commitment3, commitment4];

        let proof = super::pedersen_elgamal_aggragate_eq_proof(&mut prng, &[m1,m2,m3,m4], &[r1,r2,r3,r4], &pk, &ctexts, &commitments);
        let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng, &pk, &ctexts, &commitments, &proof);
        assert_eq!(true, verify.is_ok());

        let proof = super::pedersen_elgamal_aggragate_eq_proof(&mut prng, &[m1], &[r1], &pk, &ctexts[..1], &commitments[..1]);
        let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng, &pk, &ctexts[..1], &commitments[..1], &proof);
        assert_eq!(true, verify.is_ok());

        let proof = super::pedersen_elgamal_aggragate_eq_proof(&mut prng, &[m2], &[r2], &pk, &ctexts[1..2], &commitments[1..2]);
        let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng, &pk, &ctexts[1..2], &commitments[1..2], &proof);
        assert_eq!(true, verify.is_ok());

        let proof = super::pedersen_elgamal_aggragate_eq_proof(&mut prng, &[m2,m3], &[r2,r3], &pk, &ctexts[1..3], &commitments[1..3]);
        let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng, &pk, &ctexts[1..3], &commitments[1..3], &proof);
        assert_eq!(true, verify.is_ok());

        let proof = super::pedersen_elgamal_aggragate_eq_proof(&mut prng, &[m1,m2,m3,m3], &[r1,r2,r3,r4], &pk, &ctexts, &commitments);
        let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng, &pk, &ctexts, &commitments, &proof);
        assert_eq!(true, verify.is_err());
        assert_eq!(ZeiError::VerifyPedersenElGamalEqError, verify.err().unwrap());

        let proof = super::pedersen_elgamal_aggragate_eq_proof(&mut prng, &[m1,m2,m3,m4], &[r1,r2,r3,r1], &pk, &ctexts, &commitments);
        let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng, &pk, &ctexts, &commitments, &proof);
        assert_eq!(true, verify.is_err());
        assert_eq!(ZeiError::VerifyPedersenElGamalEqError, verify.err().unwrap());

        let proof = super::pedersen_elgamal_aggragate_eq_proof(&mut prng, &[m1,m2,m3,m4], &[r2,r2,r3,r4], &pk, &ctexts, &commitments);
        let verify = super::pedersen_elgamal_eq_aggregate_verify_fast(&mut prng, &pk, &ctexts, &commitments, &proof);
        assert_eq!(true, verify.is_err());
        assert_eq!(ZeiError::VerifyPedersenElGamalEqError, verify.err().unwrap());

    }


    #[test]
    fn to_json(){
        let m = Scalar::from(10u8);
        let r = Scalar::from(7657u32);
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let pc_gens = PedersenGens::default();

        let sk = elgamal_generate_secret_key::<_, RistrettoPoint>(&mut prng);
        let pk = elgamal_derive_public_key(&pc_gens.B, &sk);
        let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk);
        let commitment = pc_gens.commit(m,r);
        let proof = super::pedersen_elgamal_eq_prove(&mut prng, &m, &r, &pk, &ctext, &commitment);

        let json_str = serde_json::to_string(&proof).unwrap();
        let proof_de = serde_json::from_str(&json_str).unwrap();
        assert_eq!(proof, proof_de, "Deserialized proof does not match");
    }

    #[test]
    fn to_message_pack(){
        let m = Scalar::from(10u8);
        let r = Scalar::from(7657u32);
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let pc_gens = PedersenGens::default();

        let sk = elgamal_generate_secret_key::<_, RistrettoPoint>(&mut prng);
        let pk = elgamal_derive_public_key(&pc_gens.B, &sk);
        let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk);
        let commitment = pc_gens.commit(m,r);
        let proof = super::pedersen_elgamal_eq_prove(&mut prng, &m, &r, &pk, &ctext, &commitment);

        let mut vec = vec![];
        proof.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();

        let mut de = Deserializer::new(&vec[..]);
        let proof_de: PedersenElGamalEqProof = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(proof, proof_de);
    }

}