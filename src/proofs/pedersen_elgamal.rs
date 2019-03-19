use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{CompressedRistretto};
use crate::basic_crypto::elgamal::{ElGamalCiphertext, elgamal_encrypt, ElGamalPublicKey};
use rand::{CryptoRng, Rng};
use bulletproofs::PedersenGens;
use crate::errors::ZeiError;
use crate::proofs::{compute_challenge_ref};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de::{Visitor, SeqAccess};
use crate::serialization::ZeiFromToBytes;

#[derive(Debug, PartialEq, Eq)]
pub struct PedersenElGamalEqProof{
    z1: Scalar, // c*m + r_1
    z2: Scalar, // c*r + r_2
    e1: ElGamalCiphertext, // (r_2*G, r1*g + r2*PK)
    c1: CompressedRistretto, // r_1*g + r_2*H
}

impl Serialize for PedersenElGamalEqProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer
    {
        let mut v = vec![];
        v.extend_from_slice(self.z1.as_bytes());
        v.extend_from_slice(self.z2.as_bytes());
        v.extend_from_slice(self.e1.zei_to_bytes().as_slice());
        v.extend_from_slice(self.c1.as_bytes());
        serializer.serialize_bytes(v.as_slice())
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
                let mut bytes = [0u8;32];
                bytes.copy_from_slice(&v[0..32]);
                let z1 = Scalar::from_bits(bytes);
                bytes.copy_from_slice(&v[32..32*2]);
                let z2 = Scalar::from_bits(bytes);

                let e1 = ElGamalCiphertext::zei_from_bytes(&v[32*2..32*4]);
                let c1 = CompressedRistretto::from_slice(&v[32*4..]);

                Ok(PedersenElGamalEqProof{
                    z1,
                    z2,
                    e1,
                    c1,
                })
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<PedersenElGamalEqProof, V::Error>
                where V: SeqAccess<'de>,
            {
                let mut vec: Vec<u8> = vec![];
                while let Some(x) = seq.next_element().unwrap() {
                    vec.push(x);
                }
                let mut bytes = [0u8;32];
                bytes.copy_from_slice(&vec[0..32]);
                let z1 = Scalar::from_bits(bytes);
                bytes.copy_from_slice(&vec[32..32*2]);
                let z2 = Scalar::from_bits(bytes);

                let e1 = ElGamalCiphertext::zei_from_bytes(&vec[32*2..32*4]);
                let c1 = CompressedRistretto::from_slice(&vec[32*4..]);

                Ok(PedersenElGamalEqProof{
                    z1,
                    z2,
                    e1,
                    c1,
                })
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
    public_key: &ElGamalPublicKey,
    ctext: &ElGamalCiphertext,
    commitment: &CompressedRistretto
) -> PedersenElGamalEqProof
{
    let r1 = Scalar::random(prng);
    let r2 = Scalar::random(prng);
    let pc_gens = PedersenGens::default();
    let com = pc_gens.commit(r1, r2);
    let enc = elgamal_encrypt(&pc_gens.B, &r1, &r2, public_key).unwrap();
    let c = compute_challenge_ref(&[&ctext.e1, &ctext.e2, commitment, &enc.e1, &enc.e2, &com.compress()]);
    let z1 = c * m + r1;
    let z2 = c * r + r2;

    PedersenElGamalEqProof{
      z1,z2, e1:enc, c1:com.compress(),
    }
}

/// I verify perdersen/elgamal equality proof againts ctext and commitment.
pub fn pedersen_elgamal_eq_verify(
    public_key: &ElGamalPublicKey,
    ctext: &ElGamalCiphertext,
    commitment: &CompressedRistretto,
    proof: &PedersenElGamalEqProof,
) -> Result<(), ZeiError>
{
    let pc_gens = PedersenGens::default();
    let c = compute_challenge_ref(&[&ctext.e1, &ctext.e2, commitment, &proof.e1.e1, &proof.e1.e2, &proof.c1]);

    // decompress input values
    let enc_e1 = ctext.e1.decompress().ok_or(ZeiError::DecompressElementError)?;
    let enc_e2 = ctext.e2.decompress().ok_or(ZeiError::DecompressElementError)?;
    let commitment = commitment.decompress().ok_or(ZeiError::DecompressElementError)?;

    // decompress proof values
    let proof_enc_e1 = proof.e1.e1.decompress().ok_or(ZeiError::DecompressElementError)?;
    let proof_enc_e2 = proof.e1.e2.decompress().ok_or(ZeiError::DecompressElementError)?;
    let proof_c1 = proof.c1.decompress().ok_or(ZeiError::DecompressElementError)?;

    if proof_c1 + c * commitment == proof.z1 * pc_gens.B + proof.z2 * pc_gens.B_blinding {
        if proof_enc_e1 + c * enc_e1 == proof.z2 * pc_gens.B &&
            proof_enc_e2 + c * enc_e2 == proof.z1 * pc_gens.B + proof.z2 * public_key.get_curve_point() {
            return Ok(());
        }
    }
    Err(ZeiError::VerifyPedersenElGamalEqError)
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

    #[test]
    fn good_proof_verify(){
        let m = Scalar::from(10u8);
        let r = Scalar::from(7657u32);
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let pc_gens = PedersenGens::default();

        let sk = elgamal_generate_secret_key(&mut prng);
        let pk = elgamal_derive_public_key(&pc_gens.B, &sk);
        let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk).unwrap();
        let commitment = pc_gens.commit(m,r).compress();

        let proof = super::pedersen_elgamal_eq_prove(&mut prng, &m, &r, &pk, &ctext, &commitment);
        let verify = super::pedersen_elgamal_eq_verify(&pk, &ctext, &commitment, &proof);
        assert_eq!(true, verify.is_ok());
    }

    #[test]
    fn bad_proof_verify(){
        let m = Scalar::from(10u8);
        let m2 = Scalar::from(11u8);
        let r = Scalar::from(7657u32);
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let pc_gens = PedersenGens::default();

        let sk = elgamal_generate_secret_key(&mut prng);
        let pk = elgamal_derive_public_key(&pc_gens.B, &sk);
        let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk).unwrap();
        let commitment = pc_gens.commit(m2,r).compress();

        let proof = super::pedersen_elgamal_eq_prove(&mut prng, &m, &r, &pk, &ctext, &commitment);
        let verify = super::pedersen_elgamal_eq_verify(&pk, &ctext, &commitment, &proof);
        assert_eq!(true, verify.is_err());
        assert_eq!(ZeiError::VerifyPedersenElGamalEqError, verify.err().unwrap());
    }

    #[test]
    fn to_json(){
        let m = Scalar::from(10u8);
        let r = Scalar::from(7657u32);
        let mut prng = ChaChaRng::from_seed([0u8;32]);
        let pc_gens = PedersenGens::default();

        let sk = elgamal_generate_secret_key(&mut prng);
        let pk = elgamal_derive_public_key(&pc_gens.B, &sk);
        let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk).unwrap();
        let commitment = pc_gens.commit(m,r).compress();
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

        let sk = elgamal_generate_secret_key(&mut prng);
        let pk = elgamal_derive_public_key(&pc_gens.B, &sk);
        let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk).unwrap();
        let commitment = pc_gens.commit(m,r).compress();
        let proof = super::pedersen_elgamal_eq_prove(&mut prng, &m, &r, &pk, &ctext, &commitment);

        let mut vec = vec![];
        proof.serialize(&mut rmp_serde::Serializer::new(&mut vec)).unwrap();

        let mut de = Deserializer::new(&vec[..]);
        let proof_de: PedersenElGamalEqProof = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(proof, proof_de);
    }

}