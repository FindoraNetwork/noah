use blake2::{Blake2b, Digest};
use bulletproofs::PedersenGens;
use crate::errors::Error as ZeiError;
use crate::utils::u32_to_bigendian_u8array;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::CryptoRng;
use rand::Rng;

pub fn compute_challenge(context: &Vec<&CompressedRistretto>) -> Scalar{
    /*! I compute zk challenges for Dlog based proof. The challenge is a hash of the
    current context of the proof*/
    let mut hasher = Blake2b::new();

    for point in context.iter(){
        hasher.input((*point).as_bytes());
    }

    Scalar::from_hash(hasher)
}

pub fn compute_sub_challenge(challenge: &Scalar, i: u32) -> Scalar{
    /*! I compute zk sub challenges for multiple Dlog based proofs.
    The sub-challenge is a hash of the challenge and the position i of the sub-challenge*/
    let mut hasher = Blake2b::new();

    hasher.input(challenge.as_bytes());
    hasher.input(u32_to_bigendian_u8array(i));

    Scalar::from_hash(hasher)
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct DlogProof{
    pub proof_commitment: CompressedRistretto,
    pub response: Scalar,
}

pub fn prove_knowledge_dlog<R: CryptoRng + Rng>(
    prng: &mut R,
    base: &RistrettoPoint,
    point: &CompressedRistretto,
    dlog: &Scalar) -> DlogProof{
    let u = Scalar::random(prng);
    let proof_commitment = (u*base).compress();
    let challenge = compute_challenge(&vec![&base.compress(), &proof_commitment, point]);
    let response = challenge * dlog + u;

    DlogProof {
        proof_commitment,
        response,
    }
}

pub fn verify_proof_of_knowledge_dlog(
    base: &RistrettoPoint,
    point: &CompressedRistretto,
    proof:&DlogProof) -> Result<bool, ZeiError>{

    let challenge = compute_challenge(
        &vec![&base.compress(), &proof.proof_commitment, point]);

    let dpoint = point.decompress()?;
    let dproof_commit = proof.proof_commitment.decompress()?;

    let vrfy_ok = proof.response * base == challenge * dpoint + dproof_commit;

    Ok(vrfy_ok)
}

pub fn prove_multiple_knowledge_dlog<R: CryptoRng + Rng>(
    prng: &mut R,
    base: &RistrettoPoint,
    points: &[&CompressedRistretto],
    dlogs: &[&Scalar]) -> DlogProof{

    let u = Scalar::random(prng);
    let proof_commitment = (u*base).compress();
    let base_compressed = base.compress();
    let mut context = vec![&base_compressed, &proof_commitment];
    context.extend_from_slice(points);
    let challenge = compute_challenge(&context);
    let mut response = u;
    for i in 0..dlogs.len() {
        let mut hasher = Blake2b::new();
        hasher.input(challenge.as_bytes());
        hasher.input(u32_to_bigendian_u8array(i as u32));
        let challenge_i = compute_sub_challenge(&challenge, i as u32);
        response = response + challenge_i * dlogs[i];
    }
    DlogProof {
        proof_commitment,
        response,
    }
}

pub fn verify_multiple_knowledge_dlog(
    base: &RistrettoPoint,
    points: &[&CompressedRistretto],
    proof: &DlogProof) -> Result<bool, ZeiError>{

    let base_compressed = base.compress();
    let mut context = vec![&base_compressed, &proof.proof_commitment];
    context.extend_from_slice(points);
    let challenge = compute_challenge(&context);
    let mut check = proof.proof_commitment.decompress()?;
    for i in 0..points.len() {
        let mut hasher = Blake2b::new();
        hasher.input(challenge.as_bytes());
        hasher.input(u32_to_bigendian_u8array(i as u32));
        let challenge_i = Scalar::from_hash(hasher);
        check = check + challenge_i * points[i].decompress()?;
    }
    Ok(check == proof.response * base)

}


//TODO: verify the following proof is good, otherwise use Chaum-Pedersen above.
//The following proof systems assumes that source asset commitment is a valid
//perdersen commitment. Otherwise, it is not secure. If source asset commitment
//cannot be assumed to be a valid pedersen commitment, then use Chaum-Pedersen
pub type CommitmentEqProof = DlogProof;

pub fn dlog_based_prove_commitment_eq<R: CryptoRng + Rng>(
    prng: &mut R,
    pedersen_gens: &PedersenGens,
    source_asset_commitment: &CompressedRistretto,
    destination_asset_commitment: &CompressedRistretto,
    blinding_factor1: &Scalar,
    blinding_factor2: &Scalar) -> Result<CommitmentEqProof, ZeiError>
{
    let src = source_asset_commitment.decompress()?;
    let dst = destination_asset_commitment.decompress()?;
    let point = src - dst;

    let dlog = blinding_factor1 - blinding_factor2;

    let proof = prove_knowledge_dlog(prng, &pedersen_gens.B_blinding, &point.compress(), &dlog);

    Ok(proof)
}

pub fn dlog_based_verify_commitment_eq(
    pedersen_gens: &PedersenGens,
    source_asset_commitment: &CompressedRistretto,
    destination_asset_commitment: &CompressedRistretto,
    proof: &CommitmentEqProof) -> Result<bool, ZeiError>
{
    let src = source_asset_commitment.decompress()?;
    let dst = destination_asset_commitment.decompress()?;

    let point = src - dst;
    verify_proof_of_knowledge_dlog(&pedersen_gens.B_blinding, &point.compress(), proof)
}

#[cfg(test)]
mod test {
    use super::*;
    use bulletproofs::PedersenGens;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;

    #[test]
    fn test_pok_dlog(){
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);

        let base = RistrettoPoint::random(&mut csprng);
        let scalar = Scalar::random(&mut csprng);
        let scalar2 = scalar + Scalar::from(1u8);
        let point = scalar * base;

        let proof = prove_knowledge_dlog(&mut csprng, &base, &point.compress(),
                                         &scalar);
        assert_eq!(true,
                   verify_proof_of_knowledge_dlog(&base, &point.compress(), &proof).unwrap());

        let proof = prove_knowledge_dlog(&mut csprng, &base, &point.compress(),
                                         &scalar2);
        assert_eq!(false, verify_proof_of_knowledge_dlog(&base, &point.compress(), &proof).unwrap())
    }

    #[test]
    fn test_multiple_pok_dlog(){
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);

        let base = RistrettoPoint::random(&mut csprng);
        let scalar1 = Scalar::random(&mut csprng);
        let scalar2 = Scalar::random(&mut csprng);
        let scalar3 = Scalar::random(&mut csprng);
        let scalar4 = Scalar::random(&mut csprng);
        let scalar5 = Scalar::random(&mut csprng);
        let scalar6 = Scalar::random(&mut csprng);
        let scalar7 = Scalar::random(&mut csprng);

        let point1 = scalar1 * base;
        let point2 = scalar2 * base;
        let point3 = scalar3 * base;
        let point4 = scalar4 * base;
        let point5 = scalar5 * base;
        let point6 = scalar6 * base;
        let point7 = scalar7 * base;


        let proof = prove_multiple_knowledge_dlog(
            &mut csprng,
            &base,
            &[&point1.compress(), &point2.compress(), &point3.compress(),
                &point4.compress(), &point5.compress(), &point6.compress(), &point7.compress()],
            &[&scalar1, &scalar2, &scalar3, &scalar4, &scalar5, &scalar6, &scalar7]);

        assert_eq!(true,
                   verify_multiple_knowledge_dlog(
                       &base,
                       &[&point1.compress(), &point2.compress(), &point3.compress(),
                           &point4.compress(), &point5.compress(), &point6.compress(), &point7.compress()],
                       &proof).unwrap());
    }

    #[test]
    pub fn test_equality_commitment() {
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();
        let value1 = Scalar::from(16u8);
        let value2 = Scalar::from(32u8);
        let bf1 = Scalar::from(10u8);
        let bf2 = Scalar::from(100u8);
        let pedersen_bases = PedersenGens::default();
        let c1 = pedersen_bases.commit(value1, bf1).compress();
        let c2 = pedersen_bases.commit(value2, bf2).compress();

        let proof = dlog_based_prove_commitment_eq(
            &mut csprng,
            &pc_gens,
            &c1,
            &c2,
            &bf1,
            &bf2).unwrap();

        assert_eq!(false, dlog_based_verify_commitment_eq(&pc_gens,
                                                          &c1,
                                                          &c2,
                                                          &proof).unwrap());

        let c3 = pedersen_bases.commit(value1, bf2).compress();
        let proof = dlog_based_prove_commitment_eq(
            &mut csprng,
            &pc_gens,
            &c1,
            &c3,
            &bf1,
            &bf2).unwrap();

        assert_eq!(true, dlog_based_verify_commitment_eq(&pc_gens,
                                                         &c1,
                                                         &c3,
                                                         &proof).unwrap());
    }
    
}