use bulletproofs::PedersenGens;
use crate::errors::ZeiError;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::CryptoRng;
use rand::Rng;
use crate::proofs::{compute_challenge, compute_sub_challenge};


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

    /*! I compute a proof for the knowledge of dlog for point with respect to base*/
    let u = Scalar::random(prng);
    let proof_commitment = (u*base).compress();
    let challenge = compute_challenge(&vec![base.compress(), proof_commitment, point.clone()]);
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

    /*! I verify a proof of knowledge of dlog for point with respect to base*/

    let challenge = compute_challenge(
        &[base.compress(), proof.proof_commitment, *point]);

    let dpoint = point.decompress()?;
    let dproof_commit = proof.proof_commitment.decompress()?;

    let vrfy_ok = proof.response * base == challenge * dpoint + dproof_commit;

    Ok(vrfy_ok)
}

pub fn prove_multiple_knowledge_dlog<R: CryptoRng + Rng>(
    prng: &mut R,
    base: &RistrettoPoint,
    points: &[CompressedRistretto],
    dlogs: &[Scalar]) -> DlogProof{

    /*! I compute a proof for the knowledge of dlogs for points for the base*/

    let u = Scalar::random(prng);
    let proof_commitment = (u*base).compress();
    let base_compressed = base.compress();
    let mut context = vec![base_compressed, proof_commitment];
    context.extend_from_slice(points);
    let challenge = compute_challenge(context.as_slice());
    let mut response = u;
    for i in 0..dlogs.len() {
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
    points: &[CompressedRistretto],
    proof: &DlogProof) -> Result<bool, ZeiError>{

    /*! I verify a proof of knowledge of dlogs for points in the base*/

    let base_compressed = base.compress();
    let mut context = vec![base_compressed, proof.proof_commitment];
    context.extend_from_slice(points);
    let challenge = compute_challenge(context.as_slice());
    let mut check = proof.proof_commitment.decompress()?;
    for i in 0..points.len() {let challenge_i = compute_sub_challenge(&challenge, i as u32);
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
    source_blinding_factor: &Scalar,
    destination_blinding_factor: &Scalar) -> Result<CommitmentEqProof, ZeiError>
{
    /*! Assuming source_asset_commitment is a pedersen commitment, I compute a Dlog-equality-based
     * proof that source and destination_asset_commitments commit to the same value, using source
     * and destination blinding factors respectively. Return Ok(proof) in case of success,
     * and Err(Error::DeserializationError) in case a Ristretto points cannot be decompressed.
     */

    let src = source_asset_commitment.decompress()?;
    let dst = destination_asset_commitment.decompress()?;
    let point = src - dst;

    let dlog = source_blinding_factor - destination_blinding_factor;

    let proof = prove_knowledge_dlog(prng, &pedersen_gens.B_blinding, &point.compress(), &dlog);

    Ok(proof)
}

pub fn dlog_based_verify_commitment_eq(
    pedersen_gens: &PedersenGens,
    source_asset_commitment: &CompressedRistretto,
    destination_asset_commitment: &CompressedRistretto,
    proof: &CommitmentEqProof) -> Result<bool, ZeiError>
{
    /*! Assuming source_asset_commitment is a pedersen commitment, I compute a Dlog-equality-based
     * proof that source and destination_asset_commitments commit to the same value.
     * Return Ok(true) in case of success, Ok(false) in case of verification error,
     * and Err(Error::DeserializationError) in case a Ristretto points cannot be decompressed.
     */

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
            &[point1.compress(), point2.compress(), point3.compress(),
                point4.compress(), point5.compress(), point6.compress(), point7.compress()],
            &[scalar1, scalar2, scalar3, scalar4, scalar5, scalar6, scalar7]);

        assert_eq!(true,
                   verify_multiple_knowledge_dlog(
                       &base,
                       &[point1.compress(), point2.compress(), point3.compress(),
                           point4.compress(), point5.compress(), point6.compress(), point7.compress()],
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