use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::CryptoRng;
use rand::Rng;
use crate::proofs::{compute_sub_challenge, compute_challenge_ref};
use crate::algebra::groups::{Group, Scalar as ZeiScalar};


#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct DlogProof<G,S>{
    pub proof_commitment: G,
    pub response: S,
}

pub fn prove_knowledge_dlog<R: CryptoRng + Rng, G: Group>(
    prng: &mut R,
    base: &G,
    point: &G,
    dlog: &G::ScalarType) -> DlogProof<G, G::ScalarType>{
    /*! I compute a proof for the knowledge of dlog for point with respect to base*/
    let u = G::ScalarType::random_scalar(prng);
    let proof_commitment = base.mul(&u);
    let challenge = compute_challenge_ref::<G>(&[base, &proof_commitment, point]);
    let response = challenge.mul(dlog).add(&u);

    DlogProof {
        proof_commitment: proof_commitment,
        response,
    }
}

pub fn verify_proof_of_knowledge_dlog<G: Group>(
    base: &G,
    point: &G,
    proof:&DlogProof<G, G::ScalarType>) -> bool{

    /*! I verify a proof of knowledge of dlog for point with respect to base*/

    let challenge = compute_challenge_ref::<G>(
        &[base, &proof.proof_commitment, point]);

    let vrfy_ok = base.mul(&proof.response) == point.mul(&challenge).add(&proof.proof_commitment);

    vrfy_ok
}

pub fn prove_multiple_knowledge_dlog<R: CryptoRng + Rng, G: Group>(
    prng: &mut R,
    base: &G,
    points: &[G],
    dlogs: &[G::ScalarType]) -> DlogProof<G, G::ScalarType>{

    /*! I compute a proof for the knowledge of dlogs for points for the base*/

    let u = G::ScalarType::random_scalar(prng);
    let proof_commitment = base.mul(&u);
    let mut context = vec![base, &proof_commitment];
    for point in points.iter(){
        context.push(point);
    }
    //context.extend_from_slice(points.iter());
    let challenge = compute_challenge_ref::<G>(context.as_slice());
    let mut response = u;
    for i in 0..dlogs.len() {
        let challenge_i = compute_sub_challenge::<G>(&challenge, i as u32);
        response = response.add( &challenge_i.mul(&dlogs[i]) );
    }

    DlogProof {
        proof_commitment,
        response,
    }
}

pub fn verify_multiple_knowledge_dlog<G: Group>(
    base: &G,
    points: &[G],
    proof: &DlogProof<G, G::ScalarType>) -> bool{

    /*! I verify a proof of knowledge of dlogs for points in the base*/

    let mut context = vec![base, &proof.proof_commitment];
    for point in points{
        context.push(point);
    }
    //context.extend_from_slice(points);
    let challenge = compute_challenge_ref::<G>(context.as_slice());
    let mut check = proof.proof_commitment.clone();
    for i in 0..points.len() {
        let challenge_i = compute_sub_challenge::<G>(&challenge, i as u32);
        check = check.add(&points[i].mul(&challenge_i));
    }
    check == base.mul(&proof.response)

}


//TODO: verify the following proof is good, otherwise use Chaum-Pedersen above.
//The following proof systems assumes that source asset commitment is a valid
//perdersen commitment. Otherwise, it is not secure. If source asset commitment
//cannot be assumed to be a valid pedersen commitment, then use Chaum-Pedersen
pub type CommitmentEqProof = DlogProof<RistrettoPoint, curve25519_dalek::scalar::Scalar>;

pub fn dlog_based_prove_commitment_eq<R: CryptoRng + Rng>(
    prng: &mut R,
    pedersen_gens: &PedersenGens,
    source_asset_commitment: &RistrettoPoint,
    destination_asset_commitment: &RistrettoPoint,
    source_blinding_factor: &Scalar,
    destination_blinding_factor: &Scalar) -> CommitmentEqProof
{
    /*! Assuming source_asset_commitment is a pedersen commitment, I compute a Dlog-equality-based
     * proof that source and destination_asset_commitments commit to the same value, using source
     * and destination blinding factors respectively. Returns a DLog proof proof.
     */

    let point = source_asset_commitment - destination_asset_commitment;

    let dlog = source_blinding_factor - destination_blinding_factor;

    let proof = prove_knowledge_dlog(prng, &pedersen_gens.B_blinding, &point, &dlog);

    proof
}

pub fn dlog_based_verify_commitment_eq(
    pedersen_gens: &PedersenGens,
    source_asset_commitment: &RistrettoPoint,
    destination_asset_commitment: &RistrettoPoint,
    proof: &CommitmentEqProof) ->bool
{
    /*! Assuming source_asset_commitment is a pedersen commitment, I compute a Dlog-equality-based
     * proof that source and destination_asset_commitments commit to the same value.
     * Return true in case of success and false in case of verification error.
     */

    let point = source_asset_commitment - destination_asset_commitment;
    verify_proof_of_knowledge_dlog(&pedersen_gens.B_blinding, &point, proof)
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

        let proof = prove_knowledge_dlog(&mut csprng, &base, &point,
                                         &scalar);
        assert_eq!(true,
                   verify_proof_of_knowledge_dlog(&base, &point, &proof));

        let proof = prove_knowledge_dlog(&mut csprng, &base, &point,
                                         &scalar2);
        assert_eq!(false, verify_proof_of_knowledge_dlog(&base, &point, &proof))
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
            &[point1, point2, point3,
                point4, point5, point6, point7],
            &[scalar1, scalar2, scalar3, scalar4, scalar5, scalar6, scalar7]);

        assert_eq!(true,
                   verify_multiple_knowledge_dlog(
                       &base,
                       &[point1, point2, point3,
                           point4, point5, point6, point7],
                       &proof));
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
        let c1 = pedersen_bases.commit(value1, bf1);
        let c2 = pedersen_bases.commit(value2, bf2);

        let proof = dlog_based_prove_commitment_eq(
            &mut csprng,
            &pc_gens,
            &c1,
            &c2,
            &bf1,
            &bf2);

        assert_eq!(false, dlog_based_verify_commitment_eq(&pc_gens,
                                                          &c1,
                                                          &c2,
                                                          &proof));

        let c3 = pedersen_bases.commit(value1, bf2);
        let proof = dlog_based_prove_commitment_eq(
            &mut csprng,
            &pc_gens,
            &c1,
            &c3,
            &bf1,
            &bf2);

        assert_eq!(true, dlog_based_verify_commitment_eq(&pc_gens,
                                                         &c1,
                                                         &c3,
                                                         &proof));
    }

}