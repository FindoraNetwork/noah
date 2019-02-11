use bulletproofs::PedersenGens;
use crate::errors::Error as ZeiError;
use crate::utils::u32_to_bigendian_u8array;
use rand::CryptoRng;
use rand::Rng;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use blake2::{Blake2b, Digest};
use curve25519_dalek::ristretto::RistrettoPoint;

use curve25519_dalek::traits::Identity;

fn compute_challenge(context: &Vec<&CompressedRistretto>) -> Scalar{
    /*! I compute zk challenges for Dlog based proof. The challenge is a hash of the
    current context of the proof*/
    let mut hasher = Blake2b::new();

    for point in context.iter(){
        hasher.input((*point).as_bytes());
    }

    Scalar::from_hash(hasher)
}

fn compute_sub_challenge(challenge: &Scalar, i: u32) -> Scalar{
    /*! I compute zk sub challenges for multiple Dlog based proofs.
    The sub-challenge is a hash of the challenge and the position i of the sub-challenge*/
    let mut hasher = Blake2b::new();

    hasher.input(challenge.as_bytes());
    hasher.input(u32_to_bigendian_u8array(i));

    Scalar::from_hash(hasher)
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct ChaumPedersenCommitmentEqProof {
    c3: CompressedRistretto,
    c4: CompressedRistretto,
    z1: Scalar,
    z2: Scalar,
    z3: Scalar,
}

pub fn chaum_pedersen_prove_eq<R: CryptoRng + Rng>(
    prng: &mut R,
    pedersen_gens: &PedersenGens,
    value: &Scalar,
    commitment1: &CompressedRistretto,
    commitment2: &CompressedRistretto,
    blinding_factor1: &Scalar,
    blinding_factor2: &Scalar) -> ChaumPedersenCommitmentEqProof
{
    //let C1 = pedersen(a, r1) = commitment1
    //let C2 = pedersen(a, r2) = commitment2
    //Sample random scalars r3, r4 and r5
    //compute new commitments on C3 = pedersen(r3,r4) and C4 = (r3,r5)
    //compute challenge c = HASH(C1,C2,C3,C4)
    //compute response z1 = cm + r3, z2 = cr1 + r4, z3 = cr2 + r5
    //output proof = C1,C2,z1,z2,z3

    let r1 = blinding_factor1;
    let r2 = blinding_factor2;
    let r3 = Scalar::random(prng);
    let r4 = Scalar::random(prng);
    let r5 = Scalar::random(prng);

    let c3 = pedersen_gens.commit(r3, r4).compress();
    let c4 = pedersen_gens.commit(r3, r5).compress();

    let c = compute_challenge(
        &vec![commitment1, commitment2, &c3, &c4]);

    let z1 = c*value + r3;
    let z2 = c*r1 + r4;
    let z3 = c*r2 + r5;

    ChaumPedersenCommitmentEqProof{
        c3,c4,z1,z2,z3
    }
}

fn get_fake_zero_commitment() -> CompressedRistretto {
    RistrettoPoint::identity().compress()
}

fn get_fake_zero_commitment_blinding() -> Scalar {
    Scalar::from(0u8)
}

pub fn chaum_pedersen_eq_verify(
    pc_gens: &PedersenGens,
    c1: &CompressedRistretto, c2: &CompressedRistretto,
    proof:&ChaumPedersenCommitmentEqProof) -> Result<bool, ZeiError> {

    let c1_d = c1.decompress()?;
    let c2_d = c2.decompress()?;
    let c3_d = proof.c3.decompress()?;
    let c4_d = proof.c4.decompress()?;
    let z1 = proof.z1;
    let z2 = proof.z2;
    let z3 = proof.z3;
    let g = &pc_gens.B;
    let h = &pc_gens.B_blinding;

    let c = compute_challenge(&vec![c1, c2, &proof.c3, &proof.c4]);

    let mut vrfy_ok = c3_d + c*c1_d == z1*g + z2*h;
    vrfy_ok = vrfy_ok && c4_d + c*c2_d == z1*g + z3*h;
    Ok(vrfy_ok)

}

pub fn chaum_pedersen_prove_multiple_eq<R: CryptoRng +  Rng>(
    prng: &mut R,
    pedersen_gens: &PedersenGens,
    commitments: &Vec<&CompressedRistretto>,
    blinding_factors: Vec<&Scalar>) -> ChaumPedersenCommitmentEqProof
{
    /*! I produce a proof that all commitments are to the same value.
     *
    */
    let k = compute_challenge(&commitments);
    let mut d = RistrettoPoint::identity();
    let mut z = Scalar::from(0u8);
    let c1 = commitments.get(0).unwrap();
    let c1_decompressed = (*c1).decompress().unwrap();
    let r1 = blinding_factors.get(0).unwrap();
    for i in 1..commitments.len(){
        let ci = commitments.get(i).unwrap();
        let ai = compute_sub_challenge(&k, i as u32);
        let ci_decompressed = ci.decompress().unwrap();
        let di = ai * (c1_decompressed - ci_decompressed);
        let ri = blinding_factors.get(i).unwrap();
        let zi = ai * (*r1 - *ri);
        d = d + di;
        z = z + zi;
    }


    //TODO can we produce proof to zero commitment in a more direct way?
    //produce fake commitment to 0 for chaum pedersen commitment
    let proof = chaum_pedersen_prove_eq(prng,
                                        pedersen_gens,
                                        &Scalar::from(0u8),
                                        &d.compress(),
                                        &get_fake_zero_commitment(),
                                        &z,
                                        &get_fake_zero_commitment_blinding());
    proof
}

pub fn chaum_pedersen_verify_multiple_eq(
    pedersen_gens: &PedersenGens,
    commitments: &Vec<&CompressedRistretto>,
    proof: &ChaumPedersenCommitmentEqProof) -> Result<bool, ZeiError>
{
    /*! I produce a proof that all commitments are to the same value.
     *
    */
    let k = compute_challenge(&commitments);
    let mut d = RistrettoPoint::identity();
    let c1 = commitments.get(0)?;
    let c1_decompressed = c1.decompress()?;
    for i in 1..commitments.len(){
        let ci = commitments.get(i)?;
        let ai = compute_sub_challenge(&k, i as u32);
        let ci_decompressed = ci.decompress()?;
        let di = ai * (c1_decompressed - ci_decompressed);
        d = d + di;
    }


    //TODO can we produce proof to zero commitment in a more direct way?
    //produce fake commitment to 0 for chaum pedersen commitment
    let vrfy_ok = chaum_pedersen_eq_verify(
        pedersen_gens,
        &d.compress(),
        &get_fake_zero_commitment(),
        proof,
    )?;

    Ok(vrfy_ok)
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

pub fn prove_commitment_eq<R: CryptoRng + Rng>(
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

pub fn verify_eq(
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
    pub fn test_equality_asset_commitment() {
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

        let proof = prove_commitment_eq(
            &mut csprng,
            &pc_gens,
            &c1,
            &c2,
            &bf1,
            &bf2).unwrap();

        assert_eq!(false, verify_eq(&pc_gens,
                                           &c1,
                                           &c2,
                                           &proof).unwrap());

        let c3 = pedersen_bases.commit(value1, bf2).compress();
        let proof = prove_commitment_eq(
            &mut csprng,
            &pc_gens,
            &c1,
            &c3,
            &bf1,
            &bf2).unwrap();

        assert_eq!(true, verify_eq(&pc_gens,
                                          &c1,
                                          &c3,
                                          &proof).unwrap());
    }

    #[test]
    pub fn test_chaum_perdersen_equality_commitment() {
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

        let proof = chaum_pedersen_prove_eq(
            &mut csprng,
            &pc_gens,
            &value1,
            &c1,
            &c2,
            &bf1,
            &bf2);

        assert_eq!(false, chaum_pedersen_eq_verify(
            &pc_gens,
            &c1,
            &c2,
            &proof).unwrap());

        let proof = chaum_pedersen_prove_eq(
            &mut csprng,
            &pc_gens,
            &value2,
            &c1,
            &c2,
            &bf1,
            &bf2);

        assert_eq!(false, chaum_pedersen_eq_verify(&pc_gens,
                                                &c1,
                                                &c2,
                                                &proof).unwrap());


        let c3 = pedersen_bases.commit(value1, bf2).compress();
        let proof = chaum_pedersen_prove_eq(
            &mut csprng,
            &pc_gens,
            &value1,
            &c1,
            &c3,
            &bf1,
            &bf2);

        assert_eq!(true, chaum_pedersen_eq_verify(
            &pc_gens,
            &c1,
            &c3,
            &proof).unwrap());
    }

    #[test]
    fn test_chaum_perdersen_multiple_eq_proof(){
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();
        let value1 = Scalar::from(16u8);
        let value2 = Scalar::from(32u8);
        let bf1 = Scalar::from(10u8);
        let bf2 = Scalar::from(100u8);
        let bf3 = Scalar::from(1000u32);
        let pedersen_bases = PedersenGens::default();
        let c1 = pedersen_bases.commit(value1, bf1).compress();
        let c2 = pedersen_bases.commit(value2, bf2).compress();
        let c3 = pedersen_bases.commit(value1, bf3).compress();

        let com_vec = vec![&c1,&c2,&c3];
        let blind_vec = vec![&bf1,&bf2,&bf3];

        let proof = chaum_pedersen_prove_multiple_eq(
            &mut csprng,
            &pc_gens,
            &com_vec,
            blind_vec);

        assert_eq!(false, chaum_pedersen_verify_multiple_eq(
            &pc_gens,
            &com_vec,
            &proof).unwrap());

        let c1 = pedersen_bases.commit(value1, bf1).compress();
        let c2 = pedersen_bases.commit(value1, bf2).compress();
        let c3 = pedersen_bases.commit(value1, bf3).compress();

        let com_vec = vec![&c1,&c2,&c3];
        let blind_vec = vec![&bf1,&bf2,&bf3];

        let proof = chaum_pedersen_prove_multiple_eq(
            &mut csprng,
            &pc_gens,
            &com_vec,
            blind_vec);

        assert_eq!(true, chaum_pedersen_verify_multiple_eq(
            &pc_gens,
            &com_vec,
            &proof).unwrap());


    }

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

}
