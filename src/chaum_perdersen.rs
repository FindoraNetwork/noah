use bulletproofs::PedersenGens;
use crate::errors::Error as ZeiError;
use rand::CryptoRng;
use rand::Rng;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use blake2::{Blake2b, Digest};

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

    let c = chaum_perdersen_compute_eq_challenge(
        [&commitment1, &commitment2,
            &c3, &c4]);

    let z1 = c*value + r3;
    let z2 = c*r1 + r4;
    let z3 = c*r2 + r5;

    ChaumPedersenCommitmentEqProof{
        c3,c4,z1,z2,z3
    }
}

fn chaum_perdersen_compute_eq_challenge(commitments: [&CompressedRistretto;4]) -> Scalar{
    let mut hasher = Blake2b::new();
    hasher.input(commitments[0].as_bytes());
    hasher.input(commitments[1].as_bytes());
    hasher.input(commitments[2].as_bytes());
    hasher.input(commitments[3].as_bytes());
    Scalar::from_hash(hasher)
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

    let c = chaum_perdersen_compute_eq_challenge(
        [c1, c2, &proof.c3, &proof.c4]);

    let mut vrfy_ok = c3_d + c*c1_d == z1*g + z2*h;
    vrfy_ok = vrfy_ok && c4_d + c*c2_d == z1*g + z3*h;
    Ok(vrfy_ok)

}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct CommitmentEqProof {
    pub commitment: CompressedRistretto,
    pub response: Scalar,
}

pub fn prove_eq<R: CryptoRng + Rng>(
    prng: &mut R,
    pedersen_gens: &PedersenGens,
    source_asset_commitment: &CompressedRistretto,
    destination_asset_commitment: &CompressedRistretto,
    blinding_factor1: &Scalar,
    blinding_factor2: &Scalar) -> CommitmentEqProof
{
    let u = Scalar::random(prng);
    let proof_commitment = u*pedersen_gens.B_blinding;
    let compressed_propf_commitment = proof_commitment.compress();
    let proof_challenge = compute_challenge(
        pedersen_gens, source_asset_commitment, destination_asset_commitment,
        &compressed_propf_commitment);
    let proof_response = proof_challenge*(blinding_factor1-blinding_factor2) + u;
    CommitmentEqProof{
        commitment: compressed_propf_commitment,
        response: proof_response
    }
}

pub fn compute_challenge(
    pedersen_gens: &PedersenGens,
    source_asset_commitment: &CompressedRistretto,
    destination_asset_commitment: &CompressedRistretto,
    proof_commitment: &CompressedRistretto) -> Scalar
{
    let mut hasher = Blake2b::new();
    hasher.input(pedersen_gens.B.compress().as_bytes());
    hasher.input(pedersen_gens.B_blinding.compress().as_bytes());
    hasher.input(source_asset_commitment.as_bytes());
    hasher.input(destination_asset_commitment.as_bytes());
    hasher.input(proof_commitment.as_bytes());

    Scalar::from_hash(hasher)
}

pub fn verify_eq(
    pedersen_gens: &PedersenGens,
    source_asset_commitment: &CompressedRistretto,
    destination_asset_commitment: &CompressedRistretto,
    proof: &CommitmentEqProof) -> Result<bool, ZeiError>
{
    let proof_challenge = compute_challenge(
        pedersen_gens, source_asset_commitment,destination_asset_commitment,
        &proof.commitment);

    let src_com = source_asset_commitment.decompress()?;
    let dst_com = destination_asset_commitment.decompress()?;
    let pf_com = proof.commitment.decompress()?;

    Ok(proof.response * pedersen_gens.B_blinding == pf_com + proof_challenge*(src_com - dst_com))
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

        let proof = prove_eq(
            &mut csprng,
            &pc_gens,
            &c1,
            &c2,
            &bf1,
            &bf2);

        assert_eq!(false, verify_eq(&pc_gens,
                                           &c1,
                                           &c2,
                                           &proof).unwrap());

        let c3 = pedersen_bases.commit(value1, bf2).compress();
        let proof = prove_eq(
            &mut csprng,
            &pc_gens,
            &c1,
            &c3,
            &bf1,
            &bf2);

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
}
