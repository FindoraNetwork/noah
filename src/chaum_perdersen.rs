use bulletproofs::PedersenGens;
use crate::errors::Error as ZeiError;
use rand::CryptoRng;
use rand::Rng;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use blake2::{Blake2b, Digest};

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
}
