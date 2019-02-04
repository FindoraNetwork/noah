use blake2::{Blake2b, Digest};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use bulletproofs::PedersenGens;
use rand::CryptoRng;
use rand::Rng;
use curve25519_dalek::ristretto::CompressedRistretto;

#[derive(Serialize, Deserialize, Debug)]
pub struct Asset {
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct CommitmentEqProof {
    pub commitment: CompressedRistretto,
    pub response: Scalar,
}

impl Asset {

    pub fn new(asset_id: &str) -> Asset {
        Asset { id: String::from(asset_id) }
    }

    pub fn compute_commitment<R: Rng + CryptoRng>(&self, rng: &mut R) -> (RistrettoPoint,Scalar) {
        let mut hash = Blake2b::new();
        hash.input(&self.id);

        let pd_bases = PedersenGens::default();
        let value = Scalar::from_hash(hash);
        let blind = Scalar::random(rng);
        (pd_bases.commit(value, blind), blind)

    }
    pub fn compute_ristretto_point_hash(&self) -> RistrettoPoint {
        let mut hash = Blake2b::new();
        hash.input(&self.id);

        RistrettoPoint::from_hash(hash)
    }
    pub fn compute_scalar_hash(&self) -> Scalar {
        let mut hash = Blake2b::new();
        hash.input(&self.id);

        Scalar::from_hash(hash)
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
        let proof_challenge = Asset::compute_challenge(
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
        proof: &CommitmentEqProof) -> bool
    {
        let proof_challenge = Asset::compute_challenge(
            pedersen_gens, source_asset_commitment,destination_asset_commitment,
            &proof.commitment);

        let src_com = source_asset_commitment.decompress().unwrap();
        let dst_com = destination_asset_commitment.decompress().unwrap();
        let pf_com = proof.commitment.decompress().unwrap();

        proof.response * pedersen_gens.B_blinding == pf_com + proof_challenge*(src_com - dst_com)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use bulletproofs::PedersenGens;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;


    #[test]
    pub fn test_asset_creation() {
        let asset_id = "chase_usd";
        let a: Asset = Asset::new(asset_id);
        assert_eq!(a.id, asset_id);
    }

    #[test]
    pub fn test_equality_asset_commitment(){
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();
        let value1 = Scalar::from(16u8);
        let value2 = Scalar::from(32u8);
        let bf1 = Scalar::from(10u8);
        let bf2 = Scalar::from(100u8);
        let pedersen_bases = PedersenGens::default();
        let c1 = pedersen_bases.commit(value1, bf1).compress();
        let c2 = pedersen_bases.commit(value2, bf2).compress();

        let proof = Asset::prove_eq(
            &mut csprng,
            &pc_gens,
            &c1,
            &c2,
            &bf1,
            &bf2);

        assert_eq!(false, Asset::verify_eq(&pc_gens,
                                           &c1,
                                           &c2,
                                           &proof));

        let c3 = pedersen_bases.commit(value1, bf2).compress();
        let proof = Asset::prove_eq(
            &mut csprng,
            &pc_gens,
            &c1,
            &c3,
            &bf1,
            &bf2);

        assert_eq!(true, Asset::verify_eq(&pc_gens,
                                          &c1,
                                          &c3 ,
                                          &proof));
    }
}

