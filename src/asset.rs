use blake2::{Blake2b, Digest};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use bulletproofs::PedersenGens;
use rand::CryptoRng;
use rand::Rng;

#[derive(Serialize, Deserialize, Debug)]
pub struct Asset {
    pub id: String,
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
    pub fn prove_eq(blinding_factor1: Scalar, blinding_factor2: Scalar) -> Scalar{
        blinding_factor1 - blinding_factor2
    }

    pub fn verify_eq(commitment1: &RistrettoPoint,
                     commitment2: &RistrettoPoint,
                     proof: Scalar,
                     h: &RistrettoPoint) -> bool {
        if commitment1 - commitment2 == h * proof {
            return true;
        }
        false
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use bulletproofs::PedersenGens;

    #[test]
    pub fn test_asset_creation() {
        let asset_id = "chase_usd";
        let a: Asset = Asset::new(asset_id);
        assert_eq!(a.id, asset_id);
    }

    #[test]
    pub fn test_equality_asset_commitment(){
        let value1 = Scalar::from(16u8);
        let value2 = Scalar::from(32u8);
        let bf1 = Scalar::from(10u8);
        let bf2 = Scalar::from(100u8);
        let pedersen_bases = PedersenGens::default();
        let c1 = pedersen_bases.commit(value1, bf1);
        let c2 = pedersen_bases.commit(value2, bf2);

        let proof = Asset::prove_eq(bf1, bf2);
        assert_eq!(false, Asset::verify_eq(&c1,&c2, proof, &pedersen_bases.B_blinding));

        let c3 = pedersen_bases.commit(value1, bf2);
        let proof = Asset::prove_eq(bf1, bf2);
        assert_eq!(true, Asset::verify_eq(&c1,&c3, proof, &pedersen_bases.B_blinding));
    }
}

