use blake2::{Blake2b, Digest};
use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
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
    pub fn compute_scalar_hash(&self) -> Scalar {
        let mut hash = Blake2b::new();
        hash.input(&self.id);

        Scalar::from_hash(hash)
    }

}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_asset_creation() {
        let asset_id = "chase_usd";
        let a: Asset = Asset::new(asset_id);
        assert_eq!(a.id, asset_id);
    }
}

