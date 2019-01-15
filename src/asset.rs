use blake2::VarBlake2b;
use blake2::digest::{Input, VariableOutput};
use crate::constants::HASH_256_BYTE_LENGTH;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

#[derive(Serialize, Deserialize, Debug)]
pub struct Asset {
    id: String,
    asset_digest: [u8;HASH_256_BYTE_LENGTH],
}

impl Asset {
    pub fn new(asset_id: &str) -> Asset {
        let mut hasher = VarBlake2b::new(HASH_256_BYTE_LENGTH).unwrap();
        hasher.input(asset_id);
        let res: Vec<u8> = hasher.vec_result();

        let mut asset = Asset {
            id: String::from(asset_id),
            asset_digest: [0u8; HASH_256_BYTE_LENGTH],
        };

        asset.asset_digest.copy_from_slice(&res[..HASH_256_BYTE_LENGTH]);
        asset
    }
    pub fn prove_eq(blinding_factor1: Scalar, blinding_factor2: Scalar) -> Scalar{
        blinding_factor1 - blinding_factor2
    }

    pub fn verify_eq(commitment1: &RistrettoPoint, commitment2: &RistrettoPoint, proof: Scalar, h: &RistrettoPoint) -> bool {
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
        assert_eq!(a.asset_digest[..5], [73, 40, 33, 192, 98]); //first 5 bytes of Blake2[256](chase_usd)
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

        //assert_eq!(false, true);
    }
}

