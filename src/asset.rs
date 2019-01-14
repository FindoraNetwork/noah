use blake2::{VarBlake2b, Digest, Blake2b, Blake2s};
use blake2::digest::{Input, VariableOutput};
use crate::constants::HASH_256_BYTE_LENGTH;

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
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_asset_creation() {
        let asset_id = "chase_usd";
        let a: Asset = Asset::new(asset_id);
        assert_eq!(a.id, asset_id);
        assert_eq!(a.asset_digest[..5], [73, 40, 33, 192, 98]); //first 5 bytes of Blake2[256](chase_usd)
    }
}

