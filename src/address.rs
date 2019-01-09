// Zei Network Address
// An account has an address that is it's encoded public key.

// Create an address:
//   1. Convert PublicKey to base58, it has built in checksum
//   2. Append 'ZEI_' prefix

// Get public key from Address
//  1. Remove 'ZEI_' prefix
//  2. Decode from base58

use blake2::VarBlake2b;
use blake2::digest::{Input, VariableOutput};

use crate::utils::{from_base58, to_base58};


use schnorr::PublicKey;

//Account Address is just its encoded public key
pub type Address = String;


/// Encode a Given Publickey to Zei Address
pub fn enc(pk: &PublicKey) -> Address {
    let data = &pk.to_bytes();
    let mut data = data.to_vec();
    let mut hasher = VarBlake2b::new(32).unwrap();
    hasher.input(&data);
    let hash = hasher.vec_result();
    data.extend(&hash[0..4]);
    let addr: String = to_base58(&data[..]);
    let zei_str: String = "ZEI_".to_string();
    zei_str + &addr
}


/// Decode a Given Zei Address to Publickey
pub fn dec(zei_addr: &str) -> PublicKey {
    let addr = &zei_addr[4..];
    let decoded = match from_base58(addr){
        Ok(decoded) => decoded,
        Err(e) => panic!("ZEI address not in base58 format"),
    };

    let hash_start = decoded.len() - 4;
    let mut hasher = VarBlake2b::new(32).unwrap();
    hasher.input(&decoded[..hash_start]);
    let hash = hasher.vec_result();
    
    if hash[0..4] != decoded[hash_start..] {
        panic!("Bad address: checksum failed");
    }
    
    PublicKey::from_bytes(&decoded[..hash_start]).unwrap()

}


#[cfg(test)]
mod test {
    use super::*;
    use rand::ChaChaRng;
    use rand::SeedableRng;
    use schnorr::Keypair;
    use blake2::VarBlake2b;
    use blake2::digest::{Input, VariableOutput};


    #[test]
    fn test_address_encoding() {
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let enc = enc(&keypair.public);
        let dec = dec(&enc);
        assert_eq!(dec, keypair.public);
    }

    #[test]
    fn test_base58(){
        let data = vec![1,2,3];
        let base58str = to_base58(&data);
        assert_eq!(data, from_base58(&base58str[..]).unwrap());
    }
}

