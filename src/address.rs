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
use crate::errors::Error as ZeiError;
use crate::utils::{from_base58, to_base58};
use crate::keys::ZeiPublicKey;
use crate::serialization::ZeiFromToBytes;

//Account Address is just its encoded public key
pub type Address = String;


/// Encode a Given Publickey to Zei Address
pub fn enc(pk: &ZeiPublicKey) -> Address {
    let data = &mut pk.zei_to_bytes();
    let mut hasher = VarBlake2b::new(32).unwrap();
    hasher.input(&data);
    let hash = hasher.vec_result();
    data.extend(&hash[0..4]);
    let addr: String = to_base58(&data[..]);
    let zei_str: String = "ZEI_".to_string();
    zei_str + &addr
}


/// Decode a Given Zei Address to Publickey
pub fn dec(zei_addr: &str) -> Result<ZeiPublicKey, ZeiError> {
    let addr = &zei_addr[4..];
    let decoded = from_base58(addr)?;

    let hash_start = decoded.len() - 4;
    let mut hasher = VarBlake2b::new(32).unwrap();
    hasher.input(&decoded[..hash_start]);
    let hash = hasher.vec_result();
    
    if hash[0..4] != decoded[hash_start..] {
        return Err(ZeiError::BadBase58Format);
    }
    
    Ok(ZeiPublicKey::zei_from_bytes(&decoded[..hash_start]))

}


#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use crate::keys::ZeiKeyPair;


    #[test]
    fn test_address_encoding() {
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);
        let keypair = ZeiKeyPair::generate(&mut csprng);

        let enc = enc(keypair.get_pk_ref());
        let dec = dec(&enc).unwrap();
        assert_eq!(dec, *keypair.get_pk_ref());
    }

    #[test]
    fn test_base58(){
        let data = vec![1,2,3];
        let base58str = to_base58(&data);
        assert_eq!(data, from_base58(&base58str[..]).unwrap());
    }
}

