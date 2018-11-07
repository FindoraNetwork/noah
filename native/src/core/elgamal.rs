//Elgamal via ristretto

use rand::Rng;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use crate::core::errors::Error;
use crate::core::util::decode_scalar;


/// The length of a curve25519 EdDSA `SecretKey`, in bytes.
pub const KEY_LENGTH: usize = 32;


//Secret Key, stored as a scalar
#[derive(Serialize, Deserialize, Debug)]
pub struct SecretKey {
    //inner scalar
    pub inner: Scalar
}

impl SecretKey {

    //New Secret Key from given randomness generator
    pub fn new<T: Rng>(csprng: &mut T) -> Result<SecretKey, Error> {
        //temp var to hold generated randomness
        let mut bytes = [0u8; KEY_LENGTH];
        //fill me up
        csprng.fill_bytes(&mut bytes);
        //get bytes as scalar

        //TODO: CHECK THAT SECRET NUM IS ABOVE CERTAIN NUMBER
        let s = decode_scalar(&bytes);
        //ehhhhh
        //if s == 0 { return Err(ElgamalError::BadSecretError); }

        //consturct private key struct
        Ok(SecretKey {
            inner: s
        })
    }

    //returns underlying scalar point as bytes
    pub fn to_bytes(&self) -> [u8; KEY_LENGTH] { 
        self.inner.to_bytes() 
    }
    
    //returns reference to underlying scalar point as bytes
    pub fn as_bytes(&self) -> &[u8; KEY_LENGTH] { 
        self.inner.as_bytes() 
    }


}

//Public Key 
#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKey {
    //inner point
    pub inner: RistrettoPoint
}


impl PublicKey {

    //new private key from given private key
    pub fn from_secret(sk: &SecretKey) -> PublicKey {
        PublicKey {
            //y = g^x where x = secret key
            inner: (&sk.inner * &RISTRETTO_BASEPOINT_TABLE)
        }
    }

    //returns underlying curve point as bytes
    // pub fn to_bytes(&self) -> [u8; KEY_LENGTH] { 
    //     self.inner.compress().to_bytes() 
    // }
    
    // //returns reference to underlying curve point as bytes
    // pub fn as_bytes(&self) -> &[u8; KEY_LENGTH] { 
    //     self.inner.compress().as_bytes() 
    // }



}


#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::traits::Identity;

    #[test]
    fn test_keys() {
   
        //generate sk
        let sk = SecretKey {
            inner: Scalar::zero()
        };
        //generate our pk
        let pk = PublicKey::from_secret(&sk);
        
        assert_eq!(pk.inner, RistrettoPoint::identity());
    }

}