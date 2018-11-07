//Elgamal via ristretto

use rand::Rng;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_TABLE};
use errors::ElgamalError;




/// The length of a curve25519 EdDSA `SecretKey`, in bytes.
pub const KEY_LENGTH: usize = 32;


//https://github.com/dalek-cryptography/x25519-dalek/blob/master/src/x25519.rs
/// "Decode" a scalar from a 32-byte array.
///
/// By "decode" here, what is really meant is applying key clamping by twiddling
/// some bits.
///
/// # Returns
///
/// A `Scalar`.
fn decode_scalar(scalar: &[u8; KEY_LENGTH]) -> Scalar {
    let mut s: [u8; 32] = scalar.clone();

    s[0]  &= 248;
    s[31] &= 127;
    s[31] |= 64;

    Scalar::from_bits(s)
}



//Secret Key, stored as a scalar
pub struct PrivateKey {
    //key as scalar
    pub scalar: Scalar
}

impl PrivateKey {

    //New Secret Key from given randomness generator
    pub fn new<T: Rng>(csprng: &mut T) -> Result<PrivateKey, ElgamalError> {
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
        Ok(PrivateKey {
            scalar: s
        })
    }

    //pub fn decrypt(){}

}

//Public Key 
pub struct PublicKey {
    pub point: RistrettoPoint
}


impl PublicKey {
    //new private key from given private key
    pub fn new(sk: &PrivateKey) -> PublicKey {
        PublicKey {
            //y = g^x where x = secret key
            point: (&sk.scalar * &RISTRETTO_BASEPOINT_TABLE)
        }
    }

    // pub fn encrypt(&self, m: &Scalar) -> (Scalar, Scalar) {
        
    // }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::OsRng;

    #[test]
    fn test_keys() {
        //get randomness hook
        let mut csprng: OsRng = OsRng::new().unwrap();
        //generate sk
        let sk = PrivateKey::new(&mut csprng).unwrap();
        //generate our pk
        let pk = PublicKey::new(sk);


    }

}