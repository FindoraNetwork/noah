//Elgamal Keypair

use crate::core::elgamal::{SecretKey, PublicKey};
use rand::OsRng;


#[derive(Serialize, Deserialize, Debug)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey
}

impl Keypair {
    //generate new pair
    pub fn new() -> Keypair {
        //sample randomness
        let mut csprng: OsRng = OsRng::new().unwrap();
        let sk = SecretKey::new(&mut csprng).unwrap();
        let pk = PublicKey::from_secret(&sk);

        Keypair {
            secret: sk,
            public: pk
        }
    }
}