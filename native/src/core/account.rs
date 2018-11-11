//Hidden Accounts

use curve25519_dalek::scalar::Scalar;
use crate::core::keypair::Keypair;
use crate::core::transaction::{CreateTx, Transaction};
use rand::OsRng;
use crate::core::elgamal::{SecretKey, PublicKey};
use curve25519_dalek::ristretto::CompressedRistretto;
use bulletproofs::{PedersenGens};


//Balance, currently as 32bits; TODO: make 64bits via (u32, u32)
pub type Balance = u32;

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    //account tx count
    pub counter: u128,
    //Hidden
    pub balance: Balance,
    //opening from latest payment
    pub opening: Scalar,
    //commitment
    pub commitment: CompressedRistretto,
    //account keys
    pub keys: Keypair
    //public_params
}

impl Account {
    //initiate a new hidden account 
    pub fn new() -> Account {
        //def pederson from lib with Common Reference String
        let pc_gens = PedersenGens::default();


        Account {
            counter: 0,
            balance: 0,
            opening: Scalar::from(0u32),
            //initial commitment is to 0 for balance and blind
            commitment: pc_gens.commit(Scalar::from(0u32), Scalar::from(0u32)).compress(),
            keys: Keypair::new()
        }
    }

    //helper to get public key aka. address
    pub fn address(&self) -> PublicKey {
        self.keys.public.clone()
    }

    //update account state from a new balance and opening
    pub fn update_account(&mut self, amount: u32, opening: Scalar) {
        self.balance += amount;
        self.opening = opening;
    }

    //send a transaction using this account 
    pub fn send(&mut self, tx_meta: CreateTx) {
        //sample some randomness for the new opening 
        //TODO: Handle Errors better
        let mut csprng: OsRng = OsRng::new().unwrap();
        let new_opening = Scalar::random(&mut csprng);

        //update account balance
       // self.balance -= tx_meta.transfer_amount;



        //update our account opening
        self.opening = self.opening - new_opening;
        //increment counter
        self.counter += 1;
    }

    //once a transaction has been sent to us we need to apply it to our account
    pub fn recieve(&mut self, tx: Transaction) {

        //update balance


        //update our account opening
        //self.opening = self.opening + tx.opening;
    }
}



