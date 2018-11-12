//Hidden Accounts

use curve25519_dalek::scalar::Scalar;
use crate::core::keypair::Keypair;
use crate::core::transaction::{CreateTx, Transaction, reciever_verify};
use rand::OsRng;
use crate::core::elgamal::{SecretKey, PublicKey};
use curve25519_dalek::ristretto::CompressedRistretto;
use crate::core::setup::PublicParams;


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
    pub keys: Keypair,
}

impl Account {
    //initiate a new hidden account 
    pub fn new() -> Account {
        let pp = PublicParams::new();
        Account {
            counter: 0,
            balance: 0,
            opening: Scalar::from(0u32),
            //initial commitment is to 0 for balance and blind
            commitment: pp.pc_gens.commit(Scalar::from(0u32), Scalar::from(0u32)).compress(),
            keys: Keypair::new(),
        }
    }

    //helper to get public key aka. address
    pub fn address(&self) -> PublicKey {
        self.keys.public.clone()
    }

    //send a transaction using this account
    //this updates the accounts info as the transaction has been accepted by the network 
    pub fn send(&mut self, tx_meta: &CreateTx) -> Transaction {
        //update our balance
        //TODO: CHECK IF BALANCE IS ENOUGH
        self.balance -= tx.transfer_amount;

        //generate our transaction
        let (tx, updated_blind) = Transaction::new(&tx_meta.receiver, tx_meta.transfer_amount, self.balance, self.opening, tx_meta.receiver_commit.decompress().unwrap());
        //update our account blinding
        self.opening = updated_blind;
        //update our commitment
        self.commitment = tx.sender_updated_balance_commitment;     
        //increment counter
        self.counter += 1;
        //return our tx
        return tx;
    }
    
    //take a transaction that this account has sent and apply to current state once network accepts
    // pub fn apply_tx(&mut self, tx: &Transaction) {

    // }

    //once a transaction has been sent to us we need to apply it to our account
    pub fn recieve(&mut self, tx: &Transaction) {
        //unlock the box that was sent to us
        //this gets us the amount and new blind
        let (recoverd_amount, recoverd_blind) = tx.recover_plaintext(&self.keys.secret);
        //update our account opening
        self.opening = self.opening + recoverd_blind;
        //update our account commitment
        //veriy that commitments are correct that is sent
        //if reciever_verify(recoverd_amount, recoverd_blind, tx.receiver_new_commit, self.commitment) {} else {}
        
        self.commitment = tx.sender_updated_balance_commitment;

        //update our account opening
        self.opening = self.opening + recoverd_blind;

    }
}



