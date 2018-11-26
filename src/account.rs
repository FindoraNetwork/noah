//Hidden Accounts

use curve25519_dalek::scalar::Scalar;
use crate::transaction::{CreateTx, Transaction, reciever_verify};
use curve25519_dalek::ristretto::CompressedRistretto;
use crate::setup::PublicParams;
use schnorr::PublicKey;
use schnorr::SecretKey;
use schnorr::Keypair;
use schnorr::Signature;
use rand::CryptoRng;
use rand::Rng;
use crate::address;
use crate::address::Address;
use blake2::Blake2b;

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
    pub fn new<R>(csprng: &mut R) -> Account
        where R: CryptoRng + Rng,
    {
        let pp = PublicParams::new();
        //let inital_balance: u32 = 1_000_000_000;
        let inital_balance: u32 = 0;

        Account {
            counter: 0,
            balance: inital_balance,
            opening: Scalar::from(0u32),
            //initial commitment is to 0 for balance and blind
            commitment: pp.pc_gens.commit(Scalar::from(inital_balance), Scalar::from(0u32)).compress(),
            keys: Keypair::generate(csprng)
        }
    }

    //helper to get public key aka. address
    pub fn address(&self) -> Address {
        address::enc(&self.keys.public)
    }

    //send a transaction using this account
    //this updates the accounts info as the transaction has been accepted by the network
    pub fn send<R>(&mut self, csprng: &mut R, tx_meta: &CreateTx) -> Transaction
        where R: CryptoRng + Rng,
    {
        //update our balance
        //TODO: CHECK IF BALANCE IS ENOUGH
        self.balance -= tx_meta.transfer_amount;

        //generate our transaction
        let (newtx, updated_blind) = Transaction::new(csprng, &tx_meta.receiver, tx_meta.transfer_amount, self.balance, self.opening, tx_meta.receiver_commit.decompress().unwrap());
        //update our account blinding
        self.opening = updated_blind;
        //update our commitment
        self.commitment = newtx.sender_updated_balance_commitment;
        //increment counter
        self.counter += 1;
        //return our tx
        return newtx;
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

        //update our balance
        self.balance += recoverd_amount;

    }

    //Create a signature from this account on arbitary data
    pub fn sign<R>(&self, csprng: &mut R, msg: &[u8]) -> Signature
        where R: CryptoRng + Rng,
    {
        self.keys.sign::<Blake2b, _>(csprng, &msg)
    }

    //Veriy signature from
}



