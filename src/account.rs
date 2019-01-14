//Hidden Accounts

use curve25519_dalek::scalar::Scalar;
use crate::transaction::{CreateTx, Transaction};
use curve25519_dalek::ristretto::CompressedRistretto;
use crate::setup::PublicParams;
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
        //let initial_balance: u32 = 1_000_000_000;
        let initial_balance: u32 = 0;

        Account {
            counter: 0,
            balance: initial_balance,
            opening: Scalar::from(0u32),
            //initial commitment is to 0 for balance and blind
            commitment: pp.pc_gens.commit(Scalar::from(initial_balance), Scalar::from(0u32)).compress(),
            keys: Keypair::generate(csprng),
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
        let (newtx, updated_blind) = Transaction::new(csprng, &tx_meta.receiver, tx_meta.transfer_amount, self.balance, self.opening).unwrap();
        //update our account blinding
        self.opening = updated_blind;
        //update our commitment
        self.commitment = newtx.sender_updated_balance_commitment;
        //increment counter
        self.counter += 1;
        //return our tx
        newtx
    }

    //take a transaction that this account has sent and apply to current state once network accepts
    // pub fn apply_tx(&mut self, tx: &Transaction) {

    // }

    //once a transaction has been sent to us we need to apply it to our account
    pub fn receive(&mut self, tx: &Transaction) {
        //unlock the box that was sent to us
        //this gets us the amount and new blind
        let (recovered_amount, recovered_blind) = tx.recover_plaintext(&self.keys.secret);

        //update our account opening
        self.opening += recovered_blind;
        //update our account commitment
        //verify that commitments are correct that is sent
        //if receiver_verify(recovered_amount, recovered_blind, tx.receiver_new_commit, self.commitment) {} else {}
        self.commitment = tx.sender_updated_balance_commitment;

        //update our account opening
        self.opening += recovered_blind;

        //update our balance
        self.balance += recovered_amount;
    }

    //Create a signature from this account on arbitary data
    pub fn sign<R>(&self, csprng: &mut R, msg: &[u8]) -> Signature
        where R: CryptoRng + Rng,
    {
        self.keys.sign::<Blake2b, _>(csprng, &msg)
    }

    //Verify signature from
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::ChaChaRng;
    use rand::SeedableRng;
    #[test]
    pub fn test_account_creation() {
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);
        let mut acc = Account::new(&mut csprng);
        assert_eq!(acc.counter,0);
        assert_eq!(acc.balance,0);

        acc.balance=13;
        assert_eq!(acc.balance,13);
        let mut acc2 = Account::new(&mut csprng);

    }
}


