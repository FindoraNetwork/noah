//Hidden Accounts

use curve25519_dalek::scalar::Scalar;
use crate::transaction::{TxInfo, Transaction};
use curve25519_dalek::ristretto::CompressedRistretto;
use crate::setup::PublicParams;
use schnorr::Keypair;
use schnorr::Signature;
use rand::CryptoRng;
use rand::Rng;
use crate::address;
use crate::address::Address;
use blake2::Blake2b;
use crate::asset::Asset;
use crate::errors::Error as ZeiError;

//Balance, currently as 32bits; TODO: make 64bits via (u32, u32)
pub type Balance = u32;


#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    pub counter: u128,
    pub balance: Balance,
    pub blinding: Scalar,
    pub commitment: CompressedRistretto,
    pub keys: Keypair,
    pub asset: Asset,
}

impl Account {

    pub fn new<R>(csprng: &mut R, asset_type: &str) -> Account
        where R: CryptoRng + Rng,
    {
        /*! I create a new hidden account with balance 0
         *
         */
        let pp = PublicParams::new();
        let balance: u32 = 0;
        let blinding = Scalar::from(0u32);
        let value = Scalar::from(balance);
        let commitment = pp.pc_gens.commit(value, blinding);

        Account {
            counter: 0,
            balance,
            blinding,
            commitment: commitment.compress(),
            keys: Keypair::generate(csprng),
            asset: Asset::new(asset_type)
        }
    }


    pub fn address(&self) -> Address {
        /*! I return an address from the account's public key
         *
         */
        address::enc(&self.keys.public)
    }

    pub fn send<R>(&mut self, csprng: &mut R, tx_info: &TxInfo, do_confidential_asset: bool)
        -> Result<Transaction, ZeiError>
        where R: CryptoRng + Rng,
    {
        /*! I create and send a transaction from this account. Transactions can hide the asset id
         *  if @do_confidential_asset is set to true.
         * If there are enough funds, account is updated. Otherwise an NotEnoughFunds error is
         * generated.
         */


        if tx_info.transfer_amount > self.balance {
            return Err(ZeiError::NotEnoughFunds);
        }

        self.balance -= tx_info.transfer_amount;
        let (newtx, updated_blind) = Transaction::new(csprng,
                                                      &tx_info,
                                                      self.balance,
                                                      self.blinding,
                                                      do_confidential_asset).unwrap();

        self.blinding = updated_blind;
        self.commitment = newtx.sender_updated_balance_commitment;
        self.counter += 1;

        Ok(newtx)
    }

    //take a transaction that this account has sent and apply to current state once network accepts
    // pub fn apply_tx(&mut self, tx: &Transaction) {

    // }

    pub fn receive(&mut self, tx: &Transaction) {
        /*! I receive a transaction to this account and update it accordingly
         *
         */

        let (recovered_amount, recovered_blind) = tx.recover_plaintext(&self.keys.secret);
        self.blinding += recovered_blind;
        //verify that commitments are correct that is sent
        //if receiver_verify(recovered_amount, recovered_blind, tx.receiver_new_commit, self.commitment) {} else {}
        self.commitment = tx.sender_updated_balance_commitment;
        self.blinding += recovered_blind;
        self.balance += recovered_amount;
    }

    pub fn sign<R>(&self, csprng: &mut R, msg: &[u8]) -> Signature
        where R: CryptoRng + Rng,
    {
        /*! I Sign a u8 slice data using this account secret key
         */
        self.keys.sign::<Blake2b, _>(csprng, &msg)
    }

    //Verify signature from
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    #[test]
    pub fn test_account_creation() {
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);
        let mut acc = Account::new(&mut csprng, "default currency");
        assert_eq!(acc.counter,0);
        assert_eq!(acc.balance,0);

        acc.balance=13;
        assert_eq!(acc.balance,13);
    }
}


