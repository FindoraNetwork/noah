//Hidden Accounts

use curve25519_dalek::scalar::Scalar;
use crate::transaction::{TxInfo, Transaction};
use curve25519_dalek::ristretto::CompressedRistretto;
use crate::setup::PublicParams;
use schnorr::{Keypair, PublicKey, Signature};
use rand::CryptoRng;
use rand::Rng;
use crate::address;
use crate::address::Address;
use blake2::Blake2b;
use crate::asset::Asset;
use crate::errors::Error as ZeiError;
use std::collections::HashMap;
use curve25519_dalek::ristretto::RistrettoPoint;

//Balance, currently as 32bits; TODO: make 64bits via (u32, u32)
pub type Balance = u32;

#[derive(Serialize, Deserialize, Debug)]
pub struct AssetBalance {
    pub tx_counter: u128,
    pub balance: Balance,
    pub balance_commitment: CompressedRistretto,
    pub balance_blinding: Scalar,
    pub asset_info: Asset,
    pub confidential_asset: bool,
    //if confidential_asset is false, this is just a hash of asset_info
    pub asset_commitment: CompressedRistretto,
    pub asset_blinding: Scalar, //0 if confidential_asset is false
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    pub tx_counter: u128,
    pub keys: Keypair,
    pub balances: HashMap<String, AssetBalance>,
}

impl Account {

    pub fn new<R>(csprng: &mut R) -> Account
        where R: CryptoRng + Rng,
    {
        /*! I create a new hidden empty account
         *
         */
        Account {
            tx_counter: 0,
            keys: Keypair::generate(csprng),
            balances: HashMap::new(),
        }
    }

    pub fn add_asset<R>(&mut self, csprng: &mut R, asset_id: &str, confidential_asset: bool)
        where R: CryptoRng + Rng,
    {
        /*!I add an asset with 0 balance to this account
         *
         */
        let asset_info = Asset::new(asset_id);
        let pp = PublicParams::new();
        let balance: u32 = 0;
        let balance_blinding = Scalar::from(0u32);
        let value = Scalar::from(balance);
        let asset_commitment: RistrettoPoint;
        let asset_blinding: Scalar;

        if confidential_asset {
            let (a_comm, a_blind) = asset_info.compute_commitment(csprng);
            asset_commitment = a_comm;
            asset_blinding = a_blind;
        }
        else {
            asset_commitment = asset_info.compute_ristretto_point_hash();
            asset_blinding = Scalar::from(0u8);
        }
        let asset_commitment= asset_commitment.compress();
        let asset_balance = AssetBalance {
            tx_counter: 0,
            balance,
            balance_blinding,
            balance_commitment: pp.pc_gens.commit(value, balance_blinding).compress(),
            asset_info,
            confidential_asset,
            asset_commitment,
            asset_blinding,
        };

        self.balances.insert(String::from(asset_id), asset_balance);
    }

    pub fn get_balance(&self, asset_id: &str) -> u32 {
        self.balances.get(asset_id).unwrap().balance
    }

    pub fn get_asset_balance(&mut self, asset_id: &str) -> &mut AssetBalance {
        self.balances.get_mut(asset_id).unwrap()
    }

    pub fn get_public_key(&self) -> PublicKey {
        self.keys.public
    }


    pub fn address(&self) -> Address {
        /*! I return an address from the account's public key
         *
         */
        address::enc(&self.keys.public)
    }

    pub fn send<R>(&mut self, csprng: &mut R, tx_info: &TxInfo, asset_id: &str)
        -> Result<Transaction, ZeiError>
        where R: CryptoRng + Rng,
    {
        /*! I create and send a transaction from this account. Transactions can hide the asset id
         *  if @do_confidential_asset is set to true.
         * If there are enough funds, account is updated. Otherwise an NotEnoughFunds error is
         * generated.
         */

        let mut asset_balance = self.balances.get_mut(asset_id).unwrap();
        if tx_info.transfer_amount > asset_balance.balance {
            return Err(ZeiError::NotEnoughFunds);
        }

        asset_balance.balance -= tx_info.transfer_amount;
        let (newtx, updated_blind) = Transaction::new(csprng,
                                                      &tx_info,
                                                      asset_balance.balance,
                                                      asset_balance.balance_blinding,
                                                      asset_balance.confidential_asset).unwrap();

        asset_balance.balance_blinding = updated_blind;
        asset_balance.balance_commitment = newtx.sender_updated_balance_commitment;
        self.tx_counter += 1;
        Ok(newtx)
    }

    //take a transaction that this account has sent and apply to current state once network accepts
    // pub fn apply_tx(&mut self, tx: &Transaction) {

    // }

    pub fn receive(&mut self, tx: &Transaction) {
        /*! I receive a transaction to this account and update it accordingly
         *
         */

        let mut asset_id= String::from("");
        {
            for (a_id, asset_balance) in self.balances.iter() {
                if asset_balance.asset_commitment == tx.receiver_asset_commitment {
                    asset_id = a_id.clone();
                    break;
                }
            }
        }

        let mut asset_balance = self.balances.get_mut(&asset_id).unwrap();
        let (recovered_amount, recovered_blind) = tx.recover_plaintext(&self.keys.secret);
        //verify that commitments are correct that is sent
        //if receiver_verify(recovered_amount, recovered_blind, tx.receiver_new_commit, self.commitment) {} else {}
        asset_balance.balance_commitment = tx.sender_updated_balance_commitment;
        asset_balance.balance_blinding += recovered_blind;
        asset_balance.balance += recovered_amount;
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
        let mut acc = Account::new(&mut csprng);
        let asset_id = "default currency";
        acc.add_asset(&mut csprng, asset_id, false);
        assert_eq!(acc.tx_counter, 0);
        assert_eq!(acc.get_balance(asset_id),0);
    }
}


