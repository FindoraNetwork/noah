//Hidden Accounts

use crate::transaction::{TxParams, Transaction};
use crate::setup::PublicParams;
use curve25519_dalek::scalar::Scalar;

use curve25519_dalek::ristretto::CompressedRistretto;

use schnorr::{Keypair, PublicKey, Signature};
use rand::CryptoRng;
use rand::Rng;
use crate::address;
use crate::address::Address;
use blake2::Blake2b;
use crate::errors::Error as ZeiError;
use std::collections::HashMap;
use curve25519_dalek::ristretto::RistrettoPoint;
use crate::serialization;
use crate::setup::Balance;
use crate::utils::compute_str_commitment;
use crate::utils::compute_str_ristretto_point_hash;
use crate::utils::compute_str_scalar_hash;


#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct AssetBalance {
    pub tx_counter: u128,
    pub balance: Balance,
    #[serde(with = "serialization::compressed_ristretto")]
    pub balance_commitment: CompressedRistretto,
    #[serde(with = "serialization::scalar")]
    pub balance_blinding: Scalar,
    pub asset_type: String,
    pub confidential_asset: bool,
    //if confidential_asset is false, this is just a hash of asset_info
    #[serde(with = "serialization::compressed_ristretto")]
    pub asset_commitment: CompressedRistretto,
    #[serde(with = "serialization::scalar")]
    pub asset_blinding: Scalar, //0 if confidential_asset is false
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    pub tx_counter: u128,
    #[serde(with = "serialization::keypair")]
    pub keys: Keypair,
    pub balances: HashMap<String, AssetBalance>,
}

impl PartialEq for Account{
    fn eq(&self, other: &Account) -> bool {
        self.balances == other.balances &&
            self.tx_counter == other.tx_counter &&
            self.keys.to_bytes()[..] == other.keys.to_bytes()[..]

    }
}

impl Eq for Account {}

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

    pub fn add_asset<R>(&mut self, csprng: &mut R, asset_id: &str, confidential_asset: bool, starting_bal: Balance)
        where R: CryptoRng + Rng,
    {
        /*!I add an asset with 0 balance to this account
         *
         */
        let asset_info = String::from(asset_id);
        let pp = PublicParams::new(2);
        let balance  = starting_bal;
        let balance_blinding = Scalar::from(0u32);
        let value = Scalar::from(balance);
        let asset_commitment: RistrettoPoint;
        let asset_blinding: Scalar;

        if confidential_asset {
            let (a_comm, a_blind) = compute_str_commitment(csprng, asset_id);
            asset_commitment = a_comm;
            asset_blinding = a_blind;
        }
        else {
            asset_commitment = compute_str_ristretto_point_hash(asset_id);
            asset_blinding = Scalar::from(0u8);
        }
        let asset_commitment= asset_commitment.compress();
        let asset_balance = AssetBalance {
            tx_counter: 0,
            balance,
            balance_blinding,
            balance_commitment: pp.pc_gens.commit(value, balance_blinding).compress(),
            asset_type: asset_info,
            confidential_asset,
            asset_commitment,
            asset_blinding,
        };
        self.balances.insert(String::from(asset_id), asset_balance);
    }

    pub fn get_balance(&self, asset_id: &str) -> Balance {
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

    pub fn send<R>(&mut self, csprng: &mut R, tx_params: &TxParams, asset_id: &str)
                   -> Result<Transaction, ZeiError>
    where R: CryptoRng + Rng,
    {
        /*! I create and send a transaction from this account. Transactions can hide the asset id
         *  if @do_confidential_asset is set to true.
         * If there are enough funds, account is updated. Otherwise an NotEnoughFunds error is
         * generated.
         */

        let mut asset_balance = self.balances.get_mut(asset_id).unwrap();
        if tx_params.transfer_amount > asset_balance.balance {
            return Err(ZeiError::NotEnoughFunds);
        }

        asset_balance.balance -= tx_params.transfer_amount;
        let (newtx, tx_blind) = Transaction::new(
            csprng,
            &tx_params,
            asset_balance.balance,
            &asset_balance.balance_blinding,
            &compute_str_scalar_hash(&asset_balance.asset_type),
            &asset_balance.asset_blinding,
            &asset_balance.asset_commitment,
            asset_balance.confidential_asset).unwrap();

        asset_balance.balance_blinding -= tx_blind;
        asset_balance.balance_commitment = (asset_balance.balance_commitment.decompress().unwrap() - newtx.transaction_commitment.decompress().unwrap()).compress();
        self.tx_counter += 1;
        Ok(newtx)
    }

    pub fn apply_tx(&mut self,
                    tx: &Transaction,
                    amount: Balance,
                    asset_type: &str,
                    tx_blinding: &Scalar) -> Result<(),ZeiError>{
        /*! I should be called once the network has accepted a transaction issued by this account
         * I update the current status of this account.
         */
        let mut asset_balance = self.balances.get_mut(asset_type)?;
        let old_balance_com = asset_balance.balance_commitment.decompress()?;
        let tx_commitment = tx.transaction_commitment.decompress()?;
        let new_balance_commitment = old_balance_com - tx_commitment;

        asset_balance.balance -= amount;
        asset_balance.balance_commitment = new_balance_commitment.compress();
        asset_balance.balance_blinding -= tx_blinding;
        self.tx_counter += 1;
        asset_balance.tx_counter += 1;
        Ok(())
    }

    pub fn receive(&mut self, tx: &Transaction) -> bool{
        /*! I receive a transaction to this account and update it accordingly
         *
         */
        let params = PublicParams::new(2);
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

        let derived_tx_commitment = params.pc_gens.commit(Scalar::from(recovered_amount), recovered_blind);
        if derived_tx_commitment.compress() != tx.transaction_commitment {
            return false;
        }

        let new_balance_commitment = asset_balance.balance_commitment.decompress().unwrap() -
            tx.transaction_commitment.decompress().unwrap();



        asset_balance.balance_commitment = new_balance_commitment.compress();
        asset_balance.balance_blinding += recovered_blind;
        asset_balance.balance += recovered_amount;
        true
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
    use bulletproofs::PedersenGens;

    #[test]
    pub fn test_account_creation() {
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);
        let mut acc = Account::new(&mut csprng);
        let asset_id = "default currency";
        let starting_bal = 50;
        acc.add_asset(&mut csprng, asset_id, false, 50);
        assert_eq!(acc.tx_counter, 0);
        assert_eq!(acc.get_balance(asset_id),starting_bal);
    }

    #[test]
    pub fn test_account_interactions() {
        let starting_bal = 50;
        let mut csprng1: ChaChaRng;
        csprng1 = ChaChaRng::from_seed([0u8; 32]);
        let mut csprng2: ChaChaRng;
        csprng2 = ChaChaRng::from_seed([0u8; 32]);
        let mut sender = Account::new(&mut csprng1);
        let mut rec = Account::new(&mut csprng2);
        let mut csprng3: ChaChaRng;
        csprng3 = ChaChaRng::from_seed([0u8; 32]);
        let asset_id = "example_asset";
        sender.add_asset(&mut csprng3, &asset_id, true, starting_bal);
        rec.add_asset(&mut csprng3, &asset_id, true, starting_bal);
        let tx = TxParams{
            receiver_pk: rec.keys.public,
            receiver_asset_commitment: rec.balances.get(asset_id).unwrap().asset_commitment,
            receiver_asset_opening: rec.balances.get(asset_id).unwrap().asset_blinding,
            transfer_amount: 10,
        };
        let mut csprng4: ChaChaRng;
        csprng4 = ChaChaRng::from_seed([0u8; 32]);
        let tx = sender.send(&mut csprng4, &tx, &asset_id).unwrap();
        rec.receive(&tx);
    }

    #[test]
    pub fn test_account_apply_tx() {
        let starting_bal = 8*1000*1000*1000*1000;
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);
        let transfer_amount = 5*1000*1000*1000*1000;
        let mut sender = Account::new(&mut csprng);
        let mut rec = Account::new(&mut csprng);
        let asset_id = "example_asset";
        sender.add_asset(&mut csprng, &asset_id, true, starting_bal);
        rec.add_asset(&mut csprng, &asset_id, true, starting_bal);
        let tx_params = TxParams{
            receiver_pk: rec.keys.public,
            receiver_asset_commitment: rec.balances.get(asset_id).unwrap().asset_commitment,
            receiver_asset_opening: rec.balances.get(asset_id).unwrap().asset_blinding,
            transfer_amount,
        };
        let asset = compute_str_scalar_hash(&sender.balances[asset_id].asset_type);
        let account_balance = sender.balances[asset_id].balance;
        let account_blind = &sender.balances[asset_id].balance_blinding;
        let sender_asset_opening = &sender.balances[asset_id].asset_blinding;
        let sender_asset_commitment = &sender.balances[asset_id].asset_commitment;
        let (tx,tx_blind) = Transaction::new(
            &mut csprng, &tx_params, account_balance, account_blind, &asset, sender_asset_opening,
        sender_asset_commitment, true).unwrap();
        let old_account_blind = account_blind.clone();

        sender.apply_tx(&tx,transfer_amount,asset_id,&tx_blind).unwrap();

        let expected_new_balance = starting_bal - transfer_amount;
        let new_balance = sender.balances[asset_id].balance;
        assert_eq!(expected_new_balance, new_balance);

        let new_blinding = sender.balances[asset_id].balance_blinding;
        assert_eq!(old_account_blind - tx_blind, new_blinding);

        let pc_gens = PedersenGens::default();
        let com = pc_gens.commit(Scalar::from(new_balance), new_blinding).compress();
        assert_eq!(sender.balances[asset_id].balance_commitment, com);
    }

    #[test]
    pub fn test_account_ser() {
        let mut csprng1 = ChaChaRng::from_seed([0u8; 32]);
        let mut csprng2 = ChaChaRng::from_seed([0u8; 32]);
        let mut acc_old = Account::new(&mut csprng1);
        let asset_id = "default currency";
        acc_old.add_asset(&mut csprng1, asset_id, false, 50);
        acc_old.add_asset(&mut csprng1, "another currency", true, 50);

        let mut acc = Account::new(&mut csprng2);
        acc.add_asset(&mut csprng2, asset_id, false, 50);
        acc.add_asset(&mut csprng2, "another currency", true, 50);

        let json = serde_json::to_string(&acc_old).unwrap();

        let acc_deserialized: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(acc_deserialized, acc);

        let acc = Account::new(&mut ChaChaRng::from_seed([0u8; 32]));
        let json = serde_json::to_string(&acc).unwrap();

        let acc_deserialized: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(acc_deserialized, acc);
    }
}
