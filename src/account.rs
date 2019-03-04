//Hidden Accounts

use curve25519_dalek::scalar::Scalar;

use curve25519_dalek::ristretto::CompressedRistretto;

use crate::keys::ZeiPublicKey;
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
use bulletproofs::PedersenGens;
use crate::utxo_transaction::Tx;
use crate::utxo_transaction::TxAddressParams;
use crate::encryption::from_secret_key_to_scalar;
use crate::keys::ZeiKeyPair;
use crate::keys::ZeiSecretKey;
use crate::serialization::ZeiFromToBytes;
use crate::keys::ZEI_SECRET_KEY_LENGTH;
use crate::keys::ZeiSignature;

#[derive(Serialize, Deserialize, Debug)]
pub struct TxParams{
    /*
     * I am helper structure to send/receive the data for a transaction
     *
     */
    #[serde(with = "serialization::zei_obj_serde")]
    pub receiver_pk: ZeiPublicKey,
    #[serde(with = "serialization::zei_obj_serde")]
    pub receiver_asset_commitment: CompressedRistretto,
    #[serde(with = "serialization::zei_obj_serde")]
    pub receiver_asset_opening: Scalar,
    pub transfer_amount: Balance,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct AssetBalance {
    pub tx_counter: u128,
    pub balance: Balance,
    #[serde(with = "serialization::zei_obj_serde")]
    pub balance_commitment: CompressedRistretto,
    #[serde(with = "serialization::zei_obj_serde")]
    pub balance_blinding: Scalar,
    pub asset_type: String,
    pub confidential_asset: bool,
    //if confidential_asset is false, this is just a hash of asset_info
    #[serde(with = "serialization::zei_obj_serde")]
    pub asset_commitment: CompressedRistretto,
    #[serde(with = "serialization::zei_obj_serde")]
    pub asset_blinding: Scalar, //0 if confidential_asset is false
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    pub tx_counter: u128,
    #[serde(with = "serialization::zei_obj_serde")]
    pub keys: ZeiKeyPair,
    pub balances: HashMap<String, AssetBalance>,
}

impl PartialEq for Account{
    fn eq(&self, other: &Account) -> bool {
        self.balances == other.balances &&
            self.tx_counter == other.tx_counter &&
            self.keys.zei_to_bytes() == other.keys.zei_to_bytes()
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
            keys: ZeiKeyPair::generate(csprng),
            balances: HashMap::new(),
        }
    }

    pub fn add_asset<R>(&mut self, csprng: &mut R, asset_id: &str, confidential_asset: bool, starting_bal: Balance)
        where R: CryptoRng + Rng,
    {
        /*!I add an asset with 0 balance to this account
         *
         */
        let asset_type = String::from(asset_id);
        let pc_gens = PedersenGens::default();
        let balance  = starting_bal;
        let balance_blinding = Scalar::random(csprng);
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
            balance_commitment: pc_gens.commit(value, balance_blinding).compress(),
            asset_type: asset_type,
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

    pub fn get_public_key(&self) -> &ZeiPublicKey {
        self.keys.get_pk_ref()
    }

    /*
    pub fn get_public_key_as_hex(&self) -> String {

        hex::encode(&self.keys.public.as_bytes())
    }
    */

    pub fn get_secret_key(&self) -> &ZeiSecretKey {
        self.keys.get_sk_ref()
    }

    pub fn address(&self) -> Address {
        /*! I return an address from the account's public key
         *
         */
        address::enc(self.get_public_key())
    }

    pub fn send_and_update<R>(&mut self, csprng: &mut R, tx_params: &TxParams, asset_id: &str)
                   -> Result<Tx, ZeiError> where R: CryptoRng + Rng
    {

        let (tx, tx_blind) = self.send(csprng, tx_params, asset_id)?;
        self.sender_apply_tx(
            &tx, tx_params.transfer_amount, asset_id, &tx_blind)?;
        Ok(tx)
    }

    pub fn send<R>(&self, csprng: &mut R, tx_params: &TxParams, asset_id: &str)
                   -> Result<(Tx, Scalar), ZeiError>
    where R: CryptoRng + Rng,
    {
        /*! I create and send a transaction from this account. Transactions can hide the asset id
         *  if @do_confidential_asset is set to true.
         * If there are enough funds, account is updated. Otherwise an NotEnoughFunds error is
         * generated.
         */

        let asset_balance = self.balances.get(asset_id)?;
        if tx_params.transfer_amount > asset_balance.balance {
            return Err(ZeiError::NotEnoughFunds);
        }


        let secret_key_bytes = self.keys.get_sk_ref().zei_to_bytes();
        let input = TxAddressParams{
            amount: asset_balance.balance,
            amount_commitment: Some(asset_balance.balance_commitment),
            amount_blinding: Some(asset_balance.balance_blinding),
            asset_type: String::from(asset_id),
            asset_type_commitment: match asset_balance.confidential_asset{
                true => Some(asset_balance.asset_commitment),
                false => None,
            },
            asset_type_blinding: match asset_balance.confidential_asset{
                true => Some(asset_balance.asset_blinding),
                false => None,
            },
            public_key: self.keys.get_pk_ref().clone(),
            secret_key: Some(ZeiSecretKey::zei_from_bytes(&secret_key_bytes[..])),
        };

        let output = TxAddressParams{
            amount: tx_params.transfer_amount,
            amount_commitment: None,
            amount_blinding: None,
            asset_type: String::from(asset_id),
            asset_type_commitment: match asset_balance.confidential_asset{
                true => Some(tx_params.receiver_asset_commitment),
                false => None,
            },
            asset_type_blinding: match asset_balance.confidential_asset{
                true => Some(tx_params.receiver_asset_opening),
                false => None,
            },
            public_key: tx_params.receiver_pk,
            secret_key: None,
        };

        let (tx, tx_blind) = Tx::new(
            csprng,
            &[input],
            &[output],
            true,
            asset_balance.confidential_asset,
        )?;


        Ok( (tx, tx_blind.unwrap()[0]) )
    }

    pub fn sender_apply_tx(&mut self,
                    tx: &Tx,
                    amount: Balance,
                    asset_type: &str,
                    tx_blinding: &Scalar) -> Result<(),ZeiError>{
        /*! I should be called once the network has accepted a transaction issued by this account
         * I update the current status of this account.
         */
        let mut asset_balance = self.balances.get_mut(asset_type)?;
        let old_balance_com = asset_balance.balance_commitment.decompress()?;
        let tx_commitment = tx.body.output[0].public.amount_commitment?.decompress()?;
        let new_balance_commitment = old_balance_com - tx_commitment;

        asset_balance.balance -= amount;
        asset_balance.balance_commitment = new_balance_commitment.compress();
        asset_balance.balance_blinding -= tx_blinding;
        self.tx_counter += 1;
        asset_balance.tx_counter += 1;
        Ok(())
    }

    pub fn receiver_apply_tx(&mut self, tx: &Tx) -> bool{
        self.receive(tx, 0).unwrap()
    }
    pub fn receive(&mut self, tx: &Tx, out_index: usize) -> Result<bool, ZeiError>{
        /*! I receive a transaction to this account and update it accordingly
         *
         */
        let pc_gens = PedersenGens::default();
        let out_info = &tx.body.output[out_index];
        let mut asset_id = String::from("");
        if tx.body.confidential_asset {
            for (a_id, asset_balance) in self.balances.iter() {
                if asset_balance.asset_commitment == out_info.public.asset_type_commitment?{
                    asset_id = a_id.clone();
                    break;
                }
            }
        }
        else{
            asset_id = out_info.public.asset_type.as_ref()?.clone();
        }

        let mut asset_balance = self.balances.get_mut(&asset_id)?;
        let mut sk = [0u8; ZEI_SECRET_KEY_LENGTH];
        sk.copy_from_slice(self.keys.get_sk_ref().zei_to_bytes().as_slice());

        let (amount, amount_blind, _) =
            Tx::receiver_unlock_memo(
                out_info.lock_box.as_ref()?,
                &from_secret_key_to_scalar(&sk),
                true,
                tx.body.confidential_asset,
        )?;

        let blind = amount_blind?;
        let derived_tx_commitment = pc_gens.commit(
            Scalar::from(amount?), blind);

        let amount_commitment = out_info.public.amount_commitment?;
        if derived_tx_commitment.compress() != amount_commitment {
            return Ok(false);
        }

        let new_balance_commitment = asset_balance.balance_commitment.decompress()? +
            amount_commitment.decompress()?;

        asset_balance.balance_commitment = new_balance_commitment.compress();
        asset_balance.balance_blinding += blind;
        asset_balance.balance += amount?;
        Ok(true)
    }

    pub fn sign<R>(&self, csprng: &mut R, msg: &[u8]) -> ZeiSignature
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
        let starting_bal = 50;
        acc.add_asset(&mut csprng, asset_id, false, 50);
        assert_eq!(acc.tx_counter, 0);
        assert_eq!(acc.get_balance(asset_id),starting_bal);
    }

    #[test]
    pub fn test_account_interactions() {
        let starting_bal = 60;
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let mut sender = Account::new(&mut prng);
        let mut rec = Account::new(&mut prng);
        let asset_id = "example_asset";
        sender.add_asset(&mut prng, &asset_id, true, starting_bal);
        rec.add_asset(&mut prng, &asset_id, true, starting_bal);
        let tx = TxParams{
            receiver_pk: rec.keys.get_pk_ref().clone(),
            receiver_asset_commitment: rec.balances.get(asset_id).unwrap().asset_commitment,
            receiver_asset_opening: rec.balances.get(asset_id).unwrap().asset_blinding,
            transfer_amount: 10,
        };
        let tx = sender.send_and_update(&mut prng, &tx, &asset_id).unwrap();
        rec.receive(&tx, 0).unwrap();
    }

    #[test]
    pub fn test_account_apply_tx() {
        /*! I test that valid transactions are applied correctly to sender and receiver accounts */
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();
        let starting_bal = 8*1000*1000*1000*1000;
        let transfer_amount = 5*1000*1000*1000*1000;
        let mut sender = Account::new(&mut csprng);
        let mut rec = Account::new(&mut csprng);
        let asset_id = "example_asset";
        sender.add_asset(&mut csprng, &asset_id, true, starting_bal);
        rec.add_asset(&mut csprng, &asset_id, true, starting_bal);

        let tx_params = TxParams{
            receiver_pk: rec.keys.get_pk_ref().clone(),
            receiver_asset_commitment: rec.balances.get(asset_id).unwrap().asset_commitment,
            receiver_asset_opening: rec.balances.get(asset_id).unwrap().asset_blinding,
            transfer_amount,
        };

        let (tx,blind) = sender.send(&mut csprng, &tx_params, asset_id).unwrap();

        sender.sender_apply_tx(&tx, transfer_amount, asset_id, &blind).unwrap();

        assert_eq!(sender.balances[asset_id].balance, starting_bal - transfer_amount);

        let com = pc_gens.commit(
            Scalar::from(starting_bal - transfer_amount), sender.balances[asset_id].balance_blinding);
        assert_eq!(sender.balances[asset_id].balance_commitment, com.compress());

        assert_eq!(true, rec.receiver_apply_tx(&tx));

        assert_eq!(rec.balances[asset_id].balance, starting_bal + transfer_amount);

        let com = pc_gens.commit(
            Scalar::from(starting_bal + transfer_amount), rec.balances[asset_id].balance_blinding);
        assert_eq!(rec.balances[asset_id].balance_commitment, com.compress());
    }

    #[test]
    pub fn test_account_ser() {
        let mut csprng = ChaChaRng::from_seed([0u8; 32]);
        let asset_id = "default currency";

        let mut acc = Account::new(&mut csprng);
        acc.add_asset(&mut csprng, asset_id, false, 50);
        acc.add_asset(&mut csprng, "another currency", true, 50);

        let json = serde_json::to_string(&acc).unwrap();

        let acc_deserialized: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(acc_deserialized, acc);

        let acc = Account::new(&mut ChaChaRng::from_seed([0u8; 32]));
        let json = serde_json::to_string(&acc).unwrap();

        let acc_deserialized: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(acc_deserialized, acc);
    }
}
