use bulletproofs::{RangeProof};
use crate::account::{AssetBalance,Account};
use crate::errors::Error as ZeiError;
use crate::asset::Asset;
use crate::transaction::{TxParams, Transaction};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use organism_utils::crypto::lockbox::Lockbox;
use organism_utils::crypto::secretbox::{SecretBox, NonceKey};
use schnorr::{Keypair,PublicKey};
use std::collections::HashMap;
use std::convert::TryFrom;



#[derive(Serialize, Deserialize, Debug)]
pub struct AssetBalanceString{
    tx_counter: u128,
    balance: u32,
    balance_commitment: CompressedRistrettoString,
    balance_blinding: ScalarString,
    // TODO
    asset_info: Asset,
    confidential_asset: bool,
    asset_commitment: CompressedRistrettoString,
    asset_blinding: ScalarString
}

impl From<AssetBalance> for AssetBalanceString{
    fn from(a: AssetBalance) -> AssetBalanceString{
        AssetBalanceString{
            tx_counter: a.tx_counter,
            balance: a.balance,
            balance_commitment: CompressedRistrettoString::from(a.balance_commitment),
            balance_blinding: ScalarString::from(a.balance_blinding),
            asset_info: a.asset_info,
            confidential_asset: a.confidential_asset,
            asset_commitment: CompressedRistrettoString::from(a.asset_commitment),
            asset_blinding: ScalarString::from(a.asset_blinding)
        }
    }
}

impl TryFrom<AssetBalanceString> for AssetBalance{
    type Error = ZeiError;
    fn try_from(a: AssetBalanceString) -> Result<AssetBalance, ZeiError> {
        Ok(AssetBalance{
            tx_counter: a.tx_counter,
            balance: a.balance,
            balance_commitment: CompressedRistretto::try_from(a.balance_commitment)?,
            balance_blinding: Scalar::try_from(a.balance_blinding)?,
            asset_info: a.asset_info,
            confidential_asset: a.confidential_asset,
            asset_commitment: CompressedRistretto::try_from(a.asset_commitment)?,
            asset_blinding: Scalar::try_from(a.asset_blinding)?
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeypairString {
    val: String
}

impl TryFrom<KeypairString> for Keypair {
    type Error = ZeiError;
    fn try_from(value: KeypairString) -> Result<Keypair, ZeiError> {
        let vector = hex::decode(&value.val)?;
        let bytes = vector.as_slice();
        let keypair = Keypair::from_bytes(bytes)?;
        Ok(keypair)
    }
}

impl From<Keypair>  for KeypairString {
    fn from(a: Keypair) -> KeypairString {
        let bytes = a.to_bytes();
        KeypairString{val: hex::encode(&bytes[..])}
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccountString {
    tx_counter: u128,
    keys: KeypairString,
    balances: HashMap<String, AssetBalanceString>

}
impl From<Account> for AccountString {
    fn from(a: Account) -> AccountString {
        AccountString{
            tx_counter: a.tx_counter,
            keys: KeypairString::from(a.keys),
            balances: a.balances.into_iter().map(
                |(k, v)| {(k, AssetBalanceString::from(v))}).collect()
        }
    }
}

impl TryFrom<AccountString> for Account {
    type Error = ZeiError;
    fn try_from(a: AccountString) -> Result<Account,ZeiError> {
        let keys = Keypair::try_from(a.keys)?;
        Ok(Account{
            tx_counter: a.tx_counter,
            keys,
            balances: a.balances.into_iter().map(
                |(k, v)| {(k, AssetBalance::try_from(v).unwrap())}).collect()
        })
    }
}


// helper struct to save us from manually constructing json
#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionString{
    transaction_range_proof: RangeProofString,
    transaction_commitment: CompressedRistrettoString,
    sender_updated_balance_commitment: CompressedRistrettoString,
    lockbox: LockboxString,
    do_confidential_asset: bool,
    asset_eq_proof: ScalarString,
    sender_asset_commitment: CompressedRistrettoString,
    receiver_asset_commitment: CompressedRistrettoString,
}

impl From<Transaction> for TransactionString {
    fn from(a: Transaction) -> TransactionString{
        TransactionString{
            transaction_range_proof: RangeProofString::from(a.transaction_range_proof),
            transaction_commitment: CompressedRistrettoString::from(a.transaction_commitment),
            sender_updated_balance_commitment: CompressedRistrettoString::from(a.sender_updated_balance_commitment),
            lockbox: LockboxString::from(a.lockbox),
            do_confidential_asset: a.do_confidential_asset,
            asset_eq_proof: ScalarString::from(a.asset_eq_proof),
            sender_asset_commitment: CompressedRistrettoString::from(a.sender_asset_commitment),
            receiver_asset_commitment: CompressedRistrettoString::from(a.receiver_asset_commitment),
        }
    }
}

impl TryFrom<TransactionString> for Transaction{
    type Error = ZeiError;
    fn try_from(a: TransactionString) -> Result<Transaction, ZeiError> {
        Ok(Transaction{
            transaction_range_proof: RangeProof::try_from(a.transaction_range_proof)?,
            transaction_commitment: CompressedRistretto::try_from(a.transaction_commitment)?,
            sender_updated_balance_commitment: CompressedRistretto::try_from(a.sender_updated_balance_commitment)?,
            lockbox: Lockbox::try_from(a.lockbox)?,
            do_confidential_asset: a.do_confidential_asset,
            asset_eq_proof: Scalar::try_from(a.asset_eq_proof)?,
            sender_asset_commitment: CompressedRistretto::try_from(a.sender_asset_commitment)?,
            receiver_asset_commitment: CompressedRistretto::try_from(a.receiver_asset_commitment)?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CompressedRistrettoString {
    val: String
}

impl From<CompressedRistretto> for CompressedRistrettoString {
    fn from(point: CompressedRistretto) -> CompressedRistrettoString{
        CompressedRistrettoString{val:hex::encode(point.to_bytes())}
    }
}

impl TryFrom<CompressedRistrettoString> for CompressedRistretto {
    type Error = ZeiError;
    fn try_from(hex_str: CompressedRistrettoString) -> Result<CompressedRistretto, ZeiError>{
        let vector = hex::decode(hex_str.val)?;
        let bytes = vector.as_slice();
        Ok(CompressedRistretto::from_slice(bytes))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScalarString {
    val: String
}

impl From<Scalar> for ScalarString {
    fn from(scalar: Scalar) -> ScalarString {
        ScalarString {
            val: hex::encode(scalar.to_bytes())
        }
    }
}

impl TryFrom<ScalarString> for Scalar {
    type Error = ZeiError;
    fn try_from(scalar: ScalarString) -> Result<Scalar, ZeiError> {
        let vector = hex::decode(&scalar.val)?;
        let bytes = vector.as_slice();
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(Scalar::from_bits(array))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKeyString {
    val: String
}



impl TryFrom<PublicKeyString> for PublicKey {
    type Error = ZeiError;
    fn try_from(a: PublicKeyString) -> Result<PublicKey, ZeiError> {
        let vector = hex::decode(&a.val)?;
        let bytes = vector.as_slice();
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(PublicKey::from_bytes(&array)?)
    }
}

impl From<PublicKey> for PublicKeyString {
    fn from(a: PublicKey) -> PublicKeyString {
        PublicKeyString{val: hex::encode(a.to_bytes())}
    }
}

// // helper struct to save us from manually constructing json
// #[derive(Serialize, Deserialize, Debug)]
// pub struct TxInfoString {
//     receiver_pk: PublicKeyString,
//     receiver_asset_commitment: CompressedRistrettoString,
//     receiver_asset_opening: ScalarString,
//     sender_asset_commitment: CompressedRistrettoString,
//     sender_asset_opening: ScalarString,
//     transfer_amount: u32,
// }

// impl TryFrom<TxInfoString> for TxInfo {
//     type Error = ZeiError;
//     fn try_from(tx: TxInfoString) -> Result<TxInfo, ZeiError> {
//         Ok(TxInfo{
//             receiver_pk: PublicKey::try_from(tx.receiver_pk)?,
//             receiver_asset_commitment: CompressedRistretto::try_from(tx.receiver_asset_commitment)?,
//             receiver_asset_opening: Scalar::try_from(tx.receiver_asset_opening)?,
//             sender_asset_commitment: CompressedRistretto::try_from(tx.sender_asset_commitment)?,
//             sender_asset_opening: Scalar::try_from(tx.sender_asset_opening)?,
//             transfer_amount: tx.transfer_amount,
//         }
//         )
//     }
// }

// helper struct to save us from manually constructing json
#[derive(Serialize, Deserialize, Debug)]
pub struct TxParamsString{
    receiver_pk: PublicKeyString,
    receiver_asset_commitment: CompressedRistrettoString,
    receiver_asset_opening: ScalarString,
    // sender_asset_commitment: CompressedRistrettoString,
    // sender_asset_opening: ScalarString,
    transfer_amount: u32,
}

impl TryFrom<TxParamsString> for TxParams{
    type Error = ZeiError;
    fn try_from(tx: TxParamsString) -> Result<TxParams, ZeiError> {
        Ok(
            TxParams{
                receiver_pk: PublicKey::try_from(tx.receiver_pk)?,
                receiver_asset_commitment: CompressedRistretto::try_from(tx.receiver_asset_commitment)?,
                receiver_asset_opening: Scalar::try_from(tx.receiver_asset_opening)?,
                // sender_asset_commitment: CompressedRistretto::from(tx.sender_asset_commitment),
                // sender_asset_opening: Scalar::from(tx.sender_asset_opening),
                transfer_amount: tx.transfer_amount,
            }
        )
    }
}

impl From<TxParams> for TxParamsString{
    fn from(tx: TxParams) -> TxParamsString {
        TxParamsString{
            receiver_pk: PublicKeyString::from(tx.receiver_pk),
            receiver_asset_commitment: CompressedRistrettoString::from(tx.receiver_asset_commitment),
            receiver_asset_opening: ScalarString::from(tx.receiver_asset_opening),
            transfer_amount: tx.transfer_amount,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LockboxString{
    data: SecretBoxString,
    rand: CompressedRistrettoString
}

impl TryFrom<LockboxString> for Lockbox {
    type Error = ZeiError;
    fn try_from(a: LockboxString) -> Result<Lockbox, ZeiError>{
        Ok(Lockbox {
            data: SecretBox::try_from(a.data)?,
            rand: CompressedRistretto::try_from(a.rand)?,
        })

    }
}

impl From<Lockbox> for LockboxString {
    fn from(a: Lockbox) -> LockboxString{
        LockboxString{
            data: SecretBoxString::from(a.data),
            rand: CompressedRistrettoString::from(a.rand)
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretBoxString{
    nonce: Vec<u8>,
    tag: Vec<u8>,
    cipher: Vec<u8>,
}

impl TryFrom<SecretBoxString> for SecretBox{
    type Error = ZeiError;
    fn try_from(a: SecretBoxString) -> Result<SecretBox,ZeiError>{
        let mut array = [0u8; 16];
        array.copy_from_slice(a.tag.as_slice());
        Ok(SecretBox{
            nonce: NonceKey::from_bytes(a.nonce.as_slice())?,
            tag: array,
            cipher: a.cipher
        })
    }
}

impl From<SecretBox> for SecretBoxString{
    fn from(a: SecretBox) -> SecretBoxString{
        // to_bytes or as bytes ?
        SecretBoxString {
            nonce: a.nonce.as_bytes().to_vec(),
            tag: a.tag.to_vec(),
            cipher: a.cipher
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RangeProofString{
    val: Vec<u8>
}

impl TryFrom<RangeProofString> for RangeProof {
    type Error = ZeiError;
    fn try_from(a: RangeProofString) -> Result<RangeProof, ZeiError>{
        Ok(RangeProof::from_bytes(&a.val)?)
    }
}

impl From<RangeProof> for RangeProofString {
    fn from(a: RangeProof) -> RangeProofString{
        RangeProofString{val: a.to_bytes()}
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use serde::ser::Serialize;
    use std::str;
    use serde::private::ser::Error;
    use curve25519_dalek::ristretto::CompressedRistretto;
    #[test]
    pub fn serialization_compressed_ristretto(){
        let id = CompressedRistrettoString::from(CompressedRistretto::default());
        let serialized = serde_json::to_string(&id).unwrap();
        let deserialized = serde_json::from_str::<CompressedRistrettoString>(&serialized).unwrap();
        let final_deserialized = CompressedRistretto::try_from(deserialized).unwrap();
    }
    #[test]
    pub fn test_account_to_json() {
        let mut csprng1 = ChaChaRng::from_seed([0u8; 32]);
        let mut csprng2 = ChaChaRng::from_seed([0u8; 32]);
        let mut acc_old = Account::new(&mut csprng1);
        let asset_id = "default currency";
        acc_old.add_asset(&mut csprng1, asset_id, false, 50);
        acc_old.add_asset(&mut csprng1, "another currency", true, 50);

        let mut acc = Account::new(&mut csprng2);
        acc.add_asset(&mut csprng2, asset_id, false, 50);
        acc.add_asset(&mut csprng2, "another currency", true, 50);

        let acc_str = AccountString::from(acc_old);

        let json = serde_json::to_string(&acc_str).unwrap();

        let acc_deserialized = Account::try_from(serde_json::from_str::<AccountString>(&json).unwrap()).unwrap();

        assert_eq!(acc_deserialized.tx_counter, acc.tx_counter);
        assert_eq!(acc_deserialized.keys.public, acc.keys.public);
        assert_eq!(acc_deserialized.keys.secret.to_bytes(), acc.keys.secret.to_bytes());
        assert_eq!(acc_deserialized.balances.len(), acc.balances.len());
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().tx_counter, acc.balances.get("default currency").unwrap().tx_counter);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().balance, acc.balances.get("default currency").unwrap().balance);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().balance_commitment, acc.balances.get("default currency").unwrap().balance_commitment);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().balance_blinding, acc.balances.get("default currency").unwrap().balance_blinding);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().asset_commitment, acc.balances.get("default currency").unwrap().asset_commitment);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().asset_blinding, acc.balances.get("default currency").unwrap().asset_blinding);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().asset_info.id, acc.balances.get("default currency").unwrap().asset_info.id);

        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().tx_counter, acc.balances.get("another currency").unwrap().tx_counter);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().balance, acc.balances.get("another currency").unwrap().balance);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().balance_commitment, acc.balances.get("another currency").unwrap().balance_commitment);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().balance_blinding, acc.balances.get("another currency").unwrap().balance_blinding);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().asset_commitment, acc.balances.get("another currency").unwrap().asset_commitment);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().asset_blinding, acc.balances.get("another currency").unwrap().asset_blinding);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().asset_info.id, acc.balances.get("another currency").unwrap().asset_info.id);
    }
    #[test]
    pub fn test_empty_account() {
        let mut acc = Account::new(&mut ChaChaRng::from_seed([0u8; 32]));
        let json = (&acc);
        let acc_deserialized = json_to_account(&json);

        let mut acc = Account::new(&mut ChaChaRng::from_seed([0u8; 32]));
        assert_eq!(acc_deserialized.tx_counter, acc.tx_counter);
        assert_eq!(acc_deserialized.keys.public, acc.keys.public);
        assert_eq!(acc_deserialized.keys.secret.to_bytes(), acc.keys.secret.to_bytes());
        assert_eq!(acc_deserialized.balances.len(), acc.balances.len());
    }
}
