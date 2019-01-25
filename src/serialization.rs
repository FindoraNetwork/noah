use crate::account::Balance;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use schnorr::Keypair;
use crate::asset::Asset;
use crate::account::AssetBalance;
use crate::account::Account;
use std::collections::HashMap;
use serde_json::Value;

pub fn account_to_json(account: &Account) -> String {
    let mut json: String = String::from("{\"tx_counter\":\"");
    //push tx counter
    let number = account.tx_counter;
    json.push_str(&u128_to_str(number));
    json.push_str("\",\"keys\":\"");
    json.push_str(&keys_to_json(&account.keys));
    json.push_str("\",\"balances\":{");
    for (id,balance) in account.balances.iter() {
        json.push_str("\"");
        json.push_str(id);
        json.push_str("\":{");
        json.push_str(&asset_balance_to_json(balance));
        json.push_str("},");
    }
    if account.balances.len() > 0 {
        json.pop();
    }
    json.push_str("}}");
    json

}

pub fn keys_to_json(keypair: &Keypair) -> String {
    let bytes = keypair.to_bytes();
    hex::encode(&bytes[..])
}

pub fn asset_balance_to_json(asset_balance: &AssetBalance) -> String {
    let mut json = String::from("\"tx_counter\":\"");
    json.push_str(&u128_to_str(asset_balance.tx_counter));
    json.push_str("\",\"balance\":");
    json.push_str(&balance_to_str(asset_balance.balance));
    json.push_str(",\"balance_commitment\":\"");
    json.push_str(&compressed_ristretto_to_hex(&asset_balance.balance_commitment));
    json.push_str("\",\"balance_blinding\":\"");
    json.push_str(&scalar_to_hex(&asset_balance.balance_blinding));
    json.push_str("\",\"asset_info\":");
    json.push_str(&asset_to_hex(&asset_balance.asset_info));
    json.push_str(",\"confidential_asset\":");
    json.push_str(&asset_balance.confidential_asset.to_string());
    json.push_str(",\"asset_commitment\":\"");
    json.push_str(&compressed_ristretto_to_hex(&asset_balance.asset_commitment));
    json.push_str("\",\"asset_blinding\":\"");
    json.push_str(&scalar_to_hex(&asset_balance.asset_blinding));
    json.push_str("\"");

    json

}

pub fn balance_to_str(balance: Balance) -> String{
    balance.to_string()
}

pub fn u128_to_str(number: u128) -> String{
    let bytes = number.to_be_bytes();
    hex::encode(bytes)
}

pub fn compressed_ristretto_to_hex(point: &CompressedRistretto) -> String{
    hex::encode(point.to_bytes())
}

pub fn scalar_to_hex(scalar: &Scalar) -> String {
    hex::encode(scalar.to_bytes())
}

pub fn asset_to_hex(asset: &Asset) -> String {
    let mut json = String::from("{\"id\":\"");
    json.push_str(&asset.id);
    json.push_str("\"}");
    json
}

pub fn hex_str_to_compressed_ristretto(hex_str: &str) -> CompressedRistretto {
    let vector = hex::decode(hex_str).unwrap();
    let bytes = vector.as_slice();
    CompressedRistretto::from_slice(bytes)
}

pub fn hex_str_to_scalar(hex_str: &str) ->Scalar {
    let vector = hex::decode(hex_str).unwrap();
    let bytes = vector.as_slice();
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    Scalar::from_bits(array)
}

pub fn hex_str_to_u128(hex_str: &str) -> u128{
    let vector = hex::decode(hex_str).unwrap();
    let bytes = vector.as_slice();
    let mut array = [0u8; 16];
    array.copy_from_slice(bytes);
    u128::from_be_bytes(array)
}

pub fn hex_str_to_keypair(hex_str: &str) -> Keypair{
    let vector = hex::decode(hex_str).unwrap();
    let bytes = vector.as_slice();
    Keypair::from_bytes(bytes).unwrap()
}


pub fn json_to_account(json: &str) -> Account{
    let v: Value = serde_json::from_str(json).unwrap();
    let tx_counter: u128 = hex_str_to_u128(v["tx_counter"].as_str().unwrap());

    let keys = hex_str_to_keypair(v["keys"].as_str().unwrap());

    let balances_value = v["balances"].as_object().unwrap();
    let mut balances: HashMap<String, AssetBalance> =  HashMap::new();
    for (id, balance_value) in balances_value.iter() {
        let asset_balance = AssetBalance {
            tx_counter: hex_str_to_u128(balance_value["tx_counter"].as_str().unwrap()),
            balance: balance_value["balance"].as_u64().unwrap() as u32,
            balance_commitment: hex_str_to_compressed_ristretto(balance_value["balance_commitment"].as_str().unwrap()),
            balance_blinding: hex_str_to_scalar(balance_value["balance_blinding"].as_str().unwrap()),
            confidential_asset: balance_value["confidential_asset"].as_bool().unwrap(),
            asset_commitment: hex_str_to_compressed_ristretto(balance_value["asset_commitment"].as_str().unwrap()),
            asset_blinding: hex_str_to_scalar(balance_value["asset_blinding"].as_str().unwrap()),
            asset_info: Asset {
                id: String::from(balance_value["asset_info"]["id"].as_str().unwrap()),
            }
        };
        balances.insert((*id).to_string(), asset_balance);
    }

    Account{
        tx_counter,
        balances,
        keys,
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
    #[test]
    pub fn test_account_to_json() {
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);
        let mut acc = Account::new(&mut csprng);
        let asset_id = "default currency";
        acc.add_asset(&mut csprng, asset_id, false);
        acc.add_asset(&mut csprng, "another currency", true);

        let json = account_to_json(&acc);

        let acc_deserialized = json_to_account(&json);

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
        let mut csprng : ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);
        let mut acc = Account::new(&mut csprng);
        let json = account_to_json(&acc);
        let acc_deserialized = json_to_account(&json);
        assert_eq!(acc_deserialized.tx_counter, acc.tx_counter);
        assert_eq!(acc_deserialized.keys.public, acc.keys.public);
        assert_eq!(acc_deserialized.keys.secret.to_bytes(), acc.keys.secret.to_bytes());
        assert_eq!(acc_deserialized.balances.len(), acc.balances.len());


    }

}
