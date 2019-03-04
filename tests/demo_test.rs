
use rand_chacha::ChaChaRng;
use rand::SeedableRng;
use zei::account::*;
use zei::utxo_transaction::Tx;
use curve25519_dalek::scalar::Scalar;

#[test]
pub fn test_transfer(){
    let mut csprng = ChaChaRng::from_seed([0u8; 32]);
    let asset_id = "example_asset";
    let amount = 25;
    let mut sender = Account::new(&mut csprng);
    let mut json_acc = serde_json::to_string(&sender).unwrap();
    sender = serde_json::from_str(&json_acc).unwrap();
    sender.add_asset(&mut csprng, asset_id, true, 1000);

    let mut receiver = Account::new(&mut csprng);
    let json_recv = serde_json::to_string(&receiver).unwrap();
    receiver = serde_json::from_str(&json_recv).unwrap();
    receiver.add_asset(&mut csprng, asset_id, true, 300);

    let txparams = TxParams {
        receiver_pk: receiver.keys.get_pk_ref().clone(),
        receiver_asset_commitment: receiver.balances[asset_id].asset_commitment,
        receiver_asset_opening: receiver.balances[asset_id].asset_blinding,
        transfer_amount: amount,
    };

    let tx_params_json = serde_json::to_string(&txparams).unwrap();
    let tx_params_deserialized: TxParams = serde_json::from_str(&tx_params_json).unwrap();

    json_acc = serde_json::to_string(&sender).unwrap();
    sender = serde_json::from_str(&json_acc).unwrap();
    let (tx, blind) = sender.send(
        &mut csprng, &tx_params_deserialized, asset_id).unwrap();

    let tx_str = serde_json::to_string(&tx).unwrap();
    let blind_str = serde_json::to_string(&blind).unwrap();
    let blind_vec: Vec<u8> = serde_json::from_str(&blind_str).unwrap();
    let mut array = [0u8;32];
    array.copy_from_slice(blind_vec.as_slice());
    let blinding = Scalar::from_bits(array);

    let tx: Tx = serde_json::from_str(&tx_str).unwrap();

    let v = tx.verify();
    assert_eq!(true, v);

    sender = serde_json::from_str(&serde_json::to_string(&sender).unwrap()).unwrap();
    sender.sender_apply_tx(&tx, amount, asset_id, &blinding).unwrap();

    assert_eq!(975, sender.balances[asset_id].balance);

    receiver = serde_json::from_str(&serde_json::to_string(&receiver).unwrap()).unwrap();
    receiver.receiver_apply_tx(&tx);

    assert_eq!(325, receiver.balances[asset_id].balance);

}