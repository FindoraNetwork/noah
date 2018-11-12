//Zei: Confidential Payments for Accounts

extern crate bulletproofs;
extern crate rand;
extern crate blake2_rfc;
extern crate curve25519_dalek;
extern crate merlin;
#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate neon;

//microsalt
#[macro_use] extern crate index_fixed;


mod core;

use neon::prelude::*;

use core::account::Account;
use core::transaction::{CreateTx, Transaction};

//create a new account
fn create_account(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string(serde_json::to_string(&Account::new()).unwrap()))
}

//construct transaction
fn create_tx(mut cx: FunctionContext) -> JsResult<JsString> {
    //get account JSON
    let user_account = cx.argument::<JsString>(0)?.value();
    //deserilize account
    let mut account: Account = serde_json::from_str(&user_account).unwrap();
    //get new tx JSON
    let user_input_tx = cx.argument::<JsString>(1)?.value();
    //deserizlize tx struct
    let newtx: CreateTx = serde_json::from_str(&user_input_tx).unwrap();

    //apply tx with account and get back the network transaction
    let net_tx = account.send(&newtx);

    //println!("create_tx: {:?}", newtx);
    Ok(cx.string(serde_json::to_string(&net_tx).unwrap()))
}

//fn apply_tx()

//when an account recieves a tx from network it must update its account with it to recieve the payment
fn recieve_tx(mut cx: FunctionContext) -> JsResult<JsString> {
     //get account JSON
    let user_account = cx.argument::<JsString>(0)?.value();
    //deserilize account
    let mut account: Account = serde_json::from_str(&user_account).unwrap();
    //get new tx JSON
    let new_tx = cx.argument::<JsString>(1)?.value();
    //deserizlize tx struct
    let newtx: Transaction = serde_json::from_str(&new_tx).unwrap();

    account.recieve(&newtx);

    //println!("recieve_tx: {:?}", account);
    //send back updated account
    Ok(cx.string(serde_json::to_string(&account).unwrap()))
}

register_module!(mut cx, {
    cx.export_function("create_account", create_account)?;

    cx.export_function("create_tx", create_tx)?;

    cx.export_function("recieve_tx", recieve_tx)?;

    Ok(())

});
