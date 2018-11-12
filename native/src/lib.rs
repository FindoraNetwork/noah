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
use core::transaction::{CreateTx};

//create a new account
fn create_account(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string(serde_json::to_string(&Account::new()).unwrap()))
}

//construct transaction
fn create_tx(mut cx: FunctionContext) -> JsResult<JsString> {
    //get new tx JSON
    let user_input_tx = cx.argument::<JsString>(0)?.value();
    //deserizlize tx struct
    let newtx: CreateTx = serde_json::from_str(&user_input_tx).unwrap();
    //get account JSON
    let user_account = cx.argument::<JsString>(1)?.value();
    //deserilize account
    let mut account: Account = serde_json::from_str(&user_account).unwrap();
    //apply tx with account and get back the network transaction
    let net_tx = account.send(&newtx);

    println!("create_tx: {:?}", newtx);
    Ok(cx.string(serde_json::to_string(&net_tx).unwrap()))
}

//fn apply_tx()
//fn recieve_tx()

register_module!(mut cx, {
    cx.export_function("create_account", create_account)?;

    cx.export_function("create_tx", create_tx)?;



    Ok(())

});
