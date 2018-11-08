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
// use zei::transaction;

//create a new account
fn create_account(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string(serde_json::to_string(&Account::new()).unwrap()))
}

// //construct transaction
// fn create_tx(mut cx: FunctionContext) -> JsResult<JsString> {
//     Ok(cx.string("hello node"))
// }

register_module!(mut cx, {
    cx.export_function("create_account", create_account)
    //cx.export_function("create_tx", create_tx)
    // Ok(())

});
