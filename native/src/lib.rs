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

use core::keypair;
// use zei::transaction;

// // //sample keys
// fn keypair(mut cx: FunctionContext) -> JsResult<JsString> {
//     let sampled_keypair = Keypair::new();
//     let json = serde_json::to_string(&sampled_keypair)?;
//     Ok(json)
// }

// //construct transaction
// fn create_tx(mut cx: FunctionContext) -> JsResult<JsString> {
//     Ok(cx.string("hello node"))
// }

// register_module!(mut cx, {
//     cx.export_function("keypair", keypair)?;
//     cx.export_function("create_tx", create_tx)
//     //Ok(())

// });
