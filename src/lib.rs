//Zei: Confidential Payments for Accounts
#![feature(try_from)]
#![feature(try_trait)]
extern crate schnorr;
extern crate organism_utils;
extern crate bulletproofs;
extern crate rand;
extern crate blake2;
extern crate curve25519_dalek;
extern crate merlin;
#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate serde_json;

mod setup;
mod constants;

pub mod errors;
pub mod serialization;
pub mod asset;
pub mod address;
pub mod account;
pub mod transaction;
pub mod solvency;

// TODO(jackson): Real C bindings for zei
use self::account::Account;
use rand::rngs::OsRng;

#[no_mangle]
pub extern fn test_function() -> f32 {
    let mut csprng: OsRng = OsRng::new().unwrap();
    let _asset_type = "bank1_usd";  
    Account::new(&mut csprng);
    42.0
}

