//Zei: Confidential Payments for Accounts
//#![feature(try_from)]
#![feature(try_trait)]
//#![feature(custom_attribute)]

extern crate blake2;
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate merlin;
extern crate num_bigint;
extern crate num_traits;
extern crate rand;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate sha2;
extern crate sodiumoxide;
extern crate itertools;
extern crate rmp_serde;

mod errors;
mod setup;
mod basic_crypto;
mod utils;

pub mod serialization;
pub mod proofs;
pub mod transfers;
