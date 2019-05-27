//Zei: Confidential Payments for Accounts
//#![feature(try_from)]
#![feature(try_trait)]
//#![feature(custom_attribute)]

extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate itertools;
extern crate merlin;
extern crate num_bigint;
extern crate num_traits;
extern crate pairing;
extern crate rand;
extern crate rand_04;
extern crate rmp_serde;
extern crate rustc_serialize;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate bn;
extern crate digest;
extern crate serde_json;
extern crate sha2;
extern crate sodiumoxide;
extern crate spacesuit;

mod setup;
mod utils;

pub mod algebra;
pub mod basic_crypto;
pub mod credentials;
pub mod errors;
pub mod proofs;
pub mod serialization;
pub mod xfr;
