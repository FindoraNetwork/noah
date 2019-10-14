//! Zei: Eian's cryptographic library
//#![feature(test)]
//extern crate aes_ctr;

#[macro_use]
extern crate itertools;

#[macro_use] //rustc crushes if not used
extern crate serde_derive;

pub mod algebra;
pub mod basic_crypto;
pub mod crypto;
pub mod errors;
pub mod serialization;
pub mod setup;
mod utils;
pub mod xfr;
