//! Zei: Findora's cryptographic library

#![deny(warnings)]
// Skip non useful warnings from clippy
#![allow(clippy::let_and_return)]
#![allow(clippy::many_single_char_names)]

#[macro_use]
extern crate itertools;

#[macro_use]
extern crate serde_derive;

extern crate ed25519_dalek_new as ed25519_dalek;

pub mod algebra;
pub mod api;
pub mod basic_crypto;
pub mod crypto;
pub mod errors;
pub mod serialization;
pub mod setup;
pub mod utils;
pub mod xfr;
