//! Zei: Findora's cryptographic library

#![deny(warnings)]
// Skip non useful warnings from clippy
#![allow(clippy::let_and_return)]
#![allow(clippy::many_single_char_names)]

#[macro_use]
extern crate utils;

#[macro_use]
extern crate itertools;

#[macro_use]
extern crate serde_derive;

pub mod api;
pub mod serialization;
pub mod setup;
pub mod xfr;
