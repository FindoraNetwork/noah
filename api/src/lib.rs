//!
//! Zei: Findora's cryptographic library
//!

#![deny(warnings)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::let_and_return)]
#![allow(clippy::many_single_char_names)]

#[macro_use]
extern crate serde_derive;
extern crate core;

pub mod anon_xfr;
pub mod api;
pub mod parameters;
pub mod serialization;
pub mod setup;
pub mod xfr;

pub use zei_algebra::errors;
pub use zei_algebra::ristretto;
