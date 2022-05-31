#![deny(warnings)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::bool_assert_comparison)]

#[macro_use]
extern crate itertools;

#[macro_use]
extern crate serde_derive;

pub mod anon_creds;
pub mod basic;
pub mod bulletproofs;
pub mod conf_cred_reveal;
pub mod delegated_chaum_pedersen;
pub mod field_simulation;
