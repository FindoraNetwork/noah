#![deny(warnings)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::bool_assert_comparison)]

#[macro_use]
extern crate itertools;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate zei_utils;

pub mod anon_creds;
pub mod basics;
pub mod bp_circuits;
pub mod bp_range_proofs;
pub mod chaum_pedersen;
pub mod conf_cred_reveal;
pub mod field_simulation;
pub mod pc_eq_rescue_split_verifier_zk_part;
pub mod pedersen_elgamal;
pub mod sigma;
