#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]
#![allow(
    clippy::op_ref,
    clippy::suspicious_op_assign_impl,
    clippy::upper_case_acronyms
)]
#![cfg_attr(not(feature = "asm"), forbid(unsafe_code))]
#![cfg_attr(use_asm, feature(llvm_asm))]
#![cfg_attr(feature = "asm", deny(unsafe_code))]

#[macro_use]
extern crate utils;

pub mod bls12_381;
pub mod errors;
pub mod groups;
pub mod jubjub;
pub mod multi_exp;
pub mod ristretto;
pub mod serialization;
