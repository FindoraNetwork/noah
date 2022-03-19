//! The crate for algebra for the Zei library, which unifies the interfaces of different curves
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts, private_in_public)]
#![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_imports, unused_mut, missing_docs)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use, const_err)]
#![forbid(unsafe_code)]
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

#[macro_use]
extern crate utils;

/// Module for the BLS12-381 curve
pub mod bls12_381;

/// Module for error handling
pub mod errors;

/// Module for traits
pub mod traits;

/// Module for the Jubjub curve
pub mod jubjub;

/// Module for the Ristretto group
pub mod ristretto;

/// Module for serialization of scalars and group elements
pub mod serialization;

pub use ark_std::*;
