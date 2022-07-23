//! The API interfaces of the Zei library
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts, private_in_public)]
#![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_imports, unused_mut)]
#![deny(missing_docs)]
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
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

/// The wrapper for anonymous credentials.
pub mod anon_creds;
/// Module for anonymous transfer.
pub mod anon_xfr;
/// The wrapper of the parameters.
pub mod parameters;
/// Module for primitives of cryptography algorithm.
pub mod primitives;
/// Module for serialization.
pub mod serialization;
/// Module for generating parameters.
pub mod setup;
/// Module for confidential transfer.
pub mod xfr;

pub use zei_algebra::errors;
pub use zei_algebra::ristretto;
