//! The crate for Plonk and polynomial commitment for the Noah library
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts, private_in_public)]
#![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_imports, unused_mut, missing_docs)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use)]
#![doc(html_logo_url = "https://avatars.githubusercontent.com/u/74745723?s=200&v=4")]
#![doc(html_playground_url = "https://play.rust-lang.org")]
#![forbid(unsafe_code)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

#[macro_use]
extern crate serde_derive;

/// Module for error handling
pub mod errors;

/// Module for the TurboPlonk systems.
pub mod plonk;

/// Module for the polynomial commitment.
pub mod poly_commit;
