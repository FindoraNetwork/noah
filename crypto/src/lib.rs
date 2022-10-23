//! The crate implements the cryptography primitives (except TurboPlonk) for the Noah library,
//! including Bulletproofs.
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

#[macro_use]
extern crate itertools;

#[macro_use]
extern crate serde_derive;

/// The module for anonymous credentials.
pub mod anon_creds;
/// The basic cryptographic primitives.
pub mod basic;
/// The library for Bulletproofs.
pub mod bulletproofs;
/// The module for confidential anonymous credentials.
pub mod confidential_anon_creds;
/// The module for the delegated Schnorr protocol.
pub mod delegated_schnorr;
/// The module for field simulation.
pub mod field_simulation;
