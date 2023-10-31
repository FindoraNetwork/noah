//! The crate implements the cryptography primitives (except TurboPlonk) for the Noah library,
//! including Bulletproofs.
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts)]
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
#![allow(clippy::type_complexity, clippy::too_many_arguments)]

#[macro_use]
extern crate itertools;

#[macro_use]
extern crate serde_derive;

/// The module for the Anemoi-Jive hash functions.
pub mod anemoi_jive;
/// The module for anonymous credentials.
pub mod anon_creds;
/// The library for Bulletproofs.
pub mod bulletproofs;
/// The module for the Chaum-Pedersen protocol.
pub mod chaum_pedersen;
/// The module for confidential anonymous credentials.
pub mod confidential_anon_creds;
/// The module for the delegated Schnorr protocol.
pub mod delegated_schnorr;
/// The module for the doubly SNARK-friendly primitives.
pub mod doubly_snark_friendly;
/// The module for the ElGamal encryption.
pub mod elgamal;
/// The module for error handling
pub mod errors;
/// The module for field simulation.
pub mod field_simulation;
/// The module for the (modified) gap Diffie-Hellman undeniable signature.
pub mod gapdh;
/// The module for hashing to the curve.
pub mod hashing_to_the_curve;
/// The module for hybrid encryption.
pub mod hybrid_encryption;
/// The module for the matrix Sigma protocol.
pub mod matrix_sigma;
/// The module for the equality proof between a Pedersen commitment and an ElGamal ciphertext.
pub mod pedersen_elgamal;
/// The module that contains some useful Schnorr gadgets.
pub mod schnorr_gadgets;
