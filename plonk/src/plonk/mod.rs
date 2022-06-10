//! The TurboPlonk implementation.

/// Module for help functions.
pub(crate) mod helpers;

/// Module for the constraint system.
pub mod constraint_system;

/// Module for error handling.
pub mod errors;

/// Module for prover.
pub mod prover;

/// Module for indexer.
pub mod indexer;

/// Module for transcript.
pub mod transcript;

/// Module for verifier.
pub mod verifier;
