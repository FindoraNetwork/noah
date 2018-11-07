#![feature(nll)]
#![feature(external_doc)]
#![doc(include = "../README.md")]
#![doc(html_logo_url = "https://doc.dalek.rs/assets/dalek-logo-clear.png")]

extern crate byteorder;
extern crate core;
extern crate digest;
extern crate rand;
extern crate sha3;

extern crate clear_on_drop;
extern crate curve25519_dalek;
extern crate merlin;
extern crate subtle;

#[macro_use]
extern crate serde_derive;
extern crate serde;

#[macro_use]
extern crate failure;

#[cfg(test)]
extern crate bincode;

mod util;

#[doc(include = "../docs/notes.md")]
mod notes {}
mod errors;
mod generators;
mod inner_product_proof;
mod range_proof;
mod transcript;

//Eian Mod
//pub mod elgamal;

pub use errors::ProofError;
pub use generators::{BulletproofGens, BulletproofGensShare, PedersenGens};
pub use range_proof::RangeProof;


#[doc(include = "../docs/aggregation-api.md")]
pub mod aggregation {
    pub use errors::MPCError;
    pub use range_proof::dealer;
    pub use range_proof::messages;
    pub use range_proof::party;
}
