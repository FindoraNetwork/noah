pub use crate::borrow::Borrow;
pub use crate::errors::AlgebraError;
pub use crate::fmt::Formatter;
pub use crate::iter::Sum;
pub use crate::marker::PhantomData;
pub use crate::ops::*;
pub use crate::rand::{CryptoRng, Rng, RngCore, SeedableRng};
pub use crate::rand_helper::test_rng;
pub use crate::serialization::*;
pub use crate::traits::{CurveGroup, Group, LegendreSymbol, Scalar};
pub use crate::utils::*;
pub use crate::{not_matches, serialize_deserialize, One, UniformRand, Zero};
pub use ark_std::{string::String, vec, vec::Vec};
pub use itertools::Itertools;

pub(crate) type Result<T> = core::result::Result<T, AlgebraError>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
/// The ciphertext from the symmetric encryption.
pub struct CompactByteArray(pub Vec<u8>);
