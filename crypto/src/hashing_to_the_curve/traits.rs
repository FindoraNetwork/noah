use crate::errors::Result;
use noah_algebra::prelude::*;

/// Trait for hashing to the curve.
pub trait HashingToCurve<G: CurveGroup> {
    /// get the x coordinate directly
    fn get_x_coordinate_without_cofactor_clearing(t: &G::BaseType) -> Result<G::BaseType>;
}

/// Trait for the trace of the hashing to the curve.
/// It would be used both for the hardware wallet and for the witness generation in SNARK.
pub trait HashingToCurveTrace<G: CurveGroup, H: HashingToCurve<G>> {}
