use crate::errors::Result;
use noah_algebra::prelude::*;

/// Trait for hashing to the curve.
pub trait HashingToCurve<G: CurveGroup> {
    /// the type of the trace of the hashing to the curve.
    /// It would be used both for the hardware wallet and for the witness generation in SNARK.
    type Trace;

    /// get the x coordinate directly.
    fn get_cofactor_uncleared_x(t: &G::BaseType) -> Result<G::BaseType>;

    /// get the x coordinate as well as the trace.
    fn get_cofactor_uncleared_x_and_trace(t: &G::BaseType) -> Result<(G::BaseType, Self::Trace)>;
}
