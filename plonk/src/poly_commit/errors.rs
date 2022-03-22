use std::fmt;

/// Polynomial commitment scheme errors.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PolyComSchemeError {
    /// It is not possible to compute the proof as F(x) != y.
    PCSProveEvalError,
    /// Polynomial degree does not match the public parameters size.
    PCSCommitError,
    /// The degree of the polynomial is higher than the maximum degree allowed.
    DegreeError,
}

impl fmt::Display for PolyComSchemeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = match self {
            PolyComSchemeError::PCSProveEvalError => {
                "It is not possible to compute the proof as F(x) != y."
            }
            PolyComSchemeError::PCSCommitError => {
                "Polynomial degree does not match the public parameters size."
            }
            PolyComSchemeError::DegreeError => {
                "The degree of the polynomial is higher than the maximum degree allowed."
            }
        };

        write!(f, "{}", c)
    }
}
