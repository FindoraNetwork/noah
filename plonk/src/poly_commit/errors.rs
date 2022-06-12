use std::fmt;

/// Polynomial commitment scheme errors.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PolyComSchemeError {
    /// Cannot compute the proof as sumcheck fails.
    PCSProveEvalError,
    /// The degree of the polynomial is higher than the maximum degree supported.
    DegreeError,
}

impl fmt::Display for PolyComSchemeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = match self {
            PolyComSchemeError::PCSProveEvalError => "Cannot compute the proof as sumcheck fails.",
            PolyComSchemeError::DegreeError => {
                "The degree of the polynomial is higher than the maximum degree supported."
            }
        };

        write!(f, "{}", c)
    }
}
