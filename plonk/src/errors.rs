use ark_std::{boxed::Box, error, fmt, format, string::String};
use noah_algebra::prelude::AlgebraError;

pub(crate) type Result<T> = core::result::Result<T, PlonkError>;

#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum PlonkError {
    /// Algebra error
    Algebra(AlgebraError),
    /// Error with message
    Message(String),
    /// Group not found.
    GroupNotFound(usize),
    /// Group does not exist.
    GroupDoesNotExist,
    /// Error occurred when prove.
    ProofError,
    /// The witness if error when prove.
    ProofErrorInvalidWitness,
    /// Polynomial commitment error.
    CommitmentError,
    /// Error occurred when setup.
    SetupError,
    /// Error occurred when verify.
    VerificationError,
    /// Division by zero.
    DivisionByZero,
    /// Function params error.
    FuncParamsError,
    /// Challenge error
    ChallengeError,
    /// Cannot compute the proof as sumcheck fails.
    PCSProveEvalError,
    /// The degree of the polynomial is higher than the maximum degree supported.
    DegreeError,
}

impl fmt::Display for PlonkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PlonkError::*;
        f.write_str(match self {
            Algebra(e) => Box::leak(format!("Algebra: {}", e).into_boxed_str()),
            Message(e) => Box::leak(e.to_string().into_boxed_str()),
            GroupNotFound(_n) => "Group not found.",
            GroupDoesNotExist => "Group does not exist.",
            ProofError => "Proof error.",
            ProofErrorInvalidWitness => "Proof error invalid witness.",
            CommitmentError => "Commitment error.",
            SetupError => "Setup error.",
            VerificationError => "Verification error.",
            DivisionByZero => "Division by zero.",
            FuncParamsError => "Function params error",
            ChallengeError => "Challenge error",
            PCSProveEvalError => "Cannot compute the proof as sumcheck fails.",
            DegreeError => {
                "The degree of the polynomial is higher than the maximum degree supported."
            }
        })
    }
}

impl error::Error for PlonkError {
    #[cfg(feature = "std")]
    fn description(&self) -> &str {
        Box::leak(format!("{}", self).into_boxed_str())
    }
}

impl From<AlgebraError> for PlonkError {
    fn from(e: AlgebraError) -> PlonkError {
        PlonkError::Algebra(e)
    }
}
