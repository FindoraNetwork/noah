use std::fmt;

/// PLONK errors.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PlonkError {
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
}

impl fmt::Display for PlonkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = match self {
            PlonkError::GroupNotFound(_n) => "Group not found.",
            PlonkError::GroupDoesNotExist => "Group does not exist.",
            PlonkError::ProofError => "Proof error.",
            PlonkError::ProofErrorInvalidWitness => "Proof error invalid witness.",
            PlonkError::CommitmentError => "Commitment error.",
            PlonkError::SetupError => "Setup error.",
            PlonkError::VerificationError => "Verification error.",
            PlonkError::DivisionByZero => "Division by zero.",
            PlonkError::FuncParamsError => "Function params error",
        };

        write!(f, "{}", c)
    }
}
