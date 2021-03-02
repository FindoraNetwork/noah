use std::fmt;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PlonkError {
    GroupNotFound(usize),
    GroupDoesNotExist,
    ProofError,
    ProofErrorInvalidWitness,
    CommitmentError,
    SetupError,
    VerificationError,
    DivisionByZero,
    FuncParamsError,
}

impl fmt::Display for PlonkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = match self {
            PlonkError::GroupNotFound(_n) => "GroupNotFound",
            PlonkError::GroupDoesNotExist => "GroupDoesNotExist",
            PlonkError::ProofError => "ProofError",
            PlonkError::ProofErrorInvalidWitness => "ProofErrorInvalidWitness",
            PlonkError::CommitmentError => "CommitmentError",
            PlonkError::SetupError => "SetupError",
            PlonkError::VerificationError => "VerificationError",
            PlonkError::DivisionByZero => "DivisionByZero",
            PlonkError::FuncParamsError => "FuncParamsError",
        };

        write!(f, "{}", c)
    }
}
