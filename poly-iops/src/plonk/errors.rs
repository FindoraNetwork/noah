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
