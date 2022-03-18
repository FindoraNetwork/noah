use ark_std::{error, fmt};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum AlgebraError {
    ArgumentVerificationError,
    BitConversionError,
    CommitmentInputError,
    CommitmentVerificationError,
    DecompressElementError,
    DeserializationError,
    SerializationError,
    IndexError,
    ParameterError,
    InconsistentStructureError,
    SignatureError,
    GroupInversionError,
}

impl fmt::Display for AlgebraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AlgebraError::*;
        f.write_str(match self {
            ArgumentVerificationError => "Proof(argument) not valid for statement",
            BitConversionError => "Bit conversion is not valid",
            CommitmentInputError => "The number of messages to be committed is invalid",
            CommitmentVerificationError => "Commitment verification failed",
            DecompressElementError => "Could not decompress group Element",
            DeserializationError => "Could not deserialize object",
            SerializationError => "Could not serialize object",
            IndexError => "Index out of bounds",
            ParameterError => "Unexpected parameter for method or function",
            SignatureError => "Signature verification failed",
            InconsistentStructureError => "Zei Structure is inconsistent",
            GroupInversionError => "Group Element not invertible",
        })
    }
}

impl error::Error for AlgebraError {
    fn description(&self) -> &str {
        use AlgebraError::*;
        match self {
            ArgumentVerificationError => "Proof(argument) not valid for statement",
            BitConversionError => "Bit conversion is not valid",
            CommitmentInputError => "The number of messages to be committed is invalid",
            CommitmentVerificationError => "Commitment verification failed",
            DecompressElementError => "Could not decompress group Element",
            DeserializationError => "Could not deserialize object",
            SerializationError => "Could not serialize object",
            IndexError => "Index out of bounds",
            ParameterError => "Unexpected parameter for method or function",
            SignatureError => "Signature verification failed",
            InconsistentStructureError => "Zei Structure is inconsistent",
            GroupInversionError => "Group Element not invertible",
        }
    }
}
