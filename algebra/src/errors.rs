use std::{error, fmt};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AlgebraError {
  ArgumentVerificationError,
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
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.write_str(match self {
                  AlgebraError::ArgumentVerificationError => "Proof(argument) not valid for statement",
                  AlgebraError::CommitmentInputError => "The number of messages to be committed is invalid",
                  AlgebraError::CommitmentVerificationError => "Commitment verification failed",
                  AlgebraError::DecompressElementError => "Could not decompress group Element",
                  AlgebraError::DeserializationError => "Could not deserialize object",
                  AlgebraError::SerializationError => "Could not serialize object",
                  AlgebraError::IndexError => "Index out of bounds",
                  AlgebraError::ParameterError => "Unexpected parameter for method or function",
                  AlgebraError::SignatureError => "Signature verification failed",
                  AlgebraError::InconsistentStructureError => "Zei Structure is inconsistent",
                  AlgebraError::GroupInversionError => { "Group Element not invertible" }
                })
  }
}

impl error::Error for AlgebraError {
  fn description(&self) -> &str {
    match self {
      AlgebraError::ArgumentVerificationError => "Proof(argument) not valid for statement",
      AlgebraError::CommitmentInputError => "The number of messages to be committed is invalid",
      AlgebraError::CommitmentVerificationError => "Commitment verification failed",
      AlgebraError::DecompressElementError => "Could not decompress group Element",
      AlgebraError::DeserializationError => "Could not deserialize object",
      AlgebraError::SerializationError => "Could not serialize object",
      AlgebraError::IndexError => "Index out of bounds",
      AlgebraError::ParameterError => "Unexpected parameter for method or function",
      AlgebraError::SignatureError => "Signature verification failed",
      AlgebraError::InconsistentStructureError => "Zei Structure is inconsistent",
      AlgebraError::GroupInversionError => { "Group Element not invertible" }
    }
  }
}
