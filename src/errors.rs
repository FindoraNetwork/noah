use ed25519_dalek::SignatureError;
use std::{error, fmt};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ZeiError {
  ArgumentVerificationError,
  DecompressElementError,
  RangeProofProveError,
  RangeProofVerifyError,
  DeserializationError,
  SerializationError,
  DecryptionError,
  IndexError,
  ParameterError,
  InconsistentStructureError,
  SignatureError,
  XfrVerifyAssetAmountError,
  XfrVerifyConfidentialAssetError,
  XfrCreationAssetAmountError,
  XfrVerifyAssetTracingAssetAmountError,
  XfrVerifyAssetTracingIdentityError,
  XfrVerifyAssetTracingEmptyProofError,
  XfrVerifyConfidentialAmountError,
  ElGamalVerificationError,
  ElGamalDecryptionError,
  IdentityRevealVerifyError,
  AssetMixerVerificationError,
  XfrNotSupported,
  MerkleTreeVerificationError,
  WhitelistVerificationError,
  WhitelistProveError,
  SolvencyProveError,
  SolvencyVerificationError,
  ZKProofVerificationError,
  GroupSignatureTraceError,
  AssetTracingExtractionError,
  IdentityTracingExtractionError,
  AnonymousCredentialSignError,
  R1CSProofError,
}

impl fmt::Display for ZeiError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.write_str(match self {
                  ZeiError::ArgumentVerificationError => "Proof(argument) not valid for statement",
                  ZeiError::DecompressElementError => "Could not decompress group Element",
                  ZeiError::RangeProofProveError => {
                    "Could not create range proof due to incorrect input or parameters"
                  }
                  ZeiError::RangeProofVerifyError => {
                    "Range proof invalid for input commitments or parameters"
                  }
                  ZeiError::DeserializationError => "Could not deserialize object",
                  ZeiError::SerializationError => "Could not serialize object",
                  ZeiError::DecryptionError => "Ciphertext failed authentication verification",
                  ZeiError::IndexError => "Index out of bounds",
                  ZeiError::ParameterError => "Unexpected parameter for method or function",
                  ZeiError::SignatureError => "Signature verification failed",
                  ZeiError::XfrVerifyAssetAmountError => {
                    "Invalid total amount per asset in non confidential asset transfer"
                  }
                  ZeiError::XfrVerifyConfidentialAmountError => {
                    "Invalid asset type in non confidential asset transfer"
                  }
                  ZeiError::XfrVerifyAssetTracingAssetAmountError => {
                    "Asset Tracking error. Asset commitment and asset ciphertext do not match."
                  }
                  ZeiError::XfrVerifyAssetTracingIdentityError => {
                    "Asset Tracking error. Identity reveal proof does not hold"
                  }
                  ZeiError::XfrVerifyAssetTracingEmptyProofError => {
                    "Asset Tracking error. Tracked assets must contain asset tracking proof"
                  }
                  ZeiError::XfrVerifyConfidentialAssetError => {
                    "Invalid asset type in non confidential asset transfer"
                  }
                  ZeiError::XfrCreationAssetAmountError => {
                    "Invalid total amount per asset in non confidential asset transfer"
                  }
                  ZeiError::ElGamalVerificationError => {
                    "ElGamal Ciphertext not valid for proposed scalar message"
                  }
                  ZeiError::ElGamalDecryptionError => "ElGamal Ciphertext could not be decrypted",
                  ZeiError::InconsistentStructureError => "Zei Structure is inconsistent",
                  ZeiError::IdentityRevealVerifyError => {
                    "Verification error for confidential identity reveal proof"
                  }
                  ZeiError::AssetMixerVerificationError => {
                    "Verification error for asset mixing proof"
                  }
                  ZeiError::XfrNotSupported => "Transaction type not supported",
                  ZeiError::MerkleTreeVerificationError => {
                    "Invalid proof for merkle tree inclusion"
                  }
                  ZeiError::WhitelistVerificationError => "Invalid proof for whitelist inclusion",
                  ZeiError::WhitelistProveError => "Cannot build proof for whitelist",
                  ZeiError::SolvencyVerificationError => "Invalid proof for solvency",
                  ZeiError::SolvencyProveError => "Cannot build proof of solvency",
                  ZeiError::ZKProofVerificationError => "Invalid proof",
                  ZeiError::GroupSignatureTraceError => "Trace test did not match",
                  ZeiError::AssetTracingExtractionError => {
                    "Cannot extract correct data from tracing ciphertext"
                  }
                  ZeiError::IdentityTracingExtractionError => {
                    "Cannot extract identity attributes from tracing ciphertext"
                  }
                  ZeiError::AnonymousCredentialSignError =>{"The number of attributes passed as parameter differs from the number of attributes of the AC issuer public key."}
                  ZeiError::R1CSProofError => { "Could not create R1CSProof" }
                })
  }
}

impl error::Error for ZeiError {
  fn description(&self) -> &str {
    match self {
      ZeiError::ArgumentVerificationError => "Proof(argument) not valid for statement",
      ZeiError::DecompressElementError => "Could not decompress group Element",
      ZeiError::RangeProofProveError => {
        "Could not create range proof due to incorrect input or parameters"
      }
      ZeiError::RangeProofVerifyError => "Range proof invalid for input commitments or parameters",
      ZeiError::DeserializationError => "Could not deserialize object",
      ZeiError::SerializationError => "Could not serialize object",
      ZeiError::DecryptionError => "Could not decrypt message",
      ZeiError::IndexError => "Index out of bounds",
      ZeiError::ParameterError => "Unexpected parameter for method or function",
      ZeiError::SignatureError => "Signature verification failed",
      ZeiError::XfrVerifyAssetAmountError => {
        "Invalid total amount per asset in non confidential asset transfer"
      }
      ZeiError::XfrVerifyConfidentialAmountError => {
        "Invalid asset type in non confidential asset transfer"
      }
      ZeiError::XfrVerifyAssetTracingAssetAmountError => {
        "Asset Tracking error. Asset commitment and asset ciphertext do not match."
      }
      ZeiError::XfrVerifyAssetTracingIdentityError => {
        "Asset Tracking error. Identity reveal proof does not hold"
      }
      ZeiError::XfrVerifyAssetTracingEmptyProofError => {
        "Asset Tracking error. Tracked assets must contain asset tracking proof"
      }
      ZeiError::XfrVerifyConfidentialAssetError => {
        "Invalid asset type in non confidential asset transfer"
      }
      ZeiError::XfrCreationAssetAmountError => {
        "Invalid total amount per asset in non confidential asset transfer"
      }
      ZeiError::ElGamalVerificationError => {
        "ElGamal Ciphertext not valid for proposed scalar message"
      }
      ZeiError::ElGamalDecryptionError => "ElGamal Ciphertext could not be decrypted",
      ZeiError::InconsistentStructureError => "Zei Structure is inconsistent",
      ZeiError::IdentityRevealVerifyError => {
        "Verification error for confidential identity reveal proof"
      }
      ZeiError::AssetMixerVerificationError => "Verification error for asset mixing proof",
      ZeiError::XfrNotSupported => "Transaction type not supported",
      ZeiError::MerkleTreeVerificationError => "Invalid proof for merkle tree inclusion",
      ZeiError::WhitelistVerificationError => "Invalid proof for whitelist inclusion",
      ZeiError::WhitelistProveError => "Cannot build proof for whitelist",
      ZeiError::SolvencyVerificationError => "Invalid proof for solvency",
      ZeiError::SolvencyProveError => "Cannot build proof of solvency",
      ZeiError::ZKProofVerificationError => "Invalid proof",
      ZeiError::GroupSignatureTraceError => "Trace test did not match",
      ZeiError::AssetTracingExtractionError => {
        "Cannot extract correct data from tracing ciphertext"
      },
      ZeiError::IdentityTracingExtractionError => {
        "Cannot extract identity attributes from tracing ciphertext"
      },
      ZeiError::AnonymousCredentialSignError => {"The number of attributes passed as parameter differs from the number of attributes of the AC issuer public key."},
      ZeiError::R1CSProofError =>{"Could not create R1CSProof"}
    }
  }
}

impl From<serde_json::Error> for ZeiError {
  fn from(_error: serde_json::Error) -> Self {
    ZeiError::DeserializationError
  }
}

impl From<SignatureError> for ZeiError {
  fn from(_error: SignatureError) -> Self {
    ZeiError::SignatureError
  }
}

impl From<rmp_serde::encode::Error> for ZeiError {
  fn from(_error: rmp_serde::encode::Error) -> Self {
    ZeiError::SerializationError
  }
}
