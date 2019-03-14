//Zei error types

use std::{fmt, error};
use ed25519_dalek::errors::SignatureError;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ZeiError {
    //Invalid format is passed to function
    DecompressElementError,
    RangeProofProveError,
    DeserializationError,
    SerializationError,
    DecryptionError,
    IndexError,
    ParameterError,
    SignatureError,
    XfrVerifyAmountError,
    XfrVerifyAssetError,
    XfrVerifyConfidentialAssetError,
    XfrCreationAmountError,
    XfrCreationAssetError,
    XfrVerifyConfidentialAmountError,
}

impl fmt::Display for ZeiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            ZeiError::DecompressElementError => "Could not decompress group Element",
            ZeiError::RangeProofProveError => "Could not create range proof due to incorrect input or parameters",
            ZeiError::DeserializationError => "Could not deserialize object",
            ZeiError::SerializationError => "Could not serialize object",
            ZeiError::DecryptionError => "Ciphertext failed authentication verification",
            ZeiError::IndexError => "Index out of bounds",
            ZeiError::ParameterError => "Unexpected parameter for method or function",
            ZeiError::SignatureError => "Signature verification failed",
            ZeiError::XfrVerifyAmountError => "Invalid amounts in non confidential amount transfer",
            ZeiError::XfrVerifyAssetError => "Invalid asset type in non confidential asset transfer",
            ZeiError::XfrVerifyConfidentialAmountError => "Invalid asset type in non confidential asset transfer",
            ZeiError::XfrVerifyConfidentialAssetError => "Invalid asset type in non confidential asset transfer",
            ZeiError::XfrCreationAmountError => "Could not create transfer. Output amount greater than input amount",
            ZeiError::XfrCreationAssetError => "Could not create transfer. Asset types do not match",
        })
    }
}

impl error::Error for ZeiError {
    fn description(&self) -> &str {
        match self {
            ZeiError::DecompressElementError => "Could not decompress group Element",
            ZeiError::RangeProofProveError => "Could not create range proof due to incorrect input or parameters",
            ZeiError::DeserializationError => "Could not deserialize object",
            ZeiError::SerializationError => "Could not serialize object",
            ZeiError::DecryptionError => "Could not decrypt message",
            ZeiError::IndexError => "Index out of bounds",
            ZeiError::ParameterError => "Unexpected parameter for method or function",
            ZeiError::SignatureError => "Signature verification failed",
            ZeiError::XfrVerifyAmountError => "Invalid amounts in non confidential transfer",
            ZeiError::XfrVerifyAssetError => "Invalid asset type in non confidential asset transfer",
            ZeiError::XfrVerifyConfidentialAmountError => "Invalid asset type in non confidential asset transfer",
            ZeiError::XfrVerifyConfidentialAssetError => "Invalid asset type in non confidential asset transfer",
            ZeiError::XfrCreationAmountError => "Could not create transfer. Output amount greater than input amount",
            ZeiError::XfrCreationAssetError => "Could not create transfer. Asset types do not match",
        }
    }
}

impl From<serde_json::Error> for ZeiError {
    fn from(_error: serde_json::Error) -> Self {
        ZeiError::DeserializationError
    }
}

impl From<SignatureError> for ZeiError {
    fn from(_error: SignatureError) -> Self { ZeiError::SignatureError }
}

impl From<rmp_serde::encode::Error> for ZeiError {
    fn from(_error: rmp_serde::encode::Error) -> Self { ZeiError::SerializationError }
}

