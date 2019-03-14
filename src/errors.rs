//Zei error types

use std::{fmt, error};
use hex::FromHexError;
use ed25519_dalek::errors::SignatureError;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ZeiError {
    //Invalid format is passed to function
    DecompressElementError,
    BadSecretError,
    BadBase58Format,
    TxProofError,
    NotEnoughFunds,
    DeserializationError,
    SerializationError,
    DecryptionError,
    NoneError,
    ParameterError,
    ProofError, //TODO need better/fine grained  proof error handling
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
            ZeiError::BadSecretError => "Given Secret Key is not good",
            ZeiError::BadBase58Format => "Base58 string cannot be decoded",
            ZeiError::TxProofError => "Could not create transation due to range proof error",
            ZeiError::NotEnoughFunds => "There is not enough funds to make this transaction",
            ZeiError::DeserializationError => "Could not deserialize object",
            ZeiError::SerializationError => "Could not serialize object",
            ZeiError::DecryptionError => "Ciphertext failed authentication verification",
            ZeiError::NoneError => "Could not unwrap option due to None value",
            ZeiError::ParameterError => "Unexpected parameter for method or function",
            ZeiError::ProofError => "Invalid proof or bad proof parameters",
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
            ZeiError::BadSecretError => "Given Secret Key is not good",
            ZeiError::BadBase58Format => "Base58 string cannot be decoded",
            ZeiError::TxProofError => "Could not create transation due to range proof error",
            ZeiError::NotEnoughFunds => "There is not enough funds to make this transaction",
            ZeiError::DeserializationError => "Could not deserialize object",
            ZeiError::SerializationError => "Could not serialize object",
            ZeiError::DecryptionError => "Could not decrypt message",
            ZeiError::NoneError => "Could not unwrap option due to None value",
            ZeiError::ParameterError => "Unexpected parameter for method or function",
            ZeiError::ProofError => "Invalid proof",
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


impl From<FromHexError> for ZeiError {
    fn from(_error: FromHexError) -> Self {
        ZeiError::DeserializationError
    }
}

impl From<serde_json::Error> for ZeiError {
    fn from(_error: serde_json::Error) -> Self {
        ZeiError::DeserializationError
    }
}

impl From<bulletproofs::ProofError> for ZeiError {
    fn from(_error: bulletproofs::ProofError) -> Self {
        ZeiError::XfrVerifyConfidentialAmountError
    }
}

impl From<std::option::NoneError> for ZeiError {
    fn from(_error: std::option::NoneError) -> Self {
        ZeiError::NoneError
    }
}

impl From<SignatureError> for ZeiError {
    fn from(_error: SignatureError) -> Self { ZeiError::SignatureError }
}

impl From<rmp_serde::encode::Error> for ZeiError {
    fn from(_error: rmp_serde::encode::Error) -> Self { ZeiError::SerializationError }
}

