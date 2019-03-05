//Zei error types

use std::{fmt, error};
use hex::FromHexError;
use ed25519_dalek::errors::SignatureError;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    //Invalid format is passed to function
    BadSecretError,
    BadBase58Format,
    TxProofError,
    NotEnoughFunds,
    DeserializationError,
    DecryptionError,
    NoneError,
    ParameterError,
    ProofError, //TODO need better/fine grained  proof error handling
    SignatureError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Error::BadSecretError => "Given Secret Key is not good",
            Error::BadBase58Format => "Base58 string cannot be decoded",
            Error::TxProofError => "Could not create transation due to range proof error",
            Error::NotEnoughFunds => "There is not enough funds to make this transaction",
            Error::DeserializationError => "Could not deserialize object",
            Error::DecryptionError => "Ciphertext failed authentication verification",
            Error::NoneError => "Could not unwrap option due to None value",
            Error::ParameterError => "Unexpected parameter for method or function",
            Error::ProofError => "Invalid proof or bad proof parameters",
            Error::SignatureError => "Signature verification failed",
        })
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::BadSecretError => "Given Secret Key is not good",
            Error::BadBase58Format => "Base58 string cannot be decoded",
            Error::TxProofError => "Could not create transation due to range proof error",
            Error::NotEnoughFunds => "There is not enough funds to make this transaction",
            Error::DeserializationError => "Could not deserialize object",
            Error::DecryptionError => "Could not decrypt message",
            Error::NoneError => "Could not unwrap option due to None value",
            Error::ParameterError => "Unexpected parameter for method or function",
            Error::ProofError => "Invalid proof",
            Error::SignatureError => "Signature verification failed",
        }
    }
}


impl From<FromHexError> for Error {
    fn from(_error: FromHexError) -> Self {
        Error::DeserializationError
    }
}

impl From<serde_json::Error> for Error {
    fn from(_error: serde_json::Error) -> Self {
        Error::DeserializationError
    }
}

impl From<bulletproofs::ProofError> for Error {
    fn from(_error: bulletproofs::ProofError) -> Self {
        Error::ProofError
    }
}

impl From<std::option::NoneError> for Error {
    fn from(_error: std::option::NoneError) -> Self {
        Error::NoneError
    }
}

impl From<SignatureError> for Error {
    fn from(_error: SignatureError) -> Self { Error::SignatureError }
}

