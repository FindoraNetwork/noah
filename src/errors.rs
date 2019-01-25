//Zei error types

use std::{fmt, error};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    //Invalid format is passed to function
    BadSecretError,
    TxProofError,
    NotEnoughFunds,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Error::BadSecretError => "Given Secret Key is not good",
            Error::TxProofError => "Could not create transation due to range proof error",
            Error::NotEnoughFunds => "There is not enough funds to make this transaction",
        })
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::BadSecretError => "Given Secret Key is not good",
            Error::TxProofError => "Could not create transation due to range proof error",
            Error::NotEnoughFunds => "There is not enough funds to make this transaction",
        }
    }
}