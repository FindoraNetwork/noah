//Zei error types

use std::{fmt, error};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    //Invalid format is passed to function
    BadSecretError,
    BadBase58Format,

}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Error::BadSecretError => "Given Secret Key is not good",
            Error::BadBase58Format => "Base58 string cannot be decoded",
        })
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::BadSecretError => "Given Secret Key is not good",
            Error::BadBase58Format => "Base58 string cannot be decoded",
        }
    }
}
