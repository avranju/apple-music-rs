use std::time::SystemTimeError;

use biscuit::errors::Error as BiscuitError;
use pem::PemError;
use ring::error::KeyRejected;
use serde_json::error::Error as SerdeJsonError;

pub enum Error {
    Pem,
    Token,
    Serde,
}

impl From<PemError> for Error {
    fn from(_: PemError) -> Self {
        Error::Pem
    }
}

impl From<BiscuitError> for Error {
    fn from(_: BiscuitError) -> Self {
        Error::Token
    }
}

impl From<SystemTimeError> for Error {
    fn from(_: SystemTimeError) -> Self {
        Error::Token
    }
}

impl From<KeyRejected> for Error {
    fn from(_: KeyRejected) -> Self {
        Error::Token
    }
}

impl From<SerdeJsonError> for Error {
    fn from(_: SerdeJsonError) -> Self {
        Error::Serde
    }
}
