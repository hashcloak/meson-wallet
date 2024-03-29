use thiserror::Error;

#[derive(Error, Debug)]
pub enum MnemonicError {
    #[error("Mac Mismatch")]
    MacMismatch,

    #[error("serde-json: {0}")]
    SerdeJson(String),

    #[error("scrypt error{0}")]
    Scrypt(String),

    #[error("IO error {0}")]
    StdIOError(String),

    #[error("Base64 error {0}")]
    Base64Error(String),

    #[error("UTF8 error {0}")]
    UTF8Error(String),
}

impl From<scrypt::errors::InvalidParams> for MnemonicError {
    fn from(e: scrypt::errors::InvalidParams) -> Self {
        Self::Scrypt(e.to_string())
    }
}

impl From<scrypt::errors::InvalidOutputLen> for MnemonicError {
    fn from(e: scrypt::errors::InvalidOutputLen) -> Self {
        Self::Scrypt(e.to_string())
    }
}

impl From<serde_json::Error> for MnemonicError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeJson(e.to_string())
    }
}

impl From<std::io::Error> for MnemonicError {
    fn from(e: std::io::Error) -> Self {
        Self::StdIOError(e.to_string())
    }
}

impl From<std::str::Utf8Error> for MnemonicError {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::UTF8Error(e.to_string())
    }
}

impl From<base64ct::Error> for MnemonicError {
    fn from(e: base64ct::Error) -> Self {
        Self::Base64Error(e.to_string())
    }
}

#[derive(Error, Debug)]
pub enum MesonError {
    #[error("MesonError: {0}")]
    MesonError(String),
}

#[derive(Error, Debug)]
pub enum MesonWalletError {
    #[error("MesonWalletError")]
    MesonWalletError(String),
}
