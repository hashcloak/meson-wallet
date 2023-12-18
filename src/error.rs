use ethers::prelude::ProviderError;
use ethers::signers::coins_bip39::MnemonicError as MnError;
use thiserror::Error;

//todo: clean up error type after DirectPost update

#[derive(Error, Debug)]
pub enum MnemonicError {
    #[error("{source}")]
    MnemonicError {
        #[from]
        source: MnError,
    },

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
    #[error("RPCError: {0}")]
    RPCError(String),
    #[error("SerdeError: {0}")]
    SerdeError(String),
}

impl From<serde_json::Error> for MesonError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeError(e.to_string())
    }
}
impl From<MesonError> for ProviderError {
    fn from(src: MesonError) -> Self {
        ProviderError::JsonRpcClientError(Box::new(src))
    }
}

#[derive(Error, Debug)]
pub enum MesonWalletError {
    #[error("MesonWalletError: {0}")]
    MesonWalletError(String),
    #[error("SigningError: {0}")]
    SigningError(String),
    #[error("DecryptError")]
    DecryptError,
    #[error("EncryptError")]
    EncryptError,
    #[error("IOError: {source}")]
    IOError {
        #[from]
        source: std::io::Error,
    },
    #[error("SerdeError: {source}")]
    SerdeError {
        #[from]
        source: serde_json::Error,
    },
    #[error("ConfigFileError: {0}")]
    ConfigFileError(String),
    #[error("Base64 error {source}")]
    Base64Error {
        #[from]
        source: base64ct::Error,
    },
}
