#![forbid(unsafe_code)]

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("policy parse error: {0}")]
    PolicyParse(String),

    #[error("policy validation error: {0}")]
    PolicyValidation(String),

    #[error("no policy found for wallet: {0}")]
    NoPolicyFound(String),

    #[error("evaluation error: {0}")]
    Evaluation(String),

    #[error("address list not found: {0}")]
    AddressListNotFound(String),

    #[error("backend error: {0}")]
    Backend(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("signature not ready for session: {0}")]
    SignatureNotReady(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("config error: {0}")]
    Config(String),
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Self {
        Error::PolicyParse(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}
