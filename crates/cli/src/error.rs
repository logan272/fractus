//! Error handling

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("Invalid input format: {0}")]
    InvalidFormat(String),

    #[error("Share validation failed: {0}")]
    ShareValidation(String),

    #[error("Insufficient shares: need {needed}, have {available}")]
    InsufficientShares { needed: u8, available: usize },

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}
