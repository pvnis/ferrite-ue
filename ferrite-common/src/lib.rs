//! Shared types, errors, and constants for the Ferrite 5G NR UE.
//!
//! Ferrite is a clean-room implementation built from the 3GPP specifications.
//! This crate holds the vocabulary types every layer depends on.

use num_complex::Complex32;

/// A baseband IQ sample (single-precision complex).
pub type Iq = Complex32;

/// Crate-wide result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors surfaced across Ferrite layers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Underlying I/O failure (file/radio backends).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A radio backend failed.
    #[error("radio: {0}")]
    Radio(String),

    /// A physical-layer processing error.
    #[error("phy: {0}")]
    Phy(String),

    /// A parameter was outside its 3GPP-defined range.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}
