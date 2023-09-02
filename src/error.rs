//! Error handling of MPQ Parsing

pub use crate::parser;
use nom::error::ErrorKind;
use nom::error::ParseError;
use thiserror::Error;

/// Error handling for upstream crates to use
#[derive(Error, Debug)]
pub enum MPQParserError {
    /// A section magic was Unexpected
    #[error("Unexpected Section")]
    UnexpectedSection,
    /// This error does not use `input: I` from `ParserError`,
    /// just to avoid carrying over the <I> generic
    #[error("Nom Error {0}")]
    Parser(String),
}

impl ParseError<&[u8]> for MPQParserError {
    fn from_error_kind(input: &[u8], kind: ErrorKind) -> Self {
        MPQParserError::Parser(format!("{:?}: {}", kind, parser::peek_hex(input)))
    }

    fn append(_input: &[u8], _kind: ErrorKind, other: Self) -> Self {
        other
    }
}
