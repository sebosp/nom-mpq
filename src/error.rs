//! Error handling of MPQ Parsing

pub use crate::parser;
use nom::error::ErrorKind;
use nom::error::ParseError;
use thiserror::Error;

/// Holds the result of parsing progress and the possibly failures
pub type MPQResult<I, O> = Result<(I, O), MPQParserError>;

/// Error handling for upstream crates to use
#[derive(Error, Debug)]
pub enum MPQParserError {
    /// Mising Archive Header
    #[error("Missing Archive Header")]
    MissingArchiveHeader,
    /// A section magic was Unexpected
    #[error("Unexpected Section")]
    UnexpectedSection,
    /// Unable to parse the byte aligned data types
    #[error("Nom ByteAligned Error {0}")]
    ByteAligned(String),
    /// An I/O Error
    #[error("IO Error")]
    IoError(#[from] std::io::Error),
    /// The Hash Table Entry wasn't found for a filename
    #[error("Hash Table Entry not found {0}")]
    HashTableEntryNotFound(String),
    /// Unable to decrypt mpq data with key
    #[error("Unable to decrypt data with key: {0}")]
    DecryptionDataWithKey(String),
    /// Incoming data, missing bytes
    #[error("Missing bytes")]
    IncompleteData,
    /// Invalid HashType number
    #[error("Invalid HashType number: {0}")]
    InvalidHashType(u32),
    /// Unsupported Compression Type
    #[error("Invalid Compression Type: {0}")]
    UnsupportedCompression(u8),
}

/// Conversion of errors from byte aligned parser
impl<I> From<nom::Err<nom::error::Error<I>>> for MPQParserError
where
    I: Clone + std::fmt::Debug,
{
    fn from(err: nom::Err<nom::error::Error<I>>) -> Self {
        match err {
            nom::Err::Incomplete(_) => {
                unreachable!("This library is compatible with only complete parsers, not streaming")
            }
            nom::Err::Error(e) => MPQParserError::ByteAligned(format!("{:?}", e)),
            nom::Err::Failure(e) => MPQParserError::ByteAligned(format!("{:?}", e)),
        }
    }
}

impl<I> ParseError<I> for MPQParserError
where
    I: Clone,
{
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        MPQParserError::ByteAligned(format!("{:?}", kind))
    }

    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}
