//! MPQ Reader logic

use thiserror::Error;

pub mod parser;
pub use parser::MPQFileHeader;
pub use parser::MPQHashTableEntry;
pub use parser::MPQUserData;

#[derive(Error, Debug)]
pub enum MPQParserError {
    #[error("Unexpected Section")]
    UnexpectedSection,
}

#[derive(Debug, Default)]
pub struct MPQ {
    pub archive_header: MPQFileHeader,
    pub user_data: Option<MPQUserData>,
    pub hash_table: MPQHashTableEntry,
}
