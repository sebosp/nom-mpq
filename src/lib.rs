//! MPQ Reader logic

use thiserror::Error;

pub mod parser;

#[derive(Error, Debug)]
pub enum MPQParserError {
    #[error("Missing {0:} in builder")]
    BuilderMissingField(String),
}

/// The MPQ User Data
#[derive(Debug, Default)]
pub struct MPQUserData {
    pub size: u32,
    pub archive_header_offset: u32,
    pub user_data: Vec<u8>,
}

/// Extended fields only present in the Burning Crusade format and later:
#[derive(Debug, PartialEq, Default)]
pub struct MPQFileHeaderExt {
    extended_block_table_offset: i64,
    hash_table_offset_high: i16,
    block_table_offset_high: i16,
}

/// The MPQ File Header
#[derive(Debug, Default)]
pub struct MPQFileHeader {
    header_size: u32,
    archive_size: u32,
    format_version: u16,
    sector_size_shift: u16,
    hash_table_offset: u32,
    block_table_offset: u32,
    hash_table_entries: u32,
    block_table_entries: u32,
    extended_file_header: Option<MPQFileHeaderExt>,
}

#[derive(Debug, Default)]
pub struct MPQ {
    pub header: MPQFileHeader,
    pub data: Option<MPQUserData>,
}
