//! Nom Parsing the MPQ file
//! NOTES:
//! - All numbers in the MoPaQ format are in little endian byte order
//! - Signed numbers use the two's complement system.
//! - Structure members are listed in the following general form:
//!   - offset from the beginning of the structure: data type(array size)
//!     member name : member description

use super::{MPQBuilder, MPQ};
use nom::bytes::complete::{tag, take};
use nom::error::dbg_dmp;
use nom::number::Endianness;
use nom::HexDisplay;
use nom::IResult;
use std::convert::From;
use std::convert::TryFrom;
use std::fs::File;
use std::io::prelude::*;

pub mod mpq_block_table_entry;
pub mod mpq_file_header;
pub mod mpq_file_header_ext;
pub mod mpq_hash_table_entry;
pub mod mpq_user_data;
pub use mpq_block_table_entry::MPQBlockTableEntry;
pub use mpq_file_header::MPQFileHeader;
pub use mpq_file_header_ext::MPQFileHeaderExt;
pub use mpq_hash_table_entry::MPQHashTableEntry;
pub use mpq_user_data::MPQUserData;

pub const MPQ_ARCHIVE_HEADER_TYPE: u8 = 0x1a;
pub const MPQ_USER_DATA_HEADER_TYPE: u8 = 0x1b;
pub const LITTLE_ENDIAN: Endianness = Endianness::Little;

fn validate_magic(input: &[u8]) -> IResult<&[u8], &[u8]> {
    dbg_dmp(tag(b"MPQ"), "tag")(input)
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum MPQHashType {
    TableOffset,
    HashA,
    HashB,
    Table,
}

impl TryFrom<u32> for MPQHashType {
    type Error = String;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::TableOffset),
            1 => Ok(Self::HashA),
            2 => Ok(Self::HashB),
            3 => Ok(Self::Table),
            _ => Err(format!("Unknown HashType number {}", value)),
        }
    }
}

impl TryFrom<MPQHashType> for u32 {
    type Error = String;
    fn try_from(value: MPQHashType) -> Result<Self, Self::Error> {
        match value {
            MPQHashType::TableOffset => Ok(0),
            MPQHashType::HashA => Ok(1),
            MPQHashType::HashB => Ok(2),
            MPQHashType::Table => Ok(3),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum MPQSectionType {
    UserData,
    Header,
    Unknown,
}

impl From<&[u8]> for MPQSectionType {
    fn from(input: &[u8]) -> Self {
        if input.len() != 1 {
            Self::Unknown
        } else {
            match input[0] {
                MPQ_ARCHIVE_HEADER_TYPE => Self::Header,
                MPQ_USER_DATA_HEADER_TYPE => Self::UserData,
                _ => Self::Unknown,
            }
        }
    }
}

/// Gets the header type from the MPQ file
#[tracing::instrument(level = "trace", skip(input), fields(i = input[0..8].to_hex(8)))]
pub fn get_header_type(input: &[u8]) -> IResult<&[u8], MPQSectionType> {
    let (input, _) = validate_magic(input)?;
    let (input, mpq_type) = dbg_dmp(take(1usize), "mpq_type")(input)?;
    let mpq_type = MPQSectionType::from(mpq_type);
    tracing::debug!(
        "({:<16?}, tail: {})",
        mpq_type,
        input[0..8].to_hex(8).trim_end()
    );
    Ok((input, mpq_type))
}

/// Reads the file headers, headers must contain the Archive File Header
/// but they may optionally contain the User Data Headers.
#[tracing::instrument(level = "trace", skip(input), fields(i = input[0..8].to_hex(8)))]
pub fn read_headers(input: &[u8]) -> IResult<&[u8], (MPQFileHeader, Option<MPQUserData>)> {
    let mut user_data: Option<MPQUserData> = None;
    let (input, mpq_type) = get_header_type(input)?;
    let (input, archive_header) = match mpq_type {
        MPQSectionType::UserData => {
            let (input, parsed_user_data) = MPQUserData::parse(input)?;
            let header_offset = parsed_user_data.archive_header_offset;
            user_data = Some(parsed_user_data);
            // If there is user data, it must be immediately followed by the Archive Header
            let (input, mpq_type) = get_header_type(input)?;
            assert!(MPQSectionType::Header == mpq_type);
            MPQFileHeader::parse(input, header_offset as usize)?
        }
        MPQSectionType::Header => MPQFileHeader::parse(input, 0)?,
        MPQSectionType::Unknown => panic!("Unable to identify magic/section-type combination"),
    };
    Ok((input, (archive_header, user_data)))
}

/// Parses the whole input into an MPQ
pub fn parse(orig_input: &[u8]) -> IResult<&[u8], MPQ> {
    let builder = MPQBuilder::new();
    let hash_table_key = builder.mpq_string_hash("(hash table)", MPQHashType::Table);
    let block_table_key = builder.mpq_string_hash("(block table)", MPQHashType::Table);
    let (tail, (archive_header, user_data)) = read_headers(orig_input)?;
    // "seek" to the hash table offset.
    let hash_table_offset = archive_header.hash_table_offset as usize + archive_header.offset;
    let mut hash_table_entries = vec![];
    {
        let mut hash_table_position = &orig_input[hash_table_offset..];
        for _ in 0..archive_header.hash_table_entries {
            let (new_hash_table_position, hash_table_data) =
                dbg_dmp(take(16usize), "hash_table_data")(hash_table_position)?;
            let decrypted_entry = match builder.mpq_data_decrypt(hash_table_data, hash_table_key) {
                Ok((_, value)) => value,
                Err(_) => continue,
            };
            match MPQHashTableEntry::parse(&decrypted_entry) {
                Ok((_, val)) => hash_table_entries.push(val),
                Err(_) => continue,
            };
            hash_table_position = new_hash_table_position;
        }
    }
    // "seek" to the block table offset.
    let block_table_offset = archive_header.block_table_offset as usize + archive_header.offset;
    let mut block_table_position = &orig_input[block_table_offset..];
    let mut block_table_entries = vec![];
    for _ in 0..archive_header.block_table_entries {
        let (new_block_table_position, block_table_data) =
            dbg_dmp(take(16usize), "block_table_data")(&block_table_position)?;
        let decrypted_entry = match builder.mpq_data_decrypt(block_table_data, block_table_key) {
            Ok((_, value)) => value,
            Err(_) => continue,
        };
        match MPQBlockTableEntry::parse(&decrypted_entry) {
            Ok((_, val)) => block_table_entries.push(val),
            Err(_) => continue,
        };
        block_table_position = new_block_table_position;
    }
    let mpq = builder
        .with_archive_header(archive_header)
        .with_user_data(user_data)
        .with_hash_table(hash_table_entries)
        .with_block_table(block_table_entries)
        .build(orig_input)
        .unwrap();
    Ok((tail, mpq))
}

/// Convenience fMPQHashTableEntryunction to read a file to parse, mostly for testing.
pub fn read_file(path: &str) -> Vec<u8> {
    let mut f = File::open(path).unwrap();
    let mut buffer: Vec<u8> = vec![];
    // read the whole file
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

#[cfg(test)]
mod tests {
    use super::mpq_file_header::tests::basic_file_header;
    use super::mpq_user_data::tests::basic_user_header;
    use super::*;
    use nom::HexDisplay;
    use test_log::test;

    #[test]
    fn it_parses_headers() {
        // Let's build the MoPaQ progressively.
        let mut user_data_header_input = basic_user_header();
        let mut archive_header_input = basic_file_header();
        user_data_header_input.append(&mut archive_header_input);
        println!("{}", user_data_header_input.to_hex(8));
        let (_input, (_archive_header, user_data_header)) =
            read_headers(&user_data_header_input).unwrap();
        assert!(user_data_header.is_some());
    }
}
