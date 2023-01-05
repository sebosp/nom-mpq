//! Nom Parsing the MPQ file
//! NOTES:
//! - All numbers in the MoPaQ format are in little endian byte order
//! - Signed numbers use the two's complement system.
//! - Structure members are listed in the following general form:
//!   - offset from the beginning of the structure: data type(array size)
//!     member name : member description

use super::MPQ;
use nom::bytes::complete::{tag, take};
use nom::error::dbg_dmp;
use nom::HexDisplay;
use nom::IResult;
use std::convert::From;
use std::fs::File;
use std::io::prelude::*;

pub mod mpq_file_header;
pub mod mpq_file_header_ext;
pub mod mpq_hash_table_entry;
pub mod mpq_user_data;
pub use mpq_file_header::MPQFileHeader;
pub use mpq_file_header_ext::MPQFileHeaderExt;
pub use mpq_hash_table_entry::MPQHashTableEntry;
pub use mpq_user_data::MPQUserData;

pub const MPQ_ARCHIVE_HEADER_TYPE: u8 = 0x1a;
pub const MPQ_USER_DATA_HEADER_TYPE: u8 = 0x1b;
pub const LITTLE_ENDIAN: nom::number::Endianness = nom::number::Endianness::Little;

fn validate_magic(input: &[u8]) -> IResult<&[u8], &[u8]> {
    dbg_dmp(tag(b"MPQ"), "tag")(input)
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
#[tracing::instrument(skip(input), fields(i = input[0..8].to_hex(8)))]
pub fn get_header_type(input: &[u8]) -> IResult<&[u8], MPQSectionType> {
    let (input, _) = validate_magic(input)?;
    let (input, mpq_type) = take(1usize)(input)?;
    Ok((input, MPQSectionType::from(mpq_type)))
}

/// Reads the file headers, headers must contain the Archive File Header
/// but they may optionally contain the User Data Headers.
#[tracing::instrument(skip(input), fields(i = input[0..8].to_hex(8)))]
pub fn read_headers(input: &[u8]) -> IResult<&[u8], (MPQFileHeader, Option<MPQUserData>)> {
    let mut user_data: Option<MPQUserData> = None;
    let (input, mpq_type) = get_header_type(input)?;
    let (input, archive_header) = match mpq_type {
        MPQSectionType::UserData => {
            let (input, parsed_user_data) = MPQUserData::parse(input)?;
            user_data = Some(parsed_user_data);
            let (input, mpq_type) = get_header_type(input)?;
            assert!(MPQSectionType::Header == mpq_type);
            MPQFileHeader::parse(input)?
        }
        MPQSectionType::Header => MPQFileHeader::parse(input)?,
        MPQSectionType::Unknown => panic!("Unable to identify magic/section-type combination"),
    };
    Ok((input, (archive_header, user_data)))
}

/// Reads the hash table.
pub fn read_hash_table(input: &[u8]) -> IResult<&[u8], MPQHashTableEntry> {
    MPQHashTableEntry::parse(input)
}

/// Parses the whole input into an MPQ
pub fn parse(input: &[u8]) -> IResult<&[u8], MPQ> {
    let (input, (header, user_data)) = read_headers(input)?;
    let (input, hash_table) = read_hash_table(input)?;
    Ok((
        input,
        MPQ {
            user_data,
            header,
            hash_table,
        },
    ))
}

/// Convenience function to read a file to parse, mostly for testing.
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
