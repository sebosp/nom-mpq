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
use nom::IResult;
use std::convert::From;
use std::fs::File;
use std::io::prelude::*;

pub mod mpq_file_header;
pub mod mpq_hash_table_entry;
pub mod mpq_user_data;
pub use mpq_file_header::MPQFileHeader;
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

/// Gets the header from the MPQ file
pub fn get_mpq_type(input: &[u8]) -> IResult<&[u8], MPQSectionType> {
    let (input, _) = validate_magic(input)?;
    let (input, mpq_type) = take(1usize)(input)?;
    Ok((input, MPQSectionType::from(mpq_type)))
}

/// Parses the whole input into an MPQ
pub fn parse(input: &[u8]) -> IResult<&[u8], MPQ> {
    let mut res = MPQ::default();
    let (input, mpq_type) = get_mpq_type(input).unwrap();
    let (input, res) = match mpq_type {
        MPQSectionType::UserData => {
            let (input, user_data) = MPQUserData::parse(input)?;
            res.user_data = Some(user_data);
            let (input, mpq_type) = get_mpq_type(input)?;
            assert!(MPQSectionType::Header == mpq_type);
            let (input, header) = MPQFileHeader::parse(input)?;
            res.header = header;
            (input, res)
        }
        MPQSectionType::Header => {
            let (input, header) = MPQFileHeader::parse(input)?;
            res.header = header;
            (input, res)
        }
        MPQSectionType::Unknown => panic!("Unable to identify magic/section-type combination"),
    };
    Ok((input, res))
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
    use super::*;

    #[test]
    fn it_parses_magic() {
        let user_data_header: Vec<u8> = vec![
            b'M', b'P', b'Q', // Magic
            0x1b, // 0x1b for User Data
            0x00, 0x02, 0x00, 0x00, // The user data size
        ];
        let archive_header: Vec<u8> = vec![
            b'M', b'P', b'Q', // Magic
            0x1a, // 0x1a for Archive Header
            0xd0, 0x00, 0x00, 0x00, // The archive header size
        ];
        assert_eq!(
            get_mpq_type(&user_data_header),
            Ok((&b"\x00\x02\x00\x00"[..], MPQSectionType::UserData,))
        );
        assert_eq!(
            get_mpq_type(&archive_header),
            Ok((&b"\xd0\x00\x00\x00"[..], MPQSectionType::Header,))
        );
    }
}
