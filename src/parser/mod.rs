//! Nom Parsing the MPQ file
//! NOTES:
//! - All numbers in the MoPaQ format are in little endian byte order
//! - Signed numbers use the two's complement system.
//! - Structure members are listed in the following general form: offset from the beginning of the structure: data type(array size) member name : member description

use super::{MPQFileHeader, MPQFileHeaderExt, MPQ};
use nom::bytes::complete::{tag, take};
use nom::error::dbg_dmp;
use nom::number::complete::{i16, i64, u16, u32};
use nom::*;
use std::convert::From;
use std::fs::File;
use std::io::prelude::*;

pub mod mpq_file_header_parser;
pub mod mpq_user_data_parser;
pub use mpq_file_header_parser::MPQFileHeaderParser;
pub use mpq_user_data_parser::MPQUserDataParser;

pub const MPQ_ARCHIVE_HEADER_TYPE: u8 = 0x1a;
pub const MPQ_USER_DATA_HEADER_TYPE: u8 = 0x1b;
pub const LITTLE_ENDIAN: nom::number::Endianness = nom::number::Endianness::Little;

fn validate_magic(input: &[u8]) -> IResult<&[u8], &[u8]> {
    dbg_dmp(tag(b"MPQ"), "tag")(input)
}

#[derive(Debug, PartialEq)]
pub enum MPQSectionType {
    UserData(MPQUserDataParser),
    Header(MPQFileHeaderParser),
    Unknown,
}

impl MPQSectionType {
    pub fn build_archive_header(self) -> Result<MPQFileHeader, String> {
        if let Self::Header(archive_header) = self {
            archive_header.build()
        } else {
            Err("Wrong section type".to_string())
        }
    }
}

impl From<&[u8]> for MPQSectionType {
    fn from(input: &[u8]) -> Self {
        if input.len() != 1 {
            Self::Unknown
        } else {
            match input[0] {
                MPQ_ARCHIVE_HEADER_TYPE => Self::Header(MPQFileHeaderParser::new()),
                MPQ_USER_DATA_HEADER_TYPE => Self::UserData(MPQUserDataParser::new()),
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

pub fn read_mpq_archive_header(
    header_parser: MPQFileHeaderParser,
    input: &[u8],
) -> IResult<&[u8], MPQSectionType> {
    let (input, header) = header_parser.parse(input)?;
    Ok((input, MPQSectionType::Header(header)))
}

pub fn read_mpq_user_data(
    user_data_parser: MPQUserDataParser,
    input: &[u8],
) -> IResult<&[u8], MPQSectionType> {
    let (input, user_data) = user_data_parser.parse(input)?;
    Ok((input, MPQSectionType::UserData(user_data)))
}
/// The MPQ section headers contain the sizes in the headers
pub fn read_section_data(input: &[u8], mpq_type: MPQSectionType) -> IResult<&[u8], MPQSectionType> {
    match mpq_type {
        MPQSectionType::UserData(user_data_builder) => read_mpq_user_data(user_data_builder, input),
        MPQSectionType::Header(header_builder) => read_mpq_archive_header(header_builder, input),
        _ => unreachable!(),
    }
}

/// Parses the whole input into an MPQ
pub fn parse(input: &[u8]) -> IResult<&[u8], MPQ> {
    let mut res = MPQ::default();
    let (input, mpq_type) = get_mpq_type(input).unwrap();
    let (input, mpq_type) = read_section_data(input, mpq_type).unwrap();
    match mpq_type {
        MPQSectionType::UserData(user_data) => {
            res.data = Some(user_data.build().unwrap());
            // The UserData should be followed by the ArchiveHeader.
            let (input, new_mpq_type) = get_mpq_type(input).unwrap();
            let (input, new_mpq_type) = read_section_data(input, new_mpq_type).unwrap();
            res.header = new_mpq_type.build_archive_header().unwrap();
            Ok((input, res))
        }
        MPQSectionType::Header(header) => {
            res.header = header.build().unwrap();
            Ok((input, res))
        }
        MPQSectionType::Unknown => unreachable!(),
    }
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
    fn it_parses_user_data_magic() {
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
            Ok((
                &b"\x00\x02\x00\x00"[..],
                MPQSectionType::UserData(MPQUserDataParser::new())
            ))
        );
        assert_eq!(
            get_mpq_type(&archive_header),
            Ok((
                &b"\xd0\x00\x00\x00"[..],
                MPQSectionType::Header(MPQFileHeaderParser::new())
            ))
        );
    }
}
