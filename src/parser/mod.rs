//! Nom Parsing the MPQ file format
//!
//! NOTES:
//! - All numbers in the MoPaQ format are in little endian byte order
//! - Signed numbers use the two's complement system.
//! - Structure members are listed in the following general form:
//!   - offset from the beginning of the structure: data type(array size)
//!     member name : member description

use crate::{MPQParserError, MPQResult};

use super::{MPQBuilder, MPQ};
use nom::bytes::complete::{tag, take};
use nom::error::dbg_dmp;
use nom::multi::count;
use nom::number::Endianness;
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

/// Final byte of the magic to identify particularly the Archive Header.
pub const MPQ_ARCHIVE_HEADER_TYPE: u8 = 0x1a;
/// Final byte of the magic to identify particularly the User Data.
pub const MPQ_USER_DATA_HEADER_TYPE: u8 = 0x1b;
/// The numeric values read are encoded in little endian LE
pub const LITTLE_ENDIAN: Endianness = Endianness::Little;
/// The characters used as displayable by [`peek_hex`]
pub static CHARS: &[u8] = b"0123456789abcdef";

/// Validates the first three bytes of the magic, it must be followed by either the
/// [`MPQ_ARCHIVE_HEADER_TYPE`] or the [`MPQ_USER_DATA_HEADER_TYPE`]
fn validate_magic(input: &[u8]) -> MPQResult<&[u8], &[u8]> {
    dbg_dmp(tag(b"MPQ"), "tag")(input).map_err(|e| e.into())
}

/// Different HashTypes used in MPQ Archives, they are used to identify
/// embedded filenames.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum MPQHashType {
    /// A hashing of type TableOffset
    TableOffset,
    /// A Hashing of type A
    HashA,
    /// A Hashing of type B
    HashB,
    /// A Hashing of type Table
    Table,
}

impl TryFrom<u32> for MPQHashType {
    type Error = MPQParserError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::TableOffset),
            1 => Ok(Self::HashA),
            2 => Ok(Self::HashB),
            3 => Ok(Self::Table),
            _ => Err(MPQParserError::InvalidHashType(value)),
        }
    }
}

impl TryFrom<MPQHashType> for u32 {
    type Error = MPQParserError;
    fn try_from(value: MPQHashType) -> Result<Self, Self::Error> {
        match value {
            MPQHashType::TableOffset => Ok(0),
            MPQHashType::HashA => Ok(1),
            MPQHashType::HashB => Ok(2),
            MPQHashType::Table => Ok(3),
        }
    }
}

/// The type of sections that are available in an MPQ archive
#[derive(Debug, PartialEq)]
pub enum MPQSectionType {
    /// The MPQ Section is of type User Data
    UserData,
    /// The MPQ Section is of type Header
    Header,
    /// The MPQ Section type is unknown.
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

/// A helper function that shows only up to the first 8 bytes of an u8 slice in
/// xxd format.
pub fn peek_hex(data: &[u8]) -> String {
    let mut max_length = 8usize;
    if data.len() < max_length {
        max_length = data.len();
    }
    let data = &data[0..max_length];
    let chunk_size = 8usize;
    let mut v = Vec::with_capacity(data.len() * 3);
    for chunk in data.chunks(chunk_size) {
        v.push(b'[');
        let mut even_space = false;
        for &byte in chunk {
            v.push(CHARS[(byte >> 4) as usize]);
            v.push(CHARS[(byte & 0xf) as usize]);
            if even_space {
                v.push(b' ');
            }
            even_space = !even_space;
        }
        if chunk_size > chunk.len() {
            for _j in 0..(chunk_size - chunk.len()) {
                v.push(b' ');
                v.push(b' ');
                v.push(b' ');
            }
        }
        v.push(b' ');

        for &byte in chunk {
            if (32..=126).contains(&byte) {
                v.push(byte);
            } else {
                v.push(b'.');
            }
        }
        v.push(b']');
        v.push(b',');
    }
    v.pop();
    String::from_utf8_lossy(&v[..]).into_owned()
}

/// Gets the header type from the MPQ file
#[tracing::instrument(level = "trace", skip(input), fields(input = peek_hex(input)))]
pub fn get_header_type(input: &[u8]) -> MPQResult<&[u8], MPQSectionType> {
    let (input, _) = validate_magic(input)?;
    let (input, mpq_type) = dbg_dmp(take(1usize), "mpq_type")(input)?;
    let mpq_type = MPQSectionType::from(mpq_type);
    Ok((input, mpq_type))
}

/// Reads the file headers, headers must contain the Archive File Header
/// but they may optionally contain the User Data Headers.
#[tracing::instrument(level = "trace", skip(input), fields(input = peek_hex(input)))]
pub fn read_headers(input: &[u8]) -> MPQResult<&[u8], (MPQFileHeader, Option<MPQUserData>)> {
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
        MPQSectionType::Unknown => {
            tracing::error!("Unable to identify magic/section-type combination");
            return MPQResult::Err(MPQParserError::MissingArchiveHeader);
        }
    };
    Ok((input, (archive_header, user_data)))
}

/// Parses the whole input into an MPQ
pub fn parse(orig_input: &[u8]) -> MPQResult<&[u8], MPQ> {
    let builder = MPQBuilder::new();
    let hash_table_key = builder.mpq_string_hash("(hash table)", MPQHashType::Table)?;
    let block_table_key = builder.mpq_string_hash("(block table)", MPQHashType::Table)?;
    let (tail, (archive_header, user_data)) = read_headers(orig_input)?;
    // "seek" to the hash table offset.
    let hash_table_offset = archive_header.hash_table_offset as usize + archive_header.offset;
    let (_, encrypted_hash_table_data) = dbg_dmp(
        take(16usize * archive_header.hash_table_entries as usize),
        "encrypted_hash_table_data",
    )(&orig_input[hash_table_offset..])?;
    let decrypted_hash_table_data =
        match builder.mpq_data_decrypt(encrypted_hash_table_data, hash_table_key) {
            Ok((_, value)) => value,
            Err(err) => {
                tracing::warn!(
                    "Unabe to use key: '{}' to decrypt MPQHashTable data: {}: {:?}",
                    hash_table_key,
                    peek_hex(encrypted_hash_table_data),
                    err,
                );
                return Err(MPQParserError::DecryptionDataWithKey(
                    hash_table_key.to_string(),
                ));
            }
        };
    let (_, hash_table_entries) = match count(
        MPQHashTableEntry::parse,
        archive_header.hash_table_entries as usize,
    )(&decrypted_hash_table_data)
    {
        Ok((tail, value)) => (tail, value),
        Err(err) => {
            tracing::error!("Unable to use decrypted data: {:?}", err);
            return Err(MPQParserError::IncompleteData);
        }
    };
    // "seek" to the block table offset.
    let block_table_offset = archive_header.block_table_offset as usize + archive_header.offset;
    let (_, encrypted_block_table_data) = dbg_dmp(
        take(16usize * archive_header.block_table_entries as usize),
        "encrypted_block_table_data",
    )(&orig_input[block_table_offset..])?;
    let (_, decrypted_block_table_data) =
        builder.mpq_data_decrypt(encrypted_block_table_data, block_table_key)?;
    let (_, block_table_entries) = match count(
        MPQBlockTableEntry::parse,
        archive_header.block_table_entries as usize,
    )(&decrypted_block_table_data)
    {
        Ok((tail, value)) => (tail, value),
        Err(err) => {
            tracing::error!("Unable to use decrypted data: {:?}", err);
            return Err(MPQParserError::IncompleteData);
        }
    };
    let mpq = builder
        .with_archive_header(archive_header)
        .with_user_data(user_data)
        .with_hash_table(hash_table_entries)
        .with_block_table(block_table_entries)
        .build(orig_input)
        .unwrap();
    Ok((tail, mpq))
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
    use test_log::test;

    #[test]
    fn it_parses_headers() {
        // Let's build the MoPaQ progressively.
        let mut user_data_header_input = basic_user_header();
        let mut archive_header_input = basic_file_header();
        user_data_header_input.append(&mut archive_header_input);
        let (_input, (_archive_header, user_data_header)) =
            read_headers(&user_data_header_input).unwrap();
        assert!(user_data_header.is_some());
    }
    #[test]
    fn it_generates_hashes() {
        let builder = MPQBuilder::new();
        let hash_table_key = builder
            .mpq_string_hash("(hash table)", MPQHashType::Table)
            .unwrap();
        let block_table_key = builder
            .mpq_string_hash("(block table)", MPQHashType::Table)
            .unwrap();
        assert_eq!(hash_table_key, 0xc3af3770);
        assert_eq!(block_table_key, 0xec83b3a3);
        let encrypted_hash_table_data = vec![
            0x07, 0xf8, 0xb8, 0x55, 0x4f, 0xb4, 0x8e, 0x3c, 0x7c, 0xa8, 0x7b, 0xac, 0xae, 0x1a,
            0x00, 0xe0, 0xc7, 0xc9, 0xdc, 0xc5, 0x3e, 0x6c, 0xfe, 0xc3, 0xa2, 0x02, 0x33, 0xa7,
            0xb8, 0x1b, 0x6d, 0xb7, 0x83, 0x4f, 0x4c, 0x63, 0x15, 0x59, 0x4d, 0xf8, 0xda, 0x7e,
            0x55, 0xfa, 0xe7, 0xb5, 0x2b, 0x0b, 0xe6, 0xd8, 0x76, 0xe6, 0xef, 0x30, 0x78, 0x8b,
            0x70, 0x31, 0xdb, 0x02, 0xa2, 0x78, 0xb8, 0x89, 0x07, 0x90, 0x24, 0xb9, 0xb4, 0xec,
            0xdc, 0xa3, 0x53, 0xe9, 0x4e, 0x95, 0xfc, 0x4e, 0x52, 0x15, 0x92, 0x59, 0xe3, 0xf1,
            0x37, 0x9f, 0x4b, 0xec, 0x53, 0x8d, 0x7c, 0x04, 0x02, 0xdc, 0xe7, 0xcd, 0x95, 0xfe,
            0x32, 0x21, 0x83, 0x94, 0x8d, 0x32, 0x23, 0x36, 0xa9, 0xd4, 0x76, 0xe1, 0x58, 0x3e,
            0x12, 0x12, 0x33, 0x2a, 0xb1, 0x95, 0x30, 0x1e, 0xff, 0xac, 0x45, 0x0e, 0xb1, 0x11,
            0xd5, 0x00, 0xc1, 0xed, 0x64, 0x49, 0xd4, 0xa3, 0x4b, 0x5a, 0xe0, 0x69, 0x0a, 0x5a,
            0x35, 0x4a, 0x31, 0xd5, 0xa7, 0x53, 0xe3, 0xf8, 0xd8, 0x27, 0x11, 0x93, 0x86, 0x65,
            0x21, 0xd5, 0x3d, 0xfd, 0xd6, 0x4d, 0x45, 0x62, 0xda, 0xc3, 0x7b, 0x0c, 0xab, 0xc7,
            0x9d, 0x48, 0xbb, 0xbf, 0x15, 0x21, 0xfe, 0xe0, 0xca, 0x9e, 0x9a, 0x07, 0x3c, 0x91,
            0x65, 0x26, 0xe1, 0xbb, 0x74, 0xeb, 0xce, 0x93, 0x32, 0x20, 0xad, 0x73, 0x59, 0x9c,
            0x96, 0x24, 0xae, 0xfd, 0xf7, 0x99, 0xcf, 0xbb, 0x09, 0xf2, 0x39, 0x61, 0x4e, 0x36,
            0xd5, 0x80, 0xdb, 0x5b, 0xa2, 0x61, 0x5a, 0x3d, 0xc2, 0x0b, 0xe3, 0x23, 0x30, 0x5a,
            0xd4, 0xcd, 0xc6, 0x4a, 0x11, 0x47, 0xa1, 0x95, 0x7d, 0xbb, 0xd8, 0xcf, 0x76, 0xcf,
            0xc9, 0x04, 0x13, 0x75, 0xba, 0x19, 0x98, 0xc8, 0xd6, 0xe3, 0xbe, 0x91, 0xb2, 0x1c,
            0x6e, 0xb0, 0x8d, 0x87,
        ];
        let decrypted_hash_table_data = vec![
            0xcb, 0x37, 0x84, 0xd3, 0xec, 0xea, 0xdf, 0x07, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
            0x00, 0x00, 0x4b, 0xa5, 0xc2, 0xaa, 0x95, 0x2b, 0x76, 0xf4, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x70, 0xb7, 0xe5, 0xc9,
            0xb6, 0xf6, 0x18, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x7b, 0x08,
            0x3c, 0x34, 0x82, 0x36, 0x8e, 0x27, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
            0xa0, 0x1e, 0x2b, 0x3b, 0x57, 0xf0, 0x2e, 0xb7, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
            0x00, 0x00, 0xdc, 0x8b, 0x7e, 0x5a, 0x5c, 0x3f, 0x25, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x10, 0x79, 0x65, 0xfd, 0xa7, 0x98, 0x9b, 0x4e, 0x00, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x9c, 0xc2, 0x83, 0xd3, 0x92, 0x2e, 0x40, 0xef,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xcf, 0xb0, 0xa8, 0x1d, 0x28, 0xff, 0xce, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
            0x00, 0x00, 0x89, 0x22, 0x95, 0x31, 0xa3, 0xfa, 0x5f, 0x6a, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00,
        ];
        let (_, decrypted_entries) = builder
            .mpq_data_decrypt(&encrypted_hash_table_data, hash_table_key)
            .unwrap();
        assert_eq!(decrypted_entries, decrypted_hash_table_data);
        let encrypted_block_table_data = vec![
            0xa7, 0x67, 0x48, 0x3d, 0x7a, 0xd1, 0x08, 0xca, 0x4c, 0xbc, 0x35, 0xf8, 0x06, 0x04,
            0x34, 0xe9, 0xbe, 0xb3, 0xb5, 0xb3, 0x7d, 0xeb, 0x0e, 0x11, 0x05, 0xb9, 0xf4, 0x17,
            0xd3, 0x1b, 0x38, 0x21, 0x2f, 0xfd, 0x94, 0x62, 0xa1, 0xea, 0xe2, 0x2e, 0x29, 0xde,
            0xe8, 0xdf, 0x4d, 0x84, 0x0b, 0x54, 0x88, 0xe4, 0x87, 0xdc, 0xcc, 0xca, 0xd6, 0xf6,
            0xe6, 0xb4, 0x09, 0x0c, 0xf8, 0x27, 0xec, 0x87, 0x5d, 0x33, 0x7b, 0x3a, 0x9c, 0xb5,
            0xd9, 0x80, 0x8c, 0x3c, 0x19, 0x81, 0x6c, 0x76, 0xec, 0xac, 0x53, 0x55, 0xd6, 0xa6,
            0xf6, 0x7d, 0x18, 0xfb, 0xa9, 0x86, 0x30, 0x33, 0x29, 0xcb, 0x63, 0x11, 0xfa, 0xb5,
            0xe6, 0x02, 0x7f, 0x23, 0x4b, 0xe9, 0xd8, 0x77, 0x0c, 0x4d, 0xc8, 0x1e, 0x41, 0xe9,
            0xf2, 0x84, 0x6e, 0xc6, 0x75, 0xbd, 0x47, 0x8b, 0x04, 0x7d, 0x48, 0xd9, 0xc2, 0xa1,
            0x02, 0x0d, 0x04, 0xdf, 0xb3, 0xc7, 0x82, 0xf5, 0x77, 0x37, 0x81, 0x9d, 0x7f, 0xfb,
            0x65, 0x5d, 0x96, 0xe3, 0xa2, 0x0a, 0x68, 0x1b, 0xb6, 0x6b, 0x7c, 0x12, 0x3e, 0x7b,
            0x63, 0x9c, 0x00, 0x7b, 0x7e, 0x23,
        ];
        let decrypted_block_table_data = vec![
            0x2c, 0x00, 0x00, 0x00, 0xd7, 0x02, 0x00, 0x00, 0x7a, 0x03, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x81, 0x03, 0x03, 0x00, 0x00, 0x21, 0x03, 0x00, 0x00, 0xe9, 0x04, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x81, 0x24, 0x06, 0x00, 0x00, 0x30, 0xf6, 0x02, 0x00, 0x7d, 0x52,
            0x07, 0x00, 0x00, 0x02, 0x00, 0x81, 0x54, 0xfc, 0x02, 0x00, 0xe2, 0x00, 0x00, 0x00,
            0x4e, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x81, 0x36, 0xfd, 0x02, 0x00, 0x61, 0x00,
            0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x81, 0x97, 0xfd, 0x02, 0x00,
            0x2b, 0x05, 0x00, 0x00, 0xb2, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00, 0x81, 0xc2, 0x02,
            0x03, 0x00, 0x07, 0x19, 0x00, 0x00, 0x8f, 0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x81,
            0xc9, 0x1b, 0x03, 0x00, 0x15, 0x02, 0x00, 0x00, 0x60, 0x09, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x81, 0xde, 0x1d, 0x03, 0x00, 0x78, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x81, 0x56, 0x1e, 0x03, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x20, 0x01,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x81,
        ];
        let (_, decrypted_entries) = builder
            .mpq_data_decrypt(&encrypted_block_table_data, block_table_key)
            .unwrap();
        assert_eq!(decrypted_entries, decrypted_block_table_data);
    }
}
