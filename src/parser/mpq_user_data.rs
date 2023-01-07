//! Nom Parsing The MPQ User Data Section
//! NOTES:
//! - MPyQ uses struct_format: '<4s3I'
//!   - The devklog.net website doesn't have an entry for UserDataHeaderSize
//!     and claims the userdata starts at offset 0x0c.
//!     In this implementation the MPyQ version is honored.

use super::LITTLE_ENDIAN;
use nom::bytes::complete::take;
use nom::error::dbg_dmp;
use nom::number::complete::u32;
use nom::*;

/// The MPQ User Data
#[derive(Debug, Default)]
pub struct MPQUserData {
    pub user_data_size: u32, // This variable is unused
    pub archive_header_offset: u32,
    pub user_data_header_size: u32,
    pub content: Vec<u8>,
}

impl MPQUserData {
    /// Parses all the fields in the expected order
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, user_data_size) = Self::parse_user_data_size(input)?;
        let (input, archive_header_offset) = Self::parse_archive_header_offset(input)?;
        let (input, user_data_header_size) = Self::parse_user_data_header_size(input)?;
        let (input, content) = Self::parse_content(input, user_data_header_size)?;
        let (input, _) =
            Self::consume_until_header_offset(input, user_data_header_size, archive_header_offset)?;
        Ok((
            input,
            MPQUserData {
                user_data_size,
                archive_header_offset,
                user_data_header_size,
                content,
            },
        ))
    }

    /// Offset 0x04: int32 UserDataSize
    /// The number of bytes that have been allocated in this archive for user
    /// data. This does not need to be the exact size of the data itself, but
    /// merely the maximum amount of data which may be stored in this archive.
    pub fn parse_user_data_size(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "user_data_size")(input)
    }

    /// Offset 0x08: int32 ArchiveHeaderOffset
    /// The offset in the file at which to continue the search for the archive
    /// header.
    pub fn parse_archive_header_offset(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "archive_header_offset")(input)
    }

    /// Offset 0x0c: int32 UserDataHeaderSize
    /// The block to store user data in.
    pub fn parse_user_data_header_size(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "user_data_size")(input)
    }

    /// Offset 0x10: byte(UserDataSize) UserData
    /// The block to store user data in.
    pub fn parse_content(input: &[u8], user_data_header_size: u32) -> IResult<&[u8], Vec<u8>> {
        let (input, content) = dbg_dmp(take(user_data_header_size as usize), "content")(input)?;
        Ok((input, content.to_vec()))
    }

    /// Offset Varying: padded data
    /// Consumes until the header_offset, in MPyQ this is done through file.seek
    pub fn consume_until_header_offset(
        input: &[u8],
        user_data_header_size: u32,
        archive_header_offset: u32,
    ) -> IResult<&[u8], ()> {
        // Thus far we have read 16 bytes + the user_data_header_size
        // - 4 bytes for the magic
        // - 4 bytes for the user_data_size
        // - 4 bytes for the archive_header_offset
        // - 4 bytes for the user_data_header_size
        // - user_data_header_size bytes
        let curr_read_byte_count = 16;
        if archive_header_offset < user_data_header_size + curr_read_byte_count {
            panic!(
                "Invalid archive_header_offset: {}, should be bigger than {}",
                archive_header_offset,
                user_data_header_size + curr_read_byte_count
            );
        }
        let (input, _) = dbg_dmp(
            take((archive_header_offset - (user_data_header_size + curr_read_byte_count)) as usize),
            "content",
        )(input)?;
        Ok((input, ()))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::parser::*;

    pub fn basic_user_header() -> Vec<u8> {
        // - struct_format: '<4s3I'
        vec![
            b'M',
            b'P',
            b'Q', // Magic
            MPQ_USER_DATA_HEADER_TYPE,
            0x00,
            0x00,
            0x00,
            0x00, // user_data_size (unused)
            0x18,
            0x00,
            0x00,
            0x00, // archive_header_offset
            0x04,
            0x00,
            0x00,
            0x00, // user_data_header_size
            0xbe,
            0xef,
            0xca,
            0x4e, // content
            0x00,
            0x00,
            0x00,
            0x00, // Some padded data, MPQFileHeader should continue
        ]
    }

    #[test]
    fn it_parses_header() {
        // The user data header by itself
        let user_data_header_input = basic_user_header();
        let (input, header_type) = get_header_type(&user_data_header_input).unwrap();
        assert_eq!(header_type, MPQSectionType::UserData);
        let (input, user_data) = MPQUserData::parse(input).unwrap();
        assert_eq!(user_data.archive_header_offset, 0x18);
        assert_eq!(user_data.user_data_header_size, 0x04);
        assert_eq!(user_data.content, vec![0xbe, 0xef, 0xca, 0x4e]);
        assert_eq!(input, &b""[..]);
    }
}
