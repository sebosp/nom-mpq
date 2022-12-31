//! Nom Parsing The MPQ User Data Section

use super::LITTLE_ENDIAN;
use crate::MPQParserError;
use crate::MPQUserData;
use nom::bytes::complete::take;
use nom::number::complete::u32;
use nom::*;

#[derive(Debug, PartialEq, Default)]
pub struct MPQUserDataParser {
    user_data_size: Option<u32>,
    archive_header_offset: Option<u32>,
    user_data: Vec<u8>,
}

impl MPQUserDataParser {
    pub fn new() -> Self {
        Default::default()
    }

    /// Parses the whole section of the User Data
    pub fn parse(self, input: &[u8]) -> IResult<&[u8], Self> {
        let res = self;
        let (input, res) = res.parse_user_data_size(input)?;
        let (input, res) = res.parse_archive_header_offset(input)?;
        let (input, res) = res.parse_user_data(input)?;
        Ok((input, res))
    }

    /// Offset 0x04: int32 UserDataSize
    /// The number of bytes that have been allocated in this archive for user
    /// data. This does not need to be the exact size of the data itself, but
    /// merely the maximum amount of data which may be stored in this archive.
    pub fn parse_user_data_size(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, user_data_size) = u32(LITTLE_ENDIAN)(input)?;
        self.user_data_size = Some(user_data_size);
        Ok((input, self))
    }

    /// Offset 0x08: int32 ArchiveHeaderOffset
    /// The offset in the file at which to continue the search for the archive
    /// header.
    pub fn parse_archive_header_offset(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, archive_header_offset) = u32(LITTLE_ENDIAN)(input)?;
        self.archive_header_offset = Some(archive_header_offset);
        Ok((input, self))
    }

    /// Offset 0x0C: byte(UserDataSize) UserData
    /// The block to store user data in.
    pub fn parse_user_data(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let archive_header_offset = match self.archive_header_offset {
            Some(val) => val,
            None => panic!("MPQUserDataParser.archive_header_offset field hasn't been read yet."),
        };
        // Thus far we have read 12 bytes:
        // - The magic (4 bytes)
        // - The user data size (4 bytes)
        // - The archive header offset (4 bytes)
        if archive_header_offset <= 12 {
            panic!("Archive Header Offset should be more than 12 bytes");
        }
        let (input, user_data) = take(archive_header_offset as usize - 12usize)(input)?;
        self.user_data = user_data.to_vec();
        Ok((input, self))
    }

    pub fn build(self) -> Result<MPQUserData, MPQParserError> {
        let size = self
            .user_data_size
            .ok_or(MPQParserError::BuilderMissingField(
                "MPQUserData.user_data_size".to_string(),
            ))?;
        let archive_header_offset =
            self.archive_header_offset
                .ok_or(MPQParserError::BuilderMissingField(
                    "MPQUserData.archive_header_offset".to_string(),
                ))?;
        Ok(MPQUserData {
            size,
            archive_header_offset,
            user_data: self.user_data,
        })
    }
}
