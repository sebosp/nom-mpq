//! Nom Parsing The MPQ User Data Section

use super::LITTLE_ENDIAN;
use nom::bytes::complete::take;
use nom::number::complete::u32;
use nom::*;

/// The MPQ User Data
#[derive(Debug, Default)]
pub struct MPQUserData {
    pub user_data_size: u32,
    pub archive_header_offset: u32,
    pub user_data: Vec<u8>,
}

impl MPQUserData {
    /// Parses all the fields in the expected order
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, user_data_size) = Self::parse_user_data_size(input)?;
        let (input, archive_header_offset) = Self::parse_archive_header_offset(input)?;
        let (input, user_data) = Self::parse_user_data(input, archive_header_offset)?;
        Ok((
            input,
            MPQUserData {
                user_data_size,
                archive_header_offset,
                user_data,
            },
        ))
    }

    /// Offset 0x04: int32 UserDataSize
    /// The number of bytes that have been allocated in this archive for user
    /// data. This does not need to be the exact size of the data itself, but
    /// merely the maximum amount of data which may be stored in this archive.
    pub fn parse_user_data_size(input: &[u8]) -> IResult<&[u8], u32> {
        u32(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x08: int32 ArchiveHeaderOffset
    /// The offset in the file at which to continue the search for the archive
    /// header.
    pub fn parse_archive_header_offset(input: &[u8]) -> IResult<&[u8], u32> {
        u32(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x0C: byte(UserDataSize) UserData
    /// The block to store user data in.
    pub fn parse_user_data(input: &[u8], archive_header_offset: u32) -> IResult<&[u8], Vec<u8>> {
        // Thus far we have read 12 bytes:
        // - The magic (4 bytes)
        // - The user data size (4 bytes)
        // - The archive header offset (4 bytes)
        if archive_header_offset <= 12 {
            panic!("Archive Header Offset should be more than 12 bytes");
        }
        let (input, user_data) = take(archive_header_offset as usize - 12usize)(input)?;
        Ok((input, user_data.to_vec()))
    }
}

#[cfg(test)]
pub mod tests {
    use super::mpq_file_header::tests::basic_file_header;
    use super::*;

    pub fn basic_user_header() -> Vec<u8> {
        vec![
            b'M', b'P', b'Q', // Magic
            0x1b, // 0x1b for User Data
            0x00, 0x00, 0x00, 0x04, // The user data size, 4 bytes
            0x00, 0x00, 0x00, 0x11, // The archive header offset
            0x00, 0x00, 0x00, 0x00, // 4 bytes of empty user data.
        ]
    }

    #[test]
    fn it_parses_header() {
        let mut user_data_header_input = basic_user_header();
        let archive_header = basic_file_header();
        let (input, header_type) = get_mpq_type(&user_data_header_input).unwrap();
        assert_eq!(header_type, MPQSectionType::UserData);
        let (input, header_type) = get_mpq_type(&archive_header_input).unwrap();
        assert_eq!(header_type, MPQSectionType::Header);
        user_data_header_input.append(&mut archive_header_input);
        let (input, header_type) = get_mpq_type(&archive_header_input).unwrap();
        assert_eq!(
            get_mpq_type(&archive_header),
            Ok((&b"\xd0\x00\x00\x00"[..], MPQSectionType::Header,))
        );
    }
}
