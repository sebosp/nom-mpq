//! The Hash Table Parsing
//!
//! Instead of storing file names, for quick access MoPaQs use a fixed,
//! power of two-size hash table of files in the archive. A file is uniquely
//! identified by its file path, its language, and its platform.
//! The home entry for a file in the hash table is computed as a hash of the
//! file path. In the event of a collision (the home entry is occupied by
//! another file), progressive overflow is used, and the file is placed in the
//! next available hash table entry. Searches for a desired file in the hash
//! table proceed from the home entry for the file until either the file is
//! found, the entire hash table is searched, or an empty hash table entry
//! (FileBlockIndex of 0xffffffff) is encountered.
//! The hash table is always encrypted, using the hash of "(hash table)" as the
//! key.
//! Prior to Starcraft 2, the hash table is stored uncompressed.
//! In Starcraft 2, however, the table may optionally be compressed.
//! If the offset of the block table is not equal to the offset of the
//! hash table plus the uncompressed size, Starcraft 2 interprets the
//! hash table as being compressed (not imploded).
//! This calculation assumes that the block table immediately follows the
//! hash table, and will fail or crash otherwise.
//! NOTES:
//! - MPyQ uses struct_format: '2I2HI'
//!   - The format above claims the [`platform`] is a u16.
//!   - The devklog.net website claims the [`platform`] field is u8
//!   - This version uses the u16 MPyQ version.

use super::LITTLE_ENDIAN;
use nom::number::complete::{u16, u32};
use nom::*;

#[derive(Debug, PartialEq, Default)]
pub struct MPQHashTableEntry {
    hash_a: u32,
    hash_b: u32,
    locale: u16,
    platform: u16,
    block_table_index: u32,
}

impl MPQHashTableEntry {
    /// Parses all the fields in the expected order
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, hash_a) = Self::parse_hash_a(input)?;
        let (input, hash_b) = Self::parse_hash_b(input)?;
        let (input, locale) = Self::parse_locale(input)?;
        let (input, platform) = Self::parse_platform(input)?;
        let (input, block_table_index) = Self::parse_block_table_index(input)?;
        Ok((
            input,
            MPQHashTableEntry {
                hash_a,
                hash_b,
                locale,
                platform,
                block_table_index,
            },
        ))
    }

    /// Offset 0x00: int32 FilePathHashA
    /// The hash of the file path, using method A.
    pub fn parse_hash_a(input: &[u8]) -> IResult<&[u8], u32> {
        u32(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x04: int32 FilePathHashB
    /// The hash of the file path, using method B.
    pub fn parse_hash_b(input: &[u8]) -> IResult<&[u8], u32> {
        u32(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x08h: int16 Language
    /// The language of the file. This is a Windows LANGID data type, and uses
    /// the same values.
    /// 0 indicates the default language (American English), or that the file
    /// is language-neutral.
    pub fn parse_locale(input: &[u8]) -> IResult<&[u8], u16> {
        u16(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x0a: int16 Platform
    /// The platform the file is used for. 0 indicates the default platform.
    /// No other values have been observed.
    pub fn parse_platform(input: &[u8]) -> IResult<&[u8], u16> {
        u16(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x0c: int32 FileBlockIndex
    /// If the hash table entry is valid, this is the index into the
    /// block table of the file.
    /// Otherwise, one of the following two values:
    ///
    /// * `0xffffffff` -  Hash table entry is empty, and has always been empty.
    ///   Terminates searches for a given file.
    /// * `0xfffffffe` - Hash table entry is empty, but was valid at some point
    ///   (in other words, the file was deleted).  Does not terminate searches
    ///   for a given file.
    pub fn parse_block_table_index(input: &[u8]) -> IResult<&[u8], u32> {
        u32(LITTLE_ENDIAN)(input)
    }
}
