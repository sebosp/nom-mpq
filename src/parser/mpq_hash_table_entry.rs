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
//!   - In this implementation the u16 MPyQ version is honored.

use super::LITTLE_ENDIAN;
use nom::error::dbg_dmp;
use nom::number::complete::{u16, u32};
use nom::*;

#[derive(Debug, PartialEq, Default, Clone)]
pub struct MPQHashTableEntry {
    pub hash_a: u32,
    pub hash_b: u32,
    pub locale: u16,
    pub platform: u16,
    pub block_table_index: u32,
}

impl MPQHashTableEntry {
    /// This method is not related to parsing but for testing, maybe we should consider further
    /// splitting this into a MPQHashTableEntryParser, maybe overkill.
    pub fn new(
        hash_a: u32,
        hash_b: u32,
        locale: u16,
        platform: u16,
        block_table_index: u32,
    ) -> Self {
        Self {
            hash_a,
            hash_b,
            locale,
            platform,
            block_table_index,
        }
    }

    /// Parses all the fields in the expected order
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (tail, hash_a) = Self::parse_hash_a(input)?;
        let (tail, hash_b) = Self::parse_hash_b(tail)?;
        let (tail, locale) = Self::parse_locale(tail)?;
        let (tail, platform) = Self::parse_platform(tail)?;
        let (tail, block_table_index) = Self::parse_block_table_index(tail)?;
        Ok((
            tail,
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
        dbg_dmp(u32(LITTLE_ENDIAN), "hash_a")(input)
    }

    /// Offset 0x04: int32 FilePathHashB
    /// The hash of the file path, using method B.
    pub fn parse_hash_b(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "hash_b")(input)
    }

    /// Offset 0x08h: int16 Language
    /// The language of the file. This is a Windows LANGID data type, and uses
    /// the same values.
    /// 0 indicates the default language (American English), or that the file
    /// is language-neutral.
    pub fn parse_locale(input: &[u8]) -> IResult<&[u8], u16> {
        dbg_dmp(u16(LITTLE_ENDIAN), "locale")(input)
    }

    /// Offset 0x0a: int16 Platform
    /// The platform the file is used for. 0 indicates the default platform.
    /// No other values have been observed.
    pub fn parse_platform(input: &[u8]) -> IResult<&[u8], u16> {
        dbg_dmp(u16(LITTLE_ENDIAN), "platform")(input)
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
        dbg_dmp(u32(LITTLE_ENDIAN), "block_table_index")(input)
    }
}
