//! Nom Parsing The MPQ File Header Extended
//! NOTES:
//! - MPyQ uses struct_format: 'q2h'

use super::LITTLE_ENDIAN;
use nom::error::dbg_dmp;
use nom::number::complete::{i16, i64};
use nom::*;

/// Extended fields only present in the Burning Crusade format and later
#[derive(Debug, PartialEq, Default, Clone, Copy)]
pub struct MPQFileHeaderExt {
    /// Offset to the beginning of the extended block table, relative to the beginning of the archive.
    extended_block_table_offset: i64,
    /// High 16 bits of the hash table offset for large archives.
    hash_table_offset_high: i16,
    /// High 16 bits of the block table offset for large archives.
    block_table_offset_high: i16,
}

impl MPQFileHeaderExt {
    /// Parses all the fields in the expected order
    pub fn parse(input: &[u8]) -> IResult<&[u8], MPQFileHeaderExt> {
        let (input, extended_block_table_offset) = Self::parse_extended_block_table_offset(input)?;
        let (input, hash_table_offset_high) = Self::parse_hash_table_offset_high(input)?;
        let (input, block_table_offset_high) = Self::parse_block_table_offset_high(input)?;
        Ok((
            input,
            MPQFileHeaderExt {
                extended_block_table_offset,
                hash_table_offset_high,
                block_table_offset_high,
            },
        ))
    }

    /// `Offset 0x20`: int64 ExtendedBlockTableOffset
    ///
    /// Offset to the beginning of the extended block table, relative to the beginning of the archive.
    pub fn parse_extended_block_table_offset(input: &[u8]) -> IResult<&[u8], i64> {
        dbg_dmp(i64(LITTLE_ENDIAN), "extended_block_table_offset")(input)
    }

    /// `Offset 0x28`: int16 HashTableOffsetHigh
    ///
    /// High 16 bits of the hash table offset for large archives.
    pub fn parse_hash_table_offset_high(input: &[u8]) -> IResult<&[u8], i16> {
        dbg_dmp(i16(LITTLE_ENDIAN), "hash_table_offset_high")(input)
    }

    /// `Offset 0x2A`: int16 BlockTableOffsetHigh
    ///
    /// High 16 bits of the block table offset for large archives.
    pub fn parse_block_table_offset_high(input: &[u8]) -> IResult<&[u8], i16> {
        dbg_dmp(i16(LITTLE_ENDIAN), "block_table_offset_high")(input)
    }
}
