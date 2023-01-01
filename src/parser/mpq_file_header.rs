//! Nom Parsing The MPQ File Header
//! NOTES:
//! - MPyQ uses struct_format: '<4s2I2H4I'

use super::LITTLE_ENDIAN;
use nom::number::complete::{i16, i64, u16, u32};
use nom::*;

/// Extended fields only present in the Burning Crusade format and later:
#[derive(Debug, PartialEq, Default)]
pub struct MPQFileHeaderExt {
    extended_block_table_offset: i64,
    hash_table_offset_high: i16,
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

    /// Offset 0x20: int64 ExtendedBlockTableOffset
    /// Offset to the beginning of the extended block table, relative to the beginning of the archive.
    pub fn parse_extended_block_table_offset(input: &[u8]) -> IResult<&[u8], i64> {
        i64(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x28: int16 HashTableOffsetHigh
    /// High 16 bits of the hash table offset for large archives.
    pub fn parse_hash_table_offset_high(input: &[u8]) -> IResult<&[u8], i16> {
        i16(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x2A: int16 BlockTableOffsetHigh
    /// High 16 bits of the block table offset for large archives.
    pub fn parse_block_table_offset_high(input: &[u8]) -> IResult<&[u8], i16> {
        i16(LITTLE_ENDIAN)(input)
    }
}

/// The MPQ File Header
#[derive(Debug, Default, PartialEq)]
pub struct MPQFileHeader {
    header_size: u32,
    archive_size: u32,
    format_version: u16,
    sector_size_shift: u16,
    hash_table_offset: u32,
    block_table_offset: u32,
    hash_table_entries: u32,
    block_table_entries: u32,
    extended_file_header: Option<MPQFileHeaderExt>,
}

impl MPQFileHeader {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header_size) = Self::parse_header_size(input)?;
        let (input, archive_size) = Self::parse_archive_size(input)?;
        let (input, format_version) = Self::parse_format_version(input)?;
        let (input, sector_size_shift) = Self::parse_sector_size_shift(input)?;
        let (input, hash_table_offset) = Self::parse_hash_table_offset(input)?;
        let (input, block_table_offset) = Self::parse_block_table_offset(input)?;
        let (input, hash_table_entries) = Self::parse_hash_table_entries(input)?;
        let (input, block_table_entries) = Self::parse_block_table_entries(input)?;
        let (input, extended_file_header) =
            Self::parse_extended_header_if_needed(input, format_version)?;
        Ok((
            input,
            MPQFileHeader {
                header_size,
                archive_size,
                format_version,
                sector_size_shift,
                hash_table_offset,
                block_table_offset,
                hash_table_entries,
                block_table_entries,
                extended_file_header,
            },
        ))
    }

    /// Offset 0x04: int32 HeaderSize
    /// Size of the archive header.
    pub fn parse_header_size(input: &[u8]) -> IResult<&[u8], u32> {
        u32(LITTLE_ENDIAN)(input)
    }

    /// Offset: 0x08 int32 ArchiveSize
    /// Size of the whole archive, including the header.
    /// Does not include the strong digital signature, if present.
    /// This size is used, among other things, for determining the
    /// region to hash in computing the digital signature.
    /// This field is deprecated in the Burning Crusade MoPaQ format,
    /// and the size of the archive
    /// is calculated as the size from the beginning of the archive to
    /// the end of the hash table, block table, or extended block table
    /// (whichever is largest).
    pub fn parse_archive_size(input: &[u8]) -> IResult<&[u8], u32> {
        u32(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x0c: int16 FormatVersion
    /// MoPaQ format version. MPQAPI will not open archives where
    /// this is negative. Known versions:
    /// - 0x0000 Original format. HeaderSize should be 0x20, and large
    ///          archives are not supported.
    /// - 0x0001 Burning Crusade format. Header size should be 0x2c,
    ///          and large archives are supported.
    pub fn parse_format_version(input: &[u8]) -> IResult<&[u8], u16> {
        u16(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x0e: int8 SectorSizeShift
    /// Power of two exponent specifying the number of 512-byte
    /// disk sectors in each logical sector in the archive. The size
    /// of each logical sector in the archive is:
    /// 512 * 2^SectorSizeShift.
    /// Bugs in the Storm library dictate that this shouldalways be:
    /// 3 (4096 byte sectors).
    pub fn parse_sector_size_shift(input: &[u8]) -> IResult<&[u8], u16> {
        u16(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x10: int32 HashTableOffset
    /// Offset to the beginning of the hash table,
    /// relative to the beginning of the archive.
    pub fn parse_hash_table_offset(input: &[u8]) -> IResult<&[u8], u32> {
        u32(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x14: int32 BlockTableOffset
    /// Offset to the beginning of the block table,
    /// relative to the beginning of the archive.
    pub fn parse_block_table_offset(input: &[u8]) -> IResult<&[u8], u32> {
        u32(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x18: int32 HashTableEntries
    /// Desc: Number of entries in the hash table.
    /// Must be a power of two, and must be:
    ///   less than 2^16 for the original MoPaQ format,
    ///   or less than 2^20 for the Burning Crusade format.
    pub fn parse_hash_table_entries(input: &[u8]) -> IResult<&[u8], u32> {
        u32(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x1c: int32 BlockTableEntries
    /// Number of entries in the block table.
    pub fn parse_block_table_entries(input: &[u8]) -> IResult<&[u8], u32> {
        u32(LITTLE_ENDIAN)(input)
    }

    /// Offset 0x20: ExtendedBlockTable
    /// Extended Block Table only present in Burning Crusade format and later:
    pub fn parse_extended_header_if_needed(
        input: &[u8],
        format_version: u16,
    ) -> IResult<&[u8], Option<MPQFileHeaderExt>> {
        if format_version != 1u16 {
            return Ok((input, None));
        }
        let (input, extended_file_header) = MPQFileHeaderExt::parse(input)?;
        Ok((input, Some(extended_file_header)))
    }
}
