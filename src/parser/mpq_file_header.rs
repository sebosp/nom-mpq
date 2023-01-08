//! Nom Parsing The MPQ File Header
//! NOTES:
//! - MPyQ uses struct_format: '<4s2I2H4I'

use super::MPQFileHeaderExt;
use super::LITTLE_ENDIAN;
use nom::error::dbg_dmp;
use nom::number::complete::{u16, u32};
use nom::*;

/// The MPQ File Header
#[derive(Debug, Default, PartialEq)]
pub struct MPQFileHeader {
    pub header_size: u32,
    pub archive_size: u32,
    pub format_version: u16,
    pub sector_size_shift: u16,
    pub hash_table_offset: u32,
    pub block_table_offset: u32,
    pub hash_table_entries: u32,
    pub block_table_entries: u32,
    pub extended_file_header: Option<MPQFileHeaderExt>,
    // Store the offset at which the FileHeader was found.
    // this is done because other offsets are relative to this one.
    pub offset: usize,
}

impl MPQFileHeader {
    pub fn parse(input: &[u8], offset: usize) -> IResult<&[u8], Self> {
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
                offset,
            },
        ))
    }

    /// Offset 0x04: int32 HeaderSize
    /// Size of the archive header.
    pub fn parse_header_size(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "header_size")(input)
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
        dbg_dmp(u32(LITTLE_ENDIAN), "archive_size")(input)
    }

    /// Offset 0x0c: int16 FormatVersion
    /// MoPaQ format version. MPQAPI will not open archives where
    /// this is negative. Known versions:
    /// - 0x0000 Original format. HeaderSize should be 0x20, and large
    ///          archives are not supported.
    /// - 0x0001 Burning Crusade format. Header size should be 0x2c,
    ///          and large archives are supported.
    pub fn parse_format_version(input: &[u8]) -> IResult<&[u8], u16> {
        dbg_dmp(u16(LITTLE_ENDIAN), "format_version")(input)
    }

    /// Offset 0x0e: int8 SectorSizeShift
    /// Power of two exponent specifying the number of 512-byte
    /// disk sectors in each logical sector in the archive. The size
    /// of each logical sector in the archive is:
    /// 512 * 2^SectorSizeShift.
    /// Bugs in the Storm library dictate that this shouldalways be:
    /// 3 (4096 byte sectors).
    pub fn parse_sector_size_shift(input: &[u8]) -> IResult<&[u8], u16> {
        dbg_dmp(u16(LITTLE_ENDIAN), "sector_size_shift")(input)
    }

    /// Offset 0x10: int32 HashTableOffset
    /// Offset to the beginning of the hash table,
    /// relative to the beginning of the archive.
    pub fn parse_hash_table_offset(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "hash_table_offset")(input)
    }

    /// Offset 0x14: int32 BlockTableOffset
    /// Offset to the beginning of the block table,
    /// relative to the beginning of the archive.
    pub fn parse_block_table_offset(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "block_table_offset")(input)
    }

    /// Offset 0x18: int32 HashTableEntries
    /// Desc: Number of entries in the hash table.
    /// Must be a power of two, and must be:
    ///   less than 2^16 for the original MoPaQ format,
    ///   or less than 2^20 for the Burning Crusade format.
    pub fn parse_hash_table_entries(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "hash_table_entries")(input)
    }

    /// Offset 0x1c: int32 BlockTableEntries
    /// Number of entries in the block table.
    pub fn parse_block_table_entries(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "block_table_entries")(input)
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

#[cfg(test)]
pub mod tests {
    use crate::parser::*;

    pub fn basic_file_header() -> Vec<u8> {
        // struct_format: '<4s2I2H4I'
        vec![
            b'M',
            b'P',
            b'Q', // Magic
            MPQ_ARCHIVE_HEADER_TYPE,
            0xd0,
            0x00,
            0x00,
            0x00, // header_size
            0xcf,
            0xa3,
            0x03,
            0x00, // archive_size
            0x03,
            0x00, // format_version
            0x05,
            0x00, // sector_size_shift
            0xbf,
            0xa0,
            0x03,
            0x00, // hash_table_offset
            0xbf,
            0xa2,
            0x03,
            0x00, // block_table_offset
            0x01,
            0x00,
            0x00,
            0x00, // hash_table_entries
            0x02,
            0x00,
            0x00,
            0x00, // block_table_entries
        ]
    }

    #[test]
    fn it_parses_header() {
        // The archive header by itself
        let basic_file_header_input = basic_file_header();
        let (input, header_type) = get_header_type(&basic_file_header_input).unwrap();
        assert_eq!(header_type, MPQSectionType::Header);
        let (_input, header_data) = MPQFileHeader::parse(input, 0).unwrap();
        assert_eq!(header_data.hash_table_entries, 1);
        assert_eq!(header_data.block_table_entries, 2);
    }
}
