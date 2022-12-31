//! Nom Parsing The MPQ File Header

use super::LITTLE_ENDIAN;
use crate::MPQParserError;
use crate::{MPQFileHeader, MPQFileHeaderExt};
use nom::number::complete::{i16, i64, u16, u32};
use nom::*;

/// Extended fields only present in the Burning Crusade format and later:
#[derive(Debug, PartialEq, Default)]
pub struct MPQFileHeaderExtParser {
    extended_block_table_offset: Option<i64>,
    hash_table_offset_high: Option<i16>,
    block_table_offset_high: Option<i16>,
}

impl MPQFileHeaderExtParser {
    pub fn new() -> Self {
        Default::default()
    }

    /// Parses the whole section in the order of the archive.
    pub fn parse(self, input: &[u8]) -> IResult<&[u8], Self> {
        let res = self;
        let (input, res) = res.parse_extended_block_table_offset(input)?;
        let (input, res) = res.parse_hash_table_offset_high(input)?;
        let (input, res) = res.parse_block_table_offset_high(input)?;
        Ok((input, res))
    }

    /// Offset 0x20: int64 ExtendedBlockTableOffset
    /// Offset to the beginning of the extended block table, relative to the beginning of the archive.
    pub fn parse_extended_block_table_offset(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, extended_block_table_offset) = i64(LITTLE_ENDIAN)(input)?;
        self.extended_block_table_offset = Some(extended_block_table_offset);
        Ok((input, self))
    }

    /// Offset 0x28: int16 HashTableOffsetHigh
    /// High 16 bits of the hash table offset for large archives.
    pub fn parse_hash_table_offset_high(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, hash_table_offset_high) = i16(LITTLE_ENDIAN)(input)?;
        self.hash_table_offset_high = Some(hash_table_offset_high);
        Ok((input, self))
    }

    /// Offset 0x2A: int16 BlockTableOffsetHigh
    /// High 16 bits of the block table offset for large archives.
    pub fn parse_block_table_offset_high(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, block_table_offset_high) = i16(LITTLE_ENDIAN)(input)?;
        self.block_table_offset_high = Some(block_table_offset_high);
        Ok((input, self))
    }

    pub fn build(self) -> Result<MPQFileHeaderExt, String> {
        let extended_block_table_offset = self
            .extended_block_table_offset
            .ok_or("Missing extended_block_table_offset")?;
        let hash_table_offset_high = self
            .hash_table_offset_high
            .ok_or("Missing hash_table_offset_high")?;
        let block_table_offset_high = self
            .block_table_offset_high
            .ok_or("Missing block_table_offset_high")?;
        Ok(MPQFileHeaderExt {
            extended_block_table_offset,
            hash_table_offset_high,
            block_table_offset_high,
        })
    }
}

#[derive(Debug, PartialEq, Default)]
pub struct MPQFileHeaderParser {
    header_size: Option<u32>,
    archive_size: Option<u32>,
    format_version: Option<u16>,
    sector_size_shift: Option<u16>,
    hash_table_offset: Option<u32>,
    block_table_offset: Option<u32>,
    hash_table_entries: Option<u32>,
    block_table_entries: Option<u32>,
    extended_file_header: Option<MPQFileHeaderExtParser>,
}

impl MPQFileHeaderParser {
    pub fn new() -> Self {
        Default::default()
    }

    /// Parses the whole section of the File Header
    pub fn parse(self, input: &[u8]) -> IResult<&[u8], Self> {
        let res = self;
        let (input, res) = res.parse_header_size(input)?;
        let (input, res) = res.parse_archive_size(input)?;
        let (input, res) = res.parse_format_version(input)?;
        let (input, res) = res.parse_sector_size_shift(input)?;
        let (input, res) = res.parse_hash_table_offset(input)?;
        let (input, res) = res.parse_block_table_offset(input)?;
        let (input, res) = res.parse_hash_table_entries(input)?;
        let (input, res) = res.parse_block_table_entries(input)?;
        let (input, res) = res.parse_extended_header_if_needed(input)?;
        Ok((input, res))
    }

    /// Offset 0x04: int32 HeaderSize
    /// Size of the archive header.
    pub fn parse_header_size(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header_size) = u32(LITTLE_ENDIAN)(input)?;
        self.header_size = Some(header_size);
        Ok((input, self))
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
    pub fn parse_archive_size(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, archive_size) = u32(LITTLE_ENDIAN)(input)?;
        self.archive_size = Some(archive_size);
        Ok((input, self))
    }

    /// Offset 0x0c: int16 FormatVersion
    /// MoPaQ format version. MPQAPI will not open archives where
    /// this is negative. Known versions:
    /// - 0x0000 Original format. HeaderSize should be 0x20, and large
    ///          archives are not supported.
    /// - 0x0001 Burning Crusade format. Header size should be 0x2c,
    ///          and large archives are supported.
    pub fn parse_format_version(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, format_version) = u16(LITTLE_ENDIAN)(input)?;
        self.format_version = Some(format_version);
        Ok((input, self))
    }

    /// Offset 0x0e: int8 SectorSizeShift
    /// Power of two exponent specifying the number of 512-byte
    /// disk sectors in each logical sector in the archive. The size
    /// of each logical sector in the archive is:
    /// 512 * 2^SectorSizeShift.
    /// Bugs in the Storm library dictate that this shouldalways be:
    /// 3 (4096 byte sectors).
    pub fn parse_sector_size_shift(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, sector_size_shift) = u16(LITTLE_ENDIAN)(input)?;
        self.sector_size_shift = Some(sector_size_shift);
        Ok((input, self))
    }

    /// Offset 0x10: int32 HashTableOffset
    /// Offset to the beginning of the hash table,
    /// relative to the beginning of the archive.
    pub fn parse_hash_table_offset(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, hash_table_offset) = u32(LITTLE_ENDIAN)(input)?;
        self.hash_table_offset = Some(hash_table_offset);
        Ok((input, self))
    }

    /// Offset 0x14: int32 BlockTableOffset
    /// Offset to the beginning of the block table,
    /// relative to the beginning of the archive.
    pub fn parse_block_table_offset(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, block_table_offset) = u32(LITTLE_ENDIAN)(input)?;
        self.block_table_offset = Some(block_table_offset);
        Ok((input, self))
    }

    /// Offset 0x18: int32 HashTableEntries
    /// Desc: Number of entries in the hash table.
    /// Must be a power of two, and must be:
    ///   less than 2^16 for the original MoPaQ format,
    ///   or less than 2^20 for the Burning Crusade format.
    pub fn parse_hash_table_entries(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, hash_table_entries) = u32(LITTLE_ENDIAN)(input)?;
        self.hash_table_entries = Some(hash_table_entries);
        Ok((input, self))
    }

    /// Offset 0x1c: int32 BlockTableEntries
    /// Number of entries in the block table.
    pub fn parse_block_table_entries(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        let (input, block_table_entries) = u32(LITTLE_ENDIAN)(input)?;
        self.block_table_entries = Some(block_table_entries);
        Ok((input, self))
    }

    /// Offset 0x1c: int32 BlockTableEntries
    /// Number of entries in the block table.
    pub fn parse_extended_header_if_needed(mut self, input: &[u8]) -> IResult<&[u8], Self> {
        if self.format_version != Some(1) {
            return Ok((input, self));
        }
        let extended_file_header_parser = MPQFileHeaderExtParser::new();
        let (input, extended_file_header) = extended_file_header_parser.parse(input)?;
        self.extended_file_header = Some(extended_file_header);
        Ok((input, self))
    }

    pub fn build(self) -> Result<MPQFileHeader, String> {
        let header_size = self.header_size.ok_or("Missing header_size".to_string())?;
        let archive_size = self
            .archive_size
            .ok_or("Missing archive_size".to_string())?;
        let format_version = self
            .format_version
            .ok_or("Missing format_version".to_string())?;
        let sector_size_shift = self
            .sector_size_shift
            .ok_or("Missing sector_size_shift".to_string())?;
        let hash_table_offset = self
            .hash_table_offset
            .ok_or("Missing hash_table_offset".to_string())?;
        let block_table_offset = self
            .block_table_offset
            .ok_or("Missing block_table_offset".to_string())?;
        let hash_table_entries = self
            .hash_table_entries
            .ok_or("Missing hash_table_entries".to_string())?;
        let block_table_entries = self
            .block_table_entries
            .ok_or("Missing block_table_entries".to_string())?;
        let extended_file_header = match self.extended_file_header {
            Some(val) => Some(val.build()?),
            None => None,
        };
        Ok(MPQFileHeader {
            header_size,
            archive_size,
            format_version,
            sector_size_shift,
            hash_table_offset,
            block_table_offset,
            hash_table_entries,
            block_table_entries,
            extended_file_header,
        })
    }
}
