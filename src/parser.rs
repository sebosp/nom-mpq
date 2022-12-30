//! Nom Parsing the MPQ file
//! NOTES:
//! - All numbers in the MoPaQ format are in little endian byte order
//! - Signed numbers use the two's complement system.
//! - Structure members are listed in the following general form: offset from the beginning of the structure: data type(array size) member name : member description

use super::{MPQFileHeader, MPQFileHeaderExt, MPQUserData};
use nom::bytes::complete::{tag, take};
use nom::error::dbg_dmp;
use nom::number::complete::{i16, i64, u16, u32};
use nom::*;
use std::convert::From;

fn get_magic(input: &[u8]) -> IResult<&[u8], &[u8]> {
    dbg_dmp(tag(b"MPQ"), "tag")(input)
}

pub const MPQ_USER_DATA_TYPE: u8 = 0x1b;
pub const LITTLE_ENDIAN: nom::number::Endianness = nom::number::Endianness::Little;

#[derive(Debug, PartialEq)]
pub struct MPQUserDataBuilder {
    size: Option<u32>,
    archive_header_offset: Option<u32>,
    user_data: Vec<u8>,
}

impl MPQUserDataBuilder {
    pub fn new() -> Self {
        Self {
            size: None,
            archive_header_offset: None,
            user_data: vec![],
        }
    }

    pub fn with_size(mut self, size: u32) -> Self {
        self.size = Some(size);
        self
    }

    pub fn with_archive_header_offset(mut self, archive_header_offset: u32) -> Self {
        self.archive_header_offset = Some(archive_header_offset);
        self
    }

    pub fn with_user_data(mut self, user_data: &[u8]) -> Self {
        self.user_data = user_data.to_vec();
        self
    }

    pub fn build(self) -> Result<MPQUserData, String> {
        let size = if let Some(size) = self.size {
            size
        } else {
            return Err("Missing size".to_string());
        };
        let archive_header_offset = if let Some(archive_header_offset) = self.archive_header_offset
        {
            archive_header_offset
        } else {
            return Err("Missing archive_header_offset".to_string());
        };
        Ok(MPQUserData {
            size,
            archive_header_offset,
            user_data: self.user_data,
        })
    }
}

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
    pub fn parse(mut self, input: &[u8]) -> IResult<&[u8], Self> {
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
    pub fn parse(mut self, input: &[u8]) -> IResult<&[u8], Self> {
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

#[derive(Debug, PartialEq)]
pub enum MPQSectionType {
    UserData(MPQUserDataBuilder),
    Header(MPQFileHeaderParser),
    Unknown,
}

impl MPQSectionType {
    pub fn build_user_data(self) -> Result<MPQUserData, String> {
        if let Self::UserData(user_data) = self {
            user_data.build()
        } else {
            Err("Wrong section type".to_string())
        }
    }

    pub fn build_archive_header(self) -> Result<MPQFileHeader, String> {
        if let Self::Header(archive_header) = self {
            archive_header.build()
        } else {
            Err("Wrong section type".to_string())
        }
    }
}

impl From<&[u8]> for MPQSectionType {
    fn from(input: &[u8]) -> Self {
        if input.len() != 1 {
            Self::Unknown
        } else {
            match input[0] {
                0x1a => Self::Header(MPQFileHeaderParser::new()),
                0x1b => Self::UserData(MPQUserDataBuilder::new()),
                _ => Self::Unknown,
            }
        }
    }
}

/// Gets the header from the MPQ file
pub fn get_mpq_type(input: &[u8]) -> IResult<&[u8], MPQSectionType> {
    let (input, _) = get_magic(input)?;
    let (input, mpq_type) = take(1usize)(input)?;
    let is_user_data = mpq_type == &[MPQ_USER_DATA_TYPE];
    Ok((input, MPQSectionType::from(mpq_type)))
}

pub fn read_mpq_header(input: &[u8]) -> IResult<&[u8], MPQSectionType> {
    let (input, header) = MPQFileHeaderParser::new().parse(input)?;
    Ok((input, MPQSectionType::Header(header)))
}

/// The MPQ section headers contain the sizes in the headers
pub fn read_section_data(input: &[u8], mpq_type: MPQSectionType) -> IResult<&[u8], MPQSectionType> {
    match mpq_type {
        MPQSectionType::UserData(user_data_builder) => {
            let (input, user_data_size) = u32(LITTLE_ENDIAN)(input)?;
            let (input, archive_header_offset) = u32(LITTLE_ENDIAN)(input)?;
            // Thus far we have read 12 bytes:
            // - The magic (4 bytes)
            // - The user data size (4 bytes)
            // - The archive header offset (4 bytes)
            if archive_header_offset <= 12 {
                panic!("Archive Header Offset should be more than 12 bytes");
            }
            let (input, user_data) = take(archive_header_offset as usize - 12usize)(input)?;
            println!("read_section_data user_data_size: {user_data_size}, archive_header_offset: {archive_header_offset}");
            Ok((
                input,
                MPQSectionType::UserData(
                    user_data_builder
                        .with_size(user_data_size)
                        .with_archive_header_offset(archive_header_offset)
                        .with_user_data(user_data),
                ),
            ))
        }
        MPQSectionType::Header(header) => read_mpq_header(input),
        _ => unreachable!(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_parses_user_data_magic() {
        let user_data_header: Vec<u8> = vec![
            b'M', b'P', b'Q', // Magic
            0x1b, // 0x1b for User Data
            0x00, 0x02, 0x00, 0x00, // The user data size
        ];
        let archive_header: Vec<u8> = vec![
            b'M', b'P', b'Q', // Magic
            0x1a, // 0x1a for Archive Header
            0xd0, 0x00, 0x00, 0x00, // The archive header size
        ];
        assert_eq!(
            get_mpq_type(&user_data_header),
            Ok((
                &b"\x00\x02\x00\x00"[..],
                MPQSectionType::UserData(MPQUserDataBuilder::new())
            ))
        );
        assert_eq!(
            get_mpq_type(&archive_header),
            Ok((
                &b"\xd0\x00\x00\x00"[..],
                MPQSectionType::Header(MPQFileHeaderParser::new())
            ))
        );
    }

}
