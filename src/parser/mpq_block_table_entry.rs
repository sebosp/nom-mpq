//! The Block Table Parsing
//!
//! The block table contains entries for each region in the archive.
//! Regions may be either files, empty space, which may be overwritten by new
//! files (typically this space is from deleted file data), or unused block
//! table entries.
//! Empty space entries should have:
//! - BlockOffset and BlockSize nonzero.
//! - FileSize and Flags zero;
//! Unused block table entries should have:
//! - BlockSize, FileSize, and Flags zero.
//! The block table is encrypted, using the hash of "(block table)" as the key.
//! NOTES:
//! - MPyQ uses struct_format: `'4I'`

use super::LITTLE_ENDIAN;
use nom::error::dbg_dmp;
use nom::number::complete::u32;
use nom::*;

/// The block tables of the MPQ archive, they are stored sequentially and encrypted.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct MPQBlockTableEntry {
    /// Block Offset, an offset of the beginning of the block,
    /// relative to the beginning of the archive header, this can
    /// be used in conjunction with `fseek` to start reading a specific
    /// block. In the case of this crate, since the contents are in memory
    /// already, it's used as `data[(archive_header_offset + self.offset)..]`.
    /// This is because the first section of the archive may be the UserData
    /// section so the archive header offset must be known.
    pub offset: u32,
    /// Size of the block in the archive.
    pub archived_size: u32,
    /// Size of the file data stored in the block.
    /// see [`MPQBlockTableEntry::parse_size`] for more information.
    pub size: u32,
    /// Bit mask of the flags for the block,
    /// see [`MPQBlockTableEntry::parse_flags`] for more information.
    pub flags: u32,
}

impl MPQBlockTableEntry {
    /// This method is not related to parsing but for testing, maybe we should consider further
    /// splitting this into a MPQBlockTableEntryParser, maybe overkill.
    pub fn new(offset: u32, archived_size: u32, size: u32, flags: u32) -> Self {
        Self {
            offset,
            archived_size,
            size,
            flags,
        }
    }

    /// Parses all the fields in the expected order
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (tail, offset) = Self::parse_offset(input)?;
        let (tail, archived_size) = Self::parse_archived_size(tail)?;
        let (tail, size) = Self::parse_size(tail)?;
        let (tail, flags) = Self::parse_flags(tail)?;
        Ok((
            tail,
            MPQBlockTableEntry {
                offset,
                archived_size,
                size,
                flags,
            },
        ))
    }

    /// `Offset 0x00`: int32 BlockOffset
    ///
    /// Offset of the beginning of the block, relative to the beginning of the
    /// archive header.
    pub fn parse_offset(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "offset")(input)
    }

    /// `Offset 0x04`: int32 BlockSize
    ///
    /// Size of the block in the archive.
    pub fn parse_archived_size(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "archive_size")(input)
    }

    /// `Offset 0x08`: int32 FileSize
    ///
    /// Size of the file data stored in the block. Only valid if the block is
    /// a file; otherwise meaningless, and should be 0.
    /// If the file is compressed, this is the size of the uncompressed
    /// file data.
    pub fn parse_size(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "size")(input)
    }

    /// `Offset 0x0c`: int32 Flags
    ///
    /// Bit mask of the flags for the block.
    /// The following values are conclusively identified:
    /// - `0x80000000` Block is a file, and follows the file data format;
    ///              otherwise, block is free space or unused.
    ///              If the block is not a file, all other flags should be
    ///              cleared, and FileSize should be 0.
    /// - `0x04000000` File has checksums for each sector (explained in the
    ///              File Data section). Ignored if file is not compressed
    ///              or imploded.
    /// - `0x02000000` File is a deletion marker, indicating that the file no
    ///              longer exists. This is used to allow patch archives to
    ///              delete files present in lower-priority archives in the
    ///              search chain.
    /// - `0x01000000` File is stored as a single unit, rather than split into
    ///              sectors.
    /// - `0x00020000` The file's encryption key is adjusted by the block offset
    ///              and file size (explained in detail in the File Data
    ///              section). File must be encrypted.
    /// - `0x00010000` File is encrypted.
    /// - `0x00000200` File is compressed. File cannot be imploded.
    /// - `0x00000100` File is imploded. File cannot be compressed.
    pub fn parse_flags(input: &[u8]) -> IResult<&[u8], u32> {
        dbg_dmp(u32(LITTLE_ENDIAN), "flags")(input)
    }
}
