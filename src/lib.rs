//! MPQ Reader logic
use std::fs::File;
use std::io::prelude::*;

pub mod parser;

/// The MPQ User Data
///
/// The second version of the MoPaQ format, first used in Burning Crusade, features a mechanism to store some amount of data outside the archive proper, though the reason for this mechanism is not known. This is implemented by means of a shunt block that precedes the archive itself. The format of this block is as follows:
///
/// 00h: char(4) Magic                  Indicates that this is a shunt block. ASCII "MPQ" 1Bh.
/// 04h: int32 UserDataSize             The number of bytes that have been allocated in this archive for user data. This does not
///                                    need to be the exact size of the data itself, but merely the maximum amount of data which
///                                    may be stored in this archive.
/// 08h: int32 ArchiveHeaderOffset      The offset in the file at which to continue the search for the archive header.
/// 0Ch: byte(UserDataSize) UserData    The block to store user data in.

#[derive(Debug, Default)]
pub struct MPQUserData {
    pub size: u32,
    pub archive_header_offset: u32,
    pub user_data: Vec<u8>,
}

/// Extended fields only present in the Burning Crusade format and later:
#[derive(Debug, PartialEq, Default)]
pub struct MPQFileHeaderExt {
    extended_block_table_offset: i64,
    hash_table_offset_high: i16,
    block_table_offset_high: i16,
}

/// The MPQ File Header
#[derive(Debug, Default)]
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

#[derive(Debug, Default)]
pub struct MPQ {
    pub header: MPQFileHeader,
    pub data: MPQUserData,
}

pub fn read_file(path: &str) {
    let mut f = File::open(path).unwrap();
    let mut buffer: Vec<u8> = vec![];
    // read the whole file
    f.read_to_end(&mut buffer).unwrap();
    let (input, mpq_section) = parser::get_mpq_type(&buffer).unwrap();
    let (input, mpq_section) = parser::read_section_data(input, mpq_section).unwrap();
    let data: MPQUserData = mpq_section.build_user_data().unwrap();
    // We should be positioned now at the end of the user data and should be able to read the
    // archive header
    let (input, mpq_section) = parser::get_mpq_type(input).unwrap();
    let (input, mpq_section) = parser::read_section_data(input, mpq_section).unwrap();
    let header: MPQFileHeader = mpq_section.build_archive_header().unwrap();
}
