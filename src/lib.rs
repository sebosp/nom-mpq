//! MPQ Reader logic

use std::collections::HashMap;

use nom::bytes::complete::take;
use nom::error::dbg_dmp;
use nom::number::complete::{u32, u8};
use nom::IResult;
use parser::MPQBlockTableEntry;
use parser::MPQHashType;
use thiserror::Error;

pub mod parser;
use compress::zlib;
pub use parser::MPQFileHeader;
pub use parser::MPQHashTableEntry;
pub use parser::MPQUserData;
use parser::LITTLE_ENDIAN;
use std::io::Read;

pub const MPQ_FILE_IMPLODE: u32 = 0x00000100;
pub const MPQ_FILE_COMPRESS: u32 = 0x00000200;
pub const MPQ_FILE_ENCRYPTED: u32 = 0x00010000;
pub const MPQ_FILE_FIX_KEY: u32 = 0x00020000;
pub const MPQ_FILE_SINGLE_UNIT: u32 = 0x01000000;
pub const MPQ_FILE_DELETE_MARKER: u32 = 0x02000000;
pub const MPQ_FILE_SECTOR_CRC: u32 = 0x04000000;
pub const MPQ_FILE_EXISTS: u32 = 0x80000000;

pub const COMPRESSION_PLAINTEXT: u8 = 0;
pub const COMPRESSION_ZLIB: u8 = 2;
pub const COMPRESSION_BZ2: u8 = 16;

#[derive(Error, Debug)]
pub enum MPQParserError {
    #[error("Unexpected Section")]
    UnexpectedSection,
}

#[derive(Debug, Default)]
pub struct MPQ {
    pub archive_header: MPQFileHeader,
    pub user_data: Option<MPQUserData>,
    pub hash_table_entries: Vec<MPQHashTableEntry>,
    pub block_table_entries: Vec<MPQBlockTableEntry>,
}

#[derive(Debug)]
pub struct MPQBuilder {
    pub archive_header: Option<MPQFileHeader>,
    pub user_data: Option<MPQUserData>,
    pub hash_table_entries: Vec<MPQHashTableEntry>,
    pub block_table_entries: Vec<MPQBlockTableEntry>,
    pub encryption_table: HashMap<u32, u32>,
}

impl MPQBuilder {
    pub fn new() -> Self {
        Self {
            archive_header: None,
            user_data: None,
            hash_table_entries: vec![],
            block_table_entries: vec![],
            encryption_table: Self::prepare_encryption_table(),
        }
    }

    fn prepare_encryption_table() -> HashMap<u32, u32> {
        let mut seed: u32 = 0x00100001;
        let mut res = HashMap::new();
        for i in (0..256).map(|x| x as u32) {
            let mut idx = i;
            for _ in 0..5 {
                seed = (seed * 125 + 3) % 0x2AAAAB;
                let temp1 = (seed & 0xFFFF) << 0x10;

                seed = (seed * 125 + 3) % 0x2AAAAB;
                let temp2 = seed & 0xFFFF;

                res.insert(idx, temp1 | temp2);

                idx += 0x100;
            }
        }
        res
    }

    /// `_hash` on MPyQ
    /// Hash a string using MPQ's hash function
    pub fn mpq_string_hash(&self, location: &str, hash_type: MPQHashType) -> u32 {
        let mut seed1: u64 = 0x7FED7FEDu64;
        let mut seed2: u64 = 0xEEEEEEEEu64;
        for ch in location.to_uppercase().chars() {
            let ch_ord: u32 = ch.into();
            let hash_type_idx: u32 = hash_type.try_into().unwrap();
            let value = match self.encryption_table.get(&((hash_type_idx << 8) + ch_ord)) {
                Some(val) => val,
                None => panic!(
                    "Couldn't find index in map for: {}",
                    (hash_type_idx << 8) + ch_ord
                ),
            };
            seed1 = (*value as u64 ^ (seed1 + seed2)) & 0xFFFFFFFFu64;
            seed2 = ch_ord as u64 + seed1 + seed2 + (seed2 << 5) + 3 & 0xFFFFFFFFu64;
        }
        seed1 as u32
    }

    /// Get the hash table entry corresponding to a given filename.
    pub fn get_hash_table_entry(&self, filename: &str) -> Option<MPQHashTableEntry> {
        let hash_a = self.mpq_string_hash(filename, MPQHashType::HashA);
        let hash_b = self.mpq_string_hash(filename, MPQHashType::HashB);
        for entry in &self.hash_table_entries {
            if entry.hash_a == hash_a && entry.hash_b == hash_b {
                return Some(entry.clone());
            }
        }
        None
    }

    /// Read the compression type and decompress file data.
    pub fn decompress(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        let mut data = vec![];
        let (tail, compression_type) = dbg_dmp(u8, "compression_type")(input)?;
        match compression_type {
            COMPRESSION_PLAINTEXT => data = tail[..].to_vec(),
            COMPRESSION_ZLIB => {
                let _ = zlib::Decoder::new(tail).read_to_end(&mut data).unwrap();
            }
            COMPRESSION_BZ2 => {
                let mut decompressor = bzip2::Decompress::new(false);
                let _ = decompressor.decompress(tail, &mut data).unwrap();
            }
            _ => panic!("Unsupported compression type: {}", compression_type),
        };

        Ok((tail, data))
    }

    /// Read a file from the MPQ archive.
    pub fn read_file<'a>(
        &'a self,
        filename: &str,
        force_decompress: bool,
        orig_input: &'a [u8],
    ) -> IResult<&'a [u8], Option<Vec<u8>>> {
        let hash_entry = match self.get_hash_table_entry(filename) {
            Some(val) => val,
            None => return Ok((orig_input, None)),
        };
        let block_entry = self.block_table_entries[hash_entry.block_table_index as usize].clone();
        // Read the block
        if block_entry.flags & MPQ_FILE_EXISTS == 0 {
            return Ok((orig_input, None));
        }
        if block_entry.archived_size == 0 {
            return Ok((orig_input, None));
        }
        let header_offset = match &self.archive_header {
            Some(val) => val.offset,
            None => 0usize,
        };
        let offset = block_entry.offset as usize + header_offset;
        let (input, file_data) =
            dbg_dmp(take(block_entry.archived_size), "file_data")(&orig_input[offset..])?;

        if block_entry.flags & MPQ_FILE_ENCRYPTED != 0 {
            panic!("Encryption is not supported");
        }
        if block_entry.flags & MPQ_FILE_SINGLE_UNIT != 0 {
            // Single unit files only need to be decompressed, but
            // compression only happens when at least one byte is gained.
            if block_entry.flags & MPQ_FILE_COMPRESS != 0 && force_decompress
                || block_entry.size > block_entry.archived_size
            {
                let (_tail, decompressed_data) = Self::decompress(file_data)?;
                return Ok((orig_input, Some(decompressed_data)));
            }
        }
        Ok((orig_input, None))
    }

    /// `_decrypt` on MPyQ
    /// Decrypt hash or block table or a sector.
    pub fn mpq_data_decrypt<'a>(&'a self, data: &'a [u8], key: u32) -> IResult<&'a [u8], Vec<u8>> {
        let mut seed1 = key as u64;
        let mut seed2 = 0xEEEEEEEEu64;
        let mut res = vec![];

        for i in 0..(data.len() as f32 / 4f32).floor() as usize {
            let encryption_table_value =
                match self.encryption_table.get(&(0x400 + (seed1 & 0xFF) as u32)) {
                    Some(val) => *val as u64,
                    None => {
                        tracing::error!(
                            "Encryption table value not found for: {}",
                            (0x400 + (seed1 & 0xFF) as u32)
                        );
                        continue;
                    }
                };
            seed2 += encryption_table_value;
            seed2 &= 0xFFFFFFFFu64;
            let (_tail, value) =
                dbg_dmp(u32(LITTLE_ENDIAN), "encrypted_value")(&data[i * 4..i * 4 + 4])?;
            let mut value = value as u64;
            value = (value as u64 ^ (seed1 + seed2)) & 0xFFFFFFFFu64;

            seed1 = ((!seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
            seed1 &= 0xFFFFFFFF;
            seed2 = value + seed2 + (seed2 << 5) + 3 & 0xFFFFFFFFu64;

            // pack in little endian
            res.append(&mut value.to_le_bytes().to_vec());
        }

        Ok((data, res))
    }

    /// Sets the archive header field
    pub fn with_archive_header(mut self, archive_header: MPQFileHeader) -> Self {
        self.archive_header = Some(archive_header);
        self
    }

    /// Sets the user data field
    pub fn with_user_data(mut self, user_data: Option<MPQUserData>) -> Self {
        self.user_data = user_data;
        self
    }

    /// Sets the hash table entries
    pub fn with_hash_table(mut self, entries: Vec<MPQHashTableEntry>) -> Self {
        self.hash_table_entries = entries;
        self
    }

    /// Sets the block table entries
    pub fn with_block_table(mut self, entries: Vec<MPQBlockTableEntry>) -> Self {
        self.block_table_entries = entries;
        self
    }

    pub fn build(self, _orig_input: &[u8]) -> Result<MPQ, String> {
        let archive_header = self
            .archive_header
            .ok_or(String::from("Missing user data"))?;
        let user_data = self.user_data;
        let hash_table_entries = self.hash_table_entries;
        let block_table_entries = self.block_table_entries;
        Ok(MPQ {
            archive_header,
            user_data,
            hash_table_entries,
            block_table_entries,
        })
    }
}
