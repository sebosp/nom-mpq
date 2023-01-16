//! MPQ Reader logic

use std::collections::HashMap;

use parser::MPQBlockTableEntry;
use parser::MPQHashType;
use thiserror::Error;

pub mod parser;
pub use parser::MPQFileHeader;
pub use parser::MPQHashTableEntry;
pub use parser::MPQUserData;

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
    pub fn mpq_string_hash(&self, location: &'static str, hash_type: MPQHashType) -> u32 {
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
            tracing::error!("({value} ^ ({seed1} + {seed2})) & 0xFFFFFFFF");
            seed1 = (*value as u64 ^ (seed1 + seed2)) & 0xFFFFFFFFu64;
            seed2 = ch_ord as u64 + seed1 + seed2 + (seed2 << 5) + 3 & 0xFFFFFFFFu64;
        }
        seed1 as u32
    }

    /// `_decrypt` on MPyQ
    /// Decrypt hash or block table or a sector.
    pub fn mpq_data_decrypt(&self, data: &[u8], key: u32) -> Vec<u8> {
          let mut seed1 = key as u64;
          let mut seed2 = 0xEEEEEEEEu64;
          let mut res = vec![];

          for i in range(len(data) // 4):
              seed2 += self.encryption_table[0x400 + (seed1 & 0xFF)]
              seed2 &= 0xFFFFFFFF
              value = struct.unpack("<I", data[i*4:i*4+4])[0] : Any
              value = (value ^ (seed1 + seed2)) & 0xFFFFFFFF : Unknown

              seed1 = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B) : Unknown
              seed1 &= 0xFFFFFFFF
              seed2 = value + seed2 + (seed2 << 5) + 3 & 0xFFFFFFFF : Unknown

              result.write(struct.pack("<I", value))

          res
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

    pub fn parse_hash_table_entries(mut self, orig_input: &[u8]) -> Self {
        let mut res = self;
        res
    }

    pub fn parse_block_table_entries(mut self, orig_input: &[u8]) -> Self {
        let mut res = self;
        res
    }
    pub fn build(self, orig_input: &[u8]) -> Result<MPQ, String> {
        let hash_table_key = self.mpq_string_hash("(hash table)", MPQHashType::Table);
        let block_table_key = self.mpq_string_hash("(block table)", MPQHashType::Table);
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
