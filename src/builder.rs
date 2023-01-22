//! The MPQ Builder.
//! Allows progressively creating the MPQ as the file is read.
use super::parser::to_hex_with_no_context;
use super::{MPQBlockTableEntry, MPQFileHeader, MPQHashTableEntry, MPQHashType, MPQUserData, MPQ};
use nom::IResult;
use std::collections::HashMap;

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
            encryption_table: MPQ::prepare_encryption_table(),
        }
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

    pub fn mpq_string_hash(&self, location: &str, hash_type: MPQHashType) -> u32 {
        MPQ::mpq_string_hash(&self.encryption_table, location, hash_type)
    }

    #[tracing::instrument(level = "trace", skip(self, data), fields(data = to_hex_with_no_context(&data[0..8])))]
    pub fn mpq_data_decrypt<'a>(&'a self, data: &'a [u8], key: u32) -> IResult<&'a [u8], Vec<u8>> {
        let (tail, res) = MPQ::mpq_data_decrypt(&self.encryption_table, data, key)?;
        tracing::debug!("Decrypted to: {:?}", to_hex_with_no_context(&res));
        Ok((tail, res))
    }

    pub fn build(self, _orig_input: &[u8]) -> Result<MPQ, String> {
        let archive_header = self
            .archive_header
            .ok_or(String::from("Missing archive header"))?;
        let user_data = self.user_data;
        let hash_table_entries = self.hash_table_entries;
        let block_table_entries = self.block_table_entries;
        let encryption_table = self.encryption_table;
        Ok(MPQ {
            archive_header,
            user_data,
            hash_table_entries,
            block_table_entries,
            encryption_table,
        })
    }
}
