//! MPQ Reader logic

use std::collections::HashMap;

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
    pub hash_table: MPQHashTableEntry,
}

#[derive(Debug)]
pub struct MPQBuilder {
    pub archive_header: Option<MPQFileHeader>,
    pub user_data: Option<MPQUserData>,
    pub hash_table: Option<MPQHashTableEntry>,
    pub encryption_table: HashMap<u32, u32>,
}

impl MPQBuilder {
    pub fn new() -> Self {
        Self {
            archive_header: None,
            user_data: None,
            hash_table: None,
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

    pub fn mpq_string_hash(self, location: &str, hash_type: MPQHashType) -> u32 {
        let mut seed1: u32 = 0x7FED7FED;
        let mut seed2: u32 = 0xEEEEEEEE;
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
            seed1 = (value ^ (seed1 + seed2)) & 0xFFFFFFFF;
            seed2 = ch_ord + seed1 + seed2 + (seed2 << 5) + 3 & 0xFFFFFFFF;
        }
        seed1
    }
}
