//! Nom Parsing the MoPaQ file format.
//! Sources:
//! - [The_MoPaQ_Archive_Format](https://web.archive.org/web/20120222093346/http://wiki.devklog.net/index.php?title=The_MoPaQ_Archive_Format)
//! - [MPyQ](https://github.com/arkx/mpyq/)

#![warn(missing_docs)]
pub use error::MPQResult;
use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::{i32, u8, u32};
use parser::MPQHashType;
use std::collections::HashMap;
use std::io::Read;

pub mod builder;
pub mod error;
pub mod parser;
pub use builder::MPQBuilder;
pub use error::MPQParserError;
use flate2::bufread::ZlibDecoder;
use parser::LITTLE_ENDIAN;
pub use parser::MPQBlockTableEntry;
pub use parser::MPQFileHeader;
pub use parser::MPQHashTableEntry;
pub use parser::MPQUserData;

/// TEMP waiting for https://github.com/rust-bakery/nom/pull/1845 to be merged/released.
pub fn dbg_dmp<'a, F, O, E: std::fmt::Debug>(
    mut f: F,
    context: &'static str,
) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>
where
    F: FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>,
{
    move |i: &'a [u8]| match f(i) {
        Err(e) => {
            tracing::debug!(
                "{}: Error({:.32}) at: {}",
                context,
                e.to_string(),
                parser::peek_hex(i)
            );
            Err(e)
        }
        a => a,
    }
}
// Unused flags:
// pub const MPQ_FILE_IMPLODE: u32 = 0x00000100;
// pub const MPQ_FILE_FIX_KEY: u32 = 0x00020000;
// pub const MPQ_FILE_DELETE_MARKER: u32 = 0x02000000;

/// The sector is compressed
pub const MPQ_FILE_COMPRESS: u32 = 0x00000200;
/// The sector is encrypted.
pub const MPQ_FILE_ENCRYPTED: u32 = 0x00010000;
/// The sector contains a single file/unit.
pub const MPQ_FILE_SINGLE_UNIT: u32 = 0x01000000;
/// The sector has cyclic redundancy check.
pub const MPQ_FILE_SECTOR_CRC: u32 = 0x04000000;
/// The sector exists (as opposed to marked as deleted)
pub const MPQ_FILE_EXISTS: u32 = 0x80000000;

/// The sector has no compression
pub const COMPRESSION_PLAINTEXT: u8 = 0;
/// The sector is compressed using [`zlib`]
pub const COMPRESSION_ZLIB: u8 = 2;
/// The sector is compressed using [`bzip2`]
pub const COMPRESSION_BZ2: u8 = 16;
/// Another non-compressed plaintext
pub const OTHER_COMPRESSION_PLAINTEXT: u8 = 47;

/// The main MPQ object that contains the parsed entries
#[derive(Debug, Default)]
pub struct MPQ {
    /// The Archive Header containing format version, the offsets for the
    /// block table and hash table.
    pub archive_header: MPQFileHeader,
    /// The Archive may contain [`MPQUserData`], which is at the start of the file.
    pub user_data: Option<MPQUserData>,
    /// The hash table entries, after decryption and parsing
    pub hash_table_entries: Vec<MPQHashTableEntry>,
    /// The block table entries, after decryption and parsing
    pub block_table_entries: Vec<MPQBlockTableEntry>,
    /// The internal MPQ encryption table.
    pub encryption_table: HashMap<u32, u32>,
}

impl MPQ {
    /// Prepares the encryption table, this hashmap is used for block-sized
    /// decryption operations.
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

    /// Hash a string using MPQ's hash function
    ///
    /// `_hash` on MPyQ
    /// This function doesn't use self as the Builder also needs to access the same functionality.
    #[allow(clippy::precedence)]
    pub fn mpq_string_hash(
        encryption_table: &HashMap<u32, u32>,
        location: &str,
        hash_type: MPQHashType,
    ) -> Result<u32, MPQParserError> {
        let mut seed1: u64 = 0x7FED7FEDu64;
        let mut seed2: u64 = 0xEEEEEEEEu64;
        for ch in location.to_uppercase().chars() {
            let ch_ord: u32 = ch.into();
            let hash_type_idx: u32 = hash_type.try_into()?;
            let value = match encryption_table.get(&((hash_type_idx << 8) + ch_ord)) {
                Some(val) => val,
                None => {
                    tracing::error!(
                        "Couldn't find index in map for: {}",
                        (hash_type_idx << 8) + ch_ord
                    );
                    return Err(MPQParserError::EncryptionTableIndexNotFound);
                }
            };
            seed1 = (*value as u64 ^ (seed1 + seed2)) & 0xFFFFFFFFu64;
            seed2 = ch_ord as u64 + seed1 + seed2 + (seed2 << 5) + 3 & 0xFFFFFFFFu64;
        }
        tracing::trace!("Returning {} for location: {}", (seed1 as u32), location);
        Ok(seed1 as u32)
    }

    /// Get the hash table entry corresponding to a given filename.
    ///
    /// A filename is hashed with both [`MPQHashType::HashA`] and [`MPQHashType::HashB`]
    /// to uniquely identify the filename in the archive
    pub fn get_hash_table_entry(
        &self,
        filename: &str,
    ) -> Result<MPQHashTableEntry, MPQParserError> {
        let hash_a = Self::mpq_string_hash(&self.encryption_table, filename, MPQHashType::HashA)?;
        let hash_b = Self::mpq_string_hash(&self.encryption_table, filename, MPQHashType::HashB)?;
        for entry in &self.hash_table_entries {
            if entry.hash_a == hash_a && entry.hash_b == hash_b {
                tracing::debug!("Found filename: {}, as entry: {:?}", filename, entry);
                return Ok(entry.clone());
            }
        }
        Err(MPQParserError::HashTableEntryNotFound(filename.to_string()))
    }

    /// Read the compression type and decompress file data accordingly.
    pub fn decompress(input: &[u8]) -> MPQResult<&[u8], Vec<u8>> {
        let mut data = vec![];
        let (tail, compression_type) = dbg_dmp(u8, "compression_type")(input)?;
        match compression_type {
            COMPRESSION_PLAINTEXT | OTHER_COMPRESSION_PLAINTEXT => {
                tracing::debug!("Plaintext (no compression)");
                data = tail[..].to_vec()
            }
            COMPRESSION_ZLIB => {
                tracing::debug!("Attempting ZLIB compression",);
                let mut d = ZlibDecoder::new(std::io::BufReader::new(tail));

                let _ = d.read_to_end(&mut data)?;
            }
            COMPRESSION_BZ2 => {
                tracing::debug!("Attempting BZ2 compression",);
                let mut decompressor = bzip2_rs::DecoderReader::new(tail);
                std::io::copy(&mut decompressor, &mut data)?;
            }
            unknown_version => {
                tracing::debug!("File header is: {}", parser::peek_hex(tail));
                return MPQResult::Err(MPQParserError::UnsupportedCompression(unknown_version));
            }
        };

        Ok((tail, data))
    }

    /// Joins the sectors of a file, `positions` are their offsets in `file_data` and the end of
    /// the last one. A sector is compressed only when that saves at least a byte, a sector that
    /// does not compress is stored as it is, without the compression type, i.e. the last sectors
    /// of a replay.game.events. Whether a sector is compressed is known from the bytes of the file
    /// left, so the bytes of each sector once decompressed are counted, as MPyQ does.
    fn read_sectors(
        file_data: &[u8],
        positions: &[usize],
        file_size: usize,
        compressed: bool,
        force_decompress: bool,
    ) -> Result<Vec<u8>, MPQParserError> {
        let mut res = vec![];
        let mut sector_bytes_left = file_size;
        for window in positions.windows(2) {
            let sector = &file_data[window[0]..window[1]];
            let mut sector = if compressed && (force_decompress || sector_bytes_left > sector.len())
            {
                Self::decompress(sector)?.1
            } else {
                sector.to_vec()
            };
            sector_bytes_left = sector_bytes_left.saturating_sub(sector.len());
            res.append(&mut sector);
        }
        Ok(res)
    }

    /// Reads an embedded file inside the MPQ archive.
    #[tracing::instrument(level = "debug", skip(self, orig_input))]
    pub fn read_mpq_file_sector<'a>(
        &'a self,
        filename: &str,
        force_decompress: bool,
        orig_input: &'a [u8],
    ) -> MPQResult<&'a [u8], Vec<u8>> {
        let mut res = vec![];
        let hash_entry = self.get_hash_table_entry(filename)?;
        let block_entry = self.block_table_entries[hash_entry.block_table_index as usize].clone();
        tracing::debug!("block_entry {:?}", block_entry);
        // Read the block
        if block_entry.flags & MPQ_FILE_EXISTS == 0 {
            tracing::debug!("file is marked as deleted. Returning empty content");
            return Ok((orig_input, res));
        }
        if block_entry.archived_size == 0 {
            tracing::debug!("File is zero size. Returning empty content");
            return Ok((orig_input, res));
        }
        let offset = block_entry.offset as usize + self.archive_header.offset;
        let (tail, file_data) =
            dbg_dmp(take(block_entry.archived_size), "file_data")(&orig_input[offset..])?;

        tracing::debug!("Block table data: {}", parser::peek_hex(file_data));
        if block_entry.flags & MPQ_FILE_ENCRYPTED != 0 {
            return MPQResult::Err(MPQParserError::UnsupportedEncryptionType);
        }
        if block_entry.flags & MPQ_FILE_SINGLE_UNIT != 0 {
            tracing::debug!("File sector contains a single unit",);
            // Single unit files only need to be decompressed, but
            // compression only happens when at least one byte is gained.
            if block_entry.flags & MPQ_FILE_COMPRESS != 0
                && (force_decompress || block_entry.size > block_entry.archived_size)
            {
                tracing::debug!("File needs to be decompressed",);
                let (_tail, decompressed_data) = Self::decompress(file_data)?;
                return Ok((tail, decompressed_data));
            }
            tracing::debug!("File does not needs to be decompressed",);
        } else {
            tracing::debug!("File does not need to be decompressed",);
            // File consists of many sectors. They all need to be
            // decompressed separately and united.
            let sector_size = 512 << self.archive_header.sector_size_shift;
            let mut sectors =
                (block_entry.size as f32 / sector_size as f32).floor() as usize + 1usize;
            tracing::debug!("Total sectors: {sectors}");
            let crc = if block_entry.flags & MPQ_FILE_SECTOR_CRC != 0 {
                sectors += 1;
                true
            } else {
                false
            };
            let mut positions: Vec<usize> = vec![];
            let mut position_file_index = &file_data[..4 * (sectors + 1)];
            for _ in 0..sectors + 1 {
                // Note: MPyQ format for this is a list of '<I'
                // as long as there are sectors + 1
                // `'<%dI' % (sectors + 1)` (Not to confuse the `d` with
                // double, it's for the `%` format operator.
                let (new_pos_idx, position) =
                    dbg_dmp(u32(LITTLE_ENDIAN), "positions")(position_file_index)?;
                positions.push(position as usize);
                position_file_index = new_pos_idx;
            }
            let mut total_sectors = positions.len() - 1;
            if crc {
                total_sectors -= 1;
            }
            let res = Self::read_sectors(
                file_data,
                &positions[..total_sectors + 1],
                block_entry.size as usize,
                block_entry.flags & MPQ_FILE_COMPRESS != 0,
                force_decompress,
            )?;
            return Ok((tail, res));
        }
        Ok((tail, file_data.to_vec()))
    }

    /// Decrypt hash or block table or a sector.
    ///
    /// `_decrypt` on MPyQ
    #[allow(clippy::precedence)]
    pub fn mpq_data_decrypt<'a>(
        encryption_table: &'a HashMap<u32, u32>,
        data: &'a [u8],
        key: u32,
    ) -> IResult<&'a [u8], Vec<u8>> {
        let mut seed1 = key as i64;
        let mut seed2 = 0xEEEEEEEEi64;
        let mut res = vec![];

        for i in 0..(data.len() as f32 / 4f32).floor() as usize {
            let encryption_table_value =
                match encryption_table.get(&(0x400 + (seed1 as u32 & 0xFF))) {
                    Some(val) => *val as i64,
                    None => {
                        tracing::error!(
                            "Encryption table value not found for: {}",
                            (0x400 + (seed1 & 0xFF) as i32)
                        );
                        continue;
                    }
                };
            seed2 += encryption_table_value;
            seed2 &= 0xFFFFFFFFi64;
            let (_tail, value) =
                dbg_dmp(i32(LITTLE_ENDIAN), "encrypted_value")(&data[i * 4..i * 4 + 4])?;
            let mut value = value as i64;
            value = (value ^ (seed1 + seed2)) & 0xFFFFFFFFi64;

            seed1 = ((!seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
            seed1 &= 0xFFFFFFFF;
            seed2 = value + seed2 + (seed2 << 5) + 3 & 0xFFFFFFFFi64;
            let mut le_packed_value = (value as i32).to_le_bytes().to_vec();

            // pack in little endian
            res.append(&mut le_packed_value);
        }

        Ok((data, res))
    }

    /// Returns the list of filenames and their respective size as contained in the MPQ archive.
    pub fn get_files(&self, orig_input: &[u8]) -> Result<Vec<(String, usize)>, MPQParserError> {
        let mut res: Vec<(String, usize)> = vec![];
        let files: Vec<String> = match self.read_mpq_file_sector("(listfile)", false, orig_input) {
            Ok((_tail, file_buffer)) => {
                tracing::debug!(
                    "Successfully read '(listfile)' sector: {:?}",
                    parser::peek_hex(&file_buffer)
                );
                match std::str::from_utf8(&file_buffer) {
                    Ok(val) => val.lines().map(|x| x.to_string()).collect(),
                    Err(err) => {
                        tracing::error!("Invalid UTF-8 sequence: {:?}", err);
                        return Err(MPQParserError::InvalidUTF8Sequence(
                            "(listfile)".to_string(),
                        ));
                    }
                }
            }
            Err(err) => {
                tracing::error!("Unable to read '(listfile)' sector: {:?}", err);
                return Err(MPQParserError::InvalidListFileSector);
            }
        };
        for filename in files {
            let hash_entry = match self.get_hash_table_entry(&filename) {
                Ok(val) => val,
                Err(err) => {
                    tracing::warn!(
                        "Unable to find hash entry for filename: {:?}: {:?}",
                        filename,
                        err
                    );
                    continue;
                }
            };
            let block_entry = &self.block_table_entries[hash_entry.block_table_index as usize];
            tracing::debug!("{} {1:>8} bytes", filename, block_entry.size as usize);
            res.push((filename, block_entry.size as usize));
        }
        Ok(res)
    }
}

#[cfg(test)]
mod sector_tests {
    use super::*;
    use std::io::Write;

    fn zlib_sector(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::best());
        encoder.write_all(data).unwrap();
        let mut sector = vec![COMPRESSION_ZLIB];
        sector.extend(encoder.finish().unwrap());
        sector
    }

    #[test]
    fn it_reads_the_sectors_stored_without_compression() {
        // A sector that compresses, then one that does not, stored as it is and starting with a
        // byte that is not a compression type.
        let first = vec![7u8; 4096];
        let second: Vec<u8> = (0..1000u32)
            .map(|idx| (idx.wrapping_mul(2654435761) >> 24) as u8 | 0x41)
            .collect();
        let mut second = second;
        second[0] = 0x57;
        let first_sector = zlib_sector(&first);
        let mut file_data = first_sector.clone();
        file_data.extend(&second);
        let positions = [0, first_sector.len(), file_data.len()];
        let res = MPQ::read_sectors(
            &file_data,
            &positions,
            first.len() + second.len(),
            true,
            false,
        )
        .unwrap();
        assert_eq!(res.len(), first.len() + second.len());
        assert_eq!(&res[..first.len()], &first[..]);
        assert_eq!(&res[first.len()..], &second[..]);
    }
}
