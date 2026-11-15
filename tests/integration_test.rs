use nom_mpq::*;

#[test]
fn it_parses_patch_4_12_replay() {
    let file_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/SC2-Patch_4.12-2v2AI.SC2Replay"
    );
    let file_contents = parser::read_file(file_path);
    let (_input, mpq) = parser::parse(&file_contents).unwrap();
    let mpq_listfiles_res = mpq.get_files(&file_contents);
    assert!(mpq_listfiles_res.is_ok());
}

#[test]
fn mpyq_test_file_header() {
    let file_path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/mpyq-test.SC2Replay");
    let file_contents = parser::read_file(file_path);
    let (_input, mpq) = parser::parse(&file_contents).unwrap();
    assert_eq!(mpq.archive_header.header_size, 44);
    assert_eq!(mpq.archive_header.archive_size, 205044);
    assert_eq!(mpq.archive_header.format_version, 1);
    assert_eq!(mpq.archive_header.sector_size_shift, 3);
    assert_eq!(mpq.archive_header.hash_table_offset, 204628);
    assert_eq!(mpq.archive_header.block_table_offset, 204884);
    assert_eq!(mpq.archive_header.hash_table_entries, 16);
    assert_eq!(mpq.archive_header.block_table_entries, 10);
    //assert_eq!(mpq.archive_header.extended_block_table_offset, 0);
    //assert_eq!(mpq.archive_header.hash_table_offset_high, 0);
    //assert_eq!(mpq.archive_header.block_table_offset_high, 0);
}

#[test]
fn mpyq_test_encryption_table() {
    // Spot checking some encryption table entries:
    let builder = MPQBuilder::new();
    assert_eq!(builder.encryption_table.get(&0u32), Some(&1439053538u32));
    assert_eq!(builder.encryption_table.get(&51u32), Some(&3348854420u32));
    assert_eq!(builder.encryption_table.get(&317u32), Some(&809762u32));
    assert_eq!(builder.encryption_table.get(&317u32), Some(&809762u32));
    assert_eq!(builder.encryption_table.get(&1279u32), Some(&1929586796u32));
    assert_eq!(builder.encryption_table.len(), 1280usize);
}

#[test_log::test]
fn mpyq_test_file_list() {
    let file_path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/mpyq-test.SC2Replay");
    let file_contents = parser::read_file(file_path);
    let (_input, mpq) = parser::parse(&file_contents).unwrap();
    let mpq_listfiles_res = mpq.get_files(&file_contents);
    assert!(mpq_listfiles_res.is_ok());
    let mpq_listfiles_res = mpq_listfiles_res.unwrap();
    assert_eq!(
        mpq_listfiles_res,
        vec![
            ("replay.attributes.events".to_string(), 2400usize),
            ("replay.details".to_string(), 890usize),
            ("replay.game.events".to_string(), 479869usize),
            ("replay.initData".to_string(), 1257usize),
            ("replay.load.info".to_string(), 97usize),
            ("replay.message.events".to_string(), 334usize),
            ("replay.smartcam.events".to_string(), 12431usize),
            ("replay.sync.events".to_string(), 1970usize),
        ]
    );
}

#[test]
fn mpyq_test_hash_table() {
    let file_path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/mpyq-test.SC2Replay");
    let file_contents = parser::read_file(file_path);
    let (_input, mpq) = parser::parse(&file_contents).unwrap();
    let mut expected_entries: Vec<MPQHashTableEntry> = vec![];
    expected_entries.push(MPQHashTableEntry::new(
        0xD38437CB, 0x07DFEAEC, 0x0000, 0x0000, 0x00000009,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0xAAC2A54B, 0xF4762B95, 0x0000, 0x0000, 0x00000002,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFF,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFF,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFF,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0xC9E5B770, 0x3B18F6B6, 0x0000, 0x0000, 0x00000005,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0x343C087B, 0x278E3682, 0x0000, 0x0000, 0x00000004,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0x3B2B1EA0, 0xB72EF057, 0x0000, 0x0000, 0x00000006,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0x5A7E8BDC, 0xFF253F5C, 0x0000, 0x0000, 0x00000001,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0xFD657910, 0x4E9B98A7, 0x0000, 0x0000, 0x00000008,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0xD383C29C, 0xEF402E92, 0x0000, 0x0000, 0x00000000,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFF,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFF,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFF,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0x1DA8B0CF, 0xA2CEFF28, 0x0000, 0x0000, 0x00000007,
    ));
    expected_entries.push(MPQHashTableEntry::new(
        0x31952289, 0x6A5FFAA3, 0x0000, 0x0000, 0x00000003,
    ));
    assert_eq!(mpq.hash_table_entries, expected_entries);
}

#[test_log::test]
fn mpyq_test_block_table() {
    let file_path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/mpyq-test.SC2Replay");
    let file_contents = parser::read_file(file_path);
    let (_input, mpq) = parser::parse(&file_contents).unwrap();
    let mut expected_entries: Vec<MPQBlockTableEntry> = vec![];
    expected_entries.push(MPQBlockTableEntry::new(0x0000002C, 727, 890, 0x81000200u32));
    expected_entries.push(MPQBlockTableEntry::new(
        0x00000303,
        801,
        1257,
        0x81000200u32,
    ));
    expected_entries.push(MPQBlockTableEntry::new(
        0x00000624,
        194096,
        479869,
        0x81000200u32,
    ));
    expected_entries.push(MPQBlockTableEntry::new(0x0002FC54, 226, 334, 0x81000200u32));
    expected_entries.push(MPQBlockTableEntry::new(0x0002FD36, 97, 97, 0x81000200u32));
    expected_entries.push(MPQBlockTableEntry::new(
        0x0002FD97,
        1323,
        1970,
        0x81000200u32,
    ));
    expected_entries.push(MPQBlockTableEntry::new(
        0x000302C2,
        6407,
        12431,
        0x81000200u32,
    ));
    expected_entries.push(MPQBlockTableEntry::new(
        0x00031BC9,
        533,
        2400,
        0x81000200u32,
    ));
    expected_entries.push(MPQBlockTableEntry::new(0x00031DDE, 120, 164, 0x81000200u32));
    expected_entries.push(MPQBlockTableEntry::new(0x00031E56, 254, 288, 0x81000200u32));
    assert_eq!(mpq.block_table_entries, expected_entries);
}

fn mpyq_test_replay() -> Vec<u8> {
    parser::read_file(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/mpyq-test.SC2Replay"
    ))
}

#[test]
fn an_archive_cut_inside_its_tables_is_incomplete_data() {
    // A replay cut short (an interrupted download) points its tables past its end.
    let file_contents = mpyq_test_replay();
    let (_input, mpq) = parser::parse(&file_contents).unwrap();
    let header = &mpq.archive_header;
    let hash_table = header.hash_table_offset as usize + header.offset;
    let block_table = header.block_table_offset as usize + header.offset;
    for len in [
        hash_table,
        hash_table + 8,
        block_table,
        block_table + 8,
        file_contents.len() - 1,
    ] {
        let truncated = &file_contents[..len];
        assert!(
            matches!(
                parser::parse(truncated),
                Err(MPQParserError::IncompleteData)
            ),
            "cut at {len} of {}",
            file_contents.len()
        );
    }
}

#[test]
fn a_file_cut_short_is_incomplete_data() {
    // The tables are read from the whole archive, the files from a shorter copy of it.
    let file_contents = mpyq_test_replay();
    let (_input, mpq) = parser::parse(&file_contents).unwrap();
    let files = mpq.get_files(&file_contents).unwrap();
    assert!(files.len() > 5);
    for (name, _size) in &files {
        let name = name.as_str();
        let entry = mpq.get_hash_table_entry(name).unwrap();
        let block = &mpq.block_table_entries[entry.block_table_index as usize];
        let start = block.offset as usize + mpq.archive_header.offset;
        let end = start + block.archived_size as usize;
        for len in [start, start + 1, end - 1] {
            assert!(
                matches!(
                    mpq.read_mpq_file_sector(name, false, &file_contents[..len]),
                    Err(MPQParserError::IncompleteData)
                ),
                "{name} cut at {len}, its data is {start}..{end}"
            );
        }
        assert!(
            mpq.read_mpq_file_sector(name, false, &file_contents[..end])
                .is_ok()
        );
    }
}

#[test]
fn a_hash_entry_past_the_block_table_is_skipped_or_incomplete_data() {
    let file_contents = mpyq_test_replay();
    let (_input, mut mpq) = parser::parse(&file_contents).unwrap();
    let entry = mpq.get_hash_table_entry("replay.details").unwrap();
    let missing = mpq.block_table_entries.len() as u32;
    for hash_entry in &mut mpq.hash_table_entries {
        if hash_entry.hash_a == entry.hash_a && hash_entry.hash_b == entry.hash_b {
            hash_entry.block_table_index = missing;
        }
    }
    assert!(matches!(
        mpq.read_mpq_file_sector("replay.details", false, &file_contents),
        Err(MPQParserError::IncompleteData)
    ));
    let files = mpq.get_files(&file_contents).unwrap();
    assert!(!files.is_empty());
    assert!(files.iter().all(|(name, _)| name != "replay.details"));
}

#[test]
fn truncated_archives_are_errors_not_panics() {
    // Every length up to the whole archive, the tables included.
    let file_contents = mpyq_test_replay();
    for len in (0..file_contents.len()).step_by(97) {
        let truncated = &file_contents[..len];
        if let Ok((_input, mpq)) = parser::parse(truncated) {
            let _ = mpq.get_files(truncated);
            let _ = mpq.read_mpq_file_sector("replay.details", false, truncated);
        }
    }
}
