use nom_mpq::*;
use test_log::test;

#[test]
fn it_parses_patch_4_12_replay() {
    let file_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/SC2-Patch_4.12-2v2AI.SC2Replay"
    );
    let file_contents = parser::read_file(file_path);
    let (_input, mpq) = parser::parse(&file_contents).unwrap();
    dbg!(mpq.get_files(&file_contents));
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

fn mpyq_test_file_list() {
    let file_path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/mpyq-test.SC2Replay");
    let file_contents = parser::read_file(file_path);
    let (_input, mpq) = parser::parse(&file_contents).unwrap();
    assert_eq!(
        mpq.get_files(&file_contents),
        vec![
            (b"replay.attributes.events".to_vec(), 1usize),
            (b"replay.details".to_vec(), 1usize),
            (b"replay.game.events".to_vec(), 1usize),
            (b"replay.initData".to_vec(), 1usize),
            (b"replay.load.info".to_vec(), 1usize),
            (b"replay.message.events".to_vec(), 1usize),
            (b"replay.smartcam.events".to_vec(), 1usize),
            (b"replay.sync.events".to_vec(), 1usize),
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
    assert_eq!(mpq.hash_table_entries, expected_entries,);
}
