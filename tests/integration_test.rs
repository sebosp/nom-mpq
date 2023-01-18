use nom_mpq::*;
use test_log::test;

#[test]
fn it_parses_file() {
    let file_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/SC2-Patch_4.12-2v2AI.SC2Replay"
    );
    let file_contents = parser::read_file(file_path);
    let (_input, mpq) = parser::parse(&file_contents).unwrap();
    dbg!(mpq.archive_header);
    dbg!(mpq.user_data);
    assert!(false);
}
