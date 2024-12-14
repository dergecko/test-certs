//! Integration test to check if the input from stdin is read.

use std::{
    io::Write,
    process::{Command, Stdio},
};

use testdir::testdir;

#[test]
fn should_take_input_from_stdin() {
    let dir = testdir!();
    let mut process = Command::new(env!("CARGO_BIN_EXE_test-certs"))
        .stdin(Stdio::piped())
        .arg("--out-dir")
        .arg(dir.as_os_str())
        .spawn()
        .unwrap();

    let mut stdin = process.stdin.take().unwrap();
    std::thread::spawn(move || {
        stdin
            .write_all(b"my-ca:\n  type: ca")
            .expect("Failed to write to stdin");
    });

    let _ = process.wait_with_output().unwrap();

    let files = dir.read_dir().unwrap();
    assert_eq!(files.count(), 1);
}
