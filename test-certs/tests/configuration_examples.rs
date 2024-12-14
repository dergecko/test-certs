//! Integration tests to check configuration files.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use testdir::testdir;

fn examples_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples")
}

#[test]
fn should_load_example_config() {
    let dir = testdir!();
    let file = examples_path().join("intermediate_ca.yaml");
    let output = Command::new(env!("CARGO_BIN_EXE_test-certs"))
        .arg("--input")
        .arg(file.as_os_str())
        .arg("--out-dir")
        .arg(dir.as_os_str())
        .output()
        .unwrap();

    assert!(&output.status.success());

    let files = dir.read_dir().unwrap();
    assert_eq!(files.count(), 7);
}
