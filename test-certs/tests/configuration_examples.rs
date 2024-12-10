use std::{
    path::{Path, PathBuf},
    process::Command,
};

fn examples_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples")
}

#[test]
fn should_load_example_config() {
    let file = examples_path().join("intermediate_ca.yaml");
    let output = Command::new(env!("CARGO_BIN_EXE_test-certs"))
        .arg("--configuration")
        .arg(file.as_os_str())
        .output()
        .unwrap();

    assert!(dbg!(&output).status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("Loaded 1 root certificate(s)"),
        "stdout does not contain 'Loaded 1 root certificate(s)', stdout: \n{stdout}"
    )
}
