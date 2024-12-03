//! This binary can be used to generate a test certificate authority and corresponding
//! client and server certificates that can be used for mutual TLS connections.

use test_certs::create_root_ca;
use anyhow;

fn main() -> anyhow::Result<()> {
    let cert = create_root_ca()?;
    println!("{cert:?}");
    Ok(())
}
