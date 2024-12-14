//! This binary can be used to generate a test certificate authority and corresponding
//! client and server certificates that can be used for mutual TLS connections.

use clap::Parser;
use test_certs::{
    configuration::{Args, certificates::CertificateRoot},
    generate,
};
use tracing::{debug, info};

fn main() -> anyhow::Result<()> {
    // Init basic console subscriber
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let content = args.input.contents()?;

    let root: CertificateRoot = match args.format {
        test_certs::configuration::ConfigFormat::Yaml => {
            info!("Parsing input as YAML");
            serde_yaml::from_str(&content)?
        }
        test_certs::configuration::ConfigFormat::Json => {
            info!("Parsing input as JSON");
            serde_json::from_str(&content)?
        }
    };

    info!("Detected {} root certificate(s)", root.certificates.len());

    std::fs::DirBuilder::new()
        .recursive(true)
        .create(&args.outdir)?;

    let certificates = generate(&root)?;
    info!("Generated {} certificate(s)", certificates.len());

    for cert in certificates {
        cert.write(&args.outdir)?;
        debug!("Saved {cert}")
    }

    Ok(())
}
