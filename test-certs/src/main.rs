//! This binary can be used to generate a test certificate authority and corresponding
//! client and server certificates that can be used for mutual TLS connections.

use clap::Parser;
use test_certs::configuration::{certificates::Certificates, Args};
use tracing::info;

fn main() -> anyhow::Result<()> {
    // Init basic console subscriber
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let certificates: Certificates = match args.format {
        test_certs::configuration::ConfigFormat::Yaml => {
            info!(
                "Loading YAML certificate generation file {:?}",
                args.configuration
            );
            serde_yaml::from_reader(std::fs::File::open(args.configuration.as_path())?)?
        }
        test_certs::configuration::ConfigFormat::Json => {
            info!(
                "Loading JSON certificate generation file {:?}",
                args.configuration
            );
            serde_json::from_reader(std::fs::File::open(args.configuration.as_path())?)?
        }
    };

    info!(
        "Loaded {} root certificates",
        certificates.certificates.len()
    );

    Ok(())
}
