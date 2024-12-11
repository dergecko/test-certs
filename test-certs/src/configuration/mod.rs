//! Provides functionality to configure the application and certificate generation.
use std::{fmt::Display, path::PathBuf};

use clap::{Parser, ValueEnum};

pub mod certificates;

/// Create a set of certificates including a self signed CA.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Configuration file that contains the certificate generation definition.
    #[arg(short, long, default_value = "./certificate_generation.yaml")]
    pub configuration: PathBuf,

    /// Use the provided configuration language.
    #[arg(default_value_t = ConfigFormat::Yaml)]
    pub format: ConfigFormat,
}

/// Available configuration formats.
#[derive(Debug, Clone, ValueEnum)]
pub enum ConfigFormat {
    /// YAML Ain't Markup Language.
    Yaml,
    /// JavaScript Object Notation.
    Json,
}

impl Display for ConfigFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigFormat::Json => f.write_str("json"),
            ConfigFormat::Yaml => f.write_str("yaml"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_args() {
        let args = Args::try_parse_from(&["", "--configuration", "./file.yaml", "json"]).unwrap();

        assert_eq!(args.configuration.display().to_string(), "./file.yaml");
        assert_eq!(args.format.to_string(), "json");
    }
}
