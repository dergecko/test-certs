//! Provides functionality to configure the application and certificate generation.
use std::{fmt::Display, path::PathBuf};

use clap::{Parser, ValueEnum};
use clap_stdin::FileOrStdin;

pub mod certificates;

/// Create a set of certificates including a self signed CA.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// The input file that contains the certificate generation configuration.
    #[arg(short, long, default_value = "-")]
    pub input: FileOrStdin,

    /// Folder where all generated certificates will be saved.
    #[arg(short, long = "out-dir", default_value = "./certificates.d/")]
    pub outdir: PathBuf,

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
        let args =
            Args::try_parse_from(&["", "--input", "./file.yaml", "--out-dir", "./certs", "json"])
                .unwrap();

        assert_eq!(args.format.to_string(), "json");
        assert_eq!(args.outdir.display().to_string(), "./certs");
    }

    #[test]
    fn should_read_input_from_stdin() {
        let args = Args::try_parse_from(&["", "--out-dir", "./certs", "json"]).unwrap();

        assert!(args.input.is_stdin())
    }

    #[test]
    fn should_read_input_from_argument() {
        let args =
            Args::try_parse_from(&["", "--input", "./file.yaml", "--out-dir", "./certs", "json"])
                .unwrap();

        assert!(args.input.is_file());
        assert_eq!(args.input.filename(), "./file.yaml");
    }
}
