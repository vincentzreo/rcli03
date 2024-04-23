mod base64;
mod csv;
mod genpass;
mod http;
mod text;

use std::path::{Path, PathBuf};

use clap::Parser;

pub use self::base64::{Base64Format, Base64SubCommand};
pub use self::csv::CsvOpts;
pub use self::csv::OutputFormat;

pub use self::genpass::GenPassOpts;
pub use self::http::HttpSubCommand;
pub use self::text::{TextSignFormat, TextSubCommand};

// rcli csv -i input.csv -o output.csv --header -d ','
#[derive(Debug, Parser)]
#[command(name = "rcli", version, author, about, long_about=None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}
#[derive(Debug, Parser)]
pub enum SubCommand {
    #[command(name = "csv", about = "SHow CSV, or Convert CSV to other formats")]
    Csv(CsvOpts),
    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),
    #[command(subcommand)]
    Base64(Base64SubCommand),
    #[command(subcommand)]
    Text(TextSubCommand),
    #[command(subcommand)]
    Http(HttpSubCommand),
}

fn verify_file(filename: &str) -> Result<String, String> {
    if Path::new(filename).exists() || filename == "-" {
        Ok(filename.into())
    } else {
        Err("File does not exist".into())
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(path.into())
    } else {
        Err("Path does not exist or is not a directory")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_input_file() {
        assert_eq!(verify_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(verify_file("-"), Ok("-".into()));
        assert_eq!(verify_file("*"), Err("File does not exist".into()));
        assert_eq!(
            verify_file("non-existent-file"),
            Err("File does not exist".into())
        );
    }
}
