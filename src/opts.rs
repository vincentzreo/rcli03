use std::path::Path;

use clap::Parser;

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
}
#[derive(Debug, Parser)]
pub struct CsvOpts {
    #[arg(short, long, value_parser=verify_input_file)]
    pub input: String,
    #[arg(short, long, default_value = "output.json")] // "output.json".into()
    pub output: String,
    #[arg(short, long, default_value_t = ',')]
    pub delimiter: char,
    #[arg(long, default_value_t = true)]
    pub header: bool,
}
fn verify_input_file(filename: &str) -> Result<String, String> {
    if Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("File does not exist".into())
    }
}
