use clap::{Parser, Subcommand};
use nom_mpq::*;
use std::io::Write;

#[derive(Subcommand)]
enum Commands {
    /// List Files
    List,
    /// Extract a file from the archive
    ExtractFile {
        /// lists test values
        #[arg(short, long)]
        name: String,
    },
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    source: String,

    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    #[command(subcommand)]
    command: Commands,
}

fn main() {
    let cli = Cli::parse();
    let file_contents = parser::read_file(&cli.source);
    let (_input, mpq) = parser::parse(&file_contents).unwrap();
    match &cli.command {
        Commands::List => {
            for (filename, size) in mpq.get_files(&file_contents) {
                println!("{} {1:>8} bytes", filename, size);
            }
        }
        Commands::ExtractFile { name } => {
            let (_tail, file_data) = mpq
                .read_mpq_file_sector(name, false, &file_contents)
                .unwrap();
            for word in file_data {
                let bytes = word.to_le_bytes();
                let _ = std::io::stdout().write_all(&bytes);
            }
            let _ = std::io::stdout().flush();
        }
    }
}
