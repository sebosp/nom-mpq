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
    /// Extract a header from the archive
    ExtractHeader {
        /// Extract a specific named header
        #[arg(short, long)]
        name: String,
    },

    /// Generates a Rust file for a specific protocol.
    Generate {
        /// Generate a specific filename
        #[arg(short, long)]
        output: String,
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
    match &cli.command {
        Commands::Generate { output } => {
            s2protocol::generate_code_for_protocol(&cli.source, &output).unwrap();
        }
        Commands::List => {
            let file_contents = parser::read_file(&cli.source);
            let (_input, mpq) = parser::parse(&file_contents).unwrap();
            for (filename, size) in mpq.get_files(&file_contents) {
                println!("{} {1:>8} bytes", filename, size);
            }
        }
        Commands::ExtractFile { name } => {
            let file_contents = parser::read_file(&cli.source);
            let (_input, mpq) = parser::parse(&file_contents).unwrap();
            let (_tail, file_data) = mpq
                .read_mpq_file_sector(name, false, &file_contents)
                .unwrap();
            for word in file_data {
                let bytes = word.to_le_bytes();
                let _ = std::io::stdout().write_all(&bytes);
            }
            let _ = std::io::stdout().flush();
        }
        Commands::ExtractHeader { name } => {
            let file_contents = parser::read_file(&cli.source);
            let (_input, mpq) = parser::parse(&file_contents).unwrap();
            match name.as_ref() {
                "user_data.content" => {
                    let user_data = mpq
                        .user_data
                        .as_ref()
                        .expect("Unable to get user data, not provided in MPQ Archive");
                    for word in &user_data.content {
                        let bytes = word.to_le_bytes();
                        let _ = std::io::stdout().write_all(&bytes);
                    }
                    let _ = std::io::stdout().flush();
                }
                _ => eprintln!("Unknown header"),
            }
        }
    }
}
