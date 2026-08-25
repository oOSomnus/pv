use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use pv::app::{App, DEFAULT_VAULT_PATH, DialoguerInteraction};

const ASCII_ART: &str = r#"
█ ▄▄     ▄
█   █     █
█▀▀▀ █     █
█     █    █
 █     █  █
  ▀     █▐
        ▐
"#;

#[derive(Debug, Parser)]
#[command(version, about = "Simple password manager.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize a new vault.
    Init { path: Option<PathBuf> },
    /// Open a vault.
    Open { path: Option<PathBuf> },
}

fn main() -> ExitCode {
    println!("{ASCII_ART}");
    let cli = Cli::parse();
    let mut app = App::new(DialoguerInteraction);

    let result = match cli.command {
        Commands::Init { path } => app.init(&path.unwrap_or_else(default_vault_path)),
        Commands::Open { path } => app
            .open(&path.unwrap_or_else(default_vault_path))
            .map(|_| ()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn default_vault_path() -> PathBuf {
    PathBuf::from(DEFAULT_VAULT_PATH)
}
