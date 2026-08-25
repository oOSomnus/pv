//! Command-line entry point for the PV encrypted Vault manager.

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use pv::app::{App, DEFAULT_VAULT_PATH, DialoguerInteraction};

/// The banner shown when the command-line application starts.
const ASCII_ART: &str = r#"
█ ▄▄     ▄
█   █     █
█▀▀▀ █     █
█     █    █
 █     █  █
  ▀     █▐
        ▐
"#;

/// Parsed command-line arguments for the PV application.
#[derive(Debug, Parser)]
#[command(version, about = "Simple password manager.")]
struct Cli {
    /// The Vault workflow to run.
    #[command(subcommand)]
    command: Commands,
}

/// The workflows exposed by the PV command-line application.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize a new empty Vault.
    Init {
        /// An optional destination path, defaulting to `./pv.vault`.
        path: Option<PathBuf>,
    },
    /// Open an existing Vault.
    Open {
        /// An optional source path, defaulting to `./pv.vault`.
        path: Option<PathBuf>,
    },
}

/// Parses the command line and runs the selected Vault workflow.
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

/// Resolves the default Vault path used when no path argument is supplied.
fn default_vault_path() -> PathBuf {
    PathBuf::from(DEFAULT_VAULT_PATH)
}
