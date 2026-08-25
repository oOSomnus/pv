//! Command-line entry point for the PV encrypted Vault manager.

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use pv::{
    app::{App, DEFAULT_VAULT_PATH},
    tui::{TuiInteraction, TuiWorkflow},
};

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
    let cli = Cli::parse();
    let workflow = match &cli.command {
        Commands::Init { .. } => TuiWorkflow::Init,
        Commands::Open { .. } => TuiWorkflow::Open,
    };
    let interaction = match TuiInteraction::new(workflow) {
        Ok(interaction) => interaction,
        Err(error) => {
            eprintln!("Error: {error}");
            return ExitCode::FAILURE;
        }
    };

    let result = {
        let mut app = App::new(interaction);
        match cli.command {
            Commands::Init { path } => app.init(&path.unwrap_or_else(default_vault_path)),
            Commands::Open { path } => app
                .open(&path.unwrap_or_else(default_vault_path))
                .map(|_| ()),
        }
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
