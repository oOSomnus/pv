//! Command-line entry point for the PV encrypted Vault manager.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use pv::{
    app::{App, DEFAULT_VAULT_PATH, Interaction, InteractionResult},
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
    loop {
        let interaction = match TuiInteraction::new(workflow) {
            Ok(interaction) => interaction,
            Err(error) => {
                eprintln!("Error: {error}");
                return ExitCode::FAILURE;
            }
        };

        let (result, mut interaction) = {
            let mut app = App::new(interaction);
            let result = match &cli.command {
                Commands::Init { path } => {
                    let path = path
                        .as_deref()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(default_vault_path);
                    app.init(&path)
                }
                Commands::Open { path } => {
                    let path = path
                        .as_deref()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(default_vault_path);
                    app.open(&path).map(|_| ())
                }
            };
            (result, app.into_interaction())
        };

        match result {
            Ok(()) => return ExitCode::SUCCESS,
            Err(error) => {
                let message = format!("Error: {error}");
                match interaction.display("Error", &message) {
                    Ok(InteractionResult::Back) => continue,
                    Ok(InteractionResult::Value(()) | InteractionResult::Cancel) => {
                        return ExitCode::FAILURE;
                    }
                    Err(display_error) => {
                        eprintln!("{message}\nError: {display_error}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    }
}

/// Resolves the default Vault path used when no path argument is supplied.
fn default_vault_path() -> PathBuf {
    PathBuf::from(DEFAULT_VAULT_PATH)
}
