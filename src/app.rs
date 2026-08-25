use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use dialoguer::{Password, Select};
use thiserror::Error;

use crate::vault::{Vault, VaultError};

pub const DEFAULT_VAULT_PATH: &str = "./pv.vault";

pub trait Interaction {
    fn password(&mut self, prompt: &str) -> Result<String, InteractionError>;

    fn choose(&mut self, prompt: &str, options: &[&str]) -> Result<usize, InteractionError>;

    fn message(&mut self, message: &str) -> Result<(), InteractionError>;
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct InteractionError {
    message: String,
}

pub struct DialoguerInteraction;

impl Interaction for DialoguerInteraction {
    fn password(&mut self, prompt: &str) -> Result<String, InteractionError> {
        Password::new()
            .with_prompt(prompt)
            .interact()
            .map_err(|error| InteractionError::new(error.to_string()))
    }

    fn choose(&mut self, prompt: &str, options: &[&str]) -> Result<usize, InteractionError> {
        if options.is_empty() {
            return Err(InteractionError::new("no menu options are available"));
        }
        Select::new()
            .with_prompt(prompt)
            .items(options)
            .default(0)
            .interact()
            .map_err(|error| InteractionError::new(error.to_string()))
    }

    fn message(&mut self, message: &str) -> Result<(), InteractionError> {
        eprintln!("{message}");
        Ok(())
    }
}

impl InteractionError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("vault already exists at {path}; refusing to overwrite it")]
    VaultAlreadyExists { path: PathBuf },

    #[error("could not inspect vault path {path}: {source}")]
    InspectVaultPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not create vault at {path}: {source}")]
    CreateVault {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not write vault at {path}: {source}")]
    WriteVault {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not read vault at {path}: {source}")]
    ReadVault {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("master passwords do not match")]
    PasswordMismatch,

    #[error("invalid choice {choice} for {prompt}")]
    InvalidChoice { prompt: &'static str, choice: usize },

    #[error("interaction failed: {0}")]
    Interaction(#[from] InteractionError),

    #[error(transparent)]
    Vault(#[from] VaultError),
}

pub struct App<I> {
    interaction: I,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenResult {
    Exited,
    Cancelled,
}

impl<I: Interaction> App<I> {
    pub fn new(interaction: I) -> Self {
        Self { interaction }
    }

    pub fn init(&mut self, path: &Path) -> Result<(), AppError> {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(AppError::VaultAlreadyExists {
                    path: path.to_owned(),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(AppError::InspectVaultPath {
                    path: path.to_owned(),
                    source,
                });
            }
        }

        let password = self.ask_non_empty_password("Master password")?;
        let confirmation = self.ask_non_empty_password("Confirm master password")?;
        if password != confirmation {
            return Err(AppError::PasswordMismatch);
        }

        let vault = Vault::new(&password)?;
        let bytes = vault.to_bytes()?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(AppError::VaultAlreadyExists {
                    path: path.to_owned(),
                });
            }
            Err(source) => {
                return Err(AppError::CreateVault {
                    path: path.to_owned(),
                    source,
                });
            }
        };

        if let Err(source) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(AppError::WriteVault {
                path: path.to_owned(),
                source,
            });
        }

        Ok(())
    }

    pub fn open(&mut self, path: &Path) -> Result<OpenResult, AppError> {
        let bytes = fs::read(path).map_err(|source| AppError::ReadVault {
            path: path.to_owned(),
            source,
        })?;

        loop {
            let password = self.interaction.password("Master password")?;
            match Vault::unlock(&bytes, &password) {
                Ok(_vault) => {
                    let choice = self.interaction.choose("Vault", &["Exit"])?;
                    return match choice {
                        0 => Ok(OpenResult::Exited),
                        choice => Err(AppError::InvalidChoice {
                            prompt: "Vault",
                            choice,
                        }),
                    };
                }
                Err(VaultError::InvalidMasterPassword) => {
                    self.interaction
                        .message("Incorrect master password or damaged Vault.")?;
                    let choice = self
                        .interaction
                        .choose("Incorrect password", &["Retry", "Cancel"])?;
                    match choice {
                        0 => continue,
                        1 => return Ok(OpenResult::Cancelled),
                        choice => {
                            return Err(AppError::InvalidChoice {
                                prompt: "Incorrect password",
                                choice,
                            });
                        }
                    }
                }
                Err(error) => return Err(AppError::Vault(error)),
            }
        }
    }

    fn ask_non_empty_password(&mut self, prompt: &str) -> Result<String, AppError> {
        loop {
            let password = self.interaction.password(prompt)?;
            if !password.is_empty() {
                return Ok(password);
            }
            self.interaction
                .message("Master password cannot be empty.")?;
        }
    }
}
