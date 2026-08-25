use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use dialoguer::{Input, Password, Select};
use thiserror::Error;

use crate::{
    generator::{self, DEFAULT_LENGTH, GeneratedValueOptions, GeneratorError},
    vault::{Credential, Vault, VaultError},
};

/// The Vault path used by the command line when the caller omits a path.
pub const DEFAULT_VAULT_PATH: &str = "./pv.vault";

/// Supplies the user interaction needed by the Vault workflows.
pub trait Interaction {
    /// Reads a hidden password from the user.
    fn password(&mut self, prompt: &str) -> Result<String, InteractionError>;

    /// Reads visible text from the user, or returns an error when unsupported.
    fn input(&mut self, prompt: &str) -> Result<String, InteractionError> {
        Err(InteractionError::new(format!(
            "visible input is unavailable for prompt {prompt}"
        )))
    }

    /// Reads visible text and supplies `default` when the adapter returns empty text.
    fn input_with_default(
        &mut self,
        prompt: &str,
        default: &str,
    ) -> Result<String, InteractionError> {
        let input = self.input(prompt)?;
        if input.trim().is_empty() {
            Ok(default.to_owned())
        } else {
            Ok(input)
        }
    }

    /// Presents a menu and returns the selected option index.
    fn choose(&mut self, prompt: &str, options: &[&str]) -> Result<usize, InteractionError>;

    /// Displays an informational or error message to the user.
    fn message(&mut self, message: &str) -> Result<(), InteractionError>;
}

/// Describes a failure while communicating with the interaction adapter.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct InteractionError {
    /// The user-facing description of the interaction failure.
    message: String,
}

/// Uses dialoguer to provide the production interaction adapter.
pub struct DialoguerInteraction;

impl Interaction for DialoguerInteraction {
    /// Reads a hidden password using dialoguer's password prompt.
    fn password(&mut self, prompt: &str) -> Result<String, InteractionError> {
        Password::new()
            .with_prompt(prompt)
            .interact()
            .map_err(|error| InteractionError::new(error.to_string()))
    }

    /// Reads visible text using dialoguer's text prompt.
    fn input(&mut self, prompt: &str) -> Result<String, InteractionError> {
        Input::<String>::new()
            .with_prompt(prompt)
            .interact_text()
            .map_err(|error| InteractionError::new(error.to_string()))
    }

    /// Reads visible text with a dialoguer default accepted by pressing Enter.
    fn input_with_default(
        &mut self,
        prompt: &str,
        default: &str,
    ) -> Result<String, InteractionError> {
        Input::<String>::new()
            .with_prompt(prompt)
            .default(default.to_owned())
            .interact_text()
            .map_err(|error| InteractionError::new(error.to_string()))
    }

    /// Displays a dialoguer selection menu and returns its selected index.
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

    /// Writes an informational or error message to standard error.
    fn message(&mut self, message: &str) -> Result<(), InteractionError> {
        eprintln!("{message}");
        Ok(())
    }
}

impl InteractionError {
    /// Creates an interaction error from a user-facing message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Errors returned while initializing or opening a Vault.
#[derive(Debug, Error)]
pub enum AppError {
    /// The target already exists and cannot be overwritten by initialization.
    #[error("vault already exists at {path}; refusing to overwrite it")]
    VaultAlreadyExists {
        /// The path that already exists.
        path: PathBuf,
    },

    /// The application could not inspect the requested Vault path.
    #[error("could not inspect vault path {path}: {source}")]
    InspectVaultPath {
        /// The path whose metadata could not be inspected.
        path: PathBuf,
        /// The operating-system error returned by the metadata lookup.
        #[source]
        source: std::io::Error,
    },

    /// The application could not create the requested Vault file.
    #[error("could not create vault at {path}: {source}")]
    CreateVault {
        /// The path where the new Vault could not be created.
        path: PathBuf,
        /// The operating-system error returned by file creation.
        #[source]
        source: std::io::Error,
    },

    /// The application could not persist the newly created Vault.
    #[error("could not write vault at {path}: {source}")]
    WriteVault {
        /// The path where the Vault could not be persisted.
        path: PathBuf,
        /// The operating-system error returned by writing or syncing.
        #[source]
        source: std::io::Error,
    },

    /// The application could not read the requested Vault file.
    #[error("could not read vault at {path}: {source}")]
    ReadVault {
        /// The path that could not be read.
        path: PathBuf,
        /// The operating-system error returned by reading.
        #[source]
        source: std::io::Error,
    },

    /// The two initialization password entries differ.
    #[error("master passwords do not match")]
    PasswordMismatch,

    /// The interaction adapter returned an option outside the menu's range.
    #[error("invalid choice {choice} for {prompt}")]
    InvalidChoice {
        /// The menu prompt associated with the invalid selection.
        prompt: &'static str,
        /// The invalid zero-based option index.
        choice: usize,
    },

    /// The interaction adapter failed while collecting user input.
    #[error("interaction failed: {0}")]
    Interaction(#[from] InteractionError),

    /// The Vault envelope or encrypted payload was invalid.
    #[error(transparent)]
    Vault(#[from] VaultError),

    /// A Generated value could not be configured or created.
    #[error(transparent)]
    Generator(#[from] GeneratorError),
}

/// Runs the interactive Vault workflows against an injected interaction adapter.
pub struct App<I> {
    /// The adapter used to collect input and present messages and menus.
    interaction: I,
}

/// Describes how an open Vault session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenResult {
    /// The user selected Exit from the open Vault menu.
    Exited,
    /// The user cancelled after an incorrect password.
    Cancelled,
}

impl<I: Interaction> App<I> {
    /// Creates an application workflow backed by the supplied interaction adapter.
    pub fn new(interaction: I) -> Self {
        Self { interaction }
    }

    /// Prompts for a Master password and persists a new empty Vault at `path`.
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

    /// Opens `path`, unlocks it, and runs the Vault menu until it exits or cancels.
    pub fn open(&mut self, path: &Path) -> Result<OpenResult, AppError> {
        let bytes = fs::read(path).map_err(|source| AppError::ReadVault {
            path: path.to_owned(),
            source,
        })?;

        loop {
            let password = self.interaction.password("Master password")?;
            match Vault::unlock(&bytes, &password) {
                Ok(mut vault) => {
                    return self.run_open_session(path, &mut vault);
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

    /// Runs the credential menu for an already unlocked Vault.
    fn run_open_session(&mut self, path: &Path, vault: &mut Vault) -> Result<OpenResult, AppError> {
        loop {
            let choice = self
                .interaction
                .choose("Vault", &["Add", "Get", "Remove", "Exit"])?;
            match choice {
                0 => self.add_credential(path, vault)?,
                1 => self.get_credential(vault)?,
                2 => self.remove_credential(path, vault)?,
                3 => return Ok(OpenResult::Exited),
                choice => {
                    return Err(AppError::InvalidChoice {
                        prompt: "Vault",
                        choice,
                    });
                }
            }
        }
    }

    /// Resolves an exact normalized Key or fuzzy candidate, confirms removal twice, and persists the changed Vault.
    fn remove_credential(&mut self, path: &Path, vault: &mut Vault) -> Result<(), AppError> {
        let Some(credential) = self.resolve_credential(vault)? else {
            return Ok(());
        };
        let key = credential.key().to_owned();
        let name = credential.name().to_owned();

        self.interaction
            .message(&format!("Key: {key}\nName: {name}"))?;
        if !self.confirm_removal("Remove Credential entry", "Confirm")? {
            return Ok(());
        }
        if !self.confirm_removal("Confirm deletion", "Delete")? {
            return Ok(());
        }

        vault.remove_credential(&key);
        Self::persist(path, vault)
    }

    /// Presents a positive confirmation and returns `false` for the cancellation choice.
    fn confirm_removal(
        &mut self,
        prompt: &'static str,
        positive_choice: &'static str,
    ) -> Result<bool, AppError> {
        let choice = self
            .interaction
            .choose(prompt, &[positive_choice, "Cancel"])?;
        match choice {
            0 => Ok(true),
            1 => Ok(false),
            choice => Err(AppError::InvalidChoice { prompt, choice }),
        }
    }

    /// Resolves an exact or fuzzy Key, returning `None` when lookup is cancelled.
    fn resolve_credential<'vault>(
        &mut self,
        vault: &'vault Vault,
    ) -> Result<Option<&'vault Credential>, AppError> {
        loop {
            let query = self.interaction.input("Key")?;
            if let Some(credential) = vault.find_credential(&query) {
                return Ok(Some(credential));
            }

            self.interaction.message("Credential entry not found.")?;
            let suggestions = vault.find_credential_suggestions(&query);
            if !suggestions.is_empty() {
                let mut options: Vec<String> = suggestions
                    .iter()
                    .map(|credential| credential.key().to_owned())
                    .collect();
                options.push("Cancel".to_owned());
                let option_references: Vec<&str> = options.iter().map(String::as_str).collect();
                let choice = self
                    .interaction
                    .choose("Credential suggestions", &option_references)?;
                match choice {
                    choice if choice < suggestions.len() => {
                        return Ok(Some(suggestions[choice]));
                    }
                    choice if choice == suggestions.len() => return Ok(None),
                    choice => {
                        return Err(AppError::InvalidChoice {
                            prompt: "Credential suggestions",
                            choice,
                        });
                    }
                }
            }

            let choice = self
                .interaction
                .choose("Credential not found", &["Retry", "Cancel"])?;
            match choice {
                0 => {}
                1 => return Ok(None),
                choice => {
                    return Err(AppError::InvalidChoice {
                        prompt: "Credential not found",
                        choice,
                    });
                }
            }
        }
    }

    /// Collects one Credential using a manual or Generated value and persists it after duplicate handling.
    fn add_credential(&mut self, path: &Path, vault: &mut Vault) -> Result<(), AppError> {
        let use_generated_value = match self
            .interaction
            .choose("Value type", &["Manual Value", "Generated value"])?
        {
            0 => false,
            1 => true,
            choice => {
                return Err(AppError::InvalidChoice {
                    prompt: "Value type",
                    choice,
                });
            }
        };
        let key = self.interaction.input("Key")?;
        let name = self.interaction.input("Name")?;
        let value = if use_generated_value {
            match self.generated_value()? {
                Some(value) => value,
                None => return Ok(()),
            }
        } else {
            self.interaction.password("Value")?
        };
        let credential = Credential::new(key, name, value);

        if vault.find_credential(credential.key()).is_some() {
            self.interaction
                .message("A Credential entry with that Key already exists.")?;
            let choice = self
                .interaction
                .choose("Duplicate Key", &["Overwrite", "Cancel"])?;
            match choice {
                0 => {}
                1 => return Ok(()),
                choice => {
                    return Err(AppError::InvalidChoice {
                        prompt: "Duplicate Key",
                        choice,
                    });
                }
            }
        }

        vault.upsert_credential(credential);
        Self::persist(path, vault)
    }

    /// Collects Generated value options and lets the user review each generated value.
    fn generated_value(&mut self) -> Result<Option<String>, AppError> {
        let options = self.generated_value_options()?;
        let mut previous = None;

        loop {
            let value = generator::generate(options)?;
            if previous.as_deref() == Some(value.as_str()) {
                continue;
            }
            self.interaction
                .message(&format!("Generated value: {value}"))?;
            previous = Some(value.clone());

            let choice = self
                .interaction
                .choose("Generated value", &["Confirm", "Regenerate", "Cancel"])?;
            match choice {
                0 => return Ok(Some(value)),
                1 => {}
                2 => return Ok(None),
                choice => {
                    return Err(AppError::InvalidChoice {
                        prompt: "Generated value",
                        choice,
                    });
                }
            }
        }
    }

    /// Prompts for a valid Generated value length and its optional character classes.
    fn generated_value_options(&mut self) -> Result<GeneratedValueOptions, AppError> {
        let default_length = DEFAULT_LENGTH.to_string();
        let length = loop {
            let entered = self
                .interaction
                .input_with_default("Generated value length (10-100)", &default_length)?;
            let trimmed = entered.trim();
            let length = if trimmed.is_empty() {
                DEFAULT_LENGTH
            } else {
                match trimmed.parse::<usize>() {
                    Ok(length) => length,
                    Err(_) => {
                        self.interaction.message(
                            "Generated value length must be an integer from 10 through 100.",
                        )?;
                        continue;
                    }
                }
            };

            if let Err(error) = GeneratedValueOptions::new(length, true, true) {
                self.interaction.message(&error.to_string())?;
            } else {
                break length;
            }
        };

        let include_digits = self.choose_generated_option("Include digits")?;
        let include_punctuation = self.choose_generated_option("Include punctuation")?;
        Ok(GeneratedValueOptions::new(
            length,
            include_digits,
            include_punctuation,
        )?)
    }

    /// Asks whether one optional Generated value character class should be enabled.
    fn choose_generated_option(&mut self, prompt: &'static str) -> Result<bool, AppError> {
        let choice = self.interaction.choose(prompt, &["Yes", "No"])?;
        match choice {
            0 => Ok(true),
            1 => Ok(false),
            choice => Err(AppError::InvalidChoice { prompt, choice }),
        }
    }

    /// Looks up and displays one Credential, offering explicit fuzzy matches when needed.
    fn get_credential(&mut self, vault: &Vault) -> Result<(), AppError> {
        if let Some(credential) = self.resolve_credential(vault)? {
            self.display_credential(credential)?;
        }
        Ok(())
    }

    /// Displays a Credential's Key, Name, and Value through the interaction adapter.
    fn display_credential(&mut self, credential: &Credential) -> Result<(), AppError> {
        self.interaction.message(&format!(
            "Key: {}\nName: {}\nValue: {}",
            credential.key(),
            credential.name(),
            credential.value()
        ))?;
        Ok(())
    }

    /// Encrypts and synchronizes the current Vault at its existing path.
    fn persist(path: &Path, vault: &Vault) -> Result<(), AppError> {
        let bytes = vault.to_bytes()?;
        let mut options = OpenOptions::new();
        options.write(true).truncate(true);
        let mut file = options.open(path).map_err(|source| AppError::WriteVault {
            path: path.to_owned(),
            source,
        })?;

        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|source| AppError::WriteVault {
                path: path.to_owned(),
                source,
            })
    }

    /// Re-prompts until the interaction adapter returns a non-empty password.
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
