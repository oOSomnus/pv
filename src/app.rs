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

/// Represents a value or renderer-neutral navigation action returned by an adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractionResult<T> {
    /// Returns the ordinary value collected by the interaction.
    Value(T),
    /// Moves to the immediate parent of the current interaction step.
    Back,
    /// Abandons the current interaction flow.
    Cancel,
}

/// Supplies the user interaction needed by the Vault workflows.
pub trait Interaction {
    /// Reads a hidden password or returns a renderer-neutral navigation action.
    fn password(&mut self, prompt: &str) -> Result<InteractionResult<String>, InteractionError>;

    /// Reads a hidden password, applying `default` when the submitted value is empty.
    fn password_with_default(
        &mut self,
        prompt: &str,
        default: &str,
    ) -> Result<InteractionResult<String>, InteractionError> {
        match self.password(prompt)? {
            InteractionResult::Value(value) if value.is_empty() => {
                Ok(InteractionResult::Value(default.to_owned()))
            }
            InteractionResult::Value(value) => Ok(InteractionResult::Value(value)),
            InteractionResult::Back => Ok(InteractionResult::Back),
            InteractionResult::Cancel => Ok(InteractionResult::Cancel),
        }
    }

    /// Reads visible text or returns a renderer-neutral navigation action.
    fn input(&mut self, prompt: &str) -> Result<InteractionResult<String>, InteractionError>;

    /// Reads visible text, applies `default` to an empty value, or returns a navigation action.
    fn input_with_default(
        &mut self,
        prompt: &str,
        default: &str,
    ) -> Result<InteractionResult<String>, InteractionError> {
        match self.input(prompt)? {
            InteractionResult::Value(input) if input.trim().is_empty() => {
                Ok(InteractionResult::Value(default.to_owned()))
            }
            InteractionResult::Value(input) => Ok(InteractionResult::Value(input)),
            InteractionResult::Back => Ok(InteractionResult::Back),
            InteractionResult::Cancel => Ok(InteractionResult::Cancel),
        }
    }

    /// Presents a menu and returns a selected index or navigation action.
    fn choose(
        &mut self,
        prompt: &str,
        options: &[&str],
    ) -> Result<InteractionResult<usize>, InteractionError>;

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
    fn password(&mut self, prompt: &str) -> Result<InteractionResult<String>, InteractionError> {
        Password::new()
            .with_prompt(prompt)
            .interact()
            .map(InteractionResult::Value)
            .map_err(|error| InteractionError::new(error.to_string()))
    }

    /// Reads visible text using dialoguer's text prompt.
    fn input(&mut self, prompt: &str) -> Result<InteractionResult<String>, InteractionError> {
        Input::<String>::new()
            .with_prompt(prompt)
            .interact_text()
            .map(InteractionResult::Value)
            .map_err(|error| InteractionError::new(error.to_string()))
    }

    /// Reads visible text with a dialoguer default accepted by pressing Enter.
    fn input_with_default(
        &mut self,
        prompt: &str,
        default: &str,
    ) -> Result<InteractionResult<String>, InteractionError> {
        Input::<String>::new()
            .with_prompt(prompt)
            .default(default.to_owned())
            .interact_text()
            .map(InteractionResult::Value)
            .map_err(|error| InteractionError::new(error.to_string()))
    }

    /// Displays a dialoguer selection menu and returns its selected index.
    fn choose(
        &mut self,
        prompt: &str,
        options: &[&str],
    ) -> Result<InteractionResult<usize>, InteractionError> {
        if options.is_empty() {
            return Err(InteractionError::new("no menu options are available"));
        }
        Select::new()
            .with_prompt(prompt)
            .items(options)
            .default(0)
            .interact()
            .map(InteractionResult::Value)
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

/// Stores manual Add fields until the user explicitly saves the Credential.
#[derive(Default)]
struct CredentialDraft {
    /// The website or service identifier entered for the pending Credential.
    key: String,
    /// The login identity entered for the pending Credential.
    name: String,
    /// The opaque secret entered for the pending Credential.
    value: String,
}

/// Identifies the current step in the manual Credential Draft workflow.
enum ManualDraftStep {
    /// Collects or edits the pending Credential Key.
    Key,
    /// Collects or edits the pending Credential Name.
    Name,
    /// Collects or edits the pending opaque Credential Value.
    Value,
    /// Presents the pending Credential for a save decision.
    Review,
}

/// Describes how the manual Draft workflow should return to its parent.
enum ManualDraftOutcome {
    /// Returns from the Key step to the Add value-type selection.
    BackToValueType,
    /// Completes the Add interaction, whether by Save or Cancel.
    Completed,
}

/// Describes how an open Vault session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenResult {
    /// The user selected Exit or a root-level navigation action from the Vault home.
    Exited,
    /// The user cancelled or returned from the unlock workflow.
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

        let Some(password) = self.ask_non_empty_password("Master password")? else {
            return Ok(());
        };
        let Some(confirmation) = self.ask_non_empty_password("Confirm master password")? else {
            return Ok(());
        };
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
            let password = match self.interaction.password("Master password")? {
                InteractionResult::Value(password) => password,
                InteractionResult::Back | InteractionResult::Cancel => {
                    return Ok(OpenResult::Cancelled);
                }
            };
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
                        InteractionResult::Value(0) => continue,
                        InteractionResult::Value(1)
                        | InteractionResult::Back
                        | InteractionResult::Cancel => return Ok(OpenResult::Cancelled),
                        InteractionResult::Value(choice) => {
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
                InteractionResult::Value(0) => self.add_credential(path, vault)?,
                InteractionResult::Value(1) => self.get_credential(vault)?,
                InteractionResult::Value(2) => self.remove_credential(path, vault)?,
                InteractionResult::Value(3)
                | InteractionResult::Back
                | InteractionResult::Cancel => return Ok(OpenResult::Exited),
                InteractionResult::Value(choice) => {
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
            InteractionResult::Value(0) => Ok(true),
            InteractionResult::Value(1) | InteractionResult::Back | InteractionResult::Cancel => {
                Ok(false)
            }
            InteractionResult::Value(choice) => Err(AppError::InvalidChoice { prompt, choice }),
        }
    }

    /// Resolves an exact or fuzzy Key, returning `None` when lookup is cancelled.
    fn resolve_credential<'vault>(
        &mut self,
        vault: &'vault Vault,
    ) -> Result<Option<&'vault Credential>, AppError> {
        loop {
            let query = match self.interaction.input("Key")? {
                InteractionResult::Value(query) => query,
                InteractionResult::Back | InteractionResult::Cancel => return Ok(None),
            };
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
                    InteractionResult::Value(choice) if choice < suggestions.len() => {
                        return Ok(Some(suggestions[choice]));
                    }
                    InteractionResult::Value(choice) if choice == suggestions.len() => {
                        return Ok(None);
                    }
                    InteractionResult::Back | InteractionResult::Cancel => return Ok(None),
                    InteractionResult::Value(choice) => {
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
                InteractionResult::Value(0) => {}
                InteractionResult::Value(1)
                | InteractionResult::Back
                | InteractionResult::Cancel => return Ok(None),
                InteractionResult::Value(choice) => {
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
        let mut draft = CredentialDraft::default();

        loop {
            let use_generated_value = match self
                .interaction
                .choose("Value type", &["Manual Value", "Generated value"])?
            {
                InteractionResult::Value(0) => false,
                InteractionResult::Value(1) => true,
                InteractionResult::Back | InteractionResult::Cancel => return Ok(()),
                InteractionResult::Value(choice) => {
                    return Err(AppError::InvalidChoice {
                        prompt: "Value type",
                        choice,
                    });
                }
            };

            if use_generated_value {
                return self.add_generated_credential(path, vault);
            }

            match self.add_manual_credential(path, vault, &mut draft)? {
                ManualDraftOutcome::BackToValueType => {}
                ManualDraftOutcome::Completed => return Ok(()),
            }
        }
    }

    /// Collects, reviews, and conditionally saves one manual Credential Draft.
    fn add_manual_credential(
        &mut self,
        path: &Path,
        vault: &mut Vault,
        draft: &mut CredentialDraft,
    ) -> Result<ManualDraftOutcome, AppError> {
        let mut step = ManualDraftStep::Key;

        loop {
            match step {
                ManualDraftStep::Key => {
                    match self.interaction.input_with_default("Key", &draft.key)? {
                        InteractionResult::Value(key) => {
                            draft.key = key;
                            step = ManualDraftStep::Name;
                        }
                        InteractionResult::Back => {
                            return Ok(ManualDraftOutcome::BackToValueType);
                        }
                        InteractionResult::Cancel => {
                            return Ok(ManualDraftOutcome::Completed);
                        }
                    }
                }
                ManualDraftStep::Name => {
                    match self.interaction.input_with_default("Name", &draft.name)? {
                        InteractionResult::Value(name) => {
                            draft.name = name;
                            step = ManualDraftStep::Value;
                        }
                        InteractionResult::Back => step = ManualDraftStep::Key,
                        InteractionResult::Cancel => {
                            return Ok(ManualDraftOutcome::Completed);
                        }
                    }
                }
                ManualDraftStep::Value => match self
                    .interaction
                    .password_with_default("Value", &draft.value)?
                {
                    InteractionResult::Value(value) => {
                        draft.value = value;
                        step = ManualDraftStep::Review;
                    }
                    InteractionResult::Back => step = ManualDraftStep::Name,
                    InteractionResult::Cancel => {
                        return Ok(ManualDraftOutcome::Completed);
                    }
                },
                ManualDraftStep::Review => {
                    self.interaction.message(&format!(
                        "Key: {}\nName: {}\nValue: [REDACTED]",
                        draft.key, draft.name
                    ))?;
                    let choice = self
                        .interaction
                        .choose("Review", &["Save", "Back", "Cancel"])?;
                    match choice {
                        InteractionResult::Value(0) => {
                            let credential = Credential::new(
                                draft.key.clone(),
                                draft.name.clone(),
                                draft.value.clone(),
                            );
                            if vault.find_credential(credential.key()).is_some() {
                                self.interaction
                                    .message("A Credential entry with that Key already exists.")?;
                                let duplicate_choice = self
                                    .interaction
                                    .choose("Duplicate Key", &["Overwrite", "Back"])?;
                                match duplicate_choice {
                                    InteractionResult::Value(0) => {}
                                    InteractionResult::Value(1) | InteractionResult::Back => {
                                        step = ManualDraftStep::Review;
                                        continue;
                                    }
                                    InteractionResult::Cancel => {
                                        return Ok(ManualDraftOutcome::Completed);
                                    }
                                    InteractionResult::Value(choice) => {
                                        return Err(AppError::InvalidChoice {
                                            prompt: "Duplicate Key",
                                            choice,
                                        });
                                    }
                                }
                            }

                            vault.upsert_credential(credential);
                            Self::persist(path, vault)?;
                            self.interaction.message("Credential entry saved.")?;
                            return Ok(ManualDraftOutcome::Completed);
                        }
                        InteractionResult::Value(1) | InteractionResult::Back => {
                            step = ManualDraftStep::Value;
                        }
                        InteractionResult::Value(2) | InteractionResult::Cancel => {
                            return Ok(ManualDraftOutcome::Completed);
                        }
                        InteractionResult::Value(choice) => {
                            return Err(AppError::InvalidChoice {
                                prompt: "Review",
                                choice,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Collects one Generated-value Credential and persists it after duplicate handling.
    fn add_generated_credential(&mut self, path: &Path, vault: &mut Vault) -> Result<(), AppError> {
        let key = match self.interaction.input("Key")? {
            InteractionResult::Value(key) => key,
            InteractionResult::Back | InteractionResult::Cancel => return Ok(()),
        };
        let name = match self.interaction.input("Name")? {
            InteractionResult::Value(name) => name,
            InteractionResult::Back | InteractionResult::Cancel => return Ok(()),
        };
        let value = match self.generated_value()? {
            Some(value) => value,
            None => return Ok(()),
        };
        let credential = Credential::new(key, name, value);

        if vault.find_credential(credential.key()).is_some() {
            self.interaction
                .message("A Credential entry with that Key already exists.")?;
            let choice = self
                .interaction
                .choose("Duplicate Key", &["Overwrite", "Cancel"])?;
            match choice {
                InteractionResult::Value(0) => {}
                InteractionResult::Value(1)
                | InteractionResult::Back
                | InteractionResult::Cancel => return Ok(()),
                InteractionResult::Value(choice) => {
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
        let Some(options) = self.generated_value_options()? else {
            return Ok(None);
        };
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
                InteractionResult::Value(0) => return Ok(Some(value)),
                InteractionResult::Value(1) => {}
                InteractionResult::Value(2)
                | InteractionResult::Back
                | InteractionResult::Cancel => return Ok(None),
                InteractionResult::Value(choice) => {
                    return Err(AppError::InvalidChoice {
                        prompt: "Generated value",
                        choice,
                    });
                }
            }
        }
    }

    /// Prompts for a valid Generated value length and its optional character classes.
    fn generated_value_options(&mut self) -> Result<Option<GeneratedValueOptions>, AppError> {
        let default_length = DEFAULT_LENGTH.to_string();
        let length = loop {
            let entered = self
                .interaction
                .input_with_default("Generated value length (10-100)", &default_length)?;
            let entered = match entered {
                InteractionResult::Value(entered) => entered,
                InteractionResult::Back | InteractionResult::Cancel => return Ok(None),
            };
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

        let Some(include_digits) = self.choose_generated_option("Include digits")? else {
            return Ok(None);
        };
        let Some(include_punctuation) = self.choose_generated_option("Include punctuation")? else {
            return Ok(None);
        };
        Ok(Some(GeneratedValueOptions::new(
            length,
            include_digits,
            include_punctuation,
        )?))
    }

    /// Asks whether one optional Generated value character class should be enabled.
    fn choose_generated_option(&mut self, prompt: &'static str) -> Result<Option<bool>, AppError> {
        let choice = self.interaction.choose(prompt, &["Yes", "No"])?;
        match choice {
            InteractionResult::Value(0) => Ok(Some(true)),
            InteractionResult::Value(1) => Ok(Some(false)),
            InteractionResult::Back | InteractionResult::Cancel => Ok(None),
            InteractionResult::Value(choice) => Err(AppError::InvalidChoice { prompt, choice }),
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
    fn ask_non_empty_password(&mut self, prompt: &str) -> Result<Option<String>, AppError> {
        loop {
            let password = match self.interaction.password(prompt)? {
                InteractionResult::Value(password) => password,
                InteractionResult::Back | InteractionResult::Cancel => return Ok(None),
            };
            if !password.is_empty() {
                return Ok(Some(password));
            }
            self.interaction
                .message("Master password cannot be empty.")?;
        }
    }
}
