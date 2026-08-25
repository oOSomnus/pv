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
    generator::{self, GeneratedValueOptions, GeneratorError},
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

    /// Presents a menu with `default` as the initially selected zero-based option.
    ///
    /// Adapters that do not support an initial selection fall back to [`Self::choose`].
    fn choose_with_default(
        &mut self,
        prompt: &str,
        options: &[&str],
        default: usize,
    ) -> Result<InteractionResult<usize>, InteractionError> {
        let _ = default;
        self.choose(prompt, options)
    }

    /// Shows a message and menu together, preserving the page while the user chooses an action.
    ///
    /// Adapters without a combined page render the message before presenting the menu.
    fn choose_page(
        &mut self,
        prompt: &str,
        message: &str,
        options: &[&str],
    ) -> Result<InteractionResult<usize>, InteractionError> {
        self.message(message)?;
        self.choose(prompt, options)
    }

    /// Displays an informational or error message to the user.
    fn message(&mut self, message: &str) -> Result<(), InteractionError>;

    /// Shows a page that remains visible until the user continues, goes Back, or Cancels.
    ///
    /// Adapters without a dedicated page interaction display the message and continue.
    fn display(
        &mut self,
        _prompt: &str,
        message: &str,
    ) -> Result<InteractionResult<()>, InteractionError> {
        self.message(message)?;
        Ok(InteractionResult::Value(()))
    }
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

    /// Displays a dialoguer selection menu with the requested initial option.
    fn choose_with_default(
        &mut self,
        prompt: &str,
        options: &[&str],
        default: usize,
    ) -> Result<InteractionResult<usize>, InteractionError> {
        if options.is_empty() {
            return Err(InteractionError::new("no menu options are available"));
        }
        Select::new()
            .with_prompt(prompt)
            .items(options)
            .default(default)
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
    /// The source selected for the pending Value, shown on Review.
    value_source: Option<CredentialValueSource>,
    /// The Random settings retained while the Draft is navigated.
    generated_settings: GeneratedValueSettings,
    /// The current unsaved Random candidate, when one has been generated.
    generated_candidate: Option<String>,
}

/// Identifies how the pending Credential Value was collected.
#[derive(Clone, Copy)]
enum CredentialValueSource {
    /// The user entered the Value manually.
    Manual,
    /// The application generated the Value from Random settings.
    Random,
}

impl CredentialValueSource {
    /// Returns the user-visible source label shown on Review.
    fn label(self) -> &'static str {
        match self {
            Self::Manual => "Manual",
            Self::Random => "Random",
        }
    }
}

/// Identifies the current step in the Credential Draft workflow.
enum CredentialDraftStep {
    /// Collects or edits the pending Credential Key.
    Key,
    /// Collects or edits the pending Credential Name.
    Name,
    /// Chooses and collects the pending opaque Credential Value.
    Value,
    /// Presents the pending Credential for a save decision.
    Review,
}

/// Describes the result of collecting a Credential Value.
enum ValueCollectionOutcome {
    /// Returns the in-memory Value selected or generated by the user.
    Value(String),
    /// Returns to the immediate parent of the Value step without changing the Draft.
    Back,
    /// Abandons the Add Draft without persisting it.
    Cancel,
}

/// Stores the Generated value settings selected for a pending Credential Draft.
#[derive(Clone, Copy)]
struct GeneratedValueSettings {
    /// The requested Generated value length.
    length: usize,
    /// Whether decimal Numbers are enabled.
    include_numbers: bool,
    /// Whether the supported Symbols are enabled.
    include_symbols: bool,
}

impl Default for GeneratedValueSettings {
    /// Returns the 1Password-style Generated value defaults.
    fn default() -> Self {
        let defaults = GeneratedValueOptions::default();
        Self {
            length: defaults.length(),
            include_numbers: defaults.includes_numbers(),
            include_symbols: defaults.includes_symbols(),
        }
    }
}

impl GeneratedValueSettings {
    /// Validates and converts the settings into generator options.
    fn options(self) -> Result<GeneratedValueOptions, GeneratorError> {
        GeneratedValueOptions::new(self.length, self.include_numbers, self.include_symbols)
    }

    /// Validates a candidate length with the current optional character settings.
    fn with_length(self, length: usize) -> Result<GeneratedValueOptions, GeneratorError> {
        Self { length, ..self }.options()
    }
}

/// Identifies the setting currently edited in the Generated value settings flow.
enum GeneratedValueSettingsStep {
    /// Collects the requested Generated value length.
    Length,
    /// Enables or disables decimal Numbers.
    Numbers,
    /// Enables or disables the supported Symbols.
    Symbols,
}

/// Describes the result of the shared duplicate-aware Credential save operation.
enum CredentialSaveOutcome {
    /// The Credential was upserted and persisted successfully.
    Saved,
    /// The user returned to the pending Credential without changing the Vault.
    Back,
    /// The user cancelled the save without changing the Vault.
    Cancelled,
}

/// Describes how an open Vault session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenResult {
    /// The user selected Exit or a root-level navigation action from the Vault home.
    Exited,
    /// The user cancelled or returned from the unlock workflow.
    Cancelled,
}

/// Describes a credential resolved through exact lookup or fuzzy selection.
#[derive(Debug)]
enum CredentialResolution<'vault> {
    /// The Key matched a Credential entry exactly after normalization.
    Exact(&'vault Credential),
    /// A fuzzy candidate was selected and its candidate list is retained for Back navigation.
    Fuzzy {
        /// The Credential entry selected by the user.
        credential: &'vault Credential,
        /// The fuzzy candidates displayed before the selection.
        candidates: Vec<&'vault Credential>,
    },
}

/// Identifies the immediate parent to which a Get detail page returns.
#[derive(Debug)]
enum GetDetailParent<'vault> {
    /// Returns to the initial Key lookup page.
    KeyLookup,
    /// Returns to the retained fuzzy candidate selection page.
    Suggestions(Vec<&'vault Credential>),
}

/// Copies the non-secret context shown while confirming Credential entry removal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemovalCandidate {
    /// The Key identifying the Credential entry.
    key: String,
    /// The Name associated with the Credential entry.
    name: String,
}

impl RemovalCandidate {
    /// Copies the removable context without retaining or exposing the Value.
    fn from_credential(credential: &Credential) -> Self {
        Self {
            key: credential.key().to_owned(),
            name: credential.name().to_owned(),
        }
    }
}

/// Identifies the Remove step to revisit when the user presses Back.
#[derive(Debug)]
enum RemovalParent {
    /// Returns to the Key lookup step.
    Lookup,
    /// Returns to a previously displayed fuzzy candidate selection.
    CandidateSelection {
        /// The fuzzy candidates to display again.
        candidates: Vec<RemovalCandidate>,
    },
}

/// Holds a selected Credential entry and its immediate Back destination.
#[derive(Debug)]
struct RemovalConfirmation {
    /// The Credential entry selected for removal.
    candidate: RemovalCandidate,
    /// The step to revisit when this confirmation receives Back.
    parent: RemovalParent,
}

/// Represents the current reversible Remove workflow step.
#[derive(Debug)]
enum RemovalStep {
    /// Requests an exact or fuzzy Key.
    Lookup,
    /// Displays fuzzy candidates for selection.
    CandidateSelection {
        /// The candidates available for selection.
        candidates: Vec<RemovalCandidate>,
    },
    /// Shows the first independent deletion confirmation.
    FirstConfirmation(RemovalConfirmation),
    /// Shows the second independent deletion confirmation.
    SecondConfirmation(RemovalConfirmation),
}

impl<I: Interaction> App<I> {
    /// Creates an application workflow backed by the supplied interaction adapter.
    pub fn new(interaction: I) -> Self {
        Self { interaction }
    }

    /// Returns the interaction adapter after the workflow has completed.
    ///
    /// This lets command-line callers present a final renderer-owned error page
    /// after the application has returned an [`AppError`].
    pub fn into_interaction(self) -> I {
        self.interaction
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

    /// Resolves a Key, navigates reversible removal confirmations, and persists only on success.
    fn remove_credential(&mut self, path: &Path, vault: &mut Vault) -> Result<(), AppError> {
        let mut step = RemovalStep::Lookup;
        loop {
            step = match step {
                RemovalStep::Lookup => match self.resolve_credential(vault)? {
                    None => return Ok(()),
                    Some(CredentialResolution::Exact(credential)) => {
                        RemovalStep::FirstConfirmation(RemovalConfirmation {
                            candidate: RemovalCandidate::from_credential(credential),
                            parent: RemovalParent::Lookup,
                        })
                    }
                    Some(CredentialResolution::Fuzzy {
                        credential,
                        candidates,
                    }) => RemovalStep::FirstConfirmation(RemovalConfirmation {
                        candidate: RemovalCandidate::from_credential(credential),
                        parent: RemovalParent::CandidateSelection {
                            candidates: candidates
                                .iter()
                                .map(|candidate| RemovalCandidate::from_credential(candidate))
                                .collect(),
                        },
                    }),
                },
                RemovalStep::CandidateSelection { candidates } => {
                    match self.choose_removal_candidate(&candidates)? {
                        InteractionResult::Value(choice) => {
                            RemovalStep::FirstConfirmation(RemovalConfirmation {
                                candidate: candidates[choice].clone(),
                                parent: RemovalParent::CandidateSelection { candidates },
                            })
                        }
                        InteractionResult::Back => RemovalStep::Lookup,
                        InteractionResult::Cancel => return Ok(()),
                    }
                }
                RemovalStep::FirstConfirmation(RemovalConfirmation { candidate, parent }) => {
                    self.show_removal_candidate(&candidate)?;
                    match self.confirm_removal("Remove Credential entry", "Confirm")? {
                        InteractionResult::Value(()) => {
                            RemovalStep::SecondConfirmation(RemovalConfirmation {
                                candidate,
                                parent,
                            })
                        }
                        InteractionResult::Back => match parent {
                            RemovalParent::Lookup => RemovalStep::Lookup,
                            RemovalParent::CandidateSelection { candidates } => {
                                RemovalStep::CandidateSelection { candidates }
                            }
                        },
                        InteractionResult::Cancel => return Ok(()),
                    }
                }
                RemovalStep::SecondConfirmation(RemovalConfirmation { candidate, parent }) => {
                    self.show_removal_candidate(&candidate)?;
                    match self.confirm_removal("Confirm deletion", "Delete")? {
                        InteractionResult::Value(()) => {
                            if vault.remove_credential(&candidate.key).is_none() {
                                return Ok(());
                            }
                            Self::persist(path, vault)?;
                            self.interaction
                                .message(&format!("Credential entry removed: {}", candidate.key))?;
                            return Ok(());
                        }
                        InteractionResult::Back => {
                            RemovalStep::FirstConfirmation(RemovalConfirmation {
                                candidate,
                                parent,
                            })
                        }
                        InteractionResult::Cancel => return Ok(()),
                    }
                }
            };
        }
    }

    /// Displays the non-secret context for a pending Credential entry removal.
    fn show_removal_candidate(&mut self, candidate: &RemovalCandidate) -> Result<(), AppError> {
        self.interaction
            .message(&format!("Key: {}\nName: {}", candidate.key, candidate.name))?;
        Ok(())
    }

    /// Presents a fuzzy candidate list and returns its navigation result.
    fn choose_removal_candidate(
        &mut self,
        candidates: &[RemovalCandidate],
    ) -> Result<InteractionResult<usize>, AppError> {
        let keys: Vec<String> = candidates
            .iter()
            .map(|candidate| candidate.key.clone())
            .collect();
        self.choose_credential_candidate(&keys)
    }

    /// Presents a positive confirmation and preserves Back separately from Cancel.
    fn confirm_removal(
        &mut self,
        prompt: &'static str,
        positive_choice: &'static str,
    ) -> Result<InteractionResult<()>, AppError> {
        let choice = self
            .interaction
            .choose(prompt, &[positive_choice, "Cancel"])?;
        match choice {
            InteractionResult::Value(0) => Ok(InteractionResult::Value(())),
            InteractionResult::Value(1) | InteractionResult::Cancel => {
                Ok(InteractionResult::Cancel)
            }
            InteractionResult::Back => Ok(InteractionResult::Back),
            InteractionResult::Value(choice) => Err(AppError::InvalidChoice { prompt, choice }),
        }
    }

    /// Resolves an exact or fuzzy Key, retaining fuzzy candidates for later Back navigation.
    fn resolve_credential<'vault>(
        &mut self,
        vault: &'vault Vault,
    ) -> Result<Option<CredentialResolution<'vault>>, AppError> {
        loop {
            let query = match self.interaction.input("Key")? {
                InteractionResult::Value(query) => query,
                InteractionResult::Back | InteractionResult::Cancel => return Ok(None),
            };
            if let Some(credential) = vault.find_credential(&query) {
                return Ok(Some(CredentialResolution::Exact(credential)));
            }

            self.interaction.message("Credential entry not found.")?;
            let suggestions = vault.find_credential_suggestions(&query);
            if !suggestions.is_empty() {
                let options = Self::credential_suggestion_options(&suggestions);
                match self.choose_credential_candidate(&options)? {
                    InteractionResult::Value(choice) => {
                        return Ok(Some(CredentialResolution::Fuzzy {
                            credential: suggestions[choice],
                            candidates: suggestions,
                        }));
                    }
                    InteractionResult::Back => continue,
                    InteractionResult::Cancel => return Ok(None),
                }
            }

            let choice = loop {
                let choice = self
                    .interaction
                    .choose("Credential not found", &["Retry", "Cancel"])?;
                match choice {
                    InteractionResult::Value(0)
                    | InteractionResult::Value(1)
                    | InteractionResult::Back
                    | InteractionResult::Cancel => break choice,
                    InteractionResult::Value(_) => {
                        self.interaction
                            .message("Invalid retry selection. Choose Retry, Back, or Cancel.")?;
                    }
                }
            };
            match choice {
                InteractionResult::Value(0) => {}
                InteractionResult::Value(1) | InteractionResult::Cancel => return Ok(None),
                InteractionResult::Back => continue,
                InteractionResult::Value(choice) => {
                    return Err(AppError::InvalidChoice {
                        prompt: "Credential not found",
                        choice,
                    });
                }
            }
        }
    }

    /// Presents fuzzy Key candidates and maps navigation actions to workflow results.
    fn choose_credential_candidate(
        &mut self,
        candidates: &[String],
    ) -> Result<InteractionResult<usize>, AppError> {
        loop {
            let mut options = candidates.to_owned();
            options.push("Cancel".to_owned());
            let option_references: Vec<&str> = options.iter().map(String::as_str).collect();
            let choice = self
                .interaction
                .choose("Credential suggestions", &option_references)?;
            match choice {
                InteractionResult::Value(choice) if choice < candidates.len() => {
                    return Ok(InteractionResult::Value(choice));
                }
                InteractionResult::Value(choice) if choice == candidates.len() => {
                    return Ok(InteractionResult::Cancel);
                }
                InteractionResult::Back => return Ok(InteractionResult::Back),
                InteractionResult::Cancel => return Ok(InteractionResult::Cancel),
                InteractionResult::Value(_) => {
                    self.interaction.message(
                        "Invalid Credential suggestion selection. Choose a suggestion, Back, or Cancel.",
                    )?;
                }
            }
        }
    }

    /// Collects, reviews, and conditionally saves one Credential Draft.
    fn add_credential(&mut self, path: &Path, vault: &mut Vault) -> Result<(), AppError> {
        let mut draft = CredentialDraft::default();
        let mut step = CredentialDraftStep::Key;

        loop {
            match step {
                CredentialDraftStep::Key => {
                    match self.interaction.input_with_default("Key", &draft.key)? {
                        InteractionResult::Value(key) => {
                            draft.key = key;
                            step = CredentialDraftStep::Name;
                        }
                        InteractionResult::Back | InteractionResult::Cancel => return Ok(()),
                    }
                }
                CredentialDraftStep::Name => {
                    match self.interaction.input_with_default("Name", &draft.name)? {
                        InteractionResult::Value(name) => {
                            draft.name = name;
                            step = CredentialDraftStep::Value;
                        }
                        InteractionResult::Back => step = CredentialDraftStep::Key,
                        InteractionResult::Cancel => return Ok(()),
                    }
                }
                CredentialDraftStep::Value => match self.collect_value(&mut draft)? {
                    ValueCollectionOutcome::Value(value) => {
                        draft.value = value;
                        step = CredentialDraftStep::Review;
                    }
                    ValueCollectionOutcome::Back => step = CredentialDraftStep::Name,
                    ValueCollectionOutcome::Cancel => return Ok(()),
                },
                CredentialDraftStep::Review => {
                    let value_source = draft
                        .value_source
                        .map(CredentialValueSource::label)
                        .unwrap_or("Unknown");
                    self.interaction.message(&format!(
                        "Key: {}\nName: {}\nValue source: {value_source}\nValue: [REDACTED]",
                        draft.key, draft.name,
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
                            match self.save_credential(path, vault, credential, "Back")? {
                                CredentialSaveOutcome::Saved => {
                                    self.interaction.message("Credential entry saved.")?;
                                    return Ok(());
                                }
                                CredentialSaveOutcome::Back => step = CredentialDraftStep::Review,
                                CredentialSaveOutcome::Cancelled => return Ok(()),
                            }
                        }
                        InteractionResult::Value(1) | InteractionResult::Back => {
                            step = CredentialDraftStep::Value;
                        }
                        InteractionResult::Value(2) | InteractionResult::Cancel => return Ok(()),
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

    /// Collects a manual or Generated value while retaining the Draft state.
    fn collect_value(
        &mut self,
        draft: &mut CredentialDraft,
    ) -> Result<ValueCollectionOutcome, AppError> {
        loop {
            let choice = self.interaction.choose("Value", &["Manual", "Random"])?;
            match choice {
                InteractionResult::Value(0) => {
                    match self
                        .interaction
                        .password_with_default("Value", &draft.value)?
                    {
                        InteractionResult::Value(value) => {
                            draft.value = value.clone();
                            draft.value_source = Some(CredentialValueSource::Manual);
                            draft.generated_candidate = None;
                            return Ok(ValueCollectionOutcome::Value(value));
                        }
                        InteractionResult::Back => continue,
                        InteractionResult::Cancel => return Ok(ValueCollectionOutcome::Cancel),
                    }
                }
                InteractionResult::Value(1) => match self.collect_generated_value(draft)? {
                    ValueCollectionOutcome::Value(value) => {
                        draft.value = value.clone();
                        draft.value_source = Some(CredentialValueSource::Random);
                        return Ok(ValueCollectionOutcome::Value(value));
                    }
                    ValueCollectionOutcome::Back => continue,
                    ValueCollectionOutcome::Cancel => return Ok(ValueCollectionOutcome::Cancel),
                },
                InteractionResult::Back => return Ok(ValueCollectionOutcome::Back),
                InteractionResult::Cancel => return Ok(ValueCollectionOutcome::Cancel),
                InteractionResult::Value(choice) => {
                    return Err(AppError::InvalidChoice {
                        prompt: "Value",
                        choice,
                    });
                }
            }
        }
    }

    /// Collects and retains Random settings until the Draft is saved or abandoned.
    fn collect_generated_value(
        &mut self,
        draft: &mut CredentialDraft,
    ) -> Result<ValueCollectionOutcome, AppError> {
        let mut step = GeneratedValueSettingsStep::Length;

        loop {
            match step {
                GeneratedValueSettingsStep::Length => {
                    let default_length = draft.generated_settings.length.to_string();
                    let entered = match self
                        .interaction
                        .input_with_default("Generated value length (8-100)", &default_length)?
                    {
                        InteractionResult::Value(entered) => entered,
                        InteractionResult::Back => return Ok(ValueCollectionOutcome::Back),
                        InteractionResult::Cancel => return Ok(ValueCollectionOutcome::Cancel),
                    };
                    let trimmed = entered.trim();
                    let length = if trimmed.is_empty() {
                        draft.generated_settings.length
                    } else {
                        match trimmed.parse::<usize>() {
                            Ok(length) => length,
                            Err(_) => {
                                self.interaction.message(
                                    "Generated value length must be an integer from 8 through 100.",
                                )?;
                                continue;
                            }
                        }
                    };
                    if let Err(error) = draft.generated_settings.with_length(length) {
                        self.interaction.message(&error.to_string())?;
                        continue;
                    }
                    if draft.generated_settings.length != length {
                        draft.generated_candidate = None;
                    }
                    draft.generated_settings.length = length;
                    step = GeneratedValueSettingsStep::Numbers;
                }
                GeneratedValueSettingsStep::Numbers => {
                    match self.choose_generated_toggle(
                        "Numbers",
                        draft.generated_settings.include_numbers,
                    )? {
                        InteractionResult::Value(include_numbers) => {
                            if draft.generated_settings.include_numbers != include_numbers {
                                draft.generated_candidate = None;
                            }
                            draft.generated_settings.include_numbers = include_numbers;
                            step = GeneratedValueSettingsStep::Symbols;
                        }
                        InteractionResult::Back => step = GeneratedValueSettingsStep::Length,
                        InteractionResult::Cancel => return Ok(ValueCollectionOutcome::Cancel),
                    }
                }
                GeneratedValueSettingsStep::Symbols => {
                    match self.choose_generated_toggle(
                        "Symbols",
                        draft.generated_settings.include_symbols,
                    )? {
                        InteractionResult::Value(include_symbols) => {
                            if draft.generated_settings.include_symbols != include_symbols {
                                draft.generated_candidate = None;
                            }
                            draft.generated_settings.include_symbols = include_symbols;
                            let options = draft.generated_settings.options()?;
                            match self.generated_value_candidate(draft, options)? {
                                ValueCollectionOutcome::Value(value) => {
                                    return Ok(ValueCollectionOutcome::Value(value));
                                }
                                ValueCollectionOutcome::Back => {
                                    step = GeneratedValueSettingsStep::Symbols;
                                }
                                ValueCollectionOutcome::Cancel => {
                                    return Ok(ValueCollectionOutcome::Cancel);
                                }
                            }
                        }
                        InteractionResult::Back => step = GeneratedValueSettingsStep::Numbers,
                        InteractionResult::Cancel => return Ok(ValueCollectionOutcome::Cancel),
                    }
                }
            }
        }
    }

    /// Presents a Generated value setting with Enabled listed before Disabled.
    fn choose_generated_toggle(
        &mut self,
        prompt: &'static str,
        enabled: bool,
    ) -> Result<InteractionResult<bool>, AppError> {
        let options = ["Enabled", "Disabled"];
        let default = usize::from(!enabled);
        match self
            .interaction
            .choose_with_default(prompt, &options, default)?
        {
            InteractionResult::Value(0) => Ok(InteractionResult::Value(true)),
            InteractionResult::Value(1) => Ok(InteractionResult::Value(false)),
            InteractionResult::Back => Ok(InteractionResult::Back),
            InteractionResult::Cancel => Ok(InteractionResult::Cancel),
            InteractionResult::Value(choice) => Err(AppError::InvalidChoice { prompt, choice }),
        }
    }

    /// Presents a Generated value candidate and returns only an explicitly confirmed Value.
    fn generated_value_candidate(
        &mut self,
        draft: &mut CredentialDraft,
        options: GeneratedValueOptions,
    ) -> Result<ValueCollectionOutcome, AppError> {
        let mut candidate = match draft.generated_candidate.take() {
            Some(candidate) => candidate,
            None => generator::generate(options)?,
        };

        loop {
            draft.generated_candidate = Some(candidate.clone());
            let message = format!("Generated value candidate: {candidate}");
            let choice = self.interaction.choose_page(
                "Generated value",
                &message,
                &["Confirm", "Refresh", "Back", "Cancel"],
            )?;
            match choice {
                InteractionResult::Value(0) => {
                    return Ok(ValueCollectionOutcome::Value(candidate));
                }
                InteractionResult::Value(1) => {
                    let previous = candidate;
                    loop {
                        candidate = generator::generate(options)?;
                        if candidate != previous {
                            break;
                        }
                    }
                }
                InteractionResult::Value(2) | InteractionResult::Back => {
                    return Ok(ValueCollectionOutcome::Back);
                }
                InteractionResult::Value(3) | InteractionResult::Cancel => {
                    return Ok(ValueCollectionOutcome::Cancel);
                }
                InteractionResult::Value(choice) => {
                    return Err(AppError::InvalidChoice {
                        prompt: "Generated value",
                        choice,
                    });
                }
            }
        }
    }

    /// Resolves a duplicate Key and persists `credential` only after an explicit save decision.
    fn save_credential(
        &mut self,
        path: &Path,
        vault: &mut Vault,
        credential: Credential,
        duplicate_return_label: &'static str,
    ) -> Result<CredentialSaveOutcome, AppError> {
        if vault.find_credential(credential.key()).is_some() {
            self.interaction
                .message("A Credential entry with that Key already exists.")?;
            let choice = self
                .interaction
                .choose("Duplicate Key", &["Overwrite", duplicate_return_label])?;
            match choice {
                InteractionResult::Value(0) => {}
                InteractionResult::Value(1) | InteractionResult::Back => {
                    return Ok(CredentialSaveOutcome::Back);
                }
                InteractionResult::Cancel => return Ok(CredentialSaveOutcome::Cancelled),
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
        Ok(CredentialSaveOutcome::Saved)
    }

    /// Looks up and displays one Credential through the reversible Get page hierarchy.
    fn get_credential(&mut self, vault: &Vault) -> Result<(), AppError> {
        let Some(resolution) = self.resolve_credential(vault)? else {
            return Ok(());
        };
        let (credential, parent) = match resolution {
            CredentialResolution::Exact(credential) => (credential, GetDetailParent::KeyLookup),
            CredentialResolution::Fuzzy {
                credential,
                candidates,
            } => (credential, GetDetailParent::Suggestions(candidates)),
        };
        self.get_detail_page(vault, credential, parent)
    }

    /// Presents retained fuzzy Keys and routes Back to a fresh Key lookup.
    fn get_suggestions_page<'vault>(
        &mut self,
        vault: &'vault Vault,
        suggestions: Vec<&'vault Credential>,
    ) -> Result<(), AppError> {
        let options = Self::credential_suggestion_options(&suggestions);
        match self.choose_credential_candidate(&options)? {
            InteractionResult::Value(choice) => {
                let credential = suggestions[choice];
                self.get_detail_page(vault, credential, GetDetailParent::Suggestions(suggestions))
            }
            InteractionResult::Back => self.get_credential(vault),
            InteractionResult::Cancel => Ok(()),
        }
    }

    /// Displays a Credential and routes Continue or Cancel to Vault Home, or Back to its parent.
    fn get_detail_page<'vault>(
        &mut self,
        vault: &'vault Vault,
        credential: &'vault Credential,
        parent: GetDetailParent<'vault>,
    ) -> Result<(), AppError> {
        let navigation = self.interaction.display(
            "Credential entry",
            &format!(
                "Key: {}\nName: {}\nValue: {}",
                credential.key(),
                credential.name(),
                credential.value()
            ),
        )?;

        match navigation {
            InteractionResult::Value(()) | InteractionResult::Cancel => Ok(()),
            InteractionResult::Back => match parent {
                GetDetailParent::KeyLookup => self.get_credential(vault),
                GetDetailParent::Suggestions(suggestions) => {
                    self.get_suggestions_page(vault, suggestions)
                }
            },
        }
    }

    /// Builds the visible Key options used by a fuzzy Credential suggestion page.
    fn credential_suggestion_options(suggestions: &[&Credential]) -> Vec<String> {
        suggestions
            .iter()
            .map(|credential| credential.key().to_owned())
            .collect()
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
