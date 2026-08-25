use std::{cell::RefCell, collections::VecDeque, path::Path, rc::Rc};

use bincode::{Encode, config, encode_to_vec};
use pv::{
    app::{App, Interaction, InteractionError, InteractionResult},
    vault::{Credential, Vault},
};
use tempfile::tempdir;

/// Test-only representation of an envelope with an unsupported version.
#[derive(Encode)]
struct UnsupportedEnvelope {
    /// The intentionally unsupported format version.
    version: u8,
    /// A placeholder salt for the malformed fixture.
    salt: [u8; 16],
    /// A placeholder nonce for the malformed fixture.
    nonce: [u8; 12],
    /// Placeholder ciphertext that is never decrypted.
    cipher_text: Vec<u8>,
}

/// Scripted interaction adapter used to drive workflow tests deterministically.
struct ScriptedInteraction {
    /// Passwords or navigation results returned in prompt order.
    passwords: VecDeque<InteractionResult<String>>,
    /// Text input values or navigation results returned in prompt order.
    inputs: VecDeque<InteractionResult<String>>,
    /// Menu selections or navigation results returned in prompt order.
    choices: VecDeque<InteractionResult<usize>>,
    /// Detail-page navigation results returned in prompt order.
    display_results: VecDeque<InteractionResult<()>>,
    /// Messages emitted by the workflow.
    messages: Rc<RefCell<Vec<String>>>,
    /// Prompts that requested hidden password input.
    password_prompts: Rc<RefCell<Vec<String>>>,
    /// Prompts that requested visible text input.
    input_prompts: Rc<RefCell<Vec<String>>>,
    /// Prompts and options presented by menu selections.
    choice_options: Rc<RefCell<Vec<Vec<String>>>>,
}

impl ScriptedInteraction {
    /// Creates an adapter with a scripted sequence of password responses.
    fn with_passwords(passwords: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            passwords: passwords
                .into_iter()
                .map(|password| InteractionResult::Value(password.into()))
                .collect(),
            inputs: VecDeque::new(),
            choices: VecDeque::new(),
            display_results: VecDeque::new(),
            messages: Rc::new(RefCell::new(Vec::new())),
            password_prompts: Rc::new(RefCell::new(Vec::new())),
            input_prompts: Rc::new(RefCell::new(Vec::new())),
            choice_options: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// Adds scripted hidden-input results, including Back and Cancel actions.
    fn with_password_results(
        mut self,
        passwords: impl IntoIterator<Item = InteractionResult<String>>,
    ) -> Self {
        self.passwords = passwords.into_iter().collect();
        self
    }

    /// Adds a scripted sequence of visible text inputs to this adapter.
    fn with_inputs(mut self, inputs: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inputs = inputs
            .into_iter()
            .map(|input| InteractionResult::Value(input.into()))
            .collect();
        self
    }

    /// Adds scripted visible text results, including Back and Cancel actions.
    fn with_input_results(
        mut self,
        inputs: impl IntoIterator<Item = InteractionResult<String>>,
    ) -> Self {
        self.inputs = inputs.into_iter().collect();
        self
    }

    /// Adds a scripted sequence of menu selections to this adapter.
    fn with_choices(mut self, choices: impl IntoIterator<Item = usize>) -> Self {
        self.choices = choices.into_iter().map(InteractionResult::Value).collect();
        self
    }

    /// Adds menu selections and navigation results to this adapter.
    fn with_choice_results(
        mut self,
        choices: impl IntoIterator<Item = InteractionResult<usize>>,
    ) -> Self {
        self.choices = choices.into_iter().collect();
        self
    }

    /// Adds scripted Credential detail-page navigation results.
    fn with_display_results(
        mut self,
        results: impl IntoIterator<Item = InteractionResult<()>>,
    ) -> Self {
        self.display_results = results.into_iter().collect();
        self
    }

    /// Returns a shared view of the messages emitted by the adapter.
    fn message_log(&self) -> Rc<RefCell<Vec<String>>> {
        Rc::clone(&self.messages)
    }

    /// Returns a shared view of prompts that requested hidden input.
    fn password_prompt_log(&self) -> Rc<RefCell<Vec<String>>> {
        Rc::clone(&self.password_prompts)
    }

    /// Returns a shared view of prompts that requested visible input.
    fn input_prompt_log(&self) -> Rc<RefCell<Vec<String>>> {
        Rc::clone(&self.input_prompts)
    }

    /// Returns a shared view of every menu's displayed options.
    fn choice_options_log(&self) -> Rc<RefCell<Vec<Vec<String>>>> {
        Rc::clone(&self.choice_options)
    }
}

impl Interaction for ScriptedInteraction {
    /// Returns the next scripted password response.
    fn password(&mut self, prompt: &str) -> Result<InteractionResult<String>, InteractionError> {
        self.password_prompts.borrow_mut().push(prompt.to_owned());
        self.passwords
            .pop_front()
            .ok_or_else(|| InteractionError::new("no scripted password available"))
    }

    /// Returns the next scripted visible text value or navigation result.
    fn input(&mut self, prompt: &str) -> Result<InteractionResult<String>, InteractionError> {
        self.input_prompts.borrow_mut().push(prompt.to_owned());
        self.inputs
            .pop_front()
            .ok_or_else(|| InteractionError::new("no scripted input available"))
    }

    /// Returns the next scripted menu selection or navigation result.
    fn choose(
        &mut self,
        _prompt: &str,
        options: &[&str],
    ) -> Result<InteractionResult<usize>, InteractionError> {
        self.choice_options
            .borrow_mut()
            .push(options.iter().map(|option| (*option).to_owned()).collect());
        self.choices
            .pop_front()
            .ok_or_else(|| InteractionError::new("no scripted choice available"))
    }

    /// Records a workflow message for later assertions.
    fn message(&mut self, message: &str) -> Result<(), InteractionError> {
        self.messages.borrow_mut().push(message.to_owned());
        Ok(())
    }

    /// Records a Credential detail page and returns its scripted navigation result.
    fn display(
        &mut self,
        _prompt: &str,
        message: &str,
    ) -> Result<InteractionResult<()>, InteractionError> {
        self.messages.borrow_mut().push(message.to_owned());
        Ok(self
            .display_results
            .pop_front()
            .unwrap_or(InteractionResult::Value(())))
    }
}

/// Asserts that a Generated value candidate is shown as a value rather than a mask.
fn assert_visible_generated_candidate(message: &str, expected_length: usize) {
    let candidate = message
        .strip_prefix("Generated value candidate: ")
        .expect("the message should identify a Generated value candidate");
    assert_eq!(candidate.chars().count(), expected_length);
    assert!(!candidate.is_empty());
    assert!(candidate.chars().all(|character| character != '•'));
}

/// Writes an encrypted Vault fixture containing the supplied Credential entries.
fn write_vault_with_credentials(
    path: &Path,
    master_password: &str,
    credentials: impl IntoIterator<Item = Credential>,
) {
    let mut vault = Vault::new(master_password).expect("vault should be generated");
    for credential in credentials {
        vault.upsert_credential(credential);
    }
    let bytes = vault.to_bytes().expect("vault should be encoded");
    std::fs::write(path, bytes).expect("vault fixture should be written");
}

/// Verifies that initialization persists an encrypted Vault at a custom path.
#[test]
fn init_persists_an_encrypted_empty_vault_at_a_custom_path() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("custom.vault");
    let password = "correct horse battery staple";
    let mut app = App::new(ScriptedInteraction::with_passwords([password, password]));

    app.init(&path).expect("initialization should succeed");

    let bytes = std::fs::read(&path).expect("vault file should be readable");
    assert!(!bytes.is_empty());
    assert!(
        !bytes
            .windows(password.len())
            .any(|candidate| candidate == password.as_bytes())
    );
    assert!(Vault::unlock(&bytes, password).is_ok());
    assert!(Vault::unlock(&bytes, "wrong password").is_err());
}

/// Verifies that one App instance can initialize and reopen an empty Vault.
#[test]
fn init_then_open_completes_the_empty_vault_lifecycle() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("lifecycle.vault");
    let password = "lifecycle password";
    let mut app = App::new(
        ScriptedInteraction::with_passwords([password, password, password]).with_choices([3]),
    );

    app.init(&path).expect("initialization should succeed");
    let bytes_after_init = std::fs::read(&path).expect("vault should be readable");
    let result = app.open(&path).expect("opening should succeed");

    assert!(matches!(result, pv::app::OpenResult::Exited));
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_after_init
    );
}

/// Verifies that each Vault save uses a fresh encryption nonce.
#[test]
fn saving_an_unmodified_vault_uses_a_fresh_nonce() {
    let vault = Vault::new("nonce password").expect("vault should be generated");

    let first_save = vault.to_bytes().expect("first save should be encoded");
    let second_save = vault.to_bytes().expect("second save should be encoded");

    assert_ne!(first_save, second_save);
    assert!(Vault::unlock(&second_save, "nonce password").is_ok());
}

/// Verifies that mismatched initialization passwords do not create a file.
#[test]
fn init_rejects_mismatched_master_password_without_creating_a_file() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("mismatch.vault");
    let mut app = App::new(ScriptedInteraction::with_passwords([
        "first password",
        "different password",
    ]));

    let error = app
        .init(&path)
        .expect_err("mismatched passwords should fail");

    assert_eq!(error.to_string(), "master passwords do not match");
    assert!(!path.exists());
}

/// Verifies that initialization refuses to overwrite an existing file.
#[test]
fn init_refuses_to_overwrite_an_existing_vault() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("existing.vault");
    let original = b"keep this file unchanged";
    std::fs::write(&path, original).expect("existing file should be writable");
    let mut app = App::new(ScriptedInteraction::with_passwords(Vec::<String>::new()));

    let error = app
        .init(&path)
        .expect_err("existing vaults should be rejected");

    assert!(error.to_string().contains("refusing to overwrite"));
    assert_eq!(
        std::fs::read(&path).expect("existing file should remain"),
        original
    );
}

/// Verifies that initialization retries an empty Master password.
#[test]
fn init_reprompts_when_a_master_password_is_empty() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("empty-password.vault");
    let interaction =
        ScriptedInteraction::with_passwords(["", "usable password", "usable password"]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.init(&path)
        .expect("a non-empty retry should complete initialization");

    assert_eq!(
        messages.borrow().as_slice(),
        ["Master password cannot be empty."]
    );
    assert!(path.exists());
}

/// Verifies that Cancel from either Init password page leaves no partial Vault behind.
#[test]
fn init_cancel_from_each_password_page_leaves_no_vault() {
    let directory = tempdir().expect("temporary directory should be created");
    let first_path = directory.path().join("cancel-first-password.vault");
    let mut first_app = App::new(
        ScriptedInteraction::with_passwords(Vec::<String>::new())
            .with_password_results([InteractionResult::Cancel]),
    );

    first_app
        .init(&first_path)
        .expect("cancelling the first password should be clean");
    assert!(!first_path.exists());

    let second_path = directory.path().join("cancel-confirm-password.vault");
    let mut second_app = App::new(
        ScriptedInteraction::with_passwords(Vec::<String>::new()).with_password_results([
            InteractionResult::Value("master password".to_owned()),
            InteractionResult::Cancel,
        ]),
    );

    second_app
        .init(&second_path)
        .expect("cancelling password confirmation should be clean");
    assert!(!second_path.exists());
}

/// Verifies that opening an empty Vault enters a menu and exits without mutation.
#[test]
fn open_unlocks_a_vault_and_exits_the_empty_vault_menu_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("open.vault");
    let password = "open sesame";
    let bytes = Vault::new(password)
        .expect("vault should be generated")
        .to_bytes()
        .expect("vault should be encoded");
    std::fs::write(&path, &bytes).expect("vault should be written");
    let mut app = App::new(ScriptedInteraction::with_passwords([password]).with_choices([3]));

    let result = app.open(&path).expect("opening should succeed");

    assert!(matches!(result, pv::app::OpenResult::Exited));
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes
    );
}

/// Verifies that an incorrect password is reported and can be retried.
#[test]
fn open_reports_an_incorrect_password_and_allows_a_retry() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("retry.vault");
    let password = "open sesame";
    let bytes = Vault::new(password)
        .expect("vault should be generated")
        .to_bytes()
        .expect("vault should be encoded");
    std::fs::write(&path, &bytes).expect("vault should be written");
    let interaction =
        ScriptedInteraction::with_passwords(["wrong password", password]).with_choices([0, 3]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    let result = app
        .open(&path)
        .expect("retrying with the correct password should work");

    assert!(matches!(result, pv::app::OpenResult::Exited));
    assert_eq!(
        messages.borrow().as_slice(),
        ["Incorrect master password or damaged Vault."]
    );
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes
    );
}

/// Verifies that a user can cancel after an incorrect password without mutation.
#[test]
fn open_can_cancel_after_an_incorrect_password_without_mutating_the_vault() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("cancel.vault");
    let password = "open sesame";
    let bytes = Vault::new(password)
        .expect("vault should be generated")
        .to_bytes()
        .expect("vault should be encoded");
    std::fs::write(&path, &bytes).expect("vault should be written");
    let interaction = ScriptedInteraction::with_passwords(["wrong password"]).with_choices([1]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    let result = app
        .open(&path)
        .expect("cancelling should be a normal outcome");

    assert!(matches!(result, pv::app::OpenResult::Cancelled));
    assert_eq!(
        messages.borrow().as_slice(),
        ["Incorrect master password or damaged Vault."]
    );
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes
    );
}

/// Verifies that a missing Vault file produces a user-facing error.
#[test]
fn open_reports_a_missing_vault_file_as_a_user_facing_error() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("missing.vault");
    let mut app = App::new(ScriptedInteraction::with_passwords(Vec::<String>::new()));

    let error = app
        .open(&path)
        .expect_err("a missing vault should fail to open");

    assert!(error.to_string().contains("could not read vault"));
}

/// Verifies that malformed Vault bytes are reported without replacement.
#[test]
fn open_reports_malformed_vault_bytes_without_replacing_the_file() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("malformed.vault");
    let original = b"not a serialized vault";
    std::fs::write(&path, original).expect("malformed file should be writable");
    let mut app = App::new(ScriptedInteraction::with_passwords(["any password"]));

    let error = app
        .open(&path)
        .expect_err("malformed vault bytes should fail");

    assert!(error.to_string().contains("malformed vault file"));
    assert_eq!(
        std::fs::read(&path).expect("malformed file should remain"),
        original
    );
}

/// Verifies that unsupported Vault versions are reported without replacement.
#[test]
fn open_reports_an_unsupported_vault_version_without_replacing_the_file() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("unsupported.vault");
    let original = encode_to_vec(
        &UnsupportedEnvelope {
            version: 99,
            salt: [0; 16],
            nonce: [0; 12],
            cipher_text: vec![0; 16],
        },
        config::standard(),
    )
    .expect("unsupported envelope should be encodable");
    std::fs::write(&path, &original).expect("unsupported file should be writable");
    let mut app = App::new(ScriptedInteraction::with_passwords(["any password"]));

    let error = app
        .open(&path)
        .expect_err("unsupported vault versions should fail");

    assert!(error.to_string().contains("unsupported vault version 99"));
    assert_eq!(
        std::fs::read(&path).expect("unsupported file should remain"),
        original
    );
}

/// Verifies that an unreadable Vault path produces a user-facing error.
#[test]
fn open_reports_an_unreadable_vault_path_without_replacing_it() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("vault-directory");
    std::fs::create_dir(&path).expect("directory should be created");
    let mut app = App::new(ScriptedInteraction::with_passwords(Vec::<String>::new()));

    let error = app
        .open(&path)
        .expect_err("a directory is not an openable vault");

    assert!(error.to_string().contains("could not read vault"));
    assert!(path.is_dir());
}

/// Verifies that a manually entered Credential remains available after reopening.
#[test]
fn manual_add_is_persisted_and_retrievable_after_reopening() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("manual-add.vault");
    let master_password = "manual add master password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let add_interaction = ScriptedInteraction::with_passwords([master_password, "secret value"])
        .with_inputs(["  YouTube  ", "alice"])
        .with_choices([0, 0, 0, 3]);
    let password_prompts = add_interaction.password_prompt_log();
    let input_prompts = add_interaction.input_prompt_log();
    let mut add_app = App::new(add_interaction);

    add_app
        .open(&path)
        .expect("adding a Credential should succeed");
    let bytes_after_add = std::fs::read(&path).expect("vault should be readable");
    assert!(
        !bytes_after_add
            .windows("secret value".len())
            .any(|candidate| candidate == b"secret value")
    );

    assert_eq!(
        password_prompts.borrow().as_slice(),
        ["Master password", "Value"]
    );
    assert_eq!(input_prompts.borrow().as_slice(), ["Key", "Name"]);

    let get_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([1, 3]);
    let messages = get_interaction.message_log();
    let mut get_app = App::new(get_interaction);

    get_app
        .open(&path)
        .expect("the Credential should survive reopening");

    assert_eq!(
        messages.borrow().as_slice(),
        ["Key:   YouTube  \nName: alice\nValue: secret value"]
    );
}

/// Verifies that a manual Add draft can move backward through fields before saving.
#[test]
fn manual_add_backtracks_through_fields_and_preserves_the_draft() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("manual-draft.vault");
    let master_password = "manual draft master password";
    let secret_value = "opaque value !@#$%^&*";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let interaction = ScriptedInteraction::with_passwords([master_password, secret_value])
        .with_input_results([
            InteractionResult::Value("youtube".to_owned()),
            InteractionResult::Back,
            InteractionResult::Value("youtube".to_owned()),
            InteractionResult::Value("alice".to_owned()),
        ])
        .with_choice_results([
            InteractionResult::Value(0),
            InteractionResult::Value(0),
            InteractionResult::Value(0),
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let choice_options = interaction.choice_options_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("the reversible manual Add workflow should succeed");

    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Key: youtube\nName: alice\nValue source: Manual\nValue: [REDACTED]",
            "Credential entry saved."
        ]
    );
    assert!(
        choice_options
            .borrow()
            .iter()
            .any(|options| options == &["Save".to_owned(), "Back".to_owned(), "Cancel".to_owned()])
    );

    let get_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([1, 3]);
    let get_messages = get_interaction.message_log();
    let mut get_app = App::new(get_interaction);

    get_app
        .open(&path)
        .expect("the saved Credential should survive reopening");

    assert_eq!(
        get_messages.borrow().as_slice(),
        [format!("Key: youtube\nName: alice\nValue: {secret_value}")]
    );
}

/// Verifies that cancelling a manual Draft leaves the in-memory and persisted Vault unchanged.
#[test]
fn manual_add_can_be_cancelled_without_mutating_the_vault() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("manual-cancel.vault");
    let master_password = "manual cancellation master password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password, "discarded !value"])
        .with_inputs(["youtube", "alice", "youtube"])
        .with_choices([0, 0, 2, 1, 1, 3]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("cancelling a manual Draft should return to the menu");

    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Key: youtube\nName: alice\nValue source: Manual\nValue: [REDACTED]",
            "Credential entry not found."
        ]
    );
    let vault = Vault::unlock(&bytes_before_cancel, master_password)
        .expect("the unchanged Vault should still unlock");
    assert!(vault.find_credential("youtube").is_none());
}

/// Verifies that the Random Value path uses defaults, shows the candidate, and saves through Review.
#[test]
fn generated_value_path_uses_defaults_shows_candidate_and_saves_through_review() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("random-defaults.vault");
    let master_password = "random defaults master password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube", "alice", ""])
        .with_choices([0, 1, 0, 1, 0, 0, 3]);
    let messages = interaction.message_log();
    let choice_options = interaction.choice_options_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("the Generated value should reach the shared Review save gate");

    let candidate_message = messages
        .borrow()
        .iter()
        .find(|message| message.starts_with("Generated value candidate: "))
        .cloned()
        .expect("the candidate page should be displayed");
    assert_visible_generated_candidate(&candidate_message, 20);
    let message_log = messages.borrow();
    assert_eq!(message_log.len(), 3);
    assert_eq!(
        message_log[1],
        "Key: youtube\nName: alice\nValue source: Random\nValue: [REDACTED]"
    );
    assert_eq!(message_log[2], "Credential entry saved.");
    assert!(
        choice_options
            .borrow()
            .iter()
            .any(|options| options == &["Manual".to_owned(), "Random".to_owned()])
    );
    assert_eq!(
        choice_options
            .borrow()
            .iter()
            .filter(|options| options == &&["Enabled".to_owned(), "Disabled".to_owned()])
            .count(),
        2
    );
    assert!(choice_options.borrow().iter().any(|options| {
        options
            == &[
                "Confirm".to_owned(),
                "Refresh".to_owned(),
                "Back".to_owned(),
                "Cancel".to_owned(),
            ]
    }));
    assert!(choice_options.borrow().iter().any(|options| {
        options == &["Save".to_owned(), "Back".to_owned(), "Cancel".to_owned()]
    }));

    let get_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([1, 3]);
    let get_messages = get_interaction.message_log();
    let mut get_app = App::new(get_interaction);
    get_app
        .open(&path)
        .expect("the saved Generated value should survive reopening");

    let saved_value = get_messages
        .borrow()
        .first()
        .and_then(|message| message.strip_prefix("Key: youtube\nName: alice\nValue: "))
        .expect("the saved value should be retrievable")
        .to_owned();
    assert_eq!(saved_value.chars().count(), 20);
    assert!(
        saved_value
            .chars()
            .any(|character| character.is_ascii_digit())
    );
    assert!(
        saved_value
            .chars()
            .any(|character| character.is_ascii_alphabetic())
    );
    assert!(
        saved_value
            .chars()
            .all(|character| { character.is_ascii_alphanumeric() })
    );
    assert_eq!(
        saved_value,
        candidate_message
            .strip_prefix("Generated value candidate: ")
            .expect("the candidate message should expose the generated value")
    );
}

/// Verifies that Review identifies a Generated value without exposing its secret.
#[test]
fn generated_value_review_shows_the_value_source() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("random-review-source.vault");
    let master_password = "random review source password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube", "alice", ""])
        .with_choices([0, 1, 0, 1, 0, 0, 3]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("the Generated value should reach Review");

    assert!(messages.borrow().iter().any(|message| {
        message.contains("Value source: Random") && message.contains("Value: [REDACTED]")
    }));
}

/// Verifies that Random settings remain part of the Draft after Back leaves the generator.
#[test]
fn generated_value_back_preserves_settings_when_reentering_random() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("random-settings-draft.vault");
    let master_password = "random settings draft password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([
            InteractionResult::Value("youtube".to_owned()),
            InteractionResult::Value("alice".to_owned()),
            InteractionResult::Value("10".to_owned()),
            InteractionResult::Back,
            InteractionResult::Value(String::new()),
        ])
        .with_choice_results([
            InteractionResult::Value(0),
            InteractionResult::Value(1),
            InteractionResult::Value(0),
            InteractionResult::Value(1),
            InteractionResult::Value(2),
            InteractionResult::Back,
            InteractionResult::Back,
            InteractionResult::Value(1),
            InteractionResult::Value(0),
            InteractionResult::Value(0),
            InteractionResult::Value(0),
            InteractionResult::Value(0),
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("the preserved Random Draft should be saveable");

    let candidates: Vec<String> = messages
        .borrow()
        .iter()
        .filter(|message| message.starts_with("Generated value candidate: "))
        .cloned()
        .collect();
    assert_eq!(candidates.len(), 2);
    for candidate in &candidates {
        assert_visible_generated_candidate(candidate, 10);
    }
}

/// Verifies that invalid Generated value lengths are retried before applying class options.
#[test]
fn generated_value_add_retries_invalid_lengths_and_honors_optional_classes() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("generated-options.vault");
    let master_password = "generated options master password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let add_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube", "alice", "7", "not a number", "8"])
        .with_choices([0, 1, 1, 0, 0, 0, 3]);
    let messages = add_interaction.message_log();
    let mut app = App::new(add_interaction);

    app.open(&path)
        .expect("valid Generated value settings should succeed");

    let messages = messages.borrow();
    assert_eq!(
        messages
            .iter()
            .filter(|message| {
                message.starts_with("Generated value length")
                    || message.starts_with("generated value length")
            })
            .count(),
        2
    );
    let candidate = messages
        .iter()
        .find(|message| message.starts_with("Generated value candidate: "))
        .expect("the visible candidate should be shown");
    assert_visible_generated_candidate(candidate, 8);
    drop(messages);

    let get_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([1, 3]);
    let get_messages = get_interaction.message_log();
    let mut get_app = App::new(get_interaction);
    get_app
        .open(&path)
        .expect("the configured Generated value should survive reopening");

    let saved_message = get_messages
        .borrow()
        .first()
        .cloned()
        .expect("the saved value should be displayed");
    let saved_value = saved_message
        .strip_prefix("Key: youtube\nName: alice\nValue: ")
        .expect("the saved credential should have the expected context");
    /// The independent expected Symbol allowlist from the feature specification.
    const SYMBOLS: &str = "!@.-_*";
    assert_eq!(saved_value.chars().count(), 8);
    assert!(
        !saved_value
            .chars()
            .any(|character| character.is_ascii_digit())
    );
    assert!(
        saved_value
            .chars()
            .any(|character| SYMBOLS.contains(character))
    );
    assert!(saved_value.chars().all(|character| {
        character.is_ascii_alphabetic() || character.is_ascii_digit() || SYMBOLS.contains(character)
    }));
}

/// Verifies that Refresh creates another visible candidate without leaving the candidate page.
#[test]
fn generated_value_add_can_refresh_before_confirming() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("generated-regenerate.vault");
    let master_password = "generated regeneration master password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let add_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube", "alice", "10"])
        .with_choices([0, 1, 0, 1, 1, 0, 0, 3]);
    let messages = add_interaction.message_log();
    let mut app = App::new(add_interaction);

    app.open(&path)
        .expect("refreshing and confirming should succeed");

    let candidates: Vec<String> = messages
        .borrow()
        .iter()
        .filter(|message| message.starts_with("Generated value candidate: "))
        .cloned()
        .collect();
    assert_eq!(candidates.len(), 2);
    for candidate in &candidates {
        assert_visible_generated_candidate(candidate, 10);
    }
}

/// Verifies that Back climbs from the candidate through settings to the Value step without losing the Draft.
#[test]
fn generated_value_back_returns_to_the_value_step_and_preserves_the_draft() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("random-back.vault");
    let master_password = "random back master password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let interaction = ScriptedInteraction::with_passwords([master_password, "manual secret"])
        .with_input_results([
            InteractionResult::Value("youtube".to_owned()),
            InteractionResult::Value("alice".to_owned()),
            InteractionResult::Value("8".to_owned()),
            InteractionResult::Back,
            InteractionResult::Value(String::new()),
        ])
        .with_choice_results([
            InteractionResult::Value(0),
            InteractionResult::Value(1),
            InteractionResult::Value(0),
            InteractionResult::Value(1),
            InteractionResult::Value(1),
            InteractionResult::Value(2),
            InteractionResult::Back,
            InteractionResult::Back,
            InteractionResult::Back,
            InteractionResult::Value(0),
            InteractionResult::Value(0),
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let choice_options = interaction.choice_options_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Random Back should return to the Draft and allow a manual Value");

    let message_log = messages.borrow();
    assert_eq!(message_log.len(), 4);
    assert_visible_generated_candidate(&message_log[0], 8);
    assert_visible_generated_candidate(&message_log[1], 8);
    assert_eq!(
        message_log[2],
        "Key: youtube\nName: alice\nValue source: Manual\nValue: [REDACTED]"
    );
    assert_eq!(message_log[3], "Credential entry saved.");
    assert_eq!(
        choice_options
            .borrow()
            .iter()
            .filter(|options| options == &&["Enabled".to_owned(), "Disabled".to_owned()])
            .count(),
        4
    );

    let get_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([1, 3]);
    let get_messages = get_interaction.message_log();
    let mut get_app = App::new(get_interaction);
    get_app
        .open(&path)
        .expect("the preserved Draft should be saved and retrievable");

    assert_eq!(
        get_messages.borrow().as_slice(),
        ["Key: youtube\nName: alice\nValue: manual secret"]
    );
}

/// Verifies that cancelling a Generated value candidate leaves the persisted Vault unchanged.
#[test]
fn generated_value_add_can_be_cancelled_without_mutating_the_vault() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("generated-cancel.vault");
    let master_password = "generated cancellation master password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let mut app = App::new(
        ScriptedInteraction::with_passwords([master_password])
            .with_inputs(["youtube", "alice", "10"])
            .with_choices([0, 1, 0, 1, 3, 3]),
    );

    app.open(&path)
        .expect("cancelling a Generated value should return to the menu");

    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that confirming a candidate still leaves persistence behind the Review Save decision.
#[test]
fn generated_value_review_cancel_does_not_persist_the_candidate() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("random-review-cancel.vault");
    let master_password = "random review cancellation password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let mut app = App::new(
        ScriptedInteraction::with_passwords([master_password])
            .with_inputs(["youtube", "alice", "8"])
            .with_choices([0, 1, 0, 1, 0, 2, 3]),
    );
    app.open(&path)
        .expect("cancelling Review should return to the menu");

    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that a duplicate Generated value can be cancelled or explicitly overwritten.
#[test]
fn generated_value_duplicate_can_be_cancelled_or_overwritten() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("generated-duplicate.vault");
    let master_password = "generated duplicate master password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let mut original_app = App::new(
        ScriptedInteraction::with_passwords([master_password, "original secret"])
            .with_inputs(["YouTube", "original name"])
            .with_choices([0, 0, 0, 3]),
    );
    original_app
        .open(&path)
        .expect("the original Credential should be added");
    let bytes_before_duplicate_cancel = std::fs::read(&path).expect("vault should be readable");

    let mut cancel_app = App::new(
        ScriptedInteraction::with_passwords([master_password])
            .with_inputs([" youtube ", "discarded name", "10"])
            .with_choices([0, 1, 1, 0, 0, 0, 1, 2, 3]),
    );
    cancel_app
        .open(&path)
        .expect("cancelling a duplicate Generated value should return to the menu");
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_duplicate_cancel
    );

    let overwrite_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["YOUTUBE", "generated name", "10"])
        .with_choices([0, 1, 1, 0, 0, 0, 0, 3]);
    let overwrite_messages = overwrite_interaction.message_log();
    let mut overwrite_app = App::new(overwrite_interaction);
    overwrite_app
        .open(&path)
        .expect("overwriting a duplicate Generated value should succeed");

    let overwrite_candidate = overwrite_messages
        .borrow()
        .iter()
        .find(|message| message.starts_with("Generated value candidate: "))
        .cloned()
        .expect("the overwritten candidate should be displayed");
    assert_visible_generated_candidate(&overwrite_candidate, 10);

    let get_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([1, 3]);
    let get_messages = get_interaction.message_log();
    let mut get_app = App::new(get_interaction);
    get_app
        .open(&path)
        .expect("the overwritten Generated value should survive reopening");

    let saved_message = get_messages
        .borrow()
        .first()
        .cloned()
        .expect("the overwritten value should be displayed");
    assert!(saved_message.starts_with("Key: YouTube\nName: generated name\nValue: "));
    let saved_value = saved_message
        .strip_prefix("Key: YouTube\nName: generated name\nValue: ")
        .expect("the overwritten value should have the expected context");
    assert_eq!(saved_value.chars().count(), 10);
}

/// Verifies that a duplicate normalized Key overwrites its Name and Value in place.
#[test]
fn duplicate_normalized_key_overwrites_name_and_value() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("duplicate-overwrite.vault");
    let master_password = "duplicate master password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let add_interaction =
        ScriptedInteraction::with_passwords([master_password, "first secret", "second secret"])
            .with_inputs([
                "  YouTube  ",
                "first name",
                "youtube",
                "second name",
                "YOUTUBE",
            ])
            .with_choices([0, 0, 0, 0, 0, 0, 0, 3]);
    let duplicate_messages = add_interaction.message_log();
    let mut add_app = App::new(add_interaction);

    add_app
        .open(&path)
        .expect("the duplicate should be explicitly overwritten");

    assert_eq!(
        duplicate_messages.borrow().as_slice(),
        [
            "Key:   YouTube  \nName: first name\nValue source: Manual\nValue: [REDACTED]",
            "Credential entry saved.",
            "Key: youtube\nName: second name\nValue source: Manual\nValue: [REDACTED]",
            "A Credential entry with that Key already exists.",
            "Credential entry saved."
        ]
    );

    let get_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["YOUTUBE"])
        .with_choices([1, 3]);
    let messages = get_interaction.message_log();
    let mut get_app = App::new(get_interaction);

    get_app
        .open(&path)
        .expect("the overwritten Credential should survive reopening");

    assert_eq!(
        messages.borrow().as_slice(),
        ["Key:   YouTube  \nName: second name\nValue: second secret"]
    );
}

/// Verifies that duplicate Back returns to the Draft without changing memory or disk.
#[test]
fn duplicate_add_back_returns_to_the_draft_without_mutating_the_vault() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("duplicate-cancel.vault");
    let master_password = "duplicate cancellation password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let mut add_app = App::new(
        ScriptedInteraction::with_passwords([master_password, "original secret"])
            .with_inputs(["YouTube", "original name"])
            .with_choices([0, 0, 0, 3]),
    );
    add_app
        .open(&path)
        .expect("the original Credential should be added");
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let cancel_interaction =
        ScriptedInteraction::with_passwords([master_password, "discarded secret"])
            .with_inputs([" youtube ", "discarded name"])
            .with_choices([0, 0, 0, 1, 2, 3]);
    let duplicate_options = cancel_interaction.choice_options_log();
    let messages = cancel_interaction.message_log();
    let mut cancel_app = App::new(cancel_interaction);

    cancel_app
        .open(&path)
        .expect("cancelling the duplicate should return to the menu");

    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
    assert!(
        duplicate_options
            .borrow()
            .iter()
            .any(|options| options == &["Overwrite".to_owned(), "Back".to_owned()])
    );
    assert_eq!(messages.borrow().len(), 3);
    assert!(
        messages
            .borrow()
            .iter()
            .all(|message| !message.contains("discarded secret"))
    );
}

/// Verifies that a cancelled missing-key Get leaves the persisted Vault unchanged.
#[test]
fn get_can_be_cancelled_without_mutating_the_vault() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("get-cancel.vault");
    let master_password = "get cancellation password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");
    let bytes_before_get = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["missing key"])
        .with_choices([1, 1, 3]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("cancelling a missing-key Get should return to the menu");

    assert_eq!(
        messages.borrow().as_slice(),
        ["Credential entry not found."]
    );
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_get
    );
}

/// Verifies that fuzzy Get ranks candidates and caps the selection at three Keys.
#[test]
fn get_fuzzy_suggestions_are_ranked_and_limited_to_three() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("fuzzy-ranking.vault");
    let master_password = "fuzzy ranking password";
    write_vault_with_credentials(
        &path,
        master_password,
        [
            Credential::new("youtube-help", "help", "help value"),
            Credential::new("youtub", "short", "short value"),
            Credential::new("youtube-old", "old", "old value"),
            Credential::new("youtubee", "extended", "extended value"),
        ],
    );

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([1, 1, 3]);
    let choice_options = interaction.choice_options_log();
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("fuzzy Get should return the selected Credential");

    assert_eq!(
        choice_options.borrow()[1],
        [
            "youtub".to_owned(),
            "youtubee".to_owned(),
            "youtube-old".to_owned(),
            "Cancel".to_owned(),
        ]
    );
    assert_eq!(
        messages.borrow().last().map(String::as_str),
        Some("Key: youtubee\nName: extended\nValue: extended value")
    );
}

/// Verifies that cancelling fuzzy Get does not display or persist a candidate.
#[test]
fn get_fuzzy_suggestions_can_be_cancelled_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("fuzzy-cancel.vault");
    let master_password = "fuzzy cancellation password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_get = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtub"])
        .with_choices([1, 1, 3]);
    let choice_options = interaction.choice_options_log();
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("cancelling fuzzy Get should return to the menu");

    assert_eq!(choice_options.borrow()[1], ["youtube", "Cancel"]);
    assert_eq!(
        messages.borrow().as_slice(),
        ["Credential entry not found."]
    );
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_get
    );
}

/// Verifies that a query without useful candidates can retry and then select a suggestion.
#[test]
fn get_without_useful_candidates_can_retry() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("fuzzy-retry.vault");
    let master_password = "fuzzy retry password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["unrelated", "youtub"])
        .with_choices([1, 0, 0, 3]);
    let choice_options = interaction.choice_options_log();
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("retrying fuzzy Get should return the selected Credential");

    assert_eq!(choice_options.borrow()[1], ["Retry", "Cancel"]);
    assert_eq!(choice_options.borrow()[2], ["youtube", "Cancel"]);
    assert_eq!(
        messages.borrow().last().map(String::as_str),
        Some("Key: youtube\nName: alice\nValue: secret value")
    );
}

/// Verifies that Back from a Get detail page returns to its fuzzy suggestion parent.
#[test]
fn get_back_from_detail_returns_to_fuzzy_suggestions() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("get-detail-back.vault");
    let master_password = "get detail back password";
    write_vault_with_credentials(
        &path,
        master_password,
        [
            Credential::new("youtube", "alice", "youtube value"),
            Credential::new("youtube-help", "support", "help value"),
        ],
    );
    let bytes_before_get = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtub"])
        .with_choices([1, 0, 1, 3])
        .with_display_results([InteractionResult::Back, InteractionResult::Value(())]);
    let choice_options = interaction.choice_options_log();
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("returning from Get detail should preserve the Vault session");

    assert_eq!(
        choice_options.borrow().as_slice(),
        vec![
            vec!["Add", "Get", "Remove", "Exit"],
            vec!["youtube", "youtube-help", "Cancel"],
            vec!["youtube", "youtube-help", "Cancel"],
            vec!["Add", "Get", "Remove", "Exit"],
        ]
    );
    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Credential entry not found.",
            "Key: youtube\nName: alice\nValue: youtube value",
            "Key: youtube-help\nName: support\nValue: help value",
        ]
    );
    assert_eq!(
        std::fs::read(&path).expect("Vault should remain readable"),
        bytes_before_get
    );
}

/// Verifies that Back from an exact Credential detail page returns to Key lookup.
#[test]
fn get_back_from_exact_detail_returns_to_key_lookup() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("get-exact-detail-back.vault");
    let master_password = "get exact detail back password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_get = std::fs::read(&path).expect("vault should be readable");
    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube", "youtube"])
        .with_choices([1, 3])
        .with_display_results([InteractionResult::Back, InteractionResult::Value(())]);
    let input_prompts = interaction.input_prompt_log();
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Back from exact detail should return to Key lookup");

    assert_eq!(input_prompts.borrow().as_slice(), ["Key", "Key"]);
    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Key: youtube\nName: alice\nValue: secret value",
            "Key: youtube\nName: alice\nValue: secret value",
        ]
    );
    assert_eq!(
        std::fs::read(&path).expect("Vault should remain readable"),
        bytes_before_get
    );
}

/// Verifies that Back from fuzzy suggestions returns to Key lookup before a new query.
#[test]
fn get_back_from_suggestions_returns_to_key_lookup() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("get-suggestions-back.vault");
    let master_password = "get suggestions back password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let input_prompts = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtub", "youtube"])
        .with_choice_results([
            InteractionResult::Value(1),
            InteractionResult::Back,
            InteractionResult::Value(3),
        ]);
    let input_prompt_log = input_prompts.input_prompt_log();
    let messages = input_prompts.message_log();
    let mut app = App::new(input_prompts);

    app.open(&path)
        .expect("Back from suggestions should return to Key lookup");

    assert_eq!(input_prompt_log.borrow().as_slice(), ["Key", "Key"]);
    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Credential entry not found.",
            "Key: youtube\nName: alice\nValue: secret value"
        ]
    );
}

/// Verifies that Back from a failed-query retry page returns to Key lookup.
#[test]
fn get_back_from_retry_returns_to_key_lookup() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("get-retry-back.vault");
    let master_password = "get retry back password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["unrelated", "youtube"])
        .with_choice_results([
            InteractionResult::Value(1),
            InteractionResult::Back,
            InteractionResult::Value(3),
        ]);
    let input_prompts = interaction.input_prompt_log();
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Back from retry should return to Key lookup");

    assert_eq!(input_prompts.borrow().as_slice(), ["Key", "Key"]);
    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Credential entry not found.",
            "Key: youtube\nName: alice\nValue: secret value"
        ]
    );
}

/// Verifies that Back from the initial Key page returns to Vault Home.
#[test]
fn get_back_from_key_lookup_returns_to_vault_home() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("get-key-back.vault");
    let master_password = "get key back password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_get = std::fs::read(&path).expect("vault should be readable");
    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([InteractionResult::Back])
        .with_choices([1, 3]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Back from Key lookup should return to Vault Home");

    assert!(messages.borrow().is_empty());
    assert_eq!(
        std::fs::read(&path).expect("Vault should remain readable"),
        bytes_before_get
    );
}

/// Verifies that Cancel from Credential detail abandons Get without mutating the Vault.
#[test]
fn get_cancel_from_detail_returns_to_vault_home_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("get-detail-cancel.vault");
    let master_password = "get detail cancel password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_get = std::fs::read(&path).expect("vault should be readable");
    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([1, 3])
        .with_display_results([InteractionResult::Cancel]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Cancel from detail should return to Vault Home");

    assert_eq!(
        messages.borrow().as_slice(),
        ["Key: youtube\nName: alice\nValue: secret value"]
    );
    assert_eq!(
        std::fs::read(&path).expect("Vault should remain readable"),
        bytes_before_get
    );
}

/// Verifies that an invalid fuzzy selection is reported and the suggestion page can be retried.
#[test]
fn get_invalid_fuzzy_selection_can_be_retried_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("get-invalid-suggestion.vault");
    let master_password = "get invalid suggestion password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_get = std::fs::read(&path).expect("vault should be readable");
    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtub"])
        .with_choice_results([
            InteractionResult::Value(1),
            InteractionResult::Value(99),
            InteractionResult::Value(0),
            InteractionResult::Value(3),
        ]);
    let choice_options = interaction.choice_options_log();
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("an invalid suggestion should return to the suggestion page");

    assert_eq!(choice_options.borrow().len(), 4);
    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Credential entry not found.",
            "Invalid Credential suggestion selection. Choose a suggestion, Back, or Cancel.",
            "Key: youtube\nName: alice\nValue: secret value",
        ]
    );
    assert_eq!(
        std::fs::read(&path).expect("Vault should remain readable"),
        bytes_before_get
    );
}

/// Verifies that an invalid retry selection is reported before Cancel returns to Vault Home.
#[test]
fn get_invalid_retry_selection_can_be_cancelled_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("get-invalid-retry.vault");
    let master_password = "get invalid retry password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_get = std::fs::read(&path).expect("vault should be readable");
    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["unrelated"])
        .with_choice_results([
            InteractionResult::Value(1),
            InteractionResult::Value(99),
            InteractionResult::Cancel,
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("an invalid retry selection should remain recoverable");

    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Credential entry not found.",
            "Invalid retry selection. Choose Retry, Back, or Cancel.",
        ]
    );
    assert_eq!(
        std::fs::read(&path).expect("Vault should remain readable"),
        bytes_before_get
    );
}

/// Verifies that an exact normalized Key can be removed and remains absent after reopening.
#[test]
fn remove_exact_key_is_confirmed_persisted_and_absent_after_reopen() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("remove-exact.vault");
    let master_password = "remove exact password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("YouTube", "alice", "secret value")],
    );

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs([" youtube "])
        .with_choices([2, 0, 0, 3]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("confirmed exact removal should succeed");

    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Key: YouTube\nName: alice",
            "Key: YouTube\nName: alice",
            "Credential entry removed: YouTube",
        ]
    );
    assert!(
        !messages
            .borrow()
            .iter()
            .any(|message| message.contains("secret value"))
    );

    let reopen_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([1, 1, 3]);
    let reopen_messages = reopen_interaction.message_log();
    let mut reopen_app = App::new(reopen_interaction);

    reopen_app
        .open(&path)
        .expect("the reopened Vault should be usable");

    assert_eq!(
        reopen_messages.borrow().as_slice(),
        ["Credential entry not found."]
    );
}

/// Verifies that fuzzy removal resolves the selected candidate without exposing its Value.
#[test]
fn remove_can_select_a_fuzzy_candidate_before_confirming() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("remove-fuzzy.vault");
    let master_password = "remove fuzzy password";
    write_vault_with_credentials(
        &path,
        master_password,
        [
            Credential::new("youtube", "alice", "secret value"),
            Credential::new("youtube-help", "support", "help value"),
        ],
    );

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtub"])
        .with_choices([2, 0, 0, 0, 3]);
    let choice_options = interaction.choice_options_log();
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("confirmed fuzzy removal should succeed");

    assert_eq!(
        choice_options.borrow()[1],
        ["youtube", "youtube-help", "Cancel"]
    );
    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Credential entry not found.",
            "Key: youtube\nName: alice",
            "Key: youtube\nName: alice",
            "Credential entry removed: youtube",
        ]
    );
    assert!(
        !messages
            .borrow()
            .iter()
            .any(|message| message.contains("secret value"))
    );

    let reopened_bytes = std::fs::read(&path).expect("removed Vault should be readable");
    let reopened_vault = Vault::unlock(&reopened_bytes, master_password)
        .expect("the fuzzy removal should be persisted");
    assert!(reopened_vault.find_credential("youtube").is_none());
    assert!(reopened_vault.find_credential("youtube-help").is_some());
}

/// Verifies that cancelling fuzzy candidate selection leaves the Vault unchanged.
#[test]
fn remove_fuzzy_selection_can_be_cancelled_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("remove-fuzzy-cancel.vault");
    let master_password = "remove fuzzy cancellation password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtub"])
        .with_choices([2, 1, 3]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("cancelling fuzzy removal should return to the menu");

    assert_eq!(
        messages.borrow().as_slice(),
        ["Credential entry not found."]
    );
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that a query without fuzzy candidates can be cancelled without mutation.
#[test]
fn remove_without_candidates_can_be_cancelled_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("remove-missing.vault");
    let master_password = "remove missing password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["unrelated"])
        .with_choices([2, 1, 3]);
    let choice_options = interaction.choice_options_log();
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("cancelling a missing removal should return to the menu");

    assert_eq!(choice_options.borrow()[1], ["Retry", "Cancel"]);
    assert_eq!(
        messages.borrow().as_slice(),
        ["Credential entry not found."]
    );
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that Back from the Remove Key lookup returns to Vault home unchanged.
#[test]
fn remove_lookup_back_returns_to_vault_home_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("remove-lookup-back.vault");
    let master_password = "remove lookup back password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_back = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([InteractionResult::Back])
        .with_choice_results([InteractionResult::Value(2), InteractionResult::Value(3)]);
    let messages = interaction.message_log();
    let input_prompts = interaction.input_prompt_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Back from Remove lookup should return to home");

    assert_eq!(input_prompts.borrow().as_slice(), ["Key"]);
    assert!(messages.borrow().is_empty());
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_back
    );
}

/// Verifies that Cancel from the Remove Key lookup returns to Vault home unchanged.
#[test]
fn remove_lookup_cancel_returns_to_vault_home_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("remove-lookup-cancel.vault");
    let master_password = "remove lookup cancel password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([InteractionResult::Cancel])
        .with_choice_results([InteractionResult::Value(2), InteractionResult::Value(3)]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Cancel from Remove lookup should return to home");

    assert!(messages.borrow().is_empty());
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that Back from fuzzy candidate selection returns to Key lookup unchanged.
#[test]
fn remove_candidate_selection_back_returns_to_lookup_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("remove-candidates-back.vault");
    let master_password = "remove candidates back password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_back = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([
            InteractionResult::Value("youtub".to_owned()),
            InteractionResult::Cancel,
        ])
        .with_choice_results([
            InteractionResult::Value(2),
            InteractionResult::Back,
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let input_prompts = interaction.input_prompt_log();
    let choice_options = interaction.choice_options_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Back from candidates should return to Key lookup");

    assert_eq!(input_prompts.borrow().as_slice(), ["Key", "Key"]);
    assert_eq!(
        messages.borrow().as_slice(),
        ["Credential entry not found."]
    );
    assert_eq!(choice_options.borrow().len(), 3);
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_back
    );
}

/// Verifies that Cancel from fuzzy candidate selection returns home unchanged.
#[test]
fn remove_candidate_selection_cancel_returns_to_vault_home_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("remove-candidates-cancel.vault");
    let master_password = "remove candidates cancel password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([InteractionResult::Value("youtub".to_owned())])
        .with_choice_results([
            InteractionResult::Value(2),
            InteractionResult::Cancel,
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Cancel from candidates should return to home");

    assert_eq!(
        messages.borrow().as_slice(),
        ["Credential entry not found."]
    );
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that Back from fuzzy removal confirmation restores candidate selection unchanged.
#[test]
fn remove_fuzzy_confirmation_back_returns_to_candidates_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory
        .path()
        .join("remove-fuzzy-confirmation-back.vault");
    let master_password = "remove fuzzy confirmation back password";
    write_vault_with_credentials(
        &path,
        master_password,
        [
            Credential::new("youtube", "alice", "secret value"),
            Credential::new("youtube-help", "support", "help value"),
        ],
    );
    let bytes_before_back = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([InteractionResult::Value("youtub".to_owned())])
        .with_choice_results([
            InteractionResult::Value(2),
            InteractionResult::Value(0),
            InteractionResult::Back,
            InteractionResult::Cancel,
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let choice_options = interaction.choice_options_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Back from fuzzy confirmation should restore candidates");

    assert_eq!(
        choice_options.borrow()[3],
        [
            "youtube".to_owned(),
            "youtube-help".to_owned(),
            "Cancel".to_owned(),
        ]
    );
    assert_eq!(
        messages.borrow().as_slice(),
        ["Credential entry not found.", "Key: youtube\nName: alice",]
    );
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_back
    );
}

/// Verifies that rejecting the first removal confirmation leaves the Vault unchanged.
#[test]
fn remove_first_confirmation_can_be_rejected_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("remove-first-confirmation.vault");
    let master_password = "remove first confirmation password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([2, 1, 3]);
    let choice_options = interaction.choice_options_log();
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("rejecting the first removal confirmation should be safe");

    assert_eq!(messages.borrow().as_slice(), ["Key: youtube\nName: alice"]);
    assert_eq!(choice_options.borrow()[1], ["Confirm", "Cancel"]);
    assert_eq!(choice_options.borrow().len(), 3);
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that Back from the first confirmation returns to Key lookup unchanged.
#[test]
fn remove_first_confirmation_back_returns_to_lookup_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory
        .path()
        .join("remove-first-confirmation-back.vault");
    let master_password = "remove first confirmation back password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_back = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([
            InteractionResult::Value("youtube".to_owned()),
            InteractionResult::Cancel,
        ])
        .with_choice_results([
            InteractionResult::Value(2),
            InteractionResult::Back,
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let input_prompts = interaction.input_prompt_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Back from the first confirmation should return to lookup");

    assert_eq!(input_prompts.borrow().as_slice(), ["Key", "Key"]);
    assert_eq!(messages.borrow().as_slice(), ["Key: youtube\nName: alice"]);
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_back
    );
}

/// Verifies that Cancel from the first confirmation returns home unchanged.
#[test]
fn remove_first_confirmation_cancel_returns_to_vault_home_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory
        .path()
        .join("remove-first-confirmation-cancel.vault");
    let master_password = "remove first confirmation cancel password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([InteractionResult::Value("youtube".to_owned())])
        .with_choice_results([
            InteractionResult::Value(2),
            InteractionResult::Cancel,
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Cancel from the first confirmation should return home");

    assert_eq!(messages.borrow().as_slice(), ["Key: youtube\nName: alice"]);
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that rejecting the second removal confirmation leaves the Vault unchanged.
#[test]
fn remove_second_confirmation_can_be_rejected_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("remove-second-confirmation.vault");
    let master_password = "remove second confirmation password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([2, 0, 1, 3]);
    let choice_options = interaction.choice_options_log();
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("rejecting the second removal confirmation should be safe");

    assert_eq!(
        messages.borrow().as_slice(),
        ["Key: youtube\nName: alice", "Key: youtube\nName: alice"]
    );
    assert_eq!(choice_options.borrow()[1], ["Confirm", "Cancel"]);
    assert_eq!(choice_options.borrow()[2], ["Delete", "Cancel"]);
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that Back from the second confirmation returns to the first unchanged.
#[test]
fn remove_second_confirmation_back_returns_to_first_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory
        .path()
        .join("remove-second-confirmation-back.vault");
    let master_password = "remove second confirmation back password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_back = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([InteractionResult::Value("youtube".to_owned())])
        .with_choice_results([
            InteractionResult::Value(2),
            InteractionResult::Value(0),
            InteractionResult::Back,
            InteractionResult::Cancel,
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let choice_options = interaction.choice_options_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Back from the second confirmation should return to the first");

    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Key: youtube\nName: alice",
            "Key: youtube\nName: alice",
            "Key: youtube\nName: alice",
        ]
    );
    assert_eq!(choice_options.borrow().len(), 5);
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_back
    );
}

/// Verifies that Cancel from the second confirmation returns home unchanged.
#[test]
fn remove_second_confirmation_cancel_returns_to_vault_home_without_mutation() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory
        .path()
        .join("remove-second-confirmation-cancel.vault");
    let master_password = "remove second confirmation cancel password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([InteractionResult::Value("youtube".to_owned())])
        .with_choice_results([
            InteractionResult::Value(2),
            InteractionResult::Value(0),
            InteractionResult::Cancel,
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("Cancel from the second confirmation should return home");

    assert_eq!(
        messages.borrow().as_slice(),
        ["Key: youtube\nName: alice", "Key: youtube\nName: alice"]
    );
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that a cancelled removal leaves the unlocked in-memory Vault unchanged.
#[test]
fn remove_cancel_preserves_the_in_memory_vault() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("remove-in-memory-cancel.vault");
    let master_password = "remove in-memory cancel password";
    write_vault_with_credentials(
        &path,
        master_password,
        [Credential::new("youtube", "alice", "secret value")],
    );
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let interaction = ScriptedInteraction::with_passwords([master_password])
        .with_input_results([
            InteractionResult::Value("youtube".to_owned()),
            InteractionResult::Value("youtube".to_owned()),
        ])
        .with_choice_results([
            InteractionResult::Value(2),
            InteractionResult::Value(0),
            InteractionResult::Cancel,
            InteractionResult::Value(1),
            InteractionResult::Value(3),
        ]);
    let messages = interaction.message_log();
    let mut app = App::new(interaction);

    app.open(&path)
        .expect("a cancelled removal should leave the session usable");

    assert_eq!(
        messages.borrow().as_slice(),
        [
            "Key: youtube\nName: alice",
            "Key: youtube\nName: alice",
            "Key: youtube\nName: alice\nValue: secret value",
        ]
    );
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that Debug output redacts a Credential Value.
#[test]
fn credential_debug_output_does_not_expose_the_value() {
    let credential = Credential::new("youtube", "alice", "secret value");
    let debug = format!("{credential:?}");

    assert!(!debug.contains("secret value"));
    assert!(debug.contains("[REDACTED]"));
}
