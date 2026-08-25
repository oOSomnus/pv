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
    /// Passwords returned in prompt order.
    passwords: VecDeque<String>,
    /// Text inputs or navigation actions returned in prompt order.
    inputs: VecDeque<InteractionResult<String>>,
    /// Menu selections or navigation actions returned in prompt order.
    choices: VecDeque<InteractionResult<usize>>,
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
            passwords: passwords.into_iter().map(Into::into).collect(),
            inputs: VecDeque::new(),
            choices: VecDeque::new(),
            messages: Rc::new(RefCell::new(Vec::new())),
            password_prompts: Rc::new(RefCell::new(Vec::new())),
            input_prompts: Rc::new(RefCell::new(Vec::new())),
            choice_options: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// Adds a scripted sequence of visible text inputs to this adapter.
    fn with_inputs(mut self, inputs: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inputs = inputs
            .into_iter()
            .map(|input| InteractionResult::Value(input.into()))
            .collect();
        self
    }

    /// Adds visible text and navigation results to this adapter.
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
            .map(InteractionResult::Value)
    }

    /// Returns the next scripted visible text response.
    fn input(&mut self, prompt: &str) -> Result<InteractionResult<String>, InteractionError> {
        self.input_prompts.borrow_mut().push(prompt.to_owned());
        self.inputs
            .pop_front()
            .ok_or_else(|| InteractionError::new("no scripted input available"))
    }

    /// Returns the next scripted menu selection.
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
        .with_choices([0, 0, 3]);
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

/// Verifies that a confirmed Generated value is persisted and retrievable after reopening.
#[test]
fn generated_add_is_persisted_and_retrievable_after_reopening() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("generated-add.vault");
    let master_password = "generated add master password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let add_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube", "alice", ""])
        .with_choices([0, 1, 0, 0, 0, 3]);
    let messages = add_interaction.message_log();
    let mut add_app = App::new(add_interaction);

    add_app
        .open(&path)
        .expect("confirming a Generated value should succeed");

    let generated_value = messages
        .borrow()
        .iter()
        .find_map(|message| message.strip_prefix("Generated value: "))
        .expect("the generated value should be shown for review")
        .to_owned();
    assert_eq!(generated_value.chars().count(), 16);
    assert!(
        generated_value
            .chars()
            .any(|character| character.is_ascii_alphabetic())
    );
    assert!(
        generated_value
            .chars()
            .any(|character| character.is_ascii_digit())
    );
    assert!(
        generated_value
            .chars()
            .any(|character| character.is_ascii_punctuation())
    );

    let bytes_after_add = std::fs::read(&path).expect("vault should be readable");
    assert!(
        !bytes_after_add
            .windows(generated_value.len())
            .any(|candidate| candidate == generated_value.as_bytes())
    );

    let get_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["YOUTUBE"])
        .with_choices([1, 3]);
    let get_messages = get_interaction.message_log();
    let mut get_app = App::new(get_interaction);

    get_app
        .open(&path)
        .expect("the Generated value should survive reopening");

    assert_eq!(
        get_messages.borrow().as_slice(),
        [format!(
            "Key: youtube\nName: alice\nValue: {generated_value}"
        )]
    );
}

/// Verifies that invalid Generated value lengths are retried before applying class options.
#[test]
fn generated_add_retries_invalid_lengths_and_can_disable_optional_classes() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("generated-options.vault");
    let master_password = "generated options master password";
    let mut init_app = App::new(ScriptedInteraction::with_passwords([
        master_password,
        master_password,
    ]));

    init_app.init(&path).expect("initialization should succeed");

    let add_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube", "alice", "9", "not a number", "10"])
        .with_choices([0, 1, 1, 1, 0, 3]);
    let messages = add_interaction.message_log();
    let mut app = App::new(add_interaction);

    app.open(&path)
        .expect("valid Generated value options should succeed");

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
    let generated_value = messages
        .iter()
        .find_map(|message| message.strip_prefix("Generated value: "))
        .expect("the generated value should be shown for review");
    assert_eq!(generated_value.chars().count(), 10);
    assert!(
        generated_value
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    );
}

/// Verifies that regeneration creates a different value with the same selected options.
#[test]
fn generated_add_can_regenerate_before_confirming() {
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
        .with_choices([0, 1, 1, 1, 1, 0, 3]);
    let messages = add_interaction.message_log();
    let mut app = App::new(add_interaction);

    app.open(&path)
        .expect("regenerating and confirming should succeed");

    let generated_values: Vec<String> = messages
        .borrow()
        .iter()
        .filter_map(|message| message.strip_prefix("Generated value: "))
        .map(str::to_owned)
        .collect();
    assert_eq!(generated_values.len(), 2);
    assert_ne!(generated_values[0], generated_values[1]);
    assert!(
        generated_values
            .iter()
            .all(|value| value.chars().count() == 10)
    );
    assert!(generated_values.iter().all(|value| {
        value
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    }));
}

/// Verifies that cancelling a Generated value leaves the persisted Vault unchanged.
#[test]
fn generated_add_can_be_cancelled_without_mutating_the_vault() {
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
            .with_choices([0, 1, 1, 1, 2, 3]),
    );

    app.open(&path)
        .expect("cancelling a Generated value should return to the menu");

    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
    );
}

/// Verifies that a duplicate Generated value can be cancelled or explicitly overwritten.
#[test]
fn generated_duplicate_can_be_cancelled_or_overwritten() {
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
            .with_choices([0, 0, 3]),
    );
    original_app
        .open(&path)
        .expect("the original Credential should be added");
    let bytes_before_duplicate_cancel = std::fs::read(&path).expect("vault should be readable");

    let mut cancel_app = App::new(
        ScriptedInteraction::with_passwords([master_password])
            .with_inputs([" youtube ", "discarded name", "10"])
            .with_choices([0, 1, 1, 1, 0, 1, 3]),
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
        .with_choices([0, 1, 1, 1, 0, 0, 3]);
    let overwrite_messages = overwrite_interaction.message_log();
    let mut overwrite_app = App::new(overwrite_interaction);
    overwrite_app
        .open(&path)
        .expect("overwriting a duplicate Generated value should succeed");

    let generated_value = overwrite_messages
        .borrow()
        .iter()
        .find_map(|message| message.strip_prefix("Generated value: "))
        .expect("the generated value should be shown for review")
        .to_owned();

    let get_interaction = ScriptedInteraction::with_passwords([master_password])
        .with_inputs(["youtube"])
        .with_choices([1, 3]);
    let get_messages = get_interaction.message_log();
    let mut get_app = App::new(get_interaction);
    get_app
        .open(&path)
        .expect("the overwritten Generated value should survive reopening");

    assert_eq!(
        get_messages.borrow().as_slice(),
        [format!(
            "Key: YouTube\nName: generated name\nValue: {generated_value}"
        )]
    );
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
            .with_choices([0, 0, 0, 0, 0, 3]);
    let duplicate_messages = add_interaction.message_log();
    let mut add_app = App::new(add_interaction);

    add_app
        .open(&path)
        .expect("the duplicate should be explicitly overwritten");

    assert_eq!(
        duplicate_messages.borrow().as_slice(),
        ["A Credential entry with that Key already exists."]
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

/// Verifies that cancelling a duplicate Add leaves both memory and disk unchanged.
#[test]
fn duplicate_add_can_be_cancelled_without_mutating_the_vault() {
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
            .with_choices([0, 0, 3]),
    );
    add_app
        .open(&path)
        .expect("the original Credential should be added");
    let bytes_before_cancel = std::fs::read(&path).expect("vault should be readable");

    let mut cancel_app = App::new(
        ScriptedInteraction::with_passwords([master_password, "discarded secret"])
            .with_inputs([" youtube ", "discarded name"])
            .with_choices([0, 0, 1, 3]),
    );

    cancel_app
        .open(&path)
        .expect("cancelling the duplicate should return to the menu");

    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes_before_cancel
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
