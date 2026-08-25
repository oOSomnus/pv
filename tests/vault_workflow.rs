use std::{cell::RefCell, collections::VecDeque, rc::Rc};

use bincode::{Encode, config, encode_to_vec};
use pv::{
    app::{App, Interaction, InteractionError},
    vault::Vault,
};
use tempfile::tempdir;

#[derive(Encode)]
struct UnsupportedEnvelope {
    version: u8,
    salt: [u8; 16],
    nonce: [u8; 12],
    cipher_text: Vec<u8>,
}

struct ScriptedInteraction {
    passwords: VecDeque<String>,
    choices: VecDeque<usize>,
    messages: Rc<RefCell<Vec<String>>>,
}

impl ScriptedInteraction {
    fn with_passwords(passwords: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            passwords: passwords.into_iter().map(Into::into).collect(),
            choices: VecDeque::new(),
            messages: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn with_choices(mut self, choices: impl IntoIterator<Item = usize>) -> Self {
        self.choices = choices.into_iter().collect();
        self
    }

    fn message_log(&self) -> Rc<RefCell<Vec<String>>> {
        Rc::clone(&self.messages)
    }
}

impl Interaction for ScriptedInteraction {
    fn password(&mut self, _prompt: &str) -> Result<String, InteractionError> {
        self.passwords
            .pop_front()
            .ok_or_else(|| InteractionError::new("no scripted password available"))
    }

    fn choose(&mut self, _prompt: &str, _options: &[&str]) -> Result<usize, InteractionError> {
        self.choices
            .pop_front()
            .ok_or_else(|| InteractionError::new("no scripted choice available"))
    }

    fn message(&mut self, message: &str) -> Result<(), InteractionError> {
        self.messages.borrow_mut().push(message.to_owned());
        Ok(())
    }
}

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

#[test]
fn init_then_open_completes_the_empty_vault_lifecycle() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("lifecycle.vault");
    let password = "lifecycle password";
    let mut app = App::new(
        ScriptedInteraction::with_passwords([password, password, password]).with_choices([0]),
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

#[test]
fn saving_an_unmodified_vault_uses_a_fresh_nonce() {
    let vault = Vault::new("nonce password").expect("vault should be generated");

    let first_save = vault.to_bytes().expect("first save should be encoded");
    let second_save = vault.to_bytes().expect("second save should be encoded");

    assert_ne!(first_save, second_save);
    assert!(Vault::unlock(&second_save, "nonce password").is_ok());
}

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
    let mut app = App::new(ScriptedInteraction::with_passwords([password]).with_choices([0]));

    let result = app.open(&path).expect("opening should succeed");

    assert!(matches!(result, pv::app::OpenResult::Exited));
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        bytes
    );
}

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
        ScriptedInteraction::with_passwords(["wrong password", password]).with_choices([0, 0]);
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
