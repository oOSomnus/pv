use std::{cell::RefCell, path::Path, rc::Rc};

use pv::{
    app::{App, Interaction, InteractionError, InteractionResult, OpenResult},
    vault::Vault,
};
use tempfile::tempdir;

/// Adapter that cancels the first hidden input without using terminal types.
struct CancelAtPassword;

impl Interaction for CancelAtPassword {
    /// Returns the domain-level cancellation action.
    fn password(&mut self, _prompt: &str) -> Result<InteractionResult<String>, InteractionError> {
        Ok(InteractionResult::Cancel)
    }

    /// Returns an error because unlock should not ask for a menu.
    fn input(&mut self, _prompt: &str) -> Result<InteractionResult<String>, InteractionError> {
        Err(InteractionError::new("input should not be called"))
    }

    /// Returns an error because unlock should not ask for a menu.
    fn choose(
        &mut self,
        _prompt: &str,
        _options: &[&str],
    ) -> Result<InteractionResult<usize>, InteractionError> {
        Err(InteractionError::new("choice should not be called"))
    }

    /// Records messages without writing to a terminal.
    fn message(&mut self, _message: &str) -> Result<(), InteractionError> {
        Ok(())
    }
}

/// Writes an encrypted empty Vault fixture to `path`.
fn write_empty_vault(path: &Path, master_password: &str) {
    let vault = Vault::new(master_password).expect("vault should be generated");
    std::fs::write(path, vault.to_bytes().expect("vault should be encoded"))
        .expect("vault fixture should be written");
}

/// Verifies that a domain-level Cancel exits unlock without mutating the file.
#[test]
fn open_can_cancel_from_the_interaction_contract_without_mutating_the_vault() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("cancel.vault");
    write_empty_vault(&path, "correct password");
    let before = std::fs::read(&path).expect("vault should be readable");

    let mut app = App::new(CancelAtPassword);
    let result = app.open(&path).expect("cancelling unlock should be clean");

    assert_eq!(result, OpenResult::Cancelled);
    assert_eq!(
        std::fs::read(&path).expect("vault should remain readable"),
        before
    );
}

/// Adapter that records the selected home-page options and cancels the session.
struct CancelAtHome {
    /// Menu option lists recorded from the Vault home.
    options: Rc<RefCell<Vec<Vec<String>>>>,
}

impl Interaction for CancelAtHome {
    /// Supplies the valid Master password through the interaction contract.
    fn password(&mut self, _prompt: &str) -> Result<InteractionResult<String>, InteractionError> {
        Ok(InteractionResult::Value("correct password".to_owned()))
    }

    /// Returns an error because the home-page test does not ask for visible input.
    fn input(&mut self, _prompt: &str) -> Result<InteractionResult<String>, InteractionError> {
        Err(InteractionError::new("input should not be called"))
    }

    /// Records the Vault home menu and cancels from it.
    fn choose(
        &mut self,
        _prompt: &str,
        options: &[&str],
    ) -> Result<InteractionResult<usize>, InteractionError> {
        self.options
            .borrow_mut()
            .push(options.iter().map(|option| (*option).to_owned()).collect());
        Ok(InteractionResult::Cancel)
    }

    /// Records workflow messages without writing to a terminal.
    fn message(&mut self, _message: &str) -> Result<(), InteractionError> {
        Ok(())
    }
}

/// Verifies that the interaction contract exposes the unchanged Vault home actions.
#[test]
fn open_exposes_the_existing_vault_home_actions_through_the_contract() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("home.vault");
    write_empty_vault(&path, "correct password");
    let options = Rc::new(RefCell::new(Vec::new()));

    let mut app = App::new(CancelAtHome {
        options: Rc::clone(&options),
    });
    let result = app
        .open(&path)
        .expect("cancelling from home should be clean");

    assert_eq!(result, OpenResult::Exited);
    assert_eq!(
        options.borrow().as_slice(),
        [["Add", "Get", "Remove", "Exit"]]
    );
}
