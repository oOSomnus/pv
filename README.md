# PV

PV is a local command-line password manager for storing website credentials in an encrypted Vault.

## Features

- Initialize a new Vault and open an existing one with an optional custom path.
- Use `./pv.vault` when no path is supplied.
- Store each credential as a `Key` (website or service), `Name` (username), and hidden `Value` (password or secret).
- Add values manually or generate secure values from 8 to 100 characters, with a default length of 20, Numbers enabled by default, and Symbols disabled by default.
- Generated values always contain ASCII letters; optional Numbers and the exact Symbols `!@.-_*` are guaranteed when enabled, and candidates remain masked until saved. The Value step offers the Random path directly.
- Find credentials by case-insensitive, whitespace-trimmed Key matching, with up to three fuzzy suggestions for typos.
- Remove credentials only after two independent confirmations.
- Persist every successful mutation immediately.
- Run `init` and `open` in the same full-screen terminal interface with persistent context and keyboard action hints.

## Usage

Build and run PV with Cargo:

```sh
cargo run -- init
cargo run -- open
```

`init` prompts for a Master password twice and creates an empty Vault at `./pv.vault`. Initialization refuses to overwrite an existing file. Supply a path to use another Vault:

```sh
cargo run -- init ./personal.vault
cargo run -- open ./personal.vault
```

Both commands use the full-screen terminal interface. Use the arrow keys and Enter to navigate, Esc for Back, and Ctrl+C to Cancel. After unlocking, `open` provides an interactive menu with `Add`, `Get`, `Remove`, and `Exit` actions. Cancelled operations leave the Vault unchanged.

## Security

Vault payloads are encrypted at rest with AES-256-GCM. PV derives the encryption key from the Master password and a per-Vault salt using Argon2id, and generates a fresh encryption nonce for every save. The Master password and credential Values are never persisted as plaintext; on Unix, newly created Vault files are given owner-only permissions.

The Master password cannot be recovered or reset by PV. Keep it safe.

## Development

Run the local checks with:

```sh
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps
```
