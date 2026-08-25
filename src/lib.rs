//! Reusable application workflows and encrypted Vault primitives for PV.

#![warn(missing_docs)]

/// Interactive command workflows and their interaction adapters.
pub mod app;
/// Cryptographically secure Generated value options and generation.
pub mod generator;
/// Full-screen terminal interaction adapter for the application workflows.
pub mod tui;
/// Versioned encrypted Vault serialization and unlocking.
pub mod vault;
