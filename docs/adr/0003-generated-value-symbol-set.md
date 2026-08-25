# Keep the Generated value Symbol set compatibility-focused

## Status

Accepted

## Context

Generated Values need to satisfy common website rules without introducing
characters that are frequently rejected or awkward to enter. The Symbol set
is a Generated value concern only; manually entered Values remain opaque text.

## Decision

Generated Values use the exact ASCII Symbol set `!@.-_*` when Symbols are
enabled. The generator validates lengths from 8 through 100, uses length 20
with Numbers enabled and Symbols disabled by default, and guarantees at least
one character from every enabled category while excluding disabled categories.
The generated candidate remains masked and in memory until the shared Review
Save decision persists it.

## Consequences

- Domain callers and the TUI share the same length, allowlist, and category
  guarantees.
- Generated Values remain compatible with services that reject broader
  punctuation sets.
- A Symbol set change would be a compatibility decision and requires updated
  regression coverage; it does not require a Vault format migration.
