## Agent skills

### Issue tracker

Issues and specs live in GitHub Issues via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Uses the default canonical triage labels. See `docs/agents/triage-labels.md`.

### Domain docs

Uses a single-context `CONTEXT.md` and root `docs/adr/`. See `docs/agents/domain.md`.

### Rust documentation

For every Rust entity and method, add an idiomatic `///` or `//!` comment. Keep each comment concise and describe the item's purpose, observable behavior, invariants, and failure modes where relevant; keep comments synchronized with the implementation.
