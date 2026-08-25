# Use a renderer-owned page trail for the full-screen TUI

## Status

Accepted

## Context

PV has several nested Vault workflows whose business logic is intentionally
tested through the renderer-neutral `Interaction` trait. The production
terminal still needs to communicate the current hierarchy, immediate Back
target, and root-level Cancel behavior consistently across Init, Open, Add,
Get, Remove, Generated value, Review, and confirmation pages.

## Decision

The TUI adapter owns a renderer-local page trail. Application prompts identify
the current interaction, while menu selections identify the next workflow
section when the next prompt is rendered. The adapter derives page titles,
breadcrumbs, selection markers, and footer shortcuts from that trail.

Back removes one page from the trail and Cancel resets it to the command
workflow root. Vault Home is the root page for unlocked sessions and does not
advertise a Back action. Status messages are rendered in the shared shell
without replacing the current page context. No terminal-library type crosses
the `Interaction` seam, and color or animation is supplementary to text and
keyboard shortcuts.

## Consequences

- All production workflows share one readable hierarchy and navigation shell.
- The scripted application seam remains independent of terminal layout,
  colors, and events.
- The adapter maintains a small amount of renderer-only state and must keep
  prompt-to-page mappings synchronized with workflow prompts.
