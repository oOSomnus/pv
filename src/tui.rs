//! Full-screen terminal rendering and keyboard input for PV's interaction seam.

use std::io::{self, Stdout, Write};

use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{
        Attribute, Color, Print, ResetColor, SetAttribute, SetBackgroundColor, SetForegroundColor,
    },
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};

use crate::app::{Interaction, InteractionError, InteractionResult};

/// Identifies the top-level workflow displayed by the full-screen shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiWorkflow {
    /// The user is creating a new Vault.
    Init,
    /// The user is unlocking and using an existing Vault.
    Open,
}

/// Owns the terminal session and adapts keyboard input to [`Interaction`].
pub struct TuiInteraction {
    /// The stdout terminal currently in the alternate screen.
    output: Stdout,
    /// The workflow used to derive page titles and breadcrumbs.
    workflow: TuiWorkflow,
    /// The last status message emitted by the application workflow.
    status: Option<String>,
    /// The most recently rendered interaction context.
    context: String,
}

impl TuiInteraction {
    /// Enters a raw alternate-screen terminal session for `workflow`.
    pub fn new(workflow: TuiWorkflow) -> Result<Self, InteractionError> {
        terminal::enable_raw_mode().map_err(Self::terminal_error)?;
        let mut output = io::stdout();
        if let Err(error) = execute!(
            output,
            EnterAlternateScreen,
            SetBackgroundColor(Color::Black),
            Clear(ClearType::All),
            Hide
        ) {
            let _ = terminal::disable_raw_mode();
            return Err(Self::terminal_error(error));
        }

        Ok(Self {
            output,
            workflow,
            status: None,
            context: String::new(),
        })
    }

    /// Converts a terminal I/O error into the interaction error exposed to workflows.
    fn terminal_error(error: io::Error) -> InteractionError {
        InteractionError::new(format!("terminal interaction failed: {error}"))
    }

    /// Returns the title for a rendered interaction page.
    fn page_title(&self, prompt: &str) -> &'static str {
        match self.workflow {
            TuiWorkflow::Init => "Initialize Vault",
            TuiWorkflow::Open if matches!(prompt, "Master password" | "Incorrect password") => {
                "Unlock Vault"
            }
            TuiWorkflow::Open if prompt == "Vault" => "Vault Home",
            TuiWorkflow::Open => "Vault",
        }
    }

    /// Returns the breadcrumb context for a rendered interaction page.
    fn breadcrumb(&self, prompt: &str) -> String {
        let workflow = match self.workflow {
            TuiWorkflow::Init => "Init",
            TuiWorkflow::Open => "Open",
        };
        let context = if prompt.is_empty() {
            self.context.as_str()
        } else {
            prompt
        };
        if context.is_empty() {
            format!("PV / {workflow}")
        } else {
            format!("PV / {workflow} / {context}")
        }
    }

    /// Draws the shared title, context, status bar, body, and footer shell.
    fn draw(
        &mut self,
        prompt: &str,
        body: &[String],
        footer: &str,
    ) -> Result<(), InteractionError> {
        if !prompt.is_empty() {
            self.context = prompt.to_owned();
        }
        let (width, height) = terminal::size().map_err(Self::terminal_error)?;
        let body_width = usize::from(width.saturating_sub(8));
        let title = self.page_title(prompt);
        let breadcrumb = self.breadcrumb(prompt);
        let divider = "─".repeat(usize::from(width.max(1)));
        let mut lines = Vec::with_capacity(body.len() + 1);
        if let Some(status) = &self.status {
            lines.push(format!("! {status}"));
        }
        lines.extend(body.iter().cloned());

        queue!(
            self.output,
            SetBackgroundColor(Color::Black),
            Clear(ClearType::All),
            MoveTo(2, 1),
            SetForegroundColor(Color::Cyan),
            SetAttribute(Attribute::Bold),
            Print("PV"),
            SetAttribute(Attribute::Reset),
            SetForegroundColor(Color::Magenta),
            Print("  /  "),
            SetForegroundColor(Color::White),
            Print(title),
            MoveTo(2, 2),
            SetForegroundColor(Color::DarkGrey),
            Print(trim_to_width(&breadcrumb, body_width)),
            MoveTo(0, 3),
            SetForegroundColor(Color::DarkGrey),
            Print(&divider),
        )
        .map_err(Self::terminal_error)?;

        let body_end = height.saturating_sub(5);
        let mut row = 4;
        for line in lines.iter().take(usize::from(body_end.saturating_sub(4))) {
            queue!(
                self.output,
                MoveTo(4, row),
                SetForegroundColor(Color::White),
                Print(trim_to_width(line, body_width))
            )
            .map_err(Self::terminal_error)?;
            row = row.saturating_add(1);
        }

        let status_row = height.saturating_sub(3);
        let footer_row = height.saturating_sub(1);
        let status_text = self.status.as_deref().unwrap_or("Ready");
        queue!(
            self.output,
            MoveTo(0, status_row),
            SetBackgroundColor(Color::DarkGrey),
            SetForegroundColor(Color::White),
            Print(trim_to_width(
                &format!(" {status_text} "),
                usize::from(width)
            )),
            SetBackgroundColor(Color::Black),
            MoveTo(0, footer_row),
            SetForegroundColor(Color::Cyan),
            Print(trim_to_width(footer, usize::from(width))),
            ResetColor,
            SetAttribute(Attribute::Reset)
        )
        .map_err(Self::terminal_error)?;
        self.output.flush().map_err(Self::terminal_error)
    }

    /// Reads one editable text value, optionally masking it and applying a default.
    fn read_text(
        &mut self,
        prompt: &str,
        default: Option<&str>,
        hidden: bool,
    ) -> Result<InteractionResult<String>, InteractionError> {
        let mut value = String::new();
        loop {
            let displayed = if hidden {
                "•".repeat(value.chars().count())
            } else if value.is_empty() {
                default
                    .map(|default| format!("[{default}]"))
                    .unwrap_or_default()
            } else {
                value.clone()
            };
            self.draw(
                prompt,
                &[prompt.to_owned(), String::new(), displayed],
                "Enter Submit   Esc Back   Ctrl+C Cancel",
            )?;

            match event::read().map_err(Self::terminal_error)? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if is_cancel_key(key) {
                        self.status = None;
                        return Ok(InteractionResult::Cancel);
                    }
                    match key.code {
                        KeyCode::Enter => {
                            let result = default
                                .filter(|_| value.is_empty())
                                .unwrap_or(value.as_str())
                                .to_owned();
                            self.status = None;
                            return Ok(InteractionResult::Value(result));
                        }
                        KeyCode::Esc => {
                            self.status = None;
                            return Ok(InteractionResult::Back);
                        }
                        KeyCode::Backspace => {
                            value.pop();
                        }
                        KeyCode::Char(character)
                            if !key.modifiers.contains(KeyModifiers::CONTROL)
                                && !key.modifiers.contains(KeyModifiers::ALT) =>
                        {
                            value.push(character);
                        }
                        _ => {}
                    }
                }
                Event::Paste(text) => value.push_str(&text),
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }

    /// Reads a keyboard-selected option from the supplied menu.
    fn read_choice(
        &mut self,
        prompt: &str,
        options: &[&str],
    ) -> Result<InteractionResult<usize>, InteractionError> {
        if options.is_empty() {
            return Err(InteractionError::new("no menu options are available"));
        }
        let mut selected = 0;
        loop {
            let body: Vec<String> = options
                .iter()
                .enumerate()
                .map(|(index, option)| {
                    if index == selected {
                        format!("› {option}")
                    } else {
                        format!("  {option}")
                    }
                })
                .collect();
            self.draw(
                prompt,
                &body,
                "↑↓ Navigate   Enter Select   Esc Back   Ctrl+C Cancel",
            )?;

            match event::read().map_err(Self::terminal_error)? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if is_cancel_key(key) {
                        self.status = None;
                        return Ok(InteractionResult::Cancel);
                    }
                    match key.code {
                        KeyCode::Enter => {
                            self.status = None;
                            return Ok(InteractionResult::Value(selected));
                        }
                        KeyCode::Esc => {
                            self.status = None;
                            return Ok(InteractionResult::Back);
                        }
                        KeyCode::Up => {
                            selected = if selected == 0 {
                                options.len() - 1
                            } else {
                                selected - 1
                            };
                        }
                        KeyCode::Down => {
                            selected = (selected + 1) % options.len();
                        }
                        _ => {}
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}

impl Interaction for TuiInteraction {
    /// Reads a hidden password as an ordinary value, Back, or Cancel.
    fn password(&mut self, prompt: &str) -> Result<InteractionResult<String>, InteractionError> {
        self.read_text(prompt, None, true)
    }

    /// Reads visible text as an ordinary value, Back, or Cancel.
    fn input(&mut self, prompt: &str) -> Result<InteractionResult<String>, InteractionError> {
        self.read_text(prompt, None, false)
    }

    /// Reads visible text with a default as an ordinary value, Back, or Cancel.
    fn input_with_default(
        &mut self,
        prompt: &str,
        default: &str,
    ) -> Result<InteractionResult<String>, InteractionError> {
        self.read_text(prompt, Some(default), false)
    }

    /// Reads a menu selection as an ordinary value, Back, or Cancel.
    fn choose(
        &mut self,
        prompt: &str,
        options: &[&str],
    ) -> Result<InteractionResult<usize>, InteractionError> {
        self.read_choice(prompt, options)
    }

    /// Shows a status message in the shared shell without blocking the workflow.
    fn message(&mut self, message: &str) -> Result<(), InteractionError> {
        self.status = Some(message.to_owned());
        self.draw("Status", &[], "Enter Continue   Esc Back   Ctrl+C Cancel")
    }
}

impl Drop for TuiInteraction {
    /// Restores the user's cursor, terminal screen, colors, and input mode.
    fn drop(&mut self) {
        let _ = execute!(self.output, ResetColor, Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

/// Returns whether `key` is the explicit terminal cancellation shortcut.
fn is_cancel_key(key: KeyEvent) -> bool {
    key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)
}

/// Truncates a line by characters so it remains inside the terminal width.
fn trim_to_width(value: &str, width: usize) -> String {
    value.chars().take(width).collect()
}
