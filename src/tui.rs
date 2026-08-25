//! Full-screen terminal rendering and keyboard input for PV's interaction seam.

use std::{
    io::{self, Stdout, Write},
    time::Duration,
};

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

/// The ASCII frames used for lightweight status feedback.
const FEEDBACK_FRAMES: [&str; 4] = ["-", "\\", "|", "/"];

/// Identifies the top-level workflow displayed by the full-screen shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiWorkflow {
    /// The user is creating a new Vault.
    Init,
    /// The user is unlocking and using an existing Vault.
    Open,
}

/// Identifies a renderer-local page in the workflow hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiPage {
    /// The root page for the selected command workflow.
    Workflow,
    /// The home page shown after a Vault is unlocked.
    VaultHome,
    /// The Add workflow section.
    Add,
    /// The Get workflow section.
    Get,
    /// The Remove workflow section.
    Remove,
    /// The Key field or lookup page.
    Key,
    /// The Name field page.
    Name,
    /// The Value source and manual Value page.
    Value,
    /// The Generated value settings page.
    GeneratorSettings,
    /// The masked Generated value candidate page.
    GeneratedValue,
    /// The unsaved Credential review page.
    Review,
    /// The fuzzy Credential suggestion page.
    Suggestions,
    /// The Credential detail page.
    Credential,
    /// A destructive-operation confirmation page.
    Confirmation,
    /// The duplicate-Key decision page.
    Duplicate,
    /// A fatal workflow error page.
    Error,
}

impl TuiPage {
    /// Returns the short label used in the breadcrumb trail.
    fn label(self, workflow: TuiWorkflow) -> &'static str {
        match self {
            Self::Workflow => match workflow {
                TuiWorkflow::Init => "Init",
                TuiWorkflow::Open => "Open",
            },
            Self::VaultHome => "Vault",
            Self::Add => "Add",
            Self::Get => "Get",
            Self::Remove => "Remove",
            Self::Key => "Key",
            Self::Name => "Name",
            Self::Value => "Value",
            Self::GeneratorSettings => "Random",
            Self::GeneratedValue => "Generated value",
            Self::Review => "Review",
            Self::Suggestions => "Suggestions",
            Self::Credential => "Credential entry",
            Self::Confirmation => "Confirmation",
            Self::Duplicate => "Duplicate Key",
            Self::Error => "Error",
        }
    }

    /// Returns the page title displayed in the shared TUI header.
    fn title(self, workflow: TuiWorkflow) -> &'static str {
        match self {
            Self::Workflow => match workflow {
                TuiWorkflow::Init => "Initialize Vault",
                TuiWorkflow::Open => "Unlock Vault",
            },
            Self::VaultHome => "Vault Home",
            Self::Add => "Add Credential",
            Self::Get => "Get Credential",
            Self::Remove => "Remove Credential",
            Self::Key => "Key",
            Self::Name => "Name",
            Self::Value => "Value",
            Self::GeneratorSettings => "Random Generator",
            Self::GeneratedValue => "Generated value",
            Self::Review => "Review",
            Self::Suggestions => "Credential Suggestions",
            Self::Credential => "Credential entry",
            Self::Confirmation => "Confirmation",
            Self::Duplicate => "Duplicate Key",
            Self::Error => "Error",
        }
    }
}

/// Owns the terminal session and adapts keyboard input to [`Interaction`].
pub struct TuiInteraction {
    /// The stdout terminal currently in the alternate screen.
    output: Stdout,
    /// The workflow used to derive page titles and breadcrumbs.
    workflow: TuiWorkflow,
    /// The last status message emitted by the application workflow.
    status: Option<String>,
    /// The renderer-local hierarchy of the currently displayed page.
    page_trail: Vec<TuiPage>,
    /// The page selected by a menu and expected by the next interaction call.
    pending_page: Option<TuiPage>,
    /// The current frame used while waiting for terminal input after a status update.
    feedback_frame: usize,
}

impl TuiInteraction {
    /// Enters a raw alternate-screen terminal session for `workflow`.
    ///
    /// Returns an [`InteractionError`] when raw mode or alternate-screen setup fails.
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
            let _ = execute!(output, ResetColor, Show, LeaveAlternateScreen);
            let _ = terminal::disable_raw_mode();
            return Err(Self::terminal_error(error));
        }

        Ok(Self {
            output,
            workflow,
            status: None,
            page_trail: vec![TuiPage::Workflow],
            pending_page: None,
            feedback_frame: 0,
        })
    }

    /// Converts a terminal I/O error into the interaction error exposed to workflows.
    fn terminal_error(error: io::Error) -> InteractionError {
        InteractionError::new(format!("terminal interaction failed: {error}"))
    }

    /// Returns the title for the currently rendered interaction page.
    fn page_title(&self) -> &'static str {
        self.current_page().title(self.workflow)
    }

    /// Returns the complete breadcrumb trail for the current page.
    fn breadcrumb(&self) -> String {
        let pages = self
            .page_trail
            .iter()
            .map(|page| page.label(self.workflow))
            .collect::<Vec<_>>();
        format!("PV / {}", pages.join(" / "))
    }

    /// Returns the page at the end of the current breadcrumb trail.
    fn current_page(&self) -> TuiPage {
        self.page_trail.last().copied().unwrap_or(TuiPage::Workflow)
    }

    /// Maps an application prompt to a renderer-local page kind.
    fn page_for_prompt(&self, prompt: &str) -> Option<TuiPage> {
        match prompt {
            "Master password" => Some(match self.workflow {
                TuiWorkflow::Init => TuiPage::Workflow,
                TuiWorkflow::Open => TuiPage::Workflow,
            }),
            "Confirm master password" => Some(TuiPage::Workflow),
            "Incorrect password" => Some(TuiPage::Workflow),
            "Vault" => Some(TuiPage::VaultHome),
            "Key" => Some(TuiPage::Key),
            "Name" => Some(TuiPage::Name),
            "Value" => Some(TuiPage::Value),
            "Generated value length (8-100)" | "Numbers" | "Symbols" => {
                Some(TuiPage::GeneratorSettings)
            }
            "Generated value" => Some(TuiPage::GeneratedValue),
            "Review" => Some(TuiPage::Review),
            "Credential suggestions" => Some(TuiPage::Suggestions),
            "Credential entry" => Some(TuiPage::Credential),
            "Remove Credential entry" | "Confirm deletion" => Some(TuiPage::Confirmation),
            "Duplicate Key" => Some(TuiPage::Duplicate),
            "Error" => Some(TuiPage::Error),
            "Credential not found" | "Status" => None,
            _ => None,
        }
    }

    /// Enters the page associated with an application prompt and its pending menu transition.
    fn enter_page(&mut self, prompt: &str) {
        if prompt == "Status" {
            return;
        }
        if let Some(pending_page) = self.pending_page.take() {
            self.activate_page(pending_page);
        }
        if let Some(page) = self.page_for_prompt(prompt) {
            self.activate_page(page);
        }
    }

    /// Activates a page while retaining only its meaningful parent hierarchy.
    fn activate_page(&mut self, page: TuiPage) {
        match page {
            TuiPage::Workflow => self.reset_to_workflow(),
            TuiPage::VaultHome => self.reset_to_home(),
            TuiPage::Add | TuiPage::Get | TuiPage::Remove => {
                self.move_under(page, &[TuiPage::VaultHome]);
            }
            TuiPage::Key => self.move_under(page, &[TuiPage::Add, TuiPage::Get, TuiPage::Remove]),
            TuiPage::Name => self.move_under(page, &[TuiPage::Key, TuiPage::Add]),
            TuiPage::Value => {
                self.move_under(page, &[TuiPage::Name, TuiPage::Key, TuiPage::Add]);
            }
            TuiPage::Review => {
                self.move_under(
                    page,
                    &[TuiPage::Value, TuiPage::Name, TuiPage::Key, TuiPage::Add],
                );
            }
            TuiPage::GeneratorSettings => self.move_under(page, &[TuiPage::Value]),
            TuiPage::GeneratedValue => self.move_under(page, &[TuiPage::GeneratorSettings]),
            TuiPage::Suggestions => {
                self.move_under(page, &[TuiPage::Key, TuiPage::Get, TuiPage::Remove]);
            }
            TuiPage::Credential => {
                self.move_under(
                    page,
                    &[
                        TuiPage::Suggestions,
                        TuiPage::Key,
                        TuiPage::Get,
                        TuiPage::Remove,
                    ],
                );
            }
            TuiPage::Confirmation => {
                self.move_under(page, &[TuiPage::Suggestions, TuiPage::Key, TuiPage::Remove])
            }
            TuiPage::Duplicate => self.move_under(page, &[TuiPage::Review, TuiPage::Add]),
            TuiPage::Error => {
                self.page_trail.truncate(1);
                self.page_trail.push(TuiPage::Error);
            }
        }
    }

    /// Places `page` immediately below its nearest active parent page.
    fn move_under(&mut self, page: TuiPage, parents: &[TuiPage]) {
        if let Some(page_index) = self.page_trail.iter().rposition(|current| *current == page) {
            self.page_trail.truncate(page_index + 1);
            return;
        }
        if let Some(parent_index) = self
            .page_trail
            .iter()
            .rposition(|current| parents.contains(current))
        {
            self.page_trail.truncate(parent_index + 1);
        }
        self.page_trail.push(page);
    }

    /// Resets the breadcrumb trail to the selected command workflow.
    fn reset_to_workflow(&mut self) {
        self.page_trail.clear();
        self.page_trail.push(TuiPage::Workflow);
        self.pending_page = None;
    }

    /// Resets the breadcrumb trail to the unlocked Vault home page.
    fn reset_to_home(&mut self) {
        self.page_trail.clear();
        self.page_trail
            .extend([TuiPage::Workflow, TuiPage::VaultHome]);
        self.pending_page = None;
    }

    /// Records the child page implied by a successful menu selection.
    fn remember_selection(&mut self, prompt: &str, options: &[&str], selected: usize) {
        self.pending_page = match (prompt, options.get(selected).copied()) {
            ("Vault", Some("Add")) => Some(TuiPage::Add),
            ("Vault", Some("Get")) => Some(TuiPage::Get),
            ("Vault", Some("Remove")) => Some(TuiPage::Remove),
            ("Value", Some("Random")) => Some(TuiPage::GeneratorSettings),
            ("Credential suggestions", Some("Cancel")) => None,
            ("Credential suggestions", Some(_)) if self.page_trail.contains(&TuiPage::Get) => {
                Some(TuiPage::Credential)
            }
            ("Credential suggestions", Some(_)) => None,
            _ => None,
        };
    }

    /// Updates the renderer hierarchy after a returned interaction result.
    fn finish_navigation<T>(&mut self, result: &InteractionResult<T>) {
        match result {
            InteractionResult::Value(_) => {}
            InteractionResult::Back => {
                self.pending_page = None;
                if self.page_trail.len() > 1 {
                    self.page_trail.pop();
                }
            }
            InteractionResult::Cancel => self.reset_to_workflow(),
        }
    }

    /// Clears status and records the navigation represented by `result`.
    fn complete<T>(&mut self, result: InteractionResult<T>) -> InteractionResult<T> {
        self.status = None;
        self.finish_navigation(&result);
        result
    }

    /// Returns whether the current page has an immediate parent for Back navigation.
    fn can_go_back(&self) -> bool {
        self.page_trail.len() > 1
            && !matches!(self.current_page(), TuiPage::Workflow | TuiPage::VaultHome)
    }

    /// Builds a footer with shortcuts appropriate to the current page hierarchy.
    fn navigation_footer(&self, action: &str) -> String {
        if self.can_go_back() {
            format!("{action}   Esc Back   Ctrl+C Cancel")
        } else {
            format!("{action}   Ctrl+C Cancel")
        }
    }

    /// Reads the next terminal event while refreshing the status spinner on timeout.
    ///
    /// Returns an [`InteractionError`] when terminal polling, reading, or rendering fails.
    fn read_event(&mut self, body: &[String], footer: &str) -> Result<Event, InteractionError> {
        if self.status.is_none() {
            return event::read().map_err(Self::terminal_error);
        }
        loop {
            if event::poll(Duration::from_millis(120)).map_err(Self::terminal_error)? {
                return event::read().map_err(Self::terminal_error);
            }
            self.feedback_frame = (self.feedback_frame + 1) % FEEDBACK_FRAMES.len();
            self.draw(body, footer)?;
        }
    }

    /// Draws the shared title, context, status bar, body, and footer shell.
    ///
    /// Returns an [`InteractionError`] when terminal sizing, rendering, or flushing fails.
    fn draw(&mut self, body: &[String], footer: &str) -> Result<(), InteractionError> {
        let (width, height) = terminal::size().map_err(Self::terminal_error)?;
        let body_width = usize::from(width.saturating_sub(8));
        let title = self.page_title();
        let breadcrumb = self.breadcrumb();
        let divider = "─".repeat(usize::from(width.max(1)));
        let mut lines = Vec::with_capacity(body.len() + 1);
        if let Some(status) = &self.status {
            lines.extend(status.split('\n').map(|line| format!("! {line}")));
        }
        for body_line in body {
            lines.extend(body_line.split('\n').map(str::to_owned));
        }

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
        let status_text = match self.status.as_deref() {
            Some(status) => format!(
                "{} {}",
                status.replace('\n', " · "),
                FEEDBACK_FRAMES[self.feedback_frame]
            ),
            None => "Ready".to_owned(),
        };
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
    ///
    /// Returns an [`InteractionError`] when terminal rendering or event reading fails.
    fn read_text(
        &mut self,
        prompt: &str,
        default: Option<&str>,
        hidden: bool,
    ) -> Result<InteractionResult<String>, InteractionError> {
        let mut value = String::new();
        loop {
            self.enter_page(prompt);
            let displayed = if hidden {
                let character_count = if value.is_empty() {
                    default.map_or(0, |default| default.chars().count())
                } else {
                    value.chars().count()
                };
                "•".repeat(character_count)
            } else if value.is_empty() {
                default
                    .map(|default| format!("[{default}]"))
                    .unwrap_or_default()
            } else {
                value.clone()
            };
            let footer = self.navigation_footer("Enter Submit");
            let body = [prompt.to_owned(), String::new(), displayed];
            self.draw(&body, &footer)?;
            match self.read_event(&body, &footer)? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if is_cancel_key(key) {
                        return Ok(self.complete(InteractionResult::Cancel));
                    }
                    match key.code {
                        KeyCode::Enter => {
                            let result = default
                                .filter(|_| value.is_empty())
                                .unwrap_or(value.as_str())
                                .to_owned();
                            return Ok(self.complete(InteractionResult::Value(result)));
                        }
                        KeyCode::Esc => {
                            return Ok(self.complete(InteractionResult::Back));
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

    /// Reads a keyboard-selected option while keeping a message on the same page.
    ///
    /// Returns an [`InteractionError`] when `options` is empty or terminal rendering/event
    /// reading fails.
    fn read_choice_page(
        &mut self,
        prompt: &str,
        message: &str,
        options: &[&str],
    ) -> Result<InteractionResult<usize>, InteractionError> {
        if options.is_empty() {
            return Err(InteractionError::new("no menu options are available"));
        }
        let mut selected = 0;
        loop {
            self.enter_page(prompt);
            let mut body: Vec<String> = if message.is_empty() {
                Vec::new()
            } else {
                message.split('\n').map(str::to_owned).collect()
            };
            if !body.is_empty() {
                body.push(String::new());
            }
            body.extend(options.iter().enumerate().map(|(index, option)| {
                if index == selected {
                    format!("› {option}")
                } else {
                    format!("  {option}")
                }
            }));
            let footer = self.navigation_footer("↑↓ Navigate   Enter Select");
            self.draw(&body, &footer)?;

            match self.read_event(&body, &footer)? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if is_cancel_key(key) {
                        return Ok(self.complete(InteractionResult::Cancel));
                    }
                    match key.code {
                        KeyCode::Enter => {
                            self.remember_selection(prompt, options, selected);
                            return Ok(self.complete(InteractionResult::Value(selected)));
                        }
                        KeyCode::Esc => {
                            return Ok(self.complete(InteractionResult::Back));
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

    /// Reads navigation for a page whose body remains visible while the user decides where to go.
    fn read_page(
        &mut self,
        prompt: &str,
        body: &[String],
    ) -> Result<InteractionResult<()>, InteractionError> {
        loop {
            self.enter_page(prompt);
            let footer = self.navigation_footer("Enter Continue");
            self.draw(body, &footer)?;

            match self.read_event(body, &footer)? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if is_cancel_key(key) {
                        return Ok(self.complete(InteractionResult::Cancel));
                    }
                    match key.code {
                        KeyCode::Enter => {
                            return Ok(self.complete(InteractionResult::Value(())));
                        }
                        KeyCode::Esc => {
                            return Ok(self.complete(InteractionResult::Back));
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

    /// Reads a hidden value while allowing Enter to retain an existing draft Value.
    fn password_with_default(
        &mut self,
        prompt: &str,
        default: &str,
    ) -> Result<InteractionResult<String>, InteractionError> {
        self.read_text(prompt, Some(default), true)
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
        self.read_choice_page(prompt, "", options)
    }

    /// Shows a masked candidate and its actions on one refreshable terminal page.
    fn choose_page(
        &mut self,
        prompt: &str,
        message: &str,
        options: &[&str],
    ) -> Result<InteractionResult<usize>, InteractionError> {
        self.read_choice_page(prompt, message, options)
    }

    /// Shows a status message in the shared shell without blocking the workflow.
    fn message(&mut self, message: &str) -> Result<(), InteractionError> {
        self.status = Some(message.to_owned());
        self.draw(&[], "")
    }

    /// Displays a complete Credential page and returns its navigation action.
    fn display(
        &mut self,
        prompt: &str,
        message: &str,
    ) -> Result<InteractionResult<()>, InteractionError> {
        self.read_page(prompt, &[message.to_owned()])
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
