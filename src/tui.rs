//! Running a command inside scudo's own terminal, beside what it was refused.
//!
//! The rest of scudo hands its work over and disappears: `runner::exec` becomes
//! `systemd-run`, and the shim inside the unit becomes the command. Nothing is
//! left to watch what happens, which is why refusals are normally reported by a
//! third process writing lines to the stderr everyone shares.
//!
//! This module is the other arrangement. scudo stays, holds the terminal, and
//! runs the command on a pty of its own — so it can draw the command's output
//! next to the list of what its sandbox turned away, and read the notification
//! stream itself rather than spawning a watcher to do it.
//!
//! Only [`config`] is compiled unconditionally: a config file naming
//! `[scudo.tui]` has to keep parsing on a build without the `tui` feature, or a
//! machine sharing its config with one that has it would be broken by the
//! omission.

mod config;

pub use config::{DEFAULT_PREFIX, DEFAULT_SCROLLBACK, TuiConfig};

#[cfg(feature = "tui")]
mod denials;
#[cfg(feature = "tui")]
mod keys;
#[cfg(feature = "tui")]
mod mouse;
#[cfg(feature = "tui")]
pub mod pty;
#[cfg(feature = "tui")]
pub mod query;
#[cfg(feature = "tui")]
pub mod state;
#[cfg(feature = "tui")]
mod theme;
#[cfg(feature = "tui")]
mod ui;

#[cfg(feature = "tui")]
pub use run::{Options, Outcome, run};

#[cfg(feature = "tui")]
pub use ui::Reporting;

#[cfg(feature = "tui")]
mod run {
    use std::{
        io::{IsTerminal as _, Read as _, Write},
        process::{Child, Command, ExitStatus},
        sync::mpsc::{self, RecvTimeoutError, Sender},
        time::{Duration, Instant},
    };

    use anyhow::{Context as _, Result, bail};
    use ratatui::crossterm::{
        event::{
            DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
            Event as TermEvent, KeyCode, KeyEvent, KeyModifiers, MouseEvent,
        },
        execute,
    };
    use tracing::{debug, warn};
    use vt100::MouseProtocolMode;

    use super::{
        config::TuiConfig,
        denials::{Denials, Filter, Kind},
        keys::{self, KeySpec},
        mouse, pty, query,
        theme::Theme,
        ui::{self, Focus, Mode, Reporting, View},
    };
    use crate::bpfd::{client, protocol::Notification};

    /// Ask the terminal for something we can carry on without.
    ///
    /// Every one of these is a mode the host terminal may simply not have. The
    /// UI is still usable without bracketed paste or a captured mouse, so a
    /// refusal is worth a note and never worth stopping for.
    fn best_effort(what: &str, result: std::io::Result<()>) {
        if let Err(err) = result {
            debug!("the terminal would not {what}: {err}");
        }
    }

    /// The shortest gap between two frames. A command that writes without
    /// pausing — `yes`, a build log — would otherwise have us redraw per read,
    /// which costs far more than the frames anyone can see.
    const FRAME: Duration = Duration::from_millis(16);

    /// How much of the pty is taken in one read.
    const READ_CHUNK: usize = 8192;

    /// How far one press moves the panel.
    const PANEL_STEP: u16 = 1;

    /// What the UI needs to know that it cannot work out for itself.
    #[derive(Debug)]
    pub struct Options<'a> {
        /// The command's name, for titles and for the closing summary.
        pub command: &'a str,
        /// What `--verbose` would have said: which profiles matched, and the
        /// command line that was run. Shown in the context area rather than
        /// printed over the command's own output.
        pub context: Vec<String>,
        /// The sandbox to follow, when there is one.
        pub token: Option<String>,
        pub reporting: Reporting,
        pub config: TuiConfig,
        /// The panel width remembered from a previous run, if any.
        pub panel_width: Option<u16>,
    }

    /// Which way the panel's edge moves.
    #[derive(Debug, Clone, Copy)]
    enum Direction {
        Wider,
        Narrower,
    }
    use Direction::{Narrower, Wider};

    /// Everything that can wake the loop.
    enum Event {
        /// Bytes the command wrote.
        Pty(Vec<u8>),
        /// The command's terminal reached its end, which happens as it exits.
        PtyClosed,
        /// Something the person watching did.
        Input(TermEvent),
        Denial(Notification),
        /// The daemon closed the notification stream: the sandbox is gone.
        DenialsClosed,
        /// The broker started, refused or finished a delegated command.
        Delegation(crate::broker::Event),
        Exited(ExitStatus),
    }

    /// How many lines about delegated commands the context area keeps: the
    /// latest are what is worth reading, and every line kept takes a row from
    /// the command's terminal while the area is open.
    const DELEGATION_LINES: usize = 6;

    /// How the run ended.
    #[derive(Debug)]
    pub struct Outcome {
        /// What the command exited with, for scudo to exit with in turn.
        pub code: i32,
        /// The closing line about what was blocked, when there was a sandbox to
        /// report on. Returned rather than printed: it belongs in the terminal
        /// the person keeps, and only the caller knows when the logging that
        /// writes there has been put back.
        pub summary: Option<String>,
        /// The panel width as it was left, to remember for next time. `None`
        /// means it was following the screen, which is worth recording too.
        pub panel_width: Option<u16>,
    }

    /// Run `cmd` in the terminal UI, returning what it exited with.
    ///
    /// With `broker`, the sandbox's delegation requests are served from a
    /// thread of this process, and what it does is shown in the context area.
    pub fn run(
        mut cmd: Command,
        options: &Options<'_>,
        broker: Option<crate::broker::Setup>,
    ) -> Result<Outcome> {
        // Checked before anything is torn down or started: failing here has to
        // leave the person exactly where they were.
        if !std::io::stdout().is_terminal() {
            bail!("--tui needs a terminal to draw on; stdout is not one");
        }
        let prefix = keys::parse_key_spec(options.config.prefix())
            .context("reading the terminal UI prefix key")?;

        let mut terminal = ratatui::try_init().context("taking over the terminal")?;
        // From here on the terminal is ours, and every path out of this function
        // has to give it back — hence the single call site below rather than a
        // `?` on each step.
        let result = session(&mut terminal, &mut cmd, options, prefix, broker);
        ratatui::restore();
        best_effort(
            "give back the modes it was put in",
            execute!(
                std::io::stdout(),
                DisableBracketedPaste,
                DisableMouseCapture
            ),
        );

        let (code, summary, panel_width) = result?;
        Ok(Outcome {
            code,
            summary,
            panel_width,
        })
    }

    /// The body of [`run`], with the terminal already ours.
    fn session(
        terminal: &mut ratatui::DefaultTerminal,
        cmd: &mut Command,
        options: &Options<'_>,
        prefix: KeySpec,
        broker: Option<crate::broker::Setup>,
    ) -> Result<(i32, Option<String>, Option<u16>)> {
        best_effort(
            "take pastes as pastes",
            execute!(std::io::stdout(), EnableBracketedPaste),
        );

        // Before the screen is ours to draw on but after raw mode is, which is
        // what lets the answer be read at all: in cooked mode it would sit in
        // the line discipline waiting for a newline nobody is going to send.
        let host = query::Host::ask();

        let mut app = App::new(options, prefix, host);
        let area = terminal.size().context("measuring the terminal")?;
        let area = ratatui::layout::Rect {
            x: 0,
            y: 0,
            width: area.width,
            height: area.height,
        };
        app.screen_width = area.width;
        app.screen_height = area.height;
        let (rows, cols) =
            ui::terminal_size(area, app.panel_width, app.show_panel, app.context_lines());

        let mut pty = pty::open(rows, cols)?;
        let mut parser = vt100::Parser::new(rows, cols, options.config.scrollback());
        // Standard input is the command's whenever it is not the terminal:
        // something was piped in, and it was meant for the command, exactly as
        // it would have been without the UI in the way. Only a terminal on fd 0
        // is scudo's own, and then the command is given the pty instead.
        let input = if std::io::stdin().is_terminal() {
            pty::Input::Terminal
        } else {
            pty::Input::Given
        };
        let child = pty.spawn(cmd, input)?;
        let pid = i32::try_from(child.id()).unwrap_or(-1i32);
        let mut writer = pty.writer()?;

        let (tx, rx) = mpsc::channel();
        start_reader(pty.reader()?, tx.clone());
        start_input(tx.clone());
        start_waiter(child, tx.clone());
        if let Some(token) = options.token.clone() {
            start_watcher(token, tx.clone());
        }
        let broker = match broker {
            Some(setup) => {
                let tx = tx.clone();
                let sink = Box::new(move |event| drop(tx.send(Event::Delegation(event))));
                Some(setup.start_thread(sink)?)
            }
            None => None,
        };

        let mut dirty = true;
        let mut last_drawn = Instant::now()
            .checked_sub(FRAME)
            .unwrap_or_else(Instant::now);

        while !app.leaving {
            match rx.recv_timeout(FRAME) {
                Ok(event) => {
                    app.handle(event, &mut parser, &mut writer, pid);
                    dirty = true;
                }
                Err(RecvTimeoutError::Timeout) => {}
                // Every producer is gone; there is nothing left that could
                // change what is on the screen.
                Err(RecvTimeoutError::Disconnected) => break,
            }
            // Whatever else arrived while we were busy: draining first means one
            // frame for a burst of output rather than one frame per read.
            while let Ok(event) = rx.try_recv() {
                app.handle(event, &mut parser, &mut writer, pid);
            }

            app.follow_mouse_mode(parser.screen());
            app.resize(terminal, &pty, &mut parser)?;

            if dirty && last_drawn.elapsed() >= FRAME {
                terminal.draw(|frame| app.draw(frame, parser.screen()))?;
                dirty = false;
                last_drawn = Instant::now();
            }
        }
        // One last frame, so what the command printed as it exited is on screen
        // when the terminal is handed back.
        terminal.draw(|frame| app.draw(frame, parser.screen()))?;
        // Stopping it stops whatever it still runs: the sandbox those were
        // started for is gone.
        if let Some(broker) = broker {
            broker.shutdown();
        }

        let summary = matches!(options.reporting, Reporting::Watching)
            .then(|| app.denials.summary_line(options.command));
        Ok((app.code, summary, app.panel_width))
    }

    /// The state the loop keeps between events.
    #[expect(
        clippy::struct_excessive_bools,
        reason = "each is a switch the person flipped, and they are independent"
    )]
    struct App {
        denials: Denials,
        command: String,
        context: Vec<String>,
        /// How many lines of `context` were there from the start; the ones
        /// after are about delegated commands, and only the latest are kept.
        base_context: usize,
        reporting: Reporting,
        prefix: KeySpec,
        prefix_label: String,
        mode: Mode,
        focus: Focus,
        show_panel: bool,
        show_context: bool,
        /// `None` while the width follows the screen; `Some` once it was set.
        panel_width: Option<u16>,
        panel_scroll: u16,
        /// How far back from its newest line the running list has been moved.
        history_scroll: usize,
        scrollback: usize,
        max_scrollback: usize,
        /// The filter as it was before the field was opened, kept so that Esc
        /// can put it back. `None` whenever the field is not open, which is what
        /// makes leaving it by any other route keep what was typed.
        filter_saved: Option<Filter>,
        /// Set once the command has exited. The UI stays up, and stays usable:
        /// only the keys that were bytes for the command change meaning.
        finished: Option<i32>,
        /// What scudo itself will exit with.
        code: i32,
        leaving: bool,
        mouse_captured: bool,
        /// The size the pty was last told about, so a redraw that changed
        /// nothing does not resize it again.
        size: (u16, u16),
        /// The size of the whole screen, which is what a panel width has to be
        /// judged against and what the panel's lists are scrolled within. Kept
        /// because those keys need it and the terminal is not theirs to ask.
        screen_width: u16,
        screen_height: u16,
        /// What the host terminal said about its colours, ready to be repeated
        /// to a command that asks scudo the same.
        host: query::Host,
        /// Scans the command's output for questions and answers them.
        answerer: query::Answerer,
        /// The colours everything but the command's terminal is drawn in.
        theme: Theme,
    }

    impl App {
        fn new(options: &Options<'_>, prefix: KeySpec, host: query::Host) -> Self {
            App {
                base_context: options.context.len(),
                denials: Denials::default(),
                command: options.command.to_owned(),
                context: options.context.clone(),
                reporting: options.reporting,
                prefix,
                prefix_label: prefix.label(),
                mode: Mode::Normal,
                focus: Focus::Terminal,
                show_panel: true,
                // Off by default: it is diagnostic, and the terminal is what the
                // person came for. `^A s` brings it up.
                show_context: false,
                panel_width: options.panel_width,
                panel_scroll: 0,
                history_scroll: 0,
                scrollback: 0,
                max_scrollback: options.config.scrollback(),
                filter_saved: None,
                finished: None,
                code: 0,
                leaving: false,
                mouse_captured: false,
                size: (0, 0),
                screen_width: 0,
                screen_height: 0,
                host,
                answerer: query::Answerer::default(),
                theme: Theme::detect(),
            }
        }

        fn context_lines(&self) -> u16 {
            if self.show_context {
                u16::try_from(self.context.len()).unwrap_or(u16::MAX)
            } else {
                0
            }
        }

        fn draw(&self, frame: &mut ratatui::Frame<'_>, screen: &vt100::Screen) {
            let view = View {
                screen,
                denials: &self.denials,
                command: &self.command,
                focus: self.focus,
                mode: self.mode,
                prefix_label: &self.prefix_label,
                context: &self.context,
                show_context: self.show_context,
                show_panel: self.show_panel,
                panel_width: self.panel_width,
                panel_scroll: self.panel_scroll,
                history_scroll: self.history_scroll,
                scrollback: self.scrollback,
                reporting: self.reporting,
                finished: self.finished,
                theme: &self.theme,
            };
            ui::draw(frame, &view);
        }

        fn handle(
            &mut self,
            event: Event,
            parser: &mut vt100::Parser,
            writer: &mut impl Write,
            pid: i32,
        ) {
            match event {
                Event::Pty(bytes) => {
                    parser.process(&bytes);
                    // Answered as soon as the bytes arrive rather than at the
                    // next frame: the program that asked is waiting on the
                    // answer, not on anything being drawn.
                    self.answerer.answer(&bytes, &self.host, parser, writer);
                }
                // The command's terminal is gone, but its exit status may not
                // have been reaped yet; leaving is driven by `Exited` alone.
                Event::PtyClosed => {}
                Event::Input(input) => self.input(input, parser, writer, pid),
                Event::Denial(notification) => self.denials.push(&notification, &self.command),
                Event::DenialsClosed => self.denials.close(),
                Event::Delegation(event) => self.delegation(&event),
                Event::Exited(status) => self.exited(status),
            }
        }

        /// Note what the broker did in the context area, keeping the latest few.
        fn delegation(&mut self, event: &crate::broker::Event) {
            let prefix = if event.is_refusal() {
                "refused"
            } else {
                "broker"
            };
            self.context.push(format!("{prefix}: {event}"));
            let delegated = self.context.len().saturating_sub(self.base_context);
            if delegated > DELEGATION_LINES {
                self.context.remove(self.base_context);
            }
        }

        fn exited(&mut self, status: ExitStatus) {
            use std::os::unix::process::ExitStatusExt as _;
            // A command killed by a signal has no code of its own; the shell
            // convention is what everything downstream of scudo expects.
            let code = status
                .code()
                .unwrap_or_else(|| status.signal().unwrap_or(0i32).saturating_add(128i32));
            self.code = code;
            self.finished = Some(code);
            // Everything the UI was in the middle of still means what it meant —
            // reading the scrollback of a command that has finished is exactly
            // what someone would want. Only the question of whether to stop it
            // has stopped having an answer.
            if self.mode == Mode::Confirm {
                self.mode = Mode::Normal;
            }
        }

        fn input(
            &mut self,
            input: TermEvent,
            parser: &mut vt100::Parser,
            writer: &mut impl Write,
            pid: i32,
        ) {
            match input {
                TermEvent::Key(key) => self.key(key, parser, writer, pid),
                TermEvent::Mouse(event) => self.mouse(event, parser, writer),
                TermEvent::Paste(text) => {
                    // Nothing is reading the other end of it any more.
                    if self.finished.is_none() {
                        let bytes = keys::encode_paste(&text, parser.screen().bracketed_paste());
                        self.write(writer, &bytes);
                    }
                }
                // Handled by comparing sizes each pass, so a resize that arrives
                // as several events costs one resize rather than several.
                TermEvent::Resize(..) | TermEvent::FocusGained | TermEvent::FocusLost => {}
            }
        }

        fn key(
            &mut self,
            key: KeyEvent,
            parser: &mut vt100::Parser,
            writer: &mut impl Write,
            pid: i32,
        ) {
            match self.mode {
                Mode::Confirm => self.confirm(key, pid),
                Mode::Help => self.mode = Mode::Normal,
                Mode::Prefix => self.command_key(key, parser, writer),
                Mode::Resize => self.resize_key(key),
                Mode::Filter => self.filter_key(key),
                Mode::Scroll => self.scroll_key(key, parser),
                Mode::Normal => {
                    if self.prefix.matches(&key) {
                        self.mode = Mode::Prefix;
                        return;
                    }
                    if self.focus.in_panel() && self.panel_key(key) {
                        return;
                    }
                    // The command is over, so there is nobody on the other end
                    // of the keyboard: the keys that were bytes for it become
                    // the UI's own, and reading what it left is what is left.
                    if self.finished.is_some() {
                        self.review_key(key, parser);
                        return;
                    }
                    if let Some(bytes) = keys::encode(&key, parser.screen().application_cursor()) {
                        // Typing is what ends a look at the scrollback, the same
                        // way it does in a terminal that has one.
                        self.reset_scrollback(parser);
                        self.write(writer, &bytes);
                    }
                }
            }
        }

        /// A key with the command finished and no mode in the way.
        ///
        /// Deliberately the same keys the scroll mode uses rather than a set of
        /// its own: what the UI is doing here *is* reading the scrollback, and
        /// having to ask for a mode first to do the only thing left to do would
        /// be a step for nothing.
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "a key with nothing on it does nothing, whatever key it is"
        )]
        fn review_key(&mut self, key: KeyEvent, parser: &mut vt100::Parser) {
            if self.scroll_move(key, parser) {
                return;
            }
            match key.code {
                KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.leaving = true;
                }
                KeyCode::Esc | KeyCode::Char('q') => self.leaving = true,
                KeyCode::Tab => self.cycle_focus(),
                KeyCode::Char('?') => self.mode = Mode::Help,
                _ => {}
            }
        }

        /// Move the keyboard on to the next of the three places it can be.
        /// With the panel hidden there is only the one, and Tab is a key that
        /// does nothing rather than one that focuses what is not on screen.
        fn cycle_focus(&mut self) {
            if self.show_panel {
                self.focus = self.focus.next();
            }
        }

        /// A key after the prefix. Anything unrecognised simply ends the state,
        /// rather than being passed on as if the prefix had not been pressed.
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "a key with no command on it does nothing, whatever key it is"
        )]
        fn command_key(
            &mut self,
            key: KeyEvent,
            parser: &mut vt100::Parser,
            writer: &mut impl Write,
        ) {
            self.mode = Mode::Normal;

            // The prefix twice over sends it to the command, which is the only
            // way to type it at all.
            if self.prefix.matches(&key) {
                let bytes = self
                    .prefix
                    .passthrough(parser.screen().application_cursor());
                self.write(writer, &bytes);
                return;
            }

            match key.code {
                KeyCode::Char('q') => {
                    if self.finished.is_some() {
                        // There is nothing left to stop, so the question would
                        // have only one honest answer.
                        self.leaving = true;
                    } else {
                        // Nothing is killed without being asked about: the
                        // command may be a shell with unsaved work in it.
                        self.mode = Mode::Confirm;
                    }
                }
                KeyCode::Tab => self.cycle_focus(),
                KeyCode::PageUp => self.mode = Mode::Scroll,
                KeyCode::Char('r') => {
                    // Nothing to set while the panel is not on screen.
                    if self.show_panel {
                        self.mode = Mode::Resize;
                    }
                }
                KeyCode::Char('w') => {
                    self.show_panel = !self.show_panel;
                    if !self.show_panel {
                        self.focus = Focus::Terminal;
                    }
                }
                KeyCode::Char('s') => self.show_context = !self.show_context,
                // What the sandbox hid is the point of the panel; what was
                // never there outside it is context, and only on request.
                KeyCode::Char('m') => self.denials.toggle_missing(),
                // A slash for what to keep and a backslash for what to throw
                // away, so which one was pressed is the answer to a question the
                // field would otherwise have to ask.
                KeyCode::Char('/') => self.open_filter(false),
                KeyCode::Char('\\') => self.open_filter(true),
                KeyCode::Char('n') => self.toggle_kind(Kind::Network),
                KeyCode::Char('f') => self.toggle_kind(Kind::File),
                KeyCode::Char('?') => self.mode = Mode::Help,
                _ => {}
            }
        }

        /// Open the pattern field, keeping what it can be put back to.
        ///
        /// The pattern already in force is left alone rather than cleared: the
        /// usual reason to press the key twice is to add to what is there, and a
        /// field that emptied itself would make the second press cost the first.
        fn open_filter(&mut self, exclude: bool) {
            self.filter_saved = Some(self.denials.filter().clone());
            self.denials.filter_mut().set_exclude(exclude);
            self.mode = Mode::Filter;
            self.filter_changed();
        }

        fn toggle_kind(&mut self, kind: Kind) {
            self.denials.filter_mut().toggle_kind(kind);
            self.filter_changed();
        }

        /// Put both lists back to where they read from.
        ///
        /// Their offsets are clamped against how much there is to show, and a
        /// filter changes that under them: without this, narrowing a long list
        /// leaves the view somewhere past the end of the short one it became.
        fn filter_changed(&mut self) {
            self.panel_scroll = 0;
            self.history_scroll = 0;
        }

        /// A key in the pattern field.
        ///
        /// Everything typed is the pattern's, which is the one place in the UI
        /// where an ordinary character does not reach the command — the field is
        /// on screen and says so, and Enter or Esc is one key away.
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "a key with nothing to type on it leaves the pattern alone"
        )]
        fn filter_key(&mut self, key: KeyEvent) {
            match key.code {
                // Kept: leaving the field is not the same as undoing it.
                KeyCode::Enter => {
                    self.filter_saved = None;
                    self.mode = Mode::Normal;
                }
                KeyCode::Esc => {
                    if let Some(filter) = self.filter_saved.take() {
                        self.denials.set_filter(filter);
                    }
                    self.mode = Mode::Normal;
                    self.filter_changed();
                }
                KeyCode::Tab => {
                    self.denials.filter_mut().toggle_exclude();
                    self.filter_changed();
                }
                KeyCode::Backspace => {
                    self.denials.filter_mut().pop_char();
                    self.filter_changed();
                }
                // The line-editing key every terminal has, for a pattern that
                // went wrong early enough not to be worth backspacing over.
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.denials.filter_mut().clear_pattern();
                    self.filter_changed();
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.denials.filter_mut().push_char(c);
                    self.filter_changed();
                }
                _ => {}
            }
        }

        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "anything that is not yes is no"
        )]
        fn confirm(&mut self, key: KeyEvent, pid: i32) {
            match key.code {
                KeyCode::Char('y' | 'Y') => {
                    self.stop(pid);
                    self.mode = Mode::Normal;
                }
                _ => self.mode = Mode::Normal,
            }
        }

        /// Ask the command to stop, and stop waiting for it.
        ///
        /// The signal goes to the whole group rather than to the one process:
        /// what was started is `systemd-run`, and killing only that would leave
        /// the unit running with nothing attached to its terminal.
        fn stop(&mut self, pid: i32) {
            if pid > 0i32 {
                // SAFETY: a signal to a process group we started, with a signal
                // number the kernel defines and no memory of ours involved.
                unsafe {
                    libc::kill(pid.saturating_neg(), libc::SIGTERM);
                }
            }
            // `Exited` will follow and set the real code; leaving is deferred to
            // it so the command's last output still reaches the screen.
            // Nothing was signalled, so no `Exited` is coming to end the loop.
            self.leaving = pid <= 0i32;
        }

        /// Move the panel's edge, and in doing so take the width off automatic.
        ///
        /// It starts from the width currently on screen rather than from
        /// nothing, so the first press nudges what is being looked at instead of
        /// making the panel jump somewhere else.
        fn nudge_panel(&mut self, direction: Direction, by: u16) {
            let current = ui::panel_width(self.screen_width, self.panel_width);
            let width = match direction {
                Wider => current.saturating_add(by),
                Narrower => current.saturating_sub(by),
            };
            self.panel_width = Some(ui::panel_width(self.screen_width, Some(width)));
        }

        /// A key in the resize mode. The width the pty is told about follows on
        /// the next pass through the loop, where `resize` notices the change.
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "keys that do not move the edge leave it where it is"
        )]
        fn resize_key(&mut self, key: KeyEvent) {
            /// One press of an arrow.
            const STEP: u16 = 1;
            /// One press of the faster pair.
            const LEAP: u16 = 5;

            // The keys move the *edge*, which is what is being looked at, so
            // left widens the panel on the right of it and right narrows it.
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.mode = Mode::Normal,
                KeyCode::Left => self.nudge_panel(Wider, STEP),
                KeyCode::Right => self.nudge_panel(Narrower, STEP),
                // Lower case on purpose: a shift held down to resize a panel is
                // a toll paid on every press.
                KeyCode::Char('h') => self.nudge_panel(Wider, LEAP),
                KeyCode::Char('l') => self.nudge_panel(Narrower, LEAP),
                // Back to following the screen. Recorded as an absence rather
                // than as a number, or the choice could never be undone.
                KeyCode::Char('=' | '0') => self.panel_width = None,
                _ => {}
            }
        }

        /// The keys that move the view over the scrollback, and whether the key
        /// was one of them. Shared, so the scroll mode and the state a finished
        /// command leaves the UI in cannot drift into two sets of keys.
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "keys that do not move the view leave it where it is"
        )]
        fn scroll_move(&mut self, key: KeyEvent, parser: &mut vt100::Parser) -> bool {
            let page = usize::from(parser.screen().size().0).max(1usize);
            match key.code {
                KeyCode::Up => self.set_scrollback(parser, self.scrollback.saturating_add(1)),
                KeyCode::Down => self.set_scrollback(parser, self.scrollback.saturating_sub(1)),
                KeyCode::PageUp => {
                    self.set_scrollback(parser, self.scrollback.saturating_add(page));
                }
                KeyCode::PageDown => {
                    self.set_scrollback(parser, self.scrollback.saturating_sub(page));
                }
                KeyCode::Home => self.set_scrollback(parser, self.max_scrollback),
                KeyCode::End => self.set_scrollback(parser, 0usize),
                _ => return false,
            }
            true
        }

        fn scroll_key(&mut self, key: KeyEvent, parser: &mut vt100::Parser) {
            if self.scroll_move(key, parser) {
                return;
            }
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                self.reset_scrollback(parser);
                self.mode = Mode::Normal;
            }
        }

        /// How many rows each of the panel's two lists has to draw in, or
        /// nothing at all when there is no panel — hidden, or dropped because
        /// the window went too narrow to leave the terminal its floor. The keys
        /// then go back to the command rather than moving a view nobody can see.
        fn panel_heights(&self) -> Option<(u16, u16)> {
            let area = ratatui::layout::Rect {
                x: 0,
                y: 0,
                width: self.screen_width,
                height: self.screen_height,
            };
            let regions = ui::regions(
                area,
                self.panel_width,
                self.show_panel,
                self.context_lines(),
            );
            // The bodies, not the sections: a heading is drawn above its list
            // and does not move with it, so it is not room the keys may use.
            regions.panel.map(|panel| {
                let (blocked, recent) = ui::panel_split(panel);
                (
                    ui::section_body(blocked).height,
                    ui::section_body(recent).height,
                )
            })
        }

        /// Navigation keys move whichever list has the focus; everything else
        /// still reaches the command, so focus never silently swallows what was
        /// typed.
        fn panel_key(&mut self, key: KeyEvent) -> bool {
            let Some((blocked, recent)) = self.panel_heights() else {
                return false;
            };
            match self.focus {
                Focus::Terminal => false,
                Focus::Blocked => self.blocked_key(key, blocked),
                Focus::Recent => self.recent_key(key, recent),
            }
        }

        /// The tally is read from the top down — most recently refused first —
        /// so its offset is how far down the list the view has moved.
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "anything that does not move the list is for the command"
        )]
        fn blocked_key(&mut self, key: KeyEvent, height: u16) -> bool {
            let room = usize::from(height);
            // Past this the view would be showing the space under the last line
            // rather than the list, which is a place with nothing to read in it.
            let furthest = ui::targets_lines(&self.denials).saturating_sub(room);
            let page = room.max(1usize);
            let at = usize::from(self.panel_scroll);
            let to = match key.code {
                KeyCode::Up => at.saturating_sub(usize::from(PANEL_STEP)),
                KeyCode::Down => at.saturating_add(usize::from(PANEL_STEP)),
                KeyCode::PageUp => at.saturating_sub(page),
                KeyCode::PageDown => at.saturating_add(page),
                KeyCode::Home => 0usize,
                KeyCode::End => furthest,
                _ => return false,
            };
            self.panel_scroll = u16::try_from(to.min(furthest)).unwrap_or(u16::MAX);
            true
        }

        /// The log is pinned to its newest line, so its offset counts backwards
        /// from there — the same way the terminal's scrollback does. Up moves
        /// the view up either list; that the numbers run opposite ways is what
        /// makes the key do the same thing in both.
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "anything that does not move the list is for the command"
        )]
        fn recent_key(&mut self, key: KeyEvent, height: u16) -> bool {
            let room = usize::from(height);
            let furthest = self.denials.recent().count().saturating_sub(room);
            let page = room.max(1usize);
            let at = self.history_scroll;
            let to = match key.code {
                KeyCode::Up => at.saturating_add(usize::from(PANEL_STEP)),
                KeyCode::Down => at.saturating_sub(usize::from(PANEL_STEP)),
                KeyCode::PageUp => at.saturating_add(page),
                KeyCode::PageDown => at.saturating_sub(page),
                KeyCode::Home => furthest,
                KeyCode::End => 0usize,
                _ => return false,
            };
            self.history_scroll = to.min(furthest);
            true
        }

        fn mouse(
            &mut self,
            event: MouseEvent,
            parser: &mut vt100::Parser,
            writer: &mut impl Write,
        ) {
            // Nothing is reading the other end of it any more.
            if self.finished.is_some() {
                return;
            }
            let screen = parser.screen();
            let mode = screen.mouse_protocol_mode();
            let (rows, cols) = screen.size();
            // The terminal panel starts at the top left, so a column past its
            // width is the side panel and none of the command's business.
            if event.column < cols
                && event.row < rows
                && let Some(bytes) = mouse::encode(
                    event,
                    mode,
                    screen.mouse_protocol_encoding(),
                    event.column,
                    event.row,
                )
            {
                self.write(writer, &bytes);
            }
        }

        fn set_scrollback(&mut self, parser: &mut vt100::Parser, lines: usize) {
            let screen = parser.screen_mut();
            screen.set_scrollback(lines.min(self.max_scrollback));
            // Read back rather than remembered: the emulator clamps to the
            // scrollback there actually is, and a Home that left us thinking we
            // were ten thousand lines up a screen with thirty would take a
            // hundred presses to come back down from.
            self.scrollback = screen.scrollback();
        }

        fn reset_scrollback(&mut self, parser: &mut vt100::Parser) {
            if self.scrollback > 0 {
                self.set_scrollback(parser, 0);
            }
        }

        #[expect(
            clippy::unused_self,
            reason = "the app is what writes to the command; the state it needs may grow"
        )]
        fn write(&mut self, writer: &mut impl Write, bytes: &[u8]) {
            if let Err(err) = writer.write_all(bytes).and_then(|()| writer.flush()) {
                // The command is gone or going; there is nowhere to put this and
                // nothing useful to do about it.
                debug!("cannot write to the command's terminal: {err}");
            }
        }

        /// Take the mouse only while the program inside wants it — see the note
        /// in [`super::mouse`] on why this is not simply held throughout.
        fn follow_mouse_mode(&mut self, screen: &vt100::Screen) {
            let wanted = screen.mouse_protocol_mode() != MouseProtocolMode::None;
            if wanted == self.mouse_captured {
                return;
            }
            let result = if wanted {
                execute!(std::io::stdout(), EnableMouseCapture)
            } else {
                execute!(std::io::stdout(), DisableMouseCapture)
            };
            match result {
                Ok(()) => self.mouse_captured = wanted,
                Err(err) => debug!("the terminal would not hand over the mouse: {err}"),
            }
        }

        /// Keep the command's terminal the size of the panel it is drawn in.
        fn resize(
            &mut self,
            terminal: &ratatui::DefaultTerminal,
            pty: &pty::Pty,
            parser: &mut vt100::Parser,
        ) -> Result<()> {
            let area = terminal.size().context("measuring the terminal")?;
            let area = ratatui::layout::Rect {
                x: 0,
                y: 0,
                width: area.width,
                height: area.height,
            };
            self.screen_width = area.width;
            self.screen_height = area.height;
            let size = ui::terminal_size(
                area,
                self.panel_width,
                self.show_panel,
                self.context_lines(),
            );
            if size == self.size {
                return Ok(());
            }
            self.size = size;
            let (rows, cols) = size;
            parser.screen_mut().set_size(rows, cols);
            pty.resize(rows, cols)?;
            Ok(())
        }
    }

    /// Read what the command writes, until its terminal is closed.
    fn start_reader(mut reader: std::fs::File, tx: Sender<Event>) {
        std::thread::spawn(move || {
            let mut buf = vec![0u8; READ_CHUNK];
            loop {
                match reader.read(&mut buf) {
                    // Linux reports the last close of the slave as EIO rather
                    // than as end of file; both mean the same thing here.
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let chunk = buf.get(..n).unwrap_or_default().to_vec();
                        if tx.send(Event::Pty(chunk)).is_err() {
                            return;
                        }
                    }
                }
            }
            drop(tx.send(Event::PtyClosed));
        });
    }

    fn start_input(tx: Sender<Event>) {
        std::thread::spawn(move || {
            while let Ok(event) = ratatui::crossterm::event::read() {
                if tx.send(Event::Input(event)).is_err() {
                    return;
                }
            }
        });
    }

    fn start_waiter(mut child: Child, tx: Sender<Event>) {
        std::thread::spawn(move || {
            if let Ok(status) = child.wait() {
                drop(tx.send(Event::Exited(status)));
            }
        });
    }

    /// Follow the sandbox's notifications, in this process rather than in a
    /// watcher of its own: scudo is still here, and the panel is where they go.
    fn start_watcher(token: String, tx: Sender<Event>) {
        std::thread::spawn(move || {
            let mut reader = match client::watch(&token) {
                Ok(reader) => reader,
                Err(err) => {
                    warn!("cannot report blocked network accesses: {err}");
                    drop(tx.send(Event::DenialsClosed));
                    return;
                }
            };
            while let Ok(Some(event)) = reader.read::<Notification>() {
                if tx.send(Event::Denial(event)).is_err() {
                    return;
                }
            }
            drop(tx.send(Event::DenialsClosed));
        });
    }

    #[cfg(test)]
    #[expect(
        clippy::default_numeric_fallback,
        reason = "counts and sizes, spelled the way the assertions read best"
    )]
    mod tests {
        use ratatui::crossterm::event::{KeyEventKind, KeyEventState};

        use super::*;
        use crate::bpfd::protocol::{FileError, FileOp, Outside};

        /// The context area keeps the latest few delegations, and never at the
        /// expense of what it was opened with.
        #[test]
        fn only_the_latest_delegations_are_kept() {
            let mut app = app(120, 40);
            app.context
                .push("profile 'agent' matched 'claude'".to_owned());
            app.base_context = 1;
            for n in 0..10 {
                app.delegation(&crate::broker::Event::NotDelegated {
                    command: format!("cmd{n}"),
                });
            }
            assert_eq!(app.context.len(), 1 + DELEGATION_LINES);
            assert_eq!(
                app.context.first().map(String::as_str),
                Some("profile 'agent' matched 'claude'")
            );
            assert!(app.context.last().unwrap().contains("cmd9"));
            app.delegation(&crate::broker::Event::Refused {
                command: "make".to_owned(),
                reason: "outside".to_owned(),
            });
            assert!(app.context.last().unwrap().starts_with("refused: "));
        }

        fn app(width: u16, height: u16) -> App {
            let options = Options {
                command: "bash",
                context: Vec::new(),
                token: None,
                reporting: Reporting::Watching,
                config: TuiConfig::default(),
                panel_width: Some(34),
            };
            let prefix = keys::parse_key_spec("C-a").expect("a prefix");
            let mut app = App::new(&options, prefix, query::Host::default());
            app.screen_width = width;
            app.screen_height = height;
            app
        }

        fn press(code: KeyCode) -> KeyEvent {
            KeyEvent {
                code,
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Press,
                state: KeyEventState::NONE,
            }
        }

        /// The default prefix, as the terminal would deliver it.
        fn prefix() -> KeyEvent {
            KeyEvent {
                code: KeyCode::Char('a'),
                modifiers: KeyModifiers::CONTROL,
                kind: KeyEventKind::Press,
                state: KeyEventState::NONE,
            }
        }

        fn refused(path: &str) -> Notification {
            Notification::FileBlocked {
                op: FileOp::Open,
                path: path.to_owned(),
                error: FileError::Permission,
                outside: Outside::Present,
            }
        }

        fn with_refusals(app: &mut App, how_many: usize) {
            for i in 0..how_many {
                app.denials.push(&refused(&format!("/nowhere/{i}")), "bash");
            }
        }

        /// The bug this pins: the offset simply grew, so a held-down arrow
        /// scrolled the tally into the empty space under its last line, with no
        /// way back but Home.
        #[test]
        fn the_blocked_list_stops_at_its_last_line() {
            let mut app = app(120, 40);
            with_refusals(&mut app, 60);
            let (height, _) = app.panel_heights().expect("a panel fits at this width");
            assert!(height > 0);

            for _ in 0..500 {
                assert!(app.blocked_key(press(KeyCode::Down), height));
            }
            let furthest = ui::targets_lines(&app.denials) - usize::from(height);
            assert_eq!(usize::from(app.panel_scroll), furthest);
            assert!(furthest > 0, "the list should be taller than the panel");

            app.blocked_key(press(KeyCode::Home), height);
            assert_eq!(app.panel_scroll, 0);
            // And Up stops at the top rather than wrapping round it.
            app.blocked_key(press(KeyCode::Up), height);
            assert_eq!(app.panel_scroll, 0);
        }

        /// The log is pinned to its newest line, so its offset counts back from
        /// there: Up goes into the past, End returns to the present.
        #[test]
        fn the_recent_list_scrolls_back_from_its_newest_line() {
            let mut app = app(120, 40);
            with_refusals(&mut app, 60);
            let (_, height) = app.panel_heights().expect("a panel fits at this width");
            let room = usize::from(height);

            assert_eq!(app.history_scroll, 0);
            for _ in 0..500 {
                assert!(app.recent_key(press(KeyCode::Up), height));
            }
            assert_eq!(app.history_scroll, 60 - room);

            app.recent_key(press(KeyCode::End), height);
            assert_eq!(app.history_scroll, 0);
            app.recent_key(press(KeyCode::Down), height);
            assert_eq!(app.history_scroll, 0);
        }

        /// With no panel on screen there is nothing for those keys to move, and
        /// Tab has nowhere to take the keyboard. The keys go back to being the
        /// command's rather than being swallowed by a list nobody can see.
        #[test]
        fn a_hidden_panel_takes_no_keys() {
            let mut hidden = app(120, 40);
            hidden.show_panel = false;
            assert_eq!(hidden.panel_heights(), None);
            hidden.cycle_focus();
            assert_eq!(hidden.focus, Focus::Terminal);

            // And the same when it is the window that is too narrow for one:
            // the focus outlives the panel, so the keys have to check.
            let mut narrow = app(50, 20);
            narrow.focus = Focus::Blocked;
            assert_eq!(narrow.panel_heights(), None);
            assert!(!narrow.panel_key(press(KeyCode::Down)));
        }

        fn ctrl(code: KeyCode) -> KeyEvent {
            KeyEvent {
                code,
                modifiers: KeyModifiers::CONTROL,
                kind: KeyEventKind::Press,
                state: KeyEventState::NONE,
            }
        }

        /// Type a run of keys at the UI, whatever mode each one lands in.
        fn type_keys(app: &mut App, keys: &[KeyEvent]) {
            let mut parser = vt100::Parser::new(39, 86, 100);
            let mut typed: Vec<u8> = Vec::new();
            for key in keys {
                app.key(*key, &mut parser, &mut typed, 0);
            }
            assert!(
                typed.is_empty(),
                "nothing typed at the filter belongs to the command: {typed:?}"
            );
        }

        fn chars(text: &str) -> Vec<KeyEvent> {
            text.chars().map(|c| press(KeyCode::Char(c))).collect()
        }

        /// The one place an ordinary character is not the command's. It is worth
        /// the exception only if it is complete: what is typed has to reach the
        /// pattern and nothing else.
        #[test]
        fn the_pattern_takes_what_is_typed_rather_than_the_command() {
            let mut app = app(120, 40);
            type_keys(&mut app, &[prefix(), press(KeyCode::Char('/'))]);
            assert_eq!(app.mode, Mode::Filter);
            assert!(!app.denials.filter().exclude());

            type_keys(&mut app, &chars("lib/"));
            assert_eq!(app.denials.filter().pattern(), "lib/");

            type_keys(&mut app, &[press(KeyCode::Backspace)]);
            assert_eq!(app.denials.filter().pattern(), "lib");

            // Which way round it reads is one key, not a second field.
            type_keys(&mut app, &[press(KeyCode::Tab)]);
            assert!(app.denials.filter().exclude());

            type_keys(&mut app, &[ctrl(KeyCode::Char('u'))]);
            assert_eq!(app.denials.filter().pattern(), "");

            // Enter keeps what was typed and gives the keyboard back.
            type_keys(&mut app, &chars("etc"));
            type_keys(&mut app, &[press(KeyCode::Enter)]);
            assert_eq!(app.mode, Mode::Normal);
            assert_eq!(app.denials.filter().pattern(), "etc");
        }

        /// Esc is the way out of every other mode without leaving a mark, and
        /// this one is no different: what was in force before comes back whole.
        #[test]
        fn leaving_the_field_by_escape_puts_the_previous_filter_back() {
            let mut app = app(120, 40);
            type_keys(&mut app, &[prefix(), press(KeyCode::Char('/'))]);
            type_keys(&mut app, &chars("etc"));
            type_keys(&mut app, &[press(KeyCode::Enter)]);

            // Opened again, added to, then abandoned.
            type_keys(&mut app, &[prefix(), press(KeyCode::Char('\\'))]);
            type_keys(&mut app, &chars("/hosts"));
            assert_eq!(app.denials.filter().pattern(), "etc/hosts");
            assert!(app.denials.filter().exclude());

            type_keys(&mut app, &[press(KeyCode::Esc)]);
            assert_eq!(app.mode, Mode::Normal);
            assert_eq!(app.denials.filter().pattern(), "etc");
            assert!(
                !app.denials.filter().exclude(),
                "the sense the key set has to be put back with the rest"
            );
        }

        #[test]
        fn the_two_half_keys_show_one_half_and_then_everything_again() {
            let mut app = app(120, 40);
            type_keys(&mut app, &[prefix(), press(KeyCode::Char('n'))]);
            assert_eq!(app.denials.filter().label(), "[net]");

            type_keys(&mut app, &[prefix(), press(KeyCode::Char('f'))]);
            assert_eq!(app.denials.filter().label(), "[fs]");

            type_keys(&mut app, &[prefix(), press(KeyCode::Char('f'))]);
            assert!(!app.denials.is_filtering());
        }

        /// The bug this pins: both offsets are clamped against how much there is
        /// to show, and a filter changes that under them. Without the reset,
        /// narrowing a long list leaves the view somewhere past the end of the
        /// short one it just became.
        #[test]
        fn narrowing_the_lists_brings_both_views_back_to_where_they_read_from() {
            let mut app = app(120, 40);
            with_refusals(&mut app, 60);
            let (blocked, recent) = app.panel_heights().expect("a panel fits at this width");
            app.blocked_key(press(KeyCode::End), blocked);
            app.recent_key(press(KeyCode::Home), recent);
            assert!(app.panel_scroll > 0);
            assert!(app.history_scroll > 0);

            type_keys(&mut app, &[prefix(), press(KeyCode::Char('n'))]);
            assert_eq!(app.panel_scroll, 0);
            assert_eq!(app.history_scroll, 0);
        }

        /// The whole point of the change: a command that is over does not take
        /// the interface down with it.
        #[test]
        fn every_key_still_works_once_the_command_is_over() {
            let mut app = app(120, 40);
            let mut parser = vt100::Parser::new(39, 86, 100);
            let mut typed: Vec<u8> = Vec::new();
            app.exited(std::process::ExitStatus::default());

            // The prefix still opens the UI's own keys, and they still run.
            app.key(prefix(), &mut parser, &mut typed, 0);
            assert_eq!(app.mode, Mode::Prefix);
            app.key(press(KeyCode::Char('w')), &mut parser, &mut typed, 0);
            assert!(!app.show_panel);

            // And the plain keys are the UI's own, rather than bytes for a
            // command that is not there to read them.
            app.key(press(KeyCode::Char('?')), &mut parser, &mut typed, 0);
            assert_eq!(app.mode, Mode::Help);
            app.key(press(KeyCode::Char(' ')), &mut parser, &mut typed, 0);
            assert_eq!(app.mode, Mode::Normal);
            assert!(typed.is_empty(), "nothing should have been sent: {typed:?}");

            // q leaves, without asking about stopping what has already stopped.
            assert!(!app.leaving);
            app.key(press(KeyCode::Char('q')), &mut parser, &mut typed, 0);
            assert!(app.leaving);
        }
    }
}
