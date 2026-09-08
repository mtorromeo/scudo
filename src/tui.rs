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
mod query;
#[cfg(feature = "tui")]
pub mod state;
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
        denials::Denials,
        keys::{self, KeySpec},
        mouse, pty, query,
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
        Exited(ExitStatus),
    }

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
    pub fn run(mut cmd: Command, options: &Options<'_>) -> Result<Outcome> {
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
        let result = session(&mut terminal, &mut cmd, options, prefix);
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
        let (rows, cols) =
            ui::terminal_size(area, app.panel_width, app.show_panel, app.context_lines());

        let mut pty = pty::open(rows, cols)?;
        let mut parser = vt100::Parser::new(rows, cols, options.config.scrollback());
        let child = pty.spawn(cmd)?;
        let pid = i32::try_from(child.id()).unwrap_or(-1i32);
        let mut writer = pty.writer()?;

        let (tx, rx) = mpsc::channel();
        start_reader(pty.reader()?, tx.clone());
        start_input(tx.clone());
        start_waiter(child, tx.clone());
        if let Some(token) = options.token.clone() {
            start_watcher(token, tx.clone());
        }

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
        scrollback: usize,
        max_scrollback: usize,
        /// Set once the command has exited; the UI stays up until a key is hit.
        finished: Option<i32>,
        /// What scudo itself will exit with.
        code: i32,
        leaving: bool,
        mouse_captured: bool,
        /// The size the pty was last told about, so a redraw that changed
        /// nothing does not resize it again.
        size: (u16, u16),
        /// The width of the whole screen, which is what a panel width has to be
        /// judged against. Kept because the resize keys need it and the terminal
        /// is not theirs to ask.
        screen_width: u16,
        /// What the host terminal said about its colours, ready to be repeated
        /// to a command that asks scudo the same.
        host: query::Host,
        /// Scans the command's output for questions and answers them.
        answerer: query::Answerer,
    }

    impl App {
        fn new(options: &Options<'_>, prefix: KeySpec, host: query::Host) -> Self {
            App {
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
                scrollback: 0,
                max_scrollback: options.config.scrollback(),
                finished: None,
                code: 0,
                leaving: false,
                mouse_captured: false,
                size: (0, 0),
                screen_width: 0,
                host,
                answerer: query::Answerer::default(),
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
                scrollback: self.scrollback,
                reporting: self.reporting,
                finished: self.finished,
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
                Event::Exited(status) => self.exited(status),
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
            // Reading the scrollback of a command that has finished is exactly
            // what someone would want; typing into it is not.
            if self.mode != Mode::Scroll {
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
                    let bytes = keys::encode_paste(&text, parser.screen().bracketed_paste());
                    self.write(writer, &bytes);
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
            // The command is over: the UI is only still up so its last screen
            // can be read, and any key says it has been.
            if self.finished.is_some() {
                if (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('d'))
                    || matches!(key.code, KeyCode::Esc | KeyCode::Char('q'))
                {
                    self.leaving = true;
                }
                return;
            }

            match self.mode {
                Mode::Confirm => self.confirm(key, pid),
                Mode::Help => self.mode = Mode::Normal,
                Mode::Prefix => self.command_key(key, parser, writer),
                Mode::Resize => self.resize_key(key),
                Mode::Scroll => self.scroll_key(key, parser),
                Mode::Normal => {
                    if self.prefix.matches(&key) {
                        self.mode = Mode::Prefix;
                        return;
                    }
                    if self.focus == Focus::Panel && self.panel_key(key) {
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
                    // Nothing is killed without being asked about: the command
                    // may be a shell with unsaved work in it.
                    self.mode = Mode::Confirm;
                }
                KeyCode::Tab => {
                    self.focus = match self.focus {
                        Focus::Terminal => Focus::Panel,
                        Focus::Panel => Focus::Terminal,
                    };
                }
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
                KeyCode::Char('?') => self.mode = Mode::Help,
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

        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "keys that do not move the view leave it where it is"
        )]
        fn scroll_key(&mut self, key: KeyEvent, parser: &mut vt100::Parser) {
            let page = usize::from(parser.screen().size().0).max(1usize);
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.reset_scrollback(parser);
                    self.mode = Mode::Normal;
                }
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
                _ => {}
            }
        }

        /// Navigation keys move the panel; everything else still reaches the
        /// command, so focus never silently swallows what was typed.
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "anything that does not move the panel is for the command"
        )]
        fn panel_key(&mut self, key: KeyEvent) -> bool {
            match key.code {
                KeyCode::Up => {
                    self.panel_scroll = self.panel_scroll.saturating_sub(PANEL_STEP);
                    true
                }
                KeyCode::Down => {
                    self.panel_scroll = self.panel_scroll.saturating_add(PANEL_STEP);
                    true
                }
                KeyCode::Home => {
                    self.panel_scroll = 0;
                    true
                }
                _ => false,
            }
        }

        fn mouse(
            &mut self,
            event: MouseEvent,
            parser: &mut vt100::Parser,
            writer: &mut impl Write,
        ) {
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
            self.scrollback = lines.min(self.max_scrollback);
            parser.screen_mut().set_scrollback(self.scrollback);
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
}
