//! Where everything goes on the screen, and what it says.
//!
//! [`regions`] is deliberately a plain function of the area rather than
//! something the drawing code works out as it goes: the pty has to be opened at
//! the terminal panel's size *before* the first frame is ever drawn, so the
//! split has to be answerable without a frame in hand. [`panel_split`] and
//! [`section_body`] are public for the same reason turned the other way round —
//! the keys that scroll the panel's lists have to measure themselves against the
//! very rectangles the drawing uses, and a second copy of the arithmetic is a
//! second copy to keep in step.
//!
//! **Everything but the command's terminal is painted.** The panel, the context
//! area, the status bar and the help all carry [`Theme::panel`] or one of its
//! neighbours; the terminal carries nothing, so what shows through it is the host
//! terminal's own background. That contrast is the point, and it is the reason
//! the theme is written down rather than derived from the host — see
//! [`theme`](super::theme).

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Clear, List, ListItem, ListState, Padding, Paragraph,
        Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
    },
};
use tui_term::widget::{Cursor, PseudoTerminal};

use crate::tui::{denials::Denials, theme::Theme};

/// The narrowest the terminal may become before the panel is dropped
/// altogether. Below this a shell's own output starts wrapping in ways that
/// make the panel cost more than it shows.
pub const MIN_TERMINAL_WIDTH: u16 = 40;

/// The narrowest the panel is ever made. An address and a count need about this
/// much before the addresses start being cut short.
pub const MIN_PANEL_WIDTH: u16 = 34;

/// The widest the panel is made when nobody has chosen. Past this it has all the
/// room its content knows how to use, and the rest is taken from the terminal
/// for nothing.
pub const MAX_AUTO_PANEL_WIDTH: u16 = 60;

/// How much of the screen the panel takes when nobody has chosen: one part in
/// this many.
const AUTO_PANEL_SHARE: u16 = 4;

/// The row a section's heading takes. It sits above the list rather than in it,
/// which is the whole difference: a heading drawn as the list's first line
/// scrolls away with the list, and then the panel has two columns of numbers and
/// nothing to say what either of them counts.
const HEADER_ROWS: u16 = 1;

/// The column kept down the right of every section for its scrollbar.
///
/// Kept whether or not there is anything to scroll. A gutter that appeared with
/// the twentieth line would shift every line above it sideways at the moment
/// someone was reading them, which costs more than the column does.
const GUTTER_WIDTH: u16 = 1;

/// Which part of the screen the keyboard is talking to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Terminal,
    /// The tally at the top of the panel.
    Blocked,
    /// The running list underneath it.
    Recent,
}

impl Focus {
    /// The next one round, which is what `Tab` moves to.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Focus::Terminal => Focus::Blocked,
            Focus::Blocked => Focus::Recent,
            Focus::Recent => Focus::Terminal,
        }
    }

    /// Whether it is one of the panel's two lists.
    #[must_use]
    pub fn in_panel(self) -> bool {
        !matches!(self, Focus::Terminal)
    }

    /// What the status bar calls it.
    fn label(self) -> &'static str {
        match self {
            Focus::Terminal => "terminal",
            Focus::Blocked => "blocked list",
            Focus::Recent => "recent list",
        }
    }
}

/// What the UI is in the middle of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Keys go to the command.
    Normal,
    /// The prefix was pressed; the next key is a command to the UI.
    Prefix,
    /// Reading the scrollback rather than typing into it.
    Scroll,
    /// Asking whether to kill a command that is still running.
    Confirm,
    /// Setting how wide the panel is.
    Resize,
    /// The list of prefix commands is up.
    Help,
}

/// Why the panel has nothing in it, when it has nothing in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reporting {
    /// Programs are attached and reporting; an empty panel means nothing was
    /// blocked.
    Watching,
    /// The whole network was taken away, so nothing observes what is missed.
    DenyAll,
    /// Nothing to enforce on this command.
    NoPolicy,
    /// The policy is enforced, but the daemon could not be asked to report.
    Unavailable,
}

impl Reporting {
    fn note(self) -> &'static str {
        match self {
            Reporting::Watching => "watching for blocked accesses",
            Reporting::DenyAll => {
                "the network is taken away entirely, so there is nothing to report"
            }
            Reporting::NoPolicy => "no policy applies to this command",
            Reporting::Unavailable => "the sandbox could not be watched",
        }
    }
}

/// Everything one frame needs, borrowed from the running UI.
pub struct View<'a> {
    pub screen: &'a vt100::Screen,
    pub denials: &'a Denials,
    pub command: &'a str,
    pub focus: Focus,
    pub mode: Mode,
    pub prefix_label: &'a str,
    /// The lines `--verbose` would have printed: what matched, and the command
    /// line that was actually run.
    pub context: &'a [String],
    pub show_context: bool,
    pub show_panel: bool,
    /// `None` while the width follows the screen; `Some` once it was chosen.
    pub panel_width: Option<u16>,
    pub panel_scroll: u16,
    /// How far back from its newest line the running list has been moved.
    pub history_scroll: usize,
    pub scrollback: usize,
    pub reporting: Reporting,
    /// Set once the command is over; the UI stays up until a key is pressed.
    pub finished: Option<i32>,
    pub theme: &'a Theme,
}

/// The pieces of the screen.
#[derive(Debug, Clone, Copy)]
pub struct Regions {
    pub terminal: Rect,
    pub panel: Option<Rect>,
    pub context: Option<Rect>,
    pub footer: Rect,
}

/// Stands in for what was cut. One cell, where three dots would cost two more
/// of the width that was already too tight.
const ELLIPSIS: char = '\u{2026}';

/// The mark down the left of the heading of whichever section has the focus.
const FOCUS_MARK: &str = "\u{258c}";

/// A refusal, and a path that was simply never there.
const REFUSED_MARK: &str = "\u{25cf}";
const MISSING_MARK: &str = "\u{25cb}";

/// The most context lines shown at once. Past this the panel would be pushing
/// the terminal off the screen to say what it already said.
const MAX_CONTEXT_LINES: u16 = 6;

/// How wide the panel is on a screen this wide, given what the person chose.
///
/// The `Option` is the whole design in one argument. Left empty the width
/// follows the screen, so resizing the window resizes the panel with it; filled
/// in it does not, so a width someone set on purpose is not taken away from them
/// by the next resize. Without the distinction one of the two has to break.
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "a share of the screen, in whole columns because that is all there are"
)]
#[must_use]
pub fn panel_width(screen: u16, chosen: Option<u16>) -> u16 {
    // However it was arrived at, the terminal keeps its floor: a panel that
    // leaves a shell twenty columns is worse than no panel.
    let widest = screen
        .saturating_sub(MIN_TERMINAL_WIDTH)
        .max(MIN_PANEL_WIDTH);
    match chosen {
        Some(width) => width.clamp(MIN_PANEL_WIDTH, widest),
        None => (screen / AUTO_PANEL_SHARE)
            .clamp(MIN_PANEL_WIDTH, MAX_AUTO_PANEL_WIDTH)
            .min(widest),
    }
}

/// The panel's two sections: the tally above, the running log below.
///
/// A section is its heading *and* its list; [`section_body`] is what takes the
/// heading off again.
#[must_use]
pub fn panel_split(panel: Rect) -> (Rect, Rect) {
    let inner = Block::default().borders(Borders::LEFT).inner(panel);
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(inner);
    (
        split.first().copied().unwrap_or(inner),
        split.get(1).copied().unwrap_or(inner),
    )
}

/// The part of a section its list is drawn in: below the heading, and left of
/// the scrollbar's gutter.
///
/// This is what the keys that scroll a list measure against, so it has to be the
/// one the drawing uses.
#[must_use]
pub fn section_body(section: Rect) -> Rect {
    Rect {
        x: section.x,
        y: section.y.saturating_add(HEADER_ROWS),
        width: section.width.saturating_sub(GUTTER_WIDTH),
        height: section.height.saturating_sub(HEADER_ROWS),
    }
}

/// The column the section's scrollbar goes in, beside its body.
fn section_gutter(section: Rect) -> Rect {
    let body = section_body(section);
    Rect {
        x: section.x.saturating_add(body.width),
        y: body.y,
        width: section.width.min(GUTTER_WIDTH),
        height: body.height,
    }
}

/// How many lines the tally has to draw.
///
/// The heading is not among them: it is drawn above the list and stays put, so
/// counting it here would let the view scroll one line into the space past the
/// last address.
#[must_use]
pub fn targets_lines(denials: &Denials) -> usize {
    if denials.is_empty() {
        // The note saying why there is nothing here.
        1usize
    } else {
        denials.shown()
    }
}

#[must_use]
pub fn regions(area: Rect, panel: Option<u16>, show_panel: bool, context_lines: u16) -> Regions {
    let context_height = context_lines.min(MAX_CONTEXT_LINES);
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            // Plus one for the rule that separates it from the terminal, which
            // is also where its heading goes.
            Constraint::Length(if context_height > 0 {
                context_height.saturating_add(1)
            } else {
                0
            }),
            Constraint::Length(1),
        ])
        .split(area);

    let body = vertical.first().copied().unwrap_or(area);
    let context = vertical.get(1).copied().filter(|rect| rect.height > 0);
    let footer = vertical.get(2).copied().unwrap_or(area);

    // The panel is worth its width only while the terminal keeps enough of its
    // own: below that a shell's output wraps into nonsense, and what the panel
    // has to say is not worth that.
    let width = panel_width(body.width, panel);
    let room = body.width >= width.saturating_add(MIN_TERMINAL_WIDTH);
    if !show_panel || !room {
        return Regions {
            terminal: body,
            panel: None,
            context,
            footer,
        };
    }

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(MIN_TERMINAL_WIDTH),
            Constraint::Length(width),
        ])
        .split(body);

    Regions {
        terminal: horizontal.first().copied().unwrap_or(body),
        panel: horizontal.get(1).copied(),
        context,
        footer,
    }
}

/// The size the command's terminal should be, given the whole screen.
#[must_use]
pub fn terminal_size(
    area: Rect,
    panel: Option<u16>,
    show_panel: bool,
    context_lines: u16,
) -> (u16, u16) {
    let regions = regions(area, panel, show_panel, context_lines);
    // Never zero: a terminal of no size makes vt100 and the command downstream
    // of it behave in ways neither is prepared for.
    (
        regions.terminal.height.max(1),
        regions.terminal.width.max(1),
    )
}

pub fn draw(frame: &mut Frame<'_>, view: &View<'_>) {
    let context_lines = if view.show_context {
        u16::try_from(view.context.len()).unwrap_or(MAX_CONTEXT_LINES)
    } else {
        0
    };
    let regions = regions(
        frame.area(),
        view.panel_width,
        view.show_panel,
        context_lines,
    );

    draw_terminal(frame, view, regions.terminal);
    if let Some(area) = regions.panel {
        draw_panel(frame, view, area);
    }
    if let Some(area) = regions.context {
        draw_context(frame, view, area);
    }
    draw_footer(frame, view, regions.footer);

    if view.mode == Mode::Help {
        draw_help(frame, view);
    }
}

fn draw_terminal(frame: &mut Frame<'_>, view: &View<'_>, area: Rect) {
    // Left unpainted on purpose: the host terminal's own background is what
    // shows through here, and it is what the panel beside it is contrasted with.
    //
    // The block cursor is drawn by the host terminal instead, so it blinks and
    // takes the shape the person configured — which is what makes the panel
    // read as a terminal rather than as a picture of one.
    let widget = PseudoTerminal::new(view.screen).cursor(Cursor::default().visibility(false));
    frame.render_widget(widget, area);

    let editing = view.focus == Focus::Terminal
        && view.mode != Mode::Scroll
        && view.mode != Mode::Help
        && view.finished.is_none();
    if editing && !view.screen.hide_cursor() {
        let (row, col) = view.screen.cursor_position();
        // Scrolled back far enough, the cursor is off the top of what is shown;
        // there is then no cell to put it on.
        if row < area.height && col < area.width {
            frame.set_cursor_position((area.x.saturating_add(col), area.y.saturating_add(row)));
        }
    }
}

fn draw_panel(frame: &mut Frame<'_>, view: &View<'_>, area: Rect) {
    let theme = view.theme;
    let edge = if view.focus.in_panel() {
        theme.accent
    } else {
        theme.border
    };
    // One block for the whole panel: it is what lays the ground down, and the
    // sections are drawn over it.
    let block = Block::new()
        .borders(Borders::LEFT)
        .border_style(Style::new().fg(edge))
        .style(theme.panel);
    frame.render_widget(block, area);

    let (top, bottom) = panel_split(area);
    draw_targets(frame, view, top);
    draw_history(frame, view, bottom);
}

/// One section's heading: a filled bar with a label on the left and a figure on
/// the right, in its own row so that nothing scrolls it away.
fn draw_heading(
    frame: &mut Frame<'_>,
    section: Rect,
    theme: &Theme,
    focused: bool,
    label: &str,
    right: Vec<Span<'static>>,
) {
    if section.height == 0 || section.width == 0 {
        return;
    }
    let style = if focused {
        theme.header_focused
    } else {
        theme.header
    };
    let mark = if focused { FOCUS_MARK } else { " " };

    let mut left = vec![
        Span::raw(mark),
        Span::styled(
            format!(" {label}"),
            Style::new().add_modifier(Modifier::BOLD),
        ),
    ];
    let used: usize = left
        .iter()
        .chain(right.iter())
        .map(|span| span.content.chars().count())
        .sum();
    left.push(Span::raw(
        " ".repeat(usize::from(section.width).saturating_sub(used)),
    ));
    left.extend(right);

    let area = Rect {
        height: HEADER_ROWS,
        ..section
    };
    frame.render_widget(Paragraph::new(Line::from(left)).style(style), area);
}

fn draw_targets(frame: &mut Frame<'_>, view: &View<'_>, section: Rect) {
    let theme = view.theme;
    let focused = view.focus == Focus::Blocked;

    // The held-back count belongs in the heading rather than on a line of its
    // own: a panel that is empty only because of a toggle has to say so where
    // the eye already is.
    let hidden = view.denials.hidden();
    let mut right = Vec::new();
    if hidden > 0usize {
        right.push(Span::styled(
            format!("+{hidden} hidden  "),
            Style::new().fg(theme.dim),
        ));
    }
    let shown = view.denials.shown();
    right.push(Span::styled(
        format!("{shown} "),
        Style::new().fg(if shown > 0usize {
            theme.warn
        } else {
            theme.dim
        }),
    ));
    draw_heading(frame, section, theme, focused, "BLOCKED", right);

    let body = section_body(section);
    if body.height == 0 || body.width == 0 {
        return;
    }

    if view.denials.is_empty() {
        // Once the stream is closed nothing more can arrive, so an empty panel
        // has stopped being a wait and become an answer.
        let note = if view.denials.is_closed() && view.reporting == Reporting::Watching {
            "nothing was blocked"
        } else {
            view.reporting.note()
        };
        let paragraph = Paragraph::new(note)
            .style(Style::new().fg(theme.dim))
            .block(Block::new().padding(Padding::horizontal(1)))
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, body);
        return;
    }

    // The count is right-aligned against the gutter, so the numbers line up and
    // a long address is what gets cut instead of the figure.
    let width = usize::from(body.width);
    let items: Vec<ListItem<'static>> = view
        .denials
        .targets()
        .map(|target| {
            // A space at each end: the leading one sets the count off from the
            // address, the trailing one keeps it off the scrollbar's gutter.
            let count = format!(" {}x ", target.count);
            // The mark, and a space either side of it.
            let room = width
                .saturating_sub(count.chars().count())
                .saturating_sub(3);
            let label = truncate(&target.label, room);
            let padding = " ".repeat(room.saturating_sub(label.chars().count()));
            // A path that was missing outside the sandbox too is shown hollow
            // and dimmed: it is something the command wanted and did not get,
            // but the sandbox is not the reason, and widening the profile would
            // not help.
            let (mark, mark_colour, label_colour, count_colour) = if target.denial {
                (REFUSED_MARK, theme.warn, theme.text, theme.warn)
            } else {
                (MISSING_MARK, theme.dim, theme.dim, theme.dim)
            };
            ListItem::new(Line::from(vec![
                Span::raw(" "),
                Span::styled(mark, Style::new().fg(mark_colour)),
                Span::styled(format!(" {label}{padding}"), Style::new().fg(label_colour)),
                Span::styled(count, Style::new().fg(count_colour)),
            ]))
        })
        .collect();

    let total = items.len();
    let offset = usize::from(view.panel_scroll);
    let mut state = ListState::default().with_offset(offset);
    frame.render_stateful_widget(List::new(items), body, &mut state);
    draw_scrollbar(frame, section, theme, total, offset);
}

fn draw_history(frame: &mut Frame<'_>, view: &View<'_>, section: Rect) {
    let theme = view.theme;
    let total = view.denials.recent().count();
    let body = section_body(section);
    let room = usize::from(body.height);

    // How far back from the newest line the view has been moved, said in the
    // heading because it is the only place it can be said: the list itself looks
    // the same wherever it is.
    let right = if view.history_scroll > 0usize {
        vec![Span::styled(
            format!("\u{2191}{} ", view.history_scroll),
            Style::new().fg(theme.accent),
        )]
    } else {
        Vec::new()
    };
    draw_heading(
        frame,
        section,
        theme,
        view.focus == Focus::Recent,
        "RECENT",
        right,
    );

    if body.height == 0 || body.width == 0 {
        return;
    }

    // Newest at the bottom, like any log: the eye goes to the last line. The
    // offset counts back from there rather than forward from the oldest, so a
    // list nobody has scrolled stays pinned to its newest line as they arrive.
    // Left to run off the right edge rather than cut like the addresses above.
    // These read as sentences and end with the reason, which is the same words
    // on every line: cutting the front would take the path and keep the part
    // that never varies.
    let window: Vec<(String, String, bool)> = view
        .denials
        .recent()
        .rev()
        .skip(view.history_scroll)
        .take(room)
        .map(|(age, line, denial)| (ago(age), line.to_owned(), denial))
        .collect();
    let items: Vec<ListItem<'static>> = window
        .into_iter()
        .rev()
        .map(|(age, line, denial)| {
            let colour = if denial { theme.text } else { theme.dim };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {age} "), Style::new().fg(theme.dim)),
                Span::styled(line, Style::new().fg(colour)),
            ]))
        })
        .collect();
    frame.render_widget(List::new(items), body);

    // The offset counts back from the newest line and the scrollbar counts
    // forward from the oldest, hence the subtraction: they are the same place
    // said from the two ends.
    let from_top = total
        .saturating_sub(room)
        .saturating_sub(view.history_scroll);
    draw_scrollbar(frame, section, theme, total, from_top);
}

/// The bar down a section's gutter, drawn only when there is more list than
/// there is room. `offset` is how many lines are above the top of the view.
fn draw_scrollbar(
    frame: &mut Frame<'_>,
    section: Rect,
    theme: &Theme,
    total: usize,
    offset: usize,
) {
    let gutter = section_gutter(section);
    let room = usize::from(gutter.height);
    if gutter.width == 0 || room == 0 || total <= room {
        return;
    }
    let mut state = ScrollbarState::new(total.saturating_sub(room))
        .viewport_content_length(room)
        .position(offset);
    let bar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .track_symbol(Some("\u{2502}"))
        .thumb_symbol("\u{2503}")
        .track_style(Style::new().fg(theme.border))
        .thumb_style(Style::new().fg(theme.accent));
    frame.render_stateful_widget(bar, gutter, &mut state);
}

fn draw_context(frame: &mut Frame<'_>, view: &View<'_>, area: Rect) {
    let theme = view.theme;
    // The heading rides in the top rule, so it costs no row of its own and
    // `regions` can go on budgeting one line per context line plus the rule.
    let block = Block::new()
        .borders(Borders::TOP)
        .border_style(Style::new().fg(theme.border))
        .title_top(Span::styled(
            " what scudo decided ",
            Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
        ))
        .padding(Padding::horizontal(1))
        .style(theme.panel);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines: Vec<Line<'_>> = view
        .context
        .iter()
        .map(|line| Line::from(Span::styled(line.clone(), Style::new().fg(theme.dim))))
        .collect();
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

/// What the status bar says, and what it looks like saying it.
struct Status {
    /// The word in the chip on the left: the mode, or the prefix key while
    /// there is no mode to name.
    badge: String,
    /// The ground the whole row is drawn on. Every state has its own, and that
    /// is not decoration: a mode the keyboard is in has to be visible from
    /// across the room, and the colour is what carries it — the words in the bar
    /// are what it means, not that it happened.
    bar: Style,
    /// The chip, which is the bar's own colours the other way round.
    chip: Style,
    /// The figures on the right, which are context rather than the message.
    aside: Style,
    message: String,
    /// Right-aligned, and only where there is a short message to leave room for
    /// it.
    right: Option<String>,
}

/// A bar that is a colour, with its chip inverted out of it. Every mode but the
/// ordinary one, plus the command being over — the states worth interrupting a
/// reader over.
fn loud(theme: &Theme, colour: ratatui::style::Color) -> (Style, Style, Style) {
    let bar = Style::new().bg(colour).fg(theme.on_accent);
    let chip = Style::new()
        .bg(theme.on_accent)
        .fg(colour)
        .add_modifier(Modifier::BOLD);
    (bar, chip, bar)
}

fn status(view: &View<'_>, frame_width: u16) -> Status {
    let theme = view.theme;
    // On the mode first, and on the finished command only where the two could
    // disagree: a command that is over does not stop the person resizing the
    // panel, and the bar that says so has to survive it ending.
    match view.mode {
        Mode::Confirm => {
            let (bar, chip, aside) = loud(theme, theme.danger);
            Status {
                badge: "STOP?".to_owned(),
                bar,
                chip,
                aside,
                message: format!(
                    "{} is still running. Stop it and leave? [y/N]",
                    view.command
                ),
                right: None,
            }
        }
        Mode::Prefix => {
            let (bar, chip, aside) = loud(theme, theme.accent);
            Status {
                badge: "PREFIX".to_owned(),
                bar,
                chip,
                aside,
                message: format!("{}: press a command key, ? for the list", view.prefix_label),
                right: None,
            }
        }
        Mode::Resize => {
            let width = panel_width(frame_width, view.panel_width);
            let how = if view.panel_width.is_some() {
                String::new()
            } else {
                " (automatic)".to_owned()
            };
            let (bar, chip, aside) = loud(theme, theme.alt);
            Status {
                badge: "RESIZE".to_owned(),
                bar,
                chip,
                aside,
                message: format!(
                    "panel {width} columns{how} — arrows, h/l, = for automatic, Esc to return"
                ),
                right: None,
            }
        }
        Mode::Scroll => {
            let (bar, chip, aside) = loud(theme, theme.warn);
            Status {
                badge: "SCROLL".to_owned(),
                bar,
                chip,
                aside,
                message: format!(
                    "scroll: {} lines back — arrows, PgUp/PgDn, Esc to return",
                    view.scrollback
                ),
                right: None,
            }
        }
        Mode::Help | Mode::Normal => match view.finished {
            Some(code) => {
                // Green for a command that did what it was asked, amber for one
                // that did not: the code is in the message either way, and this
                // is what is read before the message is.
                let colour = if code == 0i32 { theme.ok } else { theme.warn };
                let (bar, chip, aside) = loud(theme, colour);
                // The keys that were the command's are the UI's now, and this is
                // where that is said — with where the view is, once it has been
                // moved, since the scroll bar is not the one on screen.
                let (message, right) = if view.scrollback > 0usize {
                    (
                        format!(
                            "{} exited with {code} — {} lines back │ press q, Esc or ^d to leave",
                            view.command, view.scrollback
                        ),
                        None,
                    )
                } else {
                    (
                        format!(
                            "{} exited with {code} — press q, Esc or ^d to leave",
                            view.command
                        ),
                        Some(right_status(view)),
                    )
                };
                Status {
                    badge: "DONE".to_owned(),
                    bar,
                    chip,
                    aside,
                    message,
                    right,
                }
            }
            // The one quiet state, because it is the one that is on screen for
            // the whole run: a status bar that shouts while nothing is happening
            // is a status bar people stop reading.
            None => Status {
                badge: view.prefix_label.to_owned(),
                bar: theme.footer,
                chip: Style::new()
                    .bg(theme.accent)
                    .fg(theme.on_accent)
                    .add_modifier(Modifier::BOLD),
                aside: theme.footer.fg(theme.dim),
                message: "? for help".to_owned(),
                right: Some(right_status(view)),
            },
        },
    }
}

/// Which list the arrows move, and how much has been taken away so far. The one
/// thing the bar says that the drawing does not say louder.
fn right_status(view: &View<'_>) -> String {
    format!(
        "{} │ blocked {}",
        view.focus.label(),
        view.denials.blocked()
    )
}

fn draw_footer(frame: &mut Frame<'_>, view: &View<'_>, area: Rect) {
    // The panel's own width, not the bar's: the bar spans the screen.
    let status = status(view, frame.area().width);

    let badge = Span::styled(format!(" {} ", status.badge), status.chip);
    let message = Span::raw(format!(" {}", status.message));
    let right = status
        .right
        .map(|text| format!("{text} "))
        .unwrap_or_default();

    let used = badge
        .content
        .chars()
        .count()
        .saturating_add(message.content.chars().count())
        .saturating_add(right.chars().count());
    let gap = usize::from(area.width).saturating_sub(used);

    let mut spans = vec![badge, message, Span::raw(" ".repeat(gap))];
    if !right.is_empty() && gap > 0usize {
        // Dropped rather than crushed when the message already fills the bar:
        // half of "blocked 3" says nothing at all.
        spans.push(Span::styled(right, status.aside));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)).style(status.bar), area);
}

fn draw_help(frame: &mut Frame<'_>, view: &View<'_>) {
    let theme = view.theme;
    let prefix = view.prefix_label;
    // Two lists, because after the command is over the keys are not the same
    // ones: nothing is left to type at, so the plain keys are the UI's own and
    // saying otherwise would send people looking for a prefix they do not need.
    let entries: Vec<(String, &str)> = if view.finished.is_some() {
        vec![
            ("q  Esc  ^d".to_owned(), "leave"),
            (
                "arrows".to_owned(),
                "read the scrollback, or whichever list has the focus",
            ),
            ("PgUp  PgDn".to_owned(), "a screenful of it at a time"),
            ("Home  End".to_owned(), "the far ends of it"),
            (
                "Tab".to_owned(),
                "the terminal, the blocked list, the recent list",
            ),
            (format!("{prefix} r"), "set how wide the panel is"),
            (format!("{prefix} w"), "show or hide the panel"),
            (format!("{prefix} s"), "show or hide what scudo decided"),
            (
                format!("{prefix} m"),
                "show or hide paths missing outside the sandbox too",
            ),
            ("?".to_owned(), "this list"),
        ]
    } else {
        vec![
            (
                format!("{prefix} q"),
                "leave, stopping the command if it still runs",
            ),
            (
                format!("{prefix} {prefix}"),
                "send the prefix to the command",
            ),
            (
                format!("{prefix} Tab"),
                "move between the terminal and the panel's two lists",
            ),
            (format!("{prefix} PgUp"), "read the scrollback"),
            (format!("{prefix} r"), "set how wide the panel is"),
            (format!("{prefix} w"), "show or hide the panel"),
            (format!("{prefix} s"), "show or hide what scudo decided"),
            (
                format!("{prefix} m"),
                "show or hide paths missing outside the sandbox too",
            ),
            (format!("{prefix} ?"), "this list"),
        ]
    };

    let keys_width = entries
        .iter()
        .map(|(keys, _)| keys.chars().count())
        .max()
        .unwrap_or(6usize);
    let widest = entries
        .iter()
        .map(|(_, what)| keys_width.saturating_add(2usize).saturating_add(what.len()))
        .max()
        .unwrap_or(40usize);

    // The border takes two columns and two rows, the padding two more columns.
    let width = u16::try_from(widest.saturating_add(4usize)).unwrap_or(u16::MAX);
    let height = u16::try_from(entries.len().saturating_add(2usize)).unwrap_or(u16::MAX);
    let area = centred(frame.area(), width, height);

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(theme.accent))
        .title_top(Span::styled(
            " scudo ",
            Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(" any key closes ", Style::new().fg(theme.dim)))
        .padding(Padding::horizontal(1))
        .style(theme.panel);
    let inner = block.inner(area);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);

    let lines: Vec<Line<'_>> = entries
        .into_iter()
        .map(|(keys, what)| {
            let padding = " ".repeat(keys_width.saturating_sub(keys.chars().count()));
            Line::from(vec![
                Span::styled(
                    keys,
                    Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
                ),
                Span::raw(padding),
                Span::styled(format!("  {what}"), Style::new().fg(theme.text)),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "halving a leftover to centre something; the lost row is the point"
)]
fn centred(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x.saturating_add(area.width.saturating_sub(width) / 2),
        y: area
            .y
            .saturating_add(area.height.saturating_sub(height) / 2),
        width,
        height,
    }
}

/// Cut from the left: the end of an address is the part that distinguishes it.
fn truncate(text: &str, width: usize) -> String {
    let length = text.chars().count();
    if length <= width || width == 0usize {
        return text.to_owned();
    }
    let skip = length.saturating_sub(width.saturating_sub(1usize));
    format!("{ELLIPSIS}{}", text.chars().skip(skip).collect::<String>())
}

#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "a rounded-down age is what a column three characters wide can say"
)]
fn ago(age: std::time::Duration) -> String {
    let seconds = age.as_secs();
    if seconds < 60u64 {
        return format!("{seconds:>2}s");
    }
    let minutes = seconds / 60u64;
    if minutes < 60u64 {
        return format!("{minutes:>2}m");
    }
    format!("{:>2}h", minutes / 60u64)
}

#[cfg(test)]
#[expect(
    clippy::non_ascii_literal,
    reason = "the ellipsis, spelled the way the assertion reads best"
)]
mod tests {
    use super::*;

    fn area(width: u16, height: u16) -> Rect {
        Rect {
            x: 0,
            y: 0,
            width,
            height,
        }
    }

    /// The table this was designed against: a quarter of the screen, floored so
    /// the panel stays readable and capped so it stops taking from the terminal
    /// once it has all it can use.
    #[test]
    fn the_automatic_width_follows_the_screen_between_a_floor_and_a_ceiling() {
        let auto = |screen| panel_width(screen, None);
        assert_eq!(auto(100), MIN_PANEL_WIDTH);
        assert_eq!(auto(136), 34);
        assert_eq!(auto(160), 40);
        assert_eq!(auto(200), 50);
        assert_eq!(auto(240), MAX_AUTO_PANEL_WIDTH);
        // Past the ceiling the terminal gets everything else.
        assert_eq!(auto(320), MAX_AUTO_PANEL_WIDTH);
    }

    #[test]
    fn a_width_that_was_chosen_is_the_width_used() {
        assert_eq!(panel_width(200, Some(80)), 80);
        // And it does not move when the automatic one would have.
        assert_eq!(panel_width(320, Some(80)), 80);
    }

    /// A width set on a wide monitor must not leave a shell unusable when the
    /// same session is later opened on a laptop.
    #[test]
    fn a_chosen_width_is_cut_down_to_what_the_screen_can_spare() {
        let width = panel_width(100, Some(90));
        assert_eq!(width, 100 - MIN_TERMINAL_WIDTH);
        assert!(width < 90);
        // And never below the floor, however little room there is.
        assert_eq!(panel_width(100, Some(4)), MIN_PANEL_WIDTH);
    }

    /// On a screen too small for both, the floor wins here and `regions` then
    /// drops the panel entirely rather than squeezing the terminal.
    #[test]
    fn a_screen_with_no_room_for_both_keeps_the_terminal() {
        assert_eq!(panel_width(50, None), MIN_PANEL_WIDTH);
        assert!(regions(area(50, 20), None, true, 0).panel.is_none());
    }

    #[test]
    fn the_panel_takes_the_width_it_was_given_and_the_terminal_keeps_the_rest() {
        let regions = regions(area(120, 40), Some(34), true, 0);
        let panel = regions.panel.expect("a panel fits at this width");
        assert_eq!(panel.width, 34);
        assert_eq!(regions.terminal.width, 86);
        // One row goes to the status bar, whatever else is on screen.
        assert_eq!(regions.terminal.height, 39);
        assert_eq!(regions.footer.height, 1);
    }

    /// A panel that leaves the shell 20 columns is worse than no panel.
    #[test]
    fn a_narrow_window_keeps_the_terminal_and_drops_the_panel() {
        let regions = regions(area(60, 20), Some(34), true, 0);
        assert!(regions.panel.is_none());
        assert_eq!(regions.terminal.width, 60);
    }

    #[test]
    fn the_context_takes_its_lines_plus_a_rule_and_is_capped() {
        let three = regions(area(120, 40), Some(34), true, 3);
        let context = three.context.expect("the context is shown");
        assert_eq!(context.height, 4);
        assert_eq!(three.terminal.height, 35);

        // A profile that matched twenty times must not push the terminal away.
        let many = regions(area(120, 40), Some(34), true, 40);
        let context = many.context.expect("the context is shown");
        assert_eq!(context.height, MAX_CONTEXT_LINES + 1);
    }

    #[test]
    fn the_command_is_never_told_it_has_no_room_at_all() {
        let (rows, cols) = terminal_size(area(0, 0), Some(34), true, 0);
        assert_eq!((rows, cols), (1, 1));
    }

    /// The keys that scroll the panel's lists measure themselves against this
    /// split, so it has to be the one the drawing uses.
    #[test]
    fn the_panel_is_split_between_the_tally_and_the_log() {
        let panel = regions(area(120, 40), Some(34), true, 0)
            .panel
            .expect("a panel fits at this width");
        let (blocked, recent) = panel_split(panel);
        // The border takes a column of the panel's width.
        assert_eq!(blocked.width, 33);
        assert_eq!(recent.width, 33);
        // And the two share its height, one under the other.
        assert_eq!(blocked.height.saturating_add(recent.height), panel.height);
        assert_eq!(blocked.y.saturating_add(blocked.height), recent.y);
    }

    /// The heading is above the list and the gutter is beside it; a body that
    /// counted either would let the view scroll past what there is to read.
    #[test]
    fn a_sections_body_is_what_is_left_after_its_heading_and_its_gutter() {
        let panel = regions(area(120, 40), Some(34), true, 0)
            .panel
            .expect("a panel fits at this width");
        let (blocked, _) = panel_split(panel);
        let body = section_body(blocked);
        assert_eq!(body.height, blocked.height - HEADER_ROWS);
        assert_eq!(body.width, blocked.width - GUTTER_WIDTH);
        assert_eq!(body.y, blocked.y + HEADER_ROWS);
        // And the gutter is the column beside it, over the same rows.
        let gutter = section_gutter(blocked);
        assert_eq!(gutter.x, body.x + body.width);
        assert_eq!((gutter.width, gutter.height), (GUTTER_WIDTH, body.height));
    }

    /// A section with nothing but a heading in it, which is what a very short
    /// window leaves: nothing may be drawn off the end of it.
    #[test]
    fn a_section_too_short_for_a_list_has_a_body_of_no_height() {
        let body = section_body(area(20, 1));
        assert_eq!(body.height, 0);
        assert_eq!(section_gutter(area(20, 1)).height, 0);
        assert_eq!(section_body(area(0, 0)).width, 0);
    }

    /// The heading used to be the tally's first line and scrolled away with it.
    /// Now it is drawn above, so what scrolls is the addresses and nothing else.
    #[test]
    fn the_tally_counts_only_the_lines_that_scroll() {
        use crate::bpfd::protocol::{FileError, FileOp, Notification, Outside};

        let refused = |path: &str| Notification::FileBlocked {
            op: FileOp::Open,
            path: path.to_owned(),
            error: FileError::Permission,
            outside: Outside::Present,
        };

        let mut denials = Denials::default();
        // Nothing yet: the note saying why there is nothing here.
        assert_eq!(targets_lines(&denials), 1);
        denials.push(&refused("/home/me/.bashrc"), "bash");
        assert_eq!(targets_lines(&denials), 1);
        denials.push(&refused("/home/me/.profile"), "bash");
        assert_eq!(targets_lines(&denials), 2);
    }

    #[test]
    fn a_long_address_loses_its_front_rather_than_its_port() {
        assert_eq!(truncate("1.1.1.1:443", 20), "1.1.1.1:443");
        assert_eq!(truncate("averylongname.example:443", 10), "…ample:443");
    }
}
