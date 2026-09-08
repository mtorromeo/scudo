//! Where everything goes on the screen, and what it says.
//!
//! [`regions`] is deliberately a plain function of the area rather than
//! something the drawing code works out as it goes: the pty has to be opened at
//! the terminal panel's size *before* the first frame is ever drawn, so the
//! split has to be answerable without a frame in hand.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use tui_term::widget::{Cursor, PseudoTerminal};

use crate::tui::denials::Denials;

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

    /// What the footer calls it.
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

/// The panel's two lists: the tally above, the running log below.
///
/// Taken out of the drawing because the keys that scroll them have to know how
/// tall they are, and a second copy of the split would be a second copy to keep
/// in step.
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

/// How many lines the tally draws, its heading included. What the keys that
/// scroll it measure against, so the list stops at its last line rather than
/// carrying on into the space past it.
#[must_use]
pub fn targets_lines(denials: &Denials) -> usize {
    if denials.is_empty() {
        // The heading, and the note saying why there is nothing under it.
        2usize
    } else {
        denials.shown().saturating_add(1usize)
    }
}

#[must_use]
pub fn regions(area: Rect, panel: Option<u16>, show_panel: bool, context_lines: u16) -> Regions {
    let context_height = context_lines.min(MAX_CONTEXT_LINES);
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            // Plus one for the rule that separates it from the terminal.
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
    let border_style = if view.focus.in_panel() {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let block = Block::default()
        .borders(Borders::LEFT)
        .border_style(border_style);
    frame.render_widget(block, area);

    let (top, bottom) = panel_split(area);
    draw_targets(frame, view, top);
    draw_history(frame, view, bottom);
}

fn draw_targets(frame: &mut Frame<'_>, view: &View<'_>, area: Rect) {
    let focused = view.focus == Focus::Blocked;
    // The held-back count is part of the heading rather than a line of its own:
    // an empty panel that is empty only because of a toggle has to say so where
    // the eye already is.
    let hidden = view.denials.hidden();
    let title = if hidden > 0 {
        format!("blocked ({})  +{hidden} hidden", view.denials.shown())
    } else {
        format!("blocked ({})", view.denials.shown())
    };
    let mut lines = vec![heading(&title, focused)];

    if view.denials.is_empty() {
        // Once the stream is closed nothing more can arrive, so an empty panel
        // has stopped being a wait and become an answer.
        let note = if view.denials.is_closed() && view.reporting == Reporting::Watching {
            "nothing was blocked"
        } else {
            view.reporting.note()
        };
        lines.push(Line::from(Span::styled(
            note,
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        // The count is right-aligned against the panel edge, so the numbers line
        // up and a long address is what gets cut instead of the figure.
        let width = usize::from(area.width);
        for target in view.denials.targets() {
            let count = format!(" {}x", target.count);
            let room = width.saturating_sub(count.len()).saturating_sub(1);
            let label = truncate(&target.label, room);
            let padding = " ".repeat(room.saturating_sub(label.chars().count()));
            // A path that was missing outside the sandbox too is shown greyed:
            // it is something the command wanted and did not get, but the
            // sandbox is not the reason, and widening the profile would not
            // help.
            let (label_style, count_style) = if target.denial {
                (Style::default(), Style::default().fg(Color::Yellow))
            } else {
                (
                    Style::default().fg(Color::DarkGray),
                    Style::default().fg(Color::DarkGray),
                )
            };
            lines.push(Line::from(vec![
                Span::styled(format!(" {label}{padding}"), label_style),
                Span::styled(count, count_style),
            ]));
        }
    }

    let paragraph = Paragraph::new(lines).scroll((view.panel_scroll, 0));
    frame.render_widget(paragraph, area);
}

fn draw_history(frame: &mut Frame<'_>, view: &View<'_>, area: Rect) {
    let mut lines = vec![heading("most recent", view.focus == Focus::Recent)];
    let room = usize::from(area.height).saturating_sub(1);
    // Newest at the bottom, like any log: the eye goes to the last line. The
    // offset counts back from there rather than forward from the oldest, so a
    // list nobody has scrolled stays pinned to its newest line as they arrive.
    let recent: Vec<(String, bool)> = view
        .denials
        .recent()
        .rev()
        .skip(view.history_scroll)
        .take(room)
        .map(|(age, line, denial)| (format!(" {} {line}", ago(age)), denial))
        .collect();
    lines.extend(recent.into_iter().rev().map(|(line, denial)| {
        let colour = if denial { Color::Gray } else { Color::DarkGray };
        Line::from(Span::styled(line, Style::default().fg(colour)))
    }));

    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_context(frame: &mut Frame<'_>, view: &View<'_>, area: Rect) {
    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines: Vec<Line<'_>> = view
        .context
        .iter()
        .map(|line| {
            Line::from(Span::styled(
                line.clone(),
                Style::default().fg(Color::DarkGray),
            ))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn draw_footer(frame: &mut Frame<'_>, view: &View<'_>, area: Rect) {
    // The panel's own width, not the footer's: the footer spans the screen.
    let frame_width = frame.area().width;
    // On the mode first, and on the finished command only where the two could
    // disagree: a command that is over does not stop the person resizing the
    // panel, and the footer that says so has to survive it ending.
    let (message, style) = match view.mode {
        Mode::Confirm => (
            format!(
                "{} is still running. Stop it and leave? [y/N]",
                view.command
            ),
            Style::default().bg(Color::Red).fg(Color::White),
        ),
        Mode::Prefix => (
            format!("{}: press a command key, ? for the list", view.prefix_label),
            Style::default().bg(Color::Cyan).fg(Color::Black),
        ),
        Mode::Resize => {
            let width = panel_width(frame_width, view.panel_width);
            let how = if view.panel_width.is_some() {
                String::new()
            } else {
                " (automatic)".to_owned()
            };
            (
                format!("panel {width} columns{how} — arrows, h/l, = for automatic, Esc to return"),
                Style::default().bg(Color::Magenta).fg(Color::Black),
            )
        }
        Mode::Scroll => (
            format!(
                "scroll: {} lines back — arrows, PgUp/PgDn, Esc to return",
                view.scrollback
            ),
            Style::default().bg(Color::Yellow).fg(Color::Black),
        ),
        Mode::Help | Mode::Normal => match view.finished {
            // The keys that were the command's are the UI's now, and this is
            // where that is said — with where the view is, once it has been
            // moved, since the scroll footer is not the one on screen.
            Some(code) if view.scrollback > 0usize => (
                format!(
                    "{} exited with {code} — {} lines back │ press q, Esc or ^d to leave",
                    view.command, view.scrollback
                ),
                Style::default().bg(Color::Blue).fg(Color::White),
            ),
            Some(code) => (
                // Which list the arrows move, since the focus is the one thing
                // this footer says that the drawing does not say louder.
                format!(
                    "{} exited with {code} — press q, Esc or ^d to leave │ arrows scroll {} │ {} ? help",
                    view.command,
                    match view.focus {
                        Focus::Terminal => "the scrollback",
                        Focus::Blocked => "the blocked list",
                        Focus::Recent => "the recent list",
                    },
                    view.prefix_label
                ),
                Style::default().bg(Color::Blue).fg(Color::White),
            ),
            None => (
                format!(
                    "{} ? help │ {} │ blocked {}",
                    view.prefix_label,
                    view.focus.label(),
                    view.denials.blocked()
                ),
                Style::default().bg(Color::DarkGray).fg(Color::White),
            ),
        },
    };

    let padded = format!(" {message}");
    frame.render_widget(Paragraph::new(padded).style(style), area);
}

fn draw_help(frame: &mut Frame<'_>, view: &View<'_>) {
    let prefix = view.prefix_label;
    // Two lists, because after the command is over the keys are not the same
    // ones: nothing is left to type at, so the plain keys are the UI's own and
    // saying otherwise would send people looking for a prefix they do not need.
    let entries: Vec<String> = if view.finished.is_some() {
        vec![
            "q  Esc  ^d  leave".to_owned(),
            "arrows      read the scrollback, or whichever list has the focus".to_owned(),
            "PgUp PgDn   a screenful of it at a time".to_owned(),
            "Home  End   the far ends of it".to_owned(),
            "Tab         the terminal, the blocked list, the recent list".to_owned(),
            format!("{prefix} r        set how wide the panel is"),
            format!("{prefix} w        show or hide the panel"),
            format!("{prefix} s        show or hide what scudo decided"),
            format!("{prefix} m        show or hide paths missing outside the sandbox too"),
            "?           this list".to_owned(),
        ]
    } else {
        vec![
            format!("{prefix} q     leave, stopping the command if it still runs"),
            format!("{prefix} {prefix}    send {prefix} to the command"),
            format!("{prefix} Tab   move between the terminal and the panel's two lists"),
            format!("{prefix} PgUp  read the scrollback"),
            format!("{prefix} r     set how wide the panel is"),
            format!("{prefix} w     show or hide the panel"),
            format!("{prefix} s     show or hide what scudo decided"),
            format!("{prefix} m     show or hide paths missing outside the sandbox too"),
            format!("{prefix} ?     this list"),
        ]
    };

    let width = entries
        .iter()
        .map(|line| u16::try_from(line.chars().count()).unwrap_or(u16::MAX))
        .max()
        .unwrap_or(40u16)
        .saturating_add(4u16);
    let height = u16::try_from(entries.len())
        .unwrap_or(8u16)
        .saturating_add(2u16);
    let area = centred(frame.area(), width, height);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" scudo ");
    let inner = block.inner(area);
    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(block, area);
    let lines: Vec<Line<'_>> = entries.into_iter().map(Line::from).collect();
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

fn heading(text: &str, focused: bool) -> Line<'static> {
    let style = if focused {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    };
    Line::from(Span::styled(format!(" {text}"), style))
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
        // One row goes to the footer, whatever else is on screen.
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

    /// One line out and the tally scrolls into the space under its last line,
    /// which is the bug the count exists to prevent.
    #[test]
    fn the_tally_counts_the_heading_that_is_drawn_above_it() {
        use crate::bpfd::protocol::{FileError, FileOp, Notification, Outside};

        let refused = |path: &str| Notification::FileBlocked {
            op: FileOp::Open,
            path: path.to_owned(),
            error: FileError::Permission,
            outside: Outside::Present,
        };

        let mut denials = Denials::default();
        // Nothing yet: the heading, and the note saying why there is nothing
        // under it.
        assert_eq!(targets_lines(&denials), 2);
        denials.push(&refused("/home/me/.bashrc"), "bash");
        assert_eq!(targets_lines(&denials), 2);
        denials.push(&refused("/home/me/.profile"), "bash");
        assert_eq!(targets_lines(&denials), 3);
    }

    #[test]
    fn a_long_address_loses_its_front_rather_than_its_port() {
        assert_eq!(truncate("1.1.1.1:443", 20), "1.1.1.1:443");
        assert_eq!(truncate("averylongname.example:443", 10), "…ample:443");
    }
}
