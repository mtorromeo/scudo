//! The colours the UI draws itself in.
//!
//! **Written, not derived.** scudo already knows what colour the host terminal
//! is — [`query::Host`](super::query::Host) asks it at start-up so the answer can
//! be repeated to programs that ask the same — and shading the panel from that
//! answer was the obvious thing to do and the wrong one. The panel's whole job is
//! to be *distinguishable* from the command's terminal beside it, and a panel
//! that follows the host's background is the one thing it cannot be. So the theme
//! is chosen here, once, and the command's terminal is the only part of the
//! screen left unpainted: what shows through it is the host's own background,
//! which is exactly the contrast the panel is after.
//!
//! **What the host does decide is how many colours there are to say it in.** The
//! same theme is therefore written three times over, and [`Depth`] picks between
//! them. The two lower ones are not a degraded afterthought: an indexed terminal
//! gets the same layout in the nearest greys the 256-colour cube has, and a
//! sixteen-colour one keeps its filled headings and status bar in the one blue
//! every palette has, and gives up only the panel's own ground — deliberately,
//! because the only ground available there is `Black`, which is invisible on half
//! the themes in use and unreadable on the other half.
//!
//! Nothing here uses `REVERSED`. It is the obvious way to fill a bar without
//! naming a colour, and it composes wrongly: a modifier set on a paragraph is
//! merged into every span drawn over it, so one reversed bar turns each span's
//! carefully chosen foreground into a background.

use ratatui::style::{Color, Modifier, Style};

/// How many colours the terminal scudo draws on can actually show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// Twenty-four bits: the theme as written.
    TrueColor,
    /// The 256-colour cube, which every theme role has a near neighbour in.
    Indexed,
    /// Eight or sixteen, where the only honest background is none.
    Ansi,
}

impl Depth {
    /// What the environment says the terminal can do.
    #[must_use]
    pub fn detect() -> Self {
        Depth::from_env(
            std::env::var("COLORTERM").ok().as_deref(),
            std::env::var("TERM").ok().as_deref(),
        )
    }

    /// The decision itself, kept apart from where the two strings came from:
    /// setting an environment variable is `unsafe` in this edition and shared
    /// with every other test in the binary, so the tests call this instead.
    #[must_use]
    pub fn from_env(colorterm: Option<&str>, term: Option<&str>) -> Self {
        // The only two values anyone sends, and the only reliable statement a
        // terminal makes about truecolour: there is no terminfo capability for
        // it that is filled in widely enough to use.
        if matches!(colorterm, Some("truecolor" | "24bit")) {
            return Depth::TrueColor;
        }
        let term = term.unwrap_or_default();
        if term.contains("256color") || term.contains("direct") {
            return Depth::Indexed;
        }
        Depth::Ansi
    }
}

/// Every colour the drawing is allowed to use.
///
/// The fields that carry a background are [`Style`]s rather than [`Color`]s
/// because that is how they are used: rendering one over a rect is what paints
/// the panel, and splitting them into a foreground and a background here would
/// only mean putting them back together at every call site.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// The ground the panel, the context area and the help are drawn on. The
    /// command's terminal is never given this: it keeps the host's.
    pub panel: Style,
    /// A section heading, which is a filled bar rather than a line of bold text
    /// so that it cannot be mistaken for the first row of its own list.
    pub header: Style,
    /// The same bar, for the section the keyboard is talking to.
    pub header_focused: Style,
    pub footer: Style,
    pub text: Color,
    /// Ages, notes, and paths that were missing outside the sandbox too.
    pub dim: Color,
    pub border: Color,
    /// Focus, the active border, and the keys in the help.
    pub accent: Color,
    /// The counts beside a refusal.
    pub warn: Color,
    /// Only the question about stopping a running command.
    pub danger: Color,
    /// A command that is over.
    pub ok: Color,
    /// The resize mode, which is neither good news nor bad.
    pub alt: Color,
    /// What to write on top of a fill in one of the accents above — a badge in
    /// the status bar. Named rather than reversed out of the accent for the
    /// reason in the module note.
    pub on_accent: Color,
}

impl Theme {
    /// The theme in as many colours as this terminal has.
    #[must_use]
    pub fn detect() -> Self {
        match Depth::detect() {
            Depth::TrueColor => TRUE_COLOR,
            Depth::Indexed => INDEXED,
            Depth::Ansi => ANSI,
        }
    }
}

/// A cool, dark ground with warm accents kept for the two things worth
/// interrupting a reader over: what was refused, and what is about to be killed.
const TRUE_COLOR: Theme = Theme {
    panel: Style::new()
        .bg(Color::Rgb(0x22, 0x24, 0x2f))
        .fg(Color::Rgb(0xc0, 0xca, 0xf5)),
    header: Style::new()
        .bg(Color::Rgb(0x2c, 0x30, 0x40))
        .fg(Color::Rgb(0xa9, 0xb1, 0xd6))
        .add_modifier(Modifier::BOLD),
    header_focused: Style::new()
        .bg(Color::Rgb(0x2c, 0x30, 0x40))
        .fg(Color::Rgb(0x7a, 0xa2, 0xf7))
        .add_modifier(Modifier::BOLD),
    footer: Style::new()
        .bg(Color::Rgb(0x1c, 0x1e, 0x29))
        .fg(Color::Rgb(0xa9, 0xb1, 0xd6)),
    text: Color::Rgb(0xc0, 0xca, 0xf5),
    dim: Color::Rgb(0x6b, 0x73, 0x94),
    border: Color::Rgb(0x3b, 0x42, 0x61),
    accent: Color::Rgb(0x7a, 0xa2, 0xf7),
    warn: Color::Rgb(0xe0, 0xaf, 0x68),
    danger: Color::Rgb(0xf7, 0x76, 0x8e),
    ok: Color::Rgb(0x9e, 0xce, 0x6a),
    alt: Color::Rgb(0xbb, 0x9a, 0xf7),
    on_accent: Color::Rgb(0x1a, 0x1b, 0x26),
};

/// The same theme in the nearest neighbours the 256-colour cube has.
const INDEXED: Theme = Theme {
    panel: Style::new().bg(Color::Indexed(235)).fg(Color::Indexed(189)),
    header: Style::new()
        .bg(Color::Indexed(237))
        .fg(Color::Indexed(146))
        .add_modifier(Modifier::BOLD),
    header_focused: Style::new()
        .bg(Color::Indexed(237))
        .fg(Color::Indexed(111))
        .add_modifier(Modifier::BOLD),
    footer: Style::new().bg(Color::Indexed(234)).fg(Color::Indexed(146)),
    text: Color::Indexed(189),
    dim: Color::Indexed(103),
    border: Color::Indexed(60),
    accent: Color::Indexed(111),
    warn: Color::Indexed(179),
    danger: Color::Indexed(210),
    ok: Color::Indexed(149),
    alt: Color::Indexed(141),
    on_accent: Color::Indexed(234),
};

/// Sixteen colours. The panel keeps the host's ground, since there is no colour
/// here that is reliably a shade of it; the bars that have to be bars are filled
/// in blue, which is what every full-screen program on a sixteen-colour terminal
/// has always done and which reads on a light theme and a dark one alike.
const ANSI: Theme = Theme {
    panel: Style::new(),
    header: Style::new()
        .bg(Color::Blue)
        .fg(Color::White)
        .add_modifier(Modifier::BOLD),
    header_focused: Style::new()
        .bg(Color::Cyan)
        .fg(Color::Black)
        .add_modifier(Modifier::BOLD),
    footer: Style::new().bg(Color::Blue).fg(Color::White),
    text: Color::Reset,
    dim: Color::DarkGray,
    border: Color::DarkGray,
    accent: Color::Cyan,
    warn: Color::Yellow,
    danger: Color::Red,
    ok: Color::Green,
    alt: Color::Magenta,
    on_accent: Color::Black,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truecolour_is_claimed_rather_than_guessed_at() {
        assert_eq!(
            Depth::from_env(Some("truecolor"), Some("xterm")),
            Depth::TrueColor
        );
        assert_eq!(
            Depth::from_env(Some("24bit"), Some("xterm")),
            Depth::TrueColor
        );
    }

    /// The terminal name is the fallback, and an empty `COLORTERM` — which the
    /// integration tests set, and which a login shell can leave behind — is not
    /// a claim of anything.
    #[test]
    fn the_terminal_name_decides_when_nothing_was_claimed() {
        assert_eq!(
            Depth::from_env(None, Some("xterm-256color")),
            Depth::Indexed
        );
        assert_eq!(
            Depth::from_env(Some(""), Some("xterm-direct")),
            Depth::Indexed
        );
        assert_eq!(Depth::from_env(Some(""), Some("xterm")), Depth::Ansi);
        assert_eq!(Depth::from_env(None, None), Depth::Ansi);
    }

    /// The lower two levels are the same theme, not a subset of it: two roles
    /// that fell together on one of them would be a distinction the UI relies on
    /// that vanishes on a terminal nobody tested it on.
    #[test]
    fn every_level_keeps_the_distinctions_the_drawing_relies_on() {
        for theme in [TRUE_COLOR, INDEXED, ANSI] {
            // What is dimmed has to read as dimmer than what is not, and the
            // four accents have to be four colours.
            assert_ne!(theme.dim, theme.text);
            for pair in [
                (theme.accent, theme.warn),
                (theme.accent, theme.danger),
                (theme.accent, theme.ok),
                (theme.accent, theme.alt),
                (theme.warn, theme.danger),
                (theme.danger, theme.ok),
            ] {
                assert_ne!(pair.0, pair.1);
            }
            // A heading has to be a filled bar however few colours there are,
            // or it reads as the first row of its own list.
            assert!(theme.header.bg.is_some(), "a heading that is not filled");
            assert!(theme.footer.bg.is_some(), "a status bar that is not filled");
            assert_ne!(theme.header_focused, theme.header);
            // Nothing may be reversed: see the module note on why it composes
            // wrongly with the spans drawn over it.
            for style in [
                theme.panel,
                theme.header,
                theme.header_focused,
                theme.footer,
            ] {
                assert!(!style.add_modifier.contains(Modifier::REVERSED));
            }
        }
    }

    /// The panel is the one thing that must not be the host's colour, except
    /// where there is no colour to be had.
    #[test]
    fn only_the_sixteen_colour_level_leaves_the_ground_alone() {
        assert!(TRUE_COLOR.panel.bg.is_some());
        assert!(INDEXED.panel.bg.is_some());
        assert!(ANSI.panel.bg.is_none());
    }
}
