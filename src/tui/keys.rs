//! Turning what the outer terminal reports back into what a terminal sends.
//!
//! crossterm decodes the bytes the host terminal produced into events; the
//! command on the other side of the pty expects those bytes, not the events. So
//! everything crossterm parsed has to be put back together here, and it has to
//! be put back together the way the program inside currently asks for — which
//! is why [`encode`] is handed the screen: cursor keys change shape when a
//! program enables the application cursor mode, and `less`, `vim` and bash's
//! own line editor all do.

use anyhow::{Result, bail};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// A key named in the config, such as the UI prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySpec {
    code: KeyCode,
    modifiers: KeyModifiers,
}

impl KeySpec {
    /// `true` when `event` is this key. Only the modifiers that were named are
    /// required to match, so `C-a` is not defeated by a stray shift.
    #[must_use]
    pub fn matches(self, event: &KeyEvent) -> bool {
        event.code == self.code && event.modifiers.contains(self.modifiers)
    }

    /// How this key reads back, for the help line and the status bar.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "a key with no shorter name reads well enough as its own"
    )]
    #[must_use]
    pub fn label(&self) -> String {
        let mut label = String::new();
        if self.modifiers.contains(KeyModifiers::CONTROL) {
            label.push('^');
        }
        if self.modifiers.contains(KeyModifiers::ALT) {
            label.push_str("M-");
        }
        match self.code {
            KeyCode::Char(c) => label.push(c.to_ascii_uppercase()),
            KeyCode::F(n) => {
                label.push('F');
                label.push_str(&n.to_string());
            }
            // Named after the variant, which is what a person would write in
            // the config anyway: `Esc`, `Tab`, `Home`.
            other => label.push_str(match other {
                KeyCode::Enter => "Enter",
                KeyCode::Tab => "Tab",
                KeyCode::Esc => "Esc",
                KeyCode::Backspace => "Backspace",
                KeyCode::Delete => "Delete",
                KeyCode::Insert => "Insert",
                KeyCode::Home => "Home",
                KeyCode::End => "End",
                KeyCode::PageUp => "PageUp",
                KeyCode::PageDown => "PageDown",
                KeyCode::Up => "Up",
                KeyCode::Down => "Down",
                KeyCode::Left => "Left",
                KeyCode::Right => "Right",
                _ => "?",
            }),
        }
        label
    }

    /// The bytes this key would have sent, for passing the prefix through when
    /// it is typed twice.
    #[must_use]
    pub fn passthrough(self, application_cursor: bool) -> Vec<u8> {
        let event = KeyEvent::new(self.code, self.modifiers);
        encode(&event, application_cursor).unwrap_or_default()
    }
}

/// Parse a key as written in the config: `C-a`, `M-x`, `F12`, `Space`.
pub fn parse_key_spec(spec: &str) -> Result<KeySpec> {
    let mut modifiers = KeyModifiers::NONE;
    let mut rest = spec.trim();

    loop {
        let (prefix, modifier) = if let Some(rest) = rest.strip_prefix("C-") {
            (rest, KeyModifiers::CONTROL)
        } else if let Some(rest) = rest.strip_prefix("M-") {
            (rest, KeyModifiers::ALT)
        } else if let Some(rest) = rest.strip_prefix("S-") {
            (rest, KeyModifiers::SHIFT)
        } else {
            break;
        };
        modifiers |= modifier;
        rest = prefix;
    }

    if rest.is_empty() {
        bail!("'{spec}' names modifiers but no key");
    }

    let code = match rest {
        "Space" | "space" => KeyCode::Char(' '),
        "Enter" | "enter" => KeyCode::Enter,
        "Tab" | "tab" => KeyCode::Tab,
        "Esc" | "esc" => KeyCode::Esc,
        other => match other.strip_prefix(['F', 'f']) {
            Some(number) if number.chars().all(|c| c.is_ascii_digit()) => {
                KeyCode::F(number.parse().unwrap_or(1u8))
            }
            _ => {
                let mut chars = other.chars();
                match (chars.next(), chars.next()) {
                    (Some(c), None) => KeyCode::Char(c.to_ascii_lowercase()),
                    _ => bail!("'{spec}' is not a key scudo knows how to read"),
                }
            }
        },
    };

    // A bare key would swallow itself: every press of it would open the UI
    // instead of reaching the command, and there would be no way to type it.
    if modifiers.is_empty() && matches!(code, KeyCode::Char(_)) {
        bail!("'{spec}' would take a plain character away from the command; name a modifier");
    }

    Ok(KeySpec { code, modifiers })
}

/// The bytes for one key press, or `None` for a key that sends nothing.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "a key a terminal has no sequence for sends nothing, and there are many"
)]
#[must_use]
pub fn encode(event: &KeyEvent, application_cursor: bool) -> Option<Vec<u8>> {
    // A release is not an input; without this every key would arrive twice on
    // terminals that report both.
    if matches!(event.kind, KeyEventKind::Release) {
        return None;
    }

    let ctrl = event.modifiers.contains(KeyModifiers::CONTROL);
    let alt = event.modifiers.contains(KeyModifiers::ALT);
    let modifier = modifier_code(event.modifiers);

    let bytes = match event.code {
        KeyCode::Char(c) => {
            let mut bytes = if ctrl {
                control_byte(c)
            } else {
                let mut buf = [0u8; 4];
                c.encode_utf8(&mut buf).as_bytes().to_vec()
            };
            // Meta is a prefixed escape: that is what "Alt sends escape" means.
            if alt {
                bytes.insert(0, 0x1b);
            }
            bytes
        }
        KeyCode::Enter => b"\r".to_vec(),
        KeyCode::Tab => b"\t".to_vec(),
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Backspace => b"\x7f".to_vec(),
        KeyCode::Esc => b"\x1b".to_vec(),
        KeyCode::Up => cursor_key(b'A', application_cursor, modifier),
        KeyCode::Down => cursor_key(b'B', application_cursor, modifier),
        KeyCode::Right => cursor_key(b'C', application_cursor, modifier),
        KeyCode::Left => cursor_key(b'D', application_cursor, modifier),
        KeyCode::Home => cursor_key(b'H', application_cursor, modifier),
        KeyCode::End => cursor_key(b'F', application_cursor, modifier),
        KeyCode::Insert => tilde_key(2u8, modifier),
        KeyCode::Delete => tilde_key(3u8, modifier),
        KeyCode::PageUp => tilde_key(5u8, modifier),
        KeyCode::PageDown => tilde_key(6u8, modifier),
        KeyCode::F(n) => function_key(n, modifier)?,
        _ => return None,
    };
    Some(bytes)
}

/// Wrap pasted text the way the program asked to receive it.
///
/// Without the brackets a shell runs every newline in the paste as a command,
/// which is the difference between pasting a script and executing it.
#[must_use]
pub fn encode_paste(text: &str, bracketed: bool) -> Vec<u8> {
    // The terminal's own line ending, or a multi-line paste arrives as one line.
    let text = text.replace('\n', "\r");
    if bracketed {
        format!("\x1b[200~{text}\x1b[201~").into_bytes()
    } else {
        text.into_bytes()
    }
}

/// The xterm modifier parameter: 1 plus a bit per modifier held.
fn modifier_code(modifiers: KeyModifiers) -> u8 {
    let mut code = 1u8;
    if modifiers.contains(KeyModifiers::SHIFT) {
        code = code.saturating_add(1);
    }
    if modifiers.contains(KeyModifiers::ALT) {
        code = code.saturating_add(2);
    }
    if modifiers.contains(KeyModifiers::CONTROL) {
        code = code.saturating_add(4);
    }
    code
}

/// Control characters are the letter's low five bits — `Ctrl-A` is 1 because
/// `a` is 0x61.
fn control_byte(c: char) -> Vec<u8> {
    let byte = match c {
        'a'..='z' => (c as u8).wrapping_sub(0x60),
        'A'..='Z' => (c as u8).wrapping_sub(0x40),
        '@' | ' ' => 0,
        '[' => 0x1b,
        '\\' => 0x1c,
        ']' => 0x1d,
        '^' => 0x1e,
        '_' | '/' => 0x1f,
        '?' => 0x7f,
        // Ctrl with anything else is the character itself: that is what a
        // terminal does, rather than dropping the key.
        _ => {
            let mut buf = [0u8; 4];
            return c.encode_utf8(&mut buf).as_bytes().to_vec();
        }
    };
    vec![byte]
}

/// `CSI A` normally, `SS3 A` in application cursor mode, and always `CSI 1;m A`
/// once a modifier is held — the application form has nowhere to put one.
fn cursor_key(final_byte: u8, application_cursor: bool, modifier: u8) -> Vec<u8> {
    if modifier > 1u8 {
        return format!("\x1b[1;{modifier}{}", final_byte as char).into_bytes();
    }
    if application_cursor {
        vec![0x1b, b'O', final_byte]
    } else {
        vec![0x1b, b'[', final_byte]
    }
}

fn tilde_key(number: u8, modifier: u8) -> Vec<u8> {
    if modifier > 1u8 {
        format!("\x1b[{number};{modifier}~").into_bytes()
    } else {
        format!("\x1b[{number}~").into_bytes()
    }
}

fn function_key(n: u8, modifier: u8) -> Option<Vec<u8>> {
    // F1 to F4 are SS3 keys; the rest are numbered CSI keys, and the numbers
    // skip 16 and 22 for reasons that predate all of this.
    let letter = match n {
        1u8 => Some(b'P'),
        2u8 => Some(b'Q'),
        3u8 => Some(b'R'),
        4u8 => Some(b'S'),
        _ => None,
    };
    if let Some(letter) = letter {
        if modifier > 1u8 {
            return Some(format!("\x1b[1;{modifier}{}", letter as char).into_bytes());
        }
        return Some(vec![0x1b, b'O', letter]);
    }
    let number = match n {
        5u8 => 15u8,
        6u8 => 17u8,
        7u8 => 18u8,
        8u8 => 19u8,
        9u8 => 20u8,
        10u8 => 21u8,
        11u8 => 23u8,
        12u8 => 24u8,
        _ => return None,
    };
    Some(tilde_key(number, modifier))
}

#[cfg(test)]
#[expect(
    clippy::assertions_on_result_states,
    reason = "whether the key parsed is the whole assertion"
)]
mod tests {
    use super::*;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    fn bytes(code: KeyCode, modifiers: KeyModifiers, application_cursor: bool) -> Vec<u8> {
        encode(&key(code, modifiers), application_cursor).expect("a key that sends something")
    }

    #[test]
    fn a_letter_is_itself_and_control_takes_its_low_bits() {
        assert_eq!(bytes(KeyCode::Char('a'), KeyModifiers::NONE, false), b"a");
        assert_eq!(
            bytes(KeyCode::Char('c'), KeyModifiers::CONTROL, false),
            b"\x03"
        );
        // Ctrl-Z has to reach the command, or a shell inside could not suspend.
        assert_eq!(
            bytes(KeyCode::Char('z'), KeyModifiers::CONTROL, false),
            b"\x1a"
        );
    }

    #[test]
    fn alt_is_an_escape_in_front() {
        assert_eq!(
            bytes(KeyCode::Char('x'), KeyModifiers::ALT, false),
            b"\x1bx"
        );
    }

    /// The one that breaks arrow keys inside `less` and `vim` when it is wrong.
    #[test]
    fn cursor_keys_change_shape_in_application_mode() {
        assert_eq!(bytes(KeyCode::Up, KeyModifiers::NONE, false), b"\x1b[A");
        assert_eq!(bytes(KeyCode::Up, KeyModifiers::NONE, true), b"\x1bOA");
        // With a modifier there is only one form, whatever the mode.
        assert_eq!(
            bytes(KeyCode::Right, KeyModifiers::CONTROL, true),
            b"\x1b[1;5C"
        );
    }

    #[test]
    fn the_numbered_keys_keep_their_odd_numbering() {
        assert_eq!(bytes(KeyCode::F(1), KeyModifiers::NONE, false), b"\x1bOP");
        assert_eq!(bytes(KeyCode::F(5), KeyModifiers::NONE, false), b"\x1b[15~");
        assert_eq!(
            bytes(KeyCode::F(12), KeyModifiers::NONE, false),
            b"\x1b[24~"
        );
        assert_eq!(
            bytes(KeyCode::PageUp, KeyModifiers::NONE, false),
            b"\x1b[5~"
        );
    }

    #[test]
    fn a_release_sends_nothing_so_no_key_arrives_twice() {
        let mut event = key(KeyCode::Char('a'), KeyModifiers::NONE);
        event.kind = KeyEventKind::Release;
        assert_eq!(encode(&event, false), None);
    }

    /// Pasting a script must not run it line by line.
    #[test]
    fn a_paste_is_bracketed_when_the_program_asked_for_it() {
        assert_eq!(
            encode_paste("one\ntwo", true),
            b"\x1b[200~one\rtwo\x1b[201~".to_vec()
        );
        assert_eq!(encode_paste("one\ntwo", false), b"one\rtwo".to_vec());
    }

    #[test]
    fn a_prefix_is_read_the_way_it_is_written() {
        let spec = parse_key_spec("C-a").expect("a valid prefix");
        assert!(spec.matches(&key(KeyCode::Char('a'), KeyModifiers::CONTROL)));
        assert!(!spec.matches(&key(KeyCode::Char('a'), KeyModifiers::NONE)));
        assert_eq!(spec.label(), "^A");
        assert_eq!(spec.passthrough(false), b"\x01");

        assert!(parse_key_spec("F12").is_ok());
        assert!(parse_key_spec("M-x").is_ok());
    }

    /// A prefix with no modifier would eat a printable character for good.
    #[test]
    fn a_bare_character_is_refused_as_a_prefix() {
        let err = parse_key_spec("a").expect_err("a bare letter must be refused");
        assert!(err.to_string().contains("name a modifier"), "{err}");
        assert!(parse_key_spec("C-").is_err());
        assert!(parse_key_spec("Nonsense").is_err());
    }
}
