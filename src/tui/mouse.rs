//! Passing the mouse through to the program in the terminal.
//!
//! The capture is deliberately not held all the time: while the program inside
//! has not asked for the mouse, the host terminal keeps it, and selecting and
//! copying with the mouse goes on working as it does anywhere else. The cost is
//! that such a selection takes whole screen rows, side panel included — scudo
//! is drawing one screen, and the host terminal has no notion of the columns
//! inside it.
//!
//! When the program does ask, its request says both *which* events it wants and
//! *how* it wants them spelled, and the two are independent: [`encode`] answers
//! the second, [`wants`] the first.

use ratatui::crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
use vt100::{MouseProtocolEncoding, MouseProtocolMode};

/// `true` when a program in this mode wants to hear about this event.
///
/// Sending motion to a program that only asked for presses is not harmless: it
/// arrives as a stream of unrecognised sequences and prints as rubbish.
#[must_use]
pub fn wants(mode: MouseProtocolMode, kind: MouseEventKind) -> bool {
    match mode {
        MouseProtocolMode::None => false,
        MouseProtocolMode::Press => matches!(
            kind,
            MouseEventKind::Down(_) | MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
        ),
        MouseProtocolMode::PressRelease => matches!(
            kind,
            MouseEventKind::Down(_)
                | MouseEventKind::Up(_)
                | MouseEventKind::ScrollUp
                | MouseEventKind::ScrollDown
        ),
        MouseProtocolMode::ButtonMotion => !matches!(kind, MouseEventKind::Moved),
        MouseProtocolMode::AnyMotion => true,
    }
}

/// One mouse event as the program expects to read it.
///
/// `column` and `row` are zero-based and relative to the terminal panel; the
/// wire form is one-based, which is the `+ 1` below and nothing more.
#[must_use]
pub fn encode(
    event: MouseEvent,
    mode: MouseProtocolMode,
    encoding: MouseProtocolEncoding,
    column: u16,
    row: u16,
) -> Option<Vec<u8>> {
    if !wants(mode, event.kind) {
        return None;
    }

    let released = matches!(event.kind, MouseEventKind::Up(_));
    let mut button = base_button(event.kind);
    if matches!(event.kind, MouseEventKind::Drag(_) | MouseEventKind::Moved) {
        button = button.saturating_add(32u8);
    }
    button = button.saturating_add(modifiers(event));

    let column = column.saturating_add(1);
    let row = row.saturating_add(1);

    Some(match encoding {
        // The only encoding that says which button was released, and the only
        // one without a coordinate ceiling — so it is what a modern program asks
        // for, and the other two are here for the ones that never will.
        MouseProtocolEncoding::Sgr => {
            let final_byte = if released { 'm' } else { 'M' };
            format!("\x1b[<{button};{column};{row}{final_byte}").into_bytes()
        }
        MouseProtocolEncoding::Utf8 => {
            let button = if released {
                3u16.saturating_add(modifiers(event).into())
            } else {
                button.into()
            };
            let mut bytes = b"\x1b[M".to_vec();
            push_utf8(&mut bytes, 32u16.saturating_add(button));
            push_utf8(&mut bytes, 32u16.saturating_add(column));
            push_utf8(&mut bytes, 32u16.saturating_add(row));
            bytes
        }
        MouseProtocolEncoding::Default => {
            // A single byte per field caps every coordinate at 223. Past that
            // there is nothing truthful to send, and a wrapped number would
            // point the program at the wrong cell.
            let button = if released {
                3u8.saturating_add(modifiers(event))
            } else {
                button
            };
            let column = u8::try_from(column).ok()?;
            let row = u8::try_from(row).ok()?;
            if column > 223u8 || row > 223u8 {
                return None;
            }
            vec![
                0x1b,
                b'[',
                b'M',
                32u8.saturating_add(button),
                32u8.saturating_add(column),
                32u8.saturating_add(row),
            ]
        }
    })
}

fn base_button(kind: MouseEventKind) -> u8 {
    match kind {
        MouseEventKind::Down(button)
        | MouseEventKind::Up(button)
        | MouseEventKind::Drag(button) => match button {
            MouseButton::Left => 0,
            MouseButton::Middle => 1,
            MouseButton::Right => 2,
        },
        // Motion with nothing held is reported as "button 3", the same code a
        // release uses; the added 32 is what tells them apart.
        MouseEventKind::Moved => 3u8,
        // The wheel is a second bank of buttons rather than a movement.
        MouseEventKind::ScrollUp => 64u8,
        MouseEventKind::ScrollDown => 65u8,
        MouseEventKind::ScrollLeft => 66u8,
        MouseEventKind::ScrollRight => 67u8,
    }
}

fn modifiers(event: MouseEvent) -> u8 {
    use ratatui::crossterm::event::KeyModifiers;
    let mut bits = 0u8;
    if event.modifiers.contains(KeyModifiers::SHIFT) {
        bits = bits.saturating_add(4u8);
    }
    if event.modifiers.contains(KeyModifiers::ALT) {
        bits = bits.saturating_add(8u8);
    }
    if event.modifiers.contains(KeyModifiers::CONTROL) {
        bits = bits.saturating_add(16u8);
    }
    bits
}

fn push_utf8(bytes: &mut Vec<u8>, value: u16) {
    match char::from_u32(value.into()) {
        Some(c) => {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
        None => bytes.push(b'?'),
    }
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::KeyModifiers;

    use super::*;

    fn event(kind: MouseEventKind) -> MouseEvent {
        MouseEvent {
            kind,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[test]
    fn sgr_names_the_button_and_says_which_way_round() {
        let press = encode(
            event(MouseEventKind::Down(MouseButton::Left)),
            MouseProtocolMode::PressRelease,
            MouseProtocolEncoding::Sgr,
            9,
            4,
        )
        .expect("a press is encodable");
        assert_eq!(press, b"\x1b[<0;10;5M".to_vec());

        // The release keeps the button and changes the final byte; that is the
        // whole reason a program asks for SGR.
        let release = encode(
            event(MouseEventKind::Up(MouseButton::Left)),
            MouseProtocolMode::PressRelease,
            MouseProtocolEncoding::Sgr,
            9,
            4,
        )
        .expect("a release is encodable");
        assert_eq!(release, b"\x1b[<0;10;5m".to_vec());
    }

    #[test]
    fn the_wheel_is_its_own_pair_of_buttons() {
        let up = encode(
            event(MouseEventKind::ScrollUp),
            MouseProtocolMode::Press,
            MouseProtocolEncoding::Sgr,
            0,
            0,
        )
        .expect("a wheel event is encodable");
        assert_eq!(up, b"\x1b[<64;1;1M".to_vec());
    }

    #[test]
    fn a_drag_is_a_press_with_the_motion_bit_set() {
        let drag = encode(
            event(MouseEventKind::Drag(MouseButton::Left)),
            MouseProtocolMode::ButtonMotion,
            MouseProtocolEncoding::Sgr,
            0,
            0,
        )
        .expect("a drag is encodable");
        assert_eq!(drag, b"\x1b[<32;1;1M".to_vec());
    }

    /// Sending more than was asked for prints as rubbish in the program.
    #[test]
    fn a_mode_only_hears_what_it_asked_for() {
        assert!(!wants(
            MouseProtocolMode::Press,
            MouseEventKind::Up(MouseButton::Left)
        ));
        assert!(!wants(
            MouseProtocolMode::ButtonMotion,
            MouseEventKind::Moved
        ));
        assert!(wants(MouseProtocolMode::AnyMotion, MouseEventKind::Moved));
        assert!(!wants(
            MouseProtocolMode::None,
            MouseEventKind::Down(MouseButton::Left)
        ));
        assert_eq!(
            encode(
                event(MouseEventKind::Down(MouseButton::Left)),
                MouseProtocolMode::None,
                MouseProtocolEncoding::Sgr,
                0,
                0
            ),
            None
        );
    }

    /// Past 223 the oldest encoding has no honest answer, so it gives none.
    #[test]
    fn the_original_encoding_stops_rather_than_pointing_at_the_wrong_cell() {
        assert_eq!(
            encode(
                event(MouseEventKind::Down(MouseButton::Left)),
                MouseProtocolMode::Press,
                MouseProtocolEncoding::Default,
                300,
                0
            ),
            None
        );
        let near = encode(
            event(MouseEventKind::Down(MouseButton::Left)),
            MouseProtocolMode::Press,
            MouseProtocolEncoding::Default,
            9,
            4,
        )
        .expect("a modest coordinate is encodable");
        assert_eq!(near, vec![0x1b, b'[', b'M', 32, 42, 37]);
    }
}
