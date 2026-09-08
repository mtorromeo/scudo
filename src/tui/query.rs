//! Answering the terminal queries a program inside the UI makes.
//!
//! In every other mode the command talks to a real terminal. Here it talks to
//! scudo, which draws a `vt100` screen — and a parser answers nothing, because
//! it has nobody to answer *for*. A program that asks a question therefore
//! waits out its own timeout, every time, for something that is never coming.
//!
//! **The queries are recognised by their shape, not by their bytes.** What is
//! parsed here is the two control-sequence forms a query can take, `CSI` and
//! `OSC`; what is answered is decided afterwards, from what the sequence says.
//! Matching literal strings would work for whichever program was in front of us
//! when this was written and for no other.
//!
//! Which answers are scudo's to give follows from who is really being asked:
//!
//! * **Capabilities are scudo's.** The program is talking to this emulator, not
//!   to the terminal underneath, so `DA` and `DSR` are answered from what this
//!   emulator actually is. Repeating the host's capabilities would promise
//!   things `vt100` does not draw.
//! * **Colours are the host's.** scudo draws on the host's screen, so its
//!   background really is the host's background. Those are asked once at
//!   start-up and repeated.
//!
//! Anything else goes unanswered, exactly as it would on a terminal that does
//! not implement it — and that is not a hole, because of what `DA` is *for*.
//! The convention every one of these probes follows is to send its questions
//! and then a `DA` behind them as a fence: `DA` is answered last, so its answer
//! means the earlier ones have arrived or are not coming. Answering the fence
//! is what lets a program stop waiting, whether or not we knew the rest.
//!
//! **The host's answers cannot simply be relayed as they arrive.** `crossterm`
//! owns the terminal scudo reads from and turns it into key events, so an
//! answer coming back that way is no longer a sequence anyone could forward.
//! That is why the host is asked once, at start-up, before the input thread
//! exists.

use core::time::Duration;
use std::{
    fs::File,
    io::{IsTerminal as _, Read as _, Write},
    os::fd::{AsFd as _, AsRawFd as _},
};

/// The longest a control sequence may be before we stop waiting for its end.
///
/// An `OSC` carrying a window title is the long one in practice. Past this the
/// sequence is treated as noise rather than kept for ever, which is what stops
/// a program printing binary from growing the buffer without bound.
const MAX_SEQUENCE: usize = 4096;

/// How long to wait for the host terminal to answer at start-up.
///
/// Paid once, and only until the terminal replies — which is at once when it is
/// going to. `DA` is sent behind the colour questions for the same reason
/// everyone else sends it: its answer is the signal to stop waiting.
const REPLY_TIMEOUT: Duration = Duration::from_millis(250);

/// What this emulator says it is: a VT100 with the advanced video option.
///
/// Deliberately modest. It describes `vt100`, which is what the command's
/// output is actually drawn by — claiming the host's attributes would invite a
/// program to use what the host can do and this cannot draw.
const DA1_ANSWER: &[u8] = b"\x1b[?1;2c";

/// Secondary attributes: an unidentified terminal at version zero. There is no
/// honest answer with more in it.
const DA2_ANSWER: &[u8] = b"\x1b[>0;0;0c";

/// Device status: working.
const STATUS_ANSWER: &[u8] = b"\x1b[0n";

/// A question a program asked its terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Query {
    /// `CSI c` — what kind of terminal is this?
    PrimaryAttributes,
    /// `CSI > c` — and which version?
    SecondaryAttributes,
    /// `CSI 5 n` — are you working?
    Status,
    /// `CSI 6 n` — where is the cursor?
    CursorPosition,
    /// `OSC <n> ; ?` — what colour is your foreground, background, cursor?
    Colour(u16),
}

/// What the host terminal said about itself, ready to be repeated.
#[derive(Debug, Default, Clone)]
pub struct Host {
    /// Replies by `OSC` number, kept whole and unparsed: they are only ever
    /// handed on, and taking them apart could only lose something.
    colours: Vec<(u16, Vec<u8>)>,
}

/// The colour questions worth asking the host: foreground, background, cursor.
const COLOURS: [u16; 3] = [10, 11, 12];

impl Host {
    /// Ask the terminal scudo draws on what colour it is.
    ///
    /// Must be called with the terminal already in raw mode, or the answer sits
    /// in the line discipline waiting for a newline nobody is going to send —
    /// and before the input thread exists, or the two would race for it.
    #[must_use]
    pub fn ask() -> Self {
        Host {
            colours: ask_host(),
        }
    }

    /// The reply to one query, if there is one to give.
    fn reply_to(&self, query: Query, parser: &vt100::Parser) -> Option<Vec<u8>> {
        match query {
            Query::PrimaryAttributes => Some(DA1_ANSWER.to_vec()),
            Query::SecondaryAttributes => Some(DA2_ANSWER.to_vec()),
            Query::Status => Some(STATUS_ANSWER.to_vec()),
            Query::CursorPosition => {
                let (row, col) = parser.screen().cursor_position();
                // The report is one-based, and the screen counts from zero.
                Some(
                    format!(
                        "\x1b[{};{}R",
                        u32::from(row).saturating_add(1),
                        u32::from(col).saturating_add(1)
                    )
                    .into_bytes(),
                )
            }
            Query::Colour(number) => self
                .colours
                .iter()
                .find(|&&(asked, _)| asked == number)
                .map(|(_, reply)| reply.clone()),
        }
    }
}

/// Scans the command's output for questions and answers them.
///
/// It keeps the tail of the stream, because a sequence is written in pieces
/// often enough that assuming otherwise would work in every test and fail in
/// use — `bat` sends the introducer and its terminator in separate writes.
#[derive(Debug, Default)]
pub struct Answerer {
    pending: Vec<u8>,
}

impl Answerer {
    /// Answer whatever `output` asked, writing to the terminal it came from.
    ///
    /// The screen is fed first, so an answer about the screen describes it as
    /// the command last left it. A program that asks where the cursor is then
    /// waits for the reply, so there is nothing else in flight to be wrong
    /// about.
    pub fn answer<W: Write>(
        &mut self,
        output: &[u8],
        host: &Host,
        parser: &vt100::Parser,
        to: &mut W,
    ) {
        self.pending.extend_from_slice(output);
        let mut replies: Vec<u8> = Vec::new();

        loop {
            match next_sequence(&self.pending) {
                // A complete sequence: answer it if it asked something, and in
                // either case step over it.
                Found::Sequence { end, query } => {
                    if let Some(query) = query
                        && let Some(reply) = host.reply_to(query, parser)
                    {
                        replies.extend_from_slice(&reply);
                    }
                    self.pending.drain(..end);
                }
                // Still arriving: keep it and wait for the rest.
                Found::Partial { start } => {
                    self.pending.drain(..start);
                    break;
                }
                // Nothing that could become one.
                Found::None => {
                    self.pending.clear();
                    break;
                }
            }
        }
        // Overlong means malformed or not a sequence at all; keeping it would
        // only stop everything after it from being seen.
        if self.pending.len() > MAX_SEQUENCE {
            self.pending.clear();
        }

        if !replies.is_empty() {
            // A failed write means the command has gone, which the reader
            // notices on its own; there is nothing to do about it here.
            drop(to.write_all(&replies).and_then(|()| to.flush()));
        }
    }
}

/// What scanning the buffer turned up.
enum Found {
    /// A whole sequence ending at `end`, asking `query` if it asked anything.
    Sequence { end: usize, query: Option<Query> },
    /// A sequence that starts at `start` and has not finished arriving.
    Partial { start: usize },
    /// Nothing here is or could become a sequence.
    None,
}

/// The first control sequence in `buffer`, complete or not.
fn next_sequence(buffer: &[u8]) -> Found {
    let Some(start) = buffer.iter().position(|&byte| byte == 0x1b) else {
        return Found::None;
    };
    let Some(rest) = buffer.get(start.saturating_add(1)..) else {
        return Found::None;
    };
    match rest.first() {
        Some(&b'[') => match csi_end(rest) {
            Some(csi) => Found::Sequence {
                end: start.saturating_add(1).saturating_add(csi.end),
                query: csi_query(csi.params, csi.final_byte),
            },
            None => Found::Partial { start },
        },
        Some(&b']') => match osc_end(rest) {
            Some((end, query)) => Found::Sequence {
                end: start.saturating_add(1).saturating_add(end),
                query,
            },
            None => Found::Partial { start },
        },
        // Some other escape sequence, or one whose second byte has not arrived.
        // Either way there is nothing here to answer; step over the escape so
        // the scan can go on.
        Some(_) => Found::Sequence {
            end: start.saturating_add(2),
            query: None,
        },
        None => Found::Partial { start },
    }
}

/// A `CSI` sequence taken apart: where it ends, what its parameters were, and
/// the byte that names it.
struct Csi<'a> {
    end: usize,
    params: &'a [u8],
    final_byte: u8,
}

/// Where a `CSI` sequence ends, and what it holds.
///
/// `rest` starts at the `[`. A `CSI` runs to the first byte in `0x40..=0x7e`,
/// which names it; everything before is parameters and intermediates. What it
/// means is the caller's business — a question and its answer share this shape
/// and differ only in the detail.
fn csi_end(rest: &[u8]) -> Option<Csi<'_>> {
    let body = rest.get(1..)?;
    let final_at = body
        .iter()
        .take(MAX_SEQUENCE)
        .position(|&byte| (0x40..=0x7e).contains(&byte))?;
    Some(Csi {
        // +2: the `[` and the final byte itself.
        end: final_at.saturating_add(2),
        params: body.get(..final_at)?,
        final_byte: *body.get(final_at)?,
    })
}

/// What a `CSI` sequence asked, if it asked anything.
fn csi_query(params: &[u8], final_byte: u8) -> Option<Query> {
    match final_byte {
        b'c' => match params.first() {
            // `CSI c` and `CSI 0 c` are the same question.
            None | Some(&b'0') => Some(Query::PrimaryAttributes),
            Some(&b'>') => Some(Query::SecondaryAttributes),
            // `CSI = c` asks for a unit id, which this has none of.
            Some(_) => None,
        },
        b'n' => match params {
            b"5" => Some(Query::Status),
            b"6" => Some(Query::CursorPosition),
            _ => None,
        },
        _ => None,
    }
}

/// Where an `OSC` sequence ends, and what it asked.
///
/// `rest` starts at the `]`. Either terminator is accepted: `BEL` is what most
/// programs send, `ESC \` is what the standard says.
fn osc_end(rest: &[u8]) -> Option<(usize, Option<Query>)> {
    let body = rest.get(1..)?;
    let mut end = None;
    for (index, &byte) in body.iter().take(MAX_SEQUENCE).enumerate() {
        if byte == 0x07 {
            end = Some((index, 1usize));
            break;
        }
        if byte == 0x1b && body.get(index.saturating_add(1)) == Some(&b'\\') {
            end = Some((index, 2usize));
            break;
        }
    }
    let (content_len, terminator_len) = end?;
    let content = body.get(..content_len)?;
    // +1 for the `]`.
    Some((
        content_len.saturating_add(terminator_len).saturating_add(1),
        osc_query(content),
    ))
}

/// An `OSC` colour question looks like `<number> ; ?`. Anything else — setting
/// a title, setting a colour — is not a question.
fn osc_query(content: &[u8]) -> Option<Query> {
    let (number, rest) = content.split_at_checked(content.iter().position(|&b| b == b';')?)?;
    if rest != b";?" {
        return None;
    }
    let number: u16 = core::str::from_utf8(number).ok()?.parse().ok()?;
    COLOURS.contains(&number).then_some(Query::Colour(number))
}

/// Put the colour questions to the terminal scudo is drawing on.
fn ask_host() -> Vec<(u16, Vec<u8>)> {
    let mut out = std::io::stdout();
    let mut question = Vec::new();
    for number in COLOURS {
        question.extend_from_slice(format!("\x1b]{number};?\x1b\\").as_bytes());
    }
    // The fence, for the same reason everyone else sends one: a terminal with
    // nothing to say about colours still answers this, and its answer is what
    // saves us the wait.
    question.extend_from_slice(b"\x1b[c");
    if out.write_all(&question).and_then(|()| out.flush()).is_err() {
        return Vec::new();
    }

    let Some(reply) = read_reply(REPLY_TIMEOUT) else {
        return Vec::new();
    };

    // Whatever came back, taken apart with the same scanner that reads the
    // command's output — an answer has the shape of a sequence like anything
    // else, and one parser for both is one place for this to be wrong.
    let mut answers = Vec::new();
    let mut buffer = reply.as_slice();
    while let Some(start) = buffer.iter().position(|&byte| byte == 0x1b) {
        let Some(rest) = buffer.get(start.saturating_add(1)..) else {
            break;
        };
        if rest.first() == Some(&b']')
            && let Some((end, _)) = osc_end(rest)
            && let Some(whole) = rest.get(..end)
            && let Some(number) = answered_colour(whole)
        {
            let mut reply = vec![0x1b];
            reply.extend_from_slice(whole);
            answers.push((number, reply));
            buffer = buffer
                .get(start.saturating_add(1).saturating_add(end)..)
                .unwrap_or(&[]);
            continue;
        }
        buffer = rest;
    }
    answers
}

/// Which colour an `OSC` answer is about. `rest` starts at the `]`.
fn answered_colour(rest: &[u8]) -> Option<u16> {
    let body = rest.get(1..)?;
    let semicolon = body.iter().position(|&byte| byte == b';')?;
    let number: u16 = core::str::from_utf8(body.get(..semicolon)?)
        .ok()?
        .parse()
        .ok()?;
    COLOURS.contains(&number).then_some(number)
}

/// Where an answer is to be read from.
///
/// Standard input, when that is the terminal — and the controlling terminal
/// itself when it is not. A scudo with something piped into it still has a
/// terminal to ask; it is simply no longer on fd 0, and reading fd 0 there
/// would swallow the command's input and never see the answer. `crossterm`
/// makes the same choice for the keys it reads, so both ends of the
/// conversation stay on the same terminal.
fn terminal_input() -> Option<File> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        // Duplicated so the reader owns what it reads from either way, and
        // closes only its own copy.
        return stdin.as_fd().try_clone_to_owned().ok().map(File::from);
    }
    // Missing, or ours to open no longer: there is nobody to answer, and the
    // caller already treats an answer that never comes as no answer.
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()
}

/// Read whatever the terminal sends back, until it goes quiet or answers the
/// fence.
fn read_reply(timeout: Duration) -> Option<Vec<u8>> {
    let deadline = std::time::Instant::now().checked_add(timeout)?;
    let mut buffer = Vec::with_capacity(MAX_SEQUENCE);
    let mut chunk = [0u8; 64];
    let mut terminal = terminal_input()?;

    while buffer.len() < MAX_SEQUENCE {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() || !readable(terminal.as_raw_fd(), left) {
            break;
        }
        // End of input, or a read that gave us nothing to go on: either way
        // there is no more coming.
        let Ok(read) = terminal.read(&mut chunk) else {
            break;
        };
        match chunk.get(..read) {
            Some(bytes) if !bytes.is_empty() => buffer.extend_from_slice(bytes),
            _ => break,
        }
        // The fence came back, so everything that was coming has come.
        if fence_answered(&buffer) {
            break;
        }
    }
    (!buffer.is_empty()).then_some(buffer)
}

/// A primary attributes *answer* looks like `CSI ? … c` — the same shape as the
/// question that asked for it, with the `?` that marks it as the reply.
fn fence_answered(buffer: &[u8]) -> bool {
    let mut from = buffer;
    while let Some(at) = from.iter().position(|&byte| byte == 0x1b) {
        let Some(rest) = from.get(at.saturating_add(1)..) else {
            return false;
        };
        if rest.first() == Some(&b'[')
            && let Some(csi) = csi_end(rest)
            && csi.final_byte == b'c'
            && csi.params.first() == Some(&b'?')
        {
            return true;
        }
        from = rest;
    }
    false
}

/// Wait for `fd` to have something to read, for at most `left`.
fn readable(fd: std::os::fd::RawFd, left: Duration) -> bool {
    let mut fds = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    let millis = i32::try_from(left.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: a live, correctly sized array of pollfd.
    unsafe { libc::poll(fds.as_mut_ptr(), 1, millis) > 0i32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Host {
        Host {
            colours: vec![
                (10u16, b"\x1b]10;rgb:eeee/eeee/eeee\x1b\\".to_vec()),
                (11u16, b"\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\".to_vec()),
            ],
        }
    }

    fn parser() -> vt100::Parser {
        vt100::Parser::new(24, 80, 0)
    }

    fn answered(output: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        Answerer::default().answer(output, &host(), &parser(), &mut out);
        out
    }

    /// The fence. Every one of these probes ends with it, and its answer is
    /// what lets a program stop waiting — whether or not we knew the rest.
    #[test]
    fn the_attributes_query_is_always_answered() {
        assert_eq!(answered(b"\x1b[c"), DA1_ANSWER);
        // The same question written out.
        assert_eq!(answered(b"\x1b[0c"), DA1_ANSWER);
        assert_eq!(answered(b"\x1b[>c"), DA2_ANSWER);
    }

    /// Colours are the host's to answer, because scudo draws on its screen.
    #[test]
    fn a_colour_question_is_answered_with_what_the_host_said() {
        assert_eq!(
            answered(b"\x1b]11;?\x07"),
            b"\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\"
        );
        assert_eq!(
            answered(b"\x1b]10;?\x1b\\"),
            b"\x1b]10;rgb:eeee/eeee/eeee\x1b\\"
        );
        // Asked but never answered by the host: nothing to repeat, and the
        // command is no worse off than it would have been there.
        assert!(answered(b"\x1b]12;?\x07").is_empty());
    }

    /// The whole sequence a program really sends, in the order it sends it.
    /// This is the case the feature exists for, and the answers have to come
    /// back in the same order or a program reading them in turn misreads them.
    #[test]
    fn a_whole_probe_is_answered_in_order() {
        let out = answered(b"\x1b]10;?\x07\x1b]11;?\x07\x1b[c");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x1b]10;rgb:eeee/eeee/eeee\x1b\\");
        expected.extend_from_slice(b"\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\");
        expected.extend_from_slice(DA1_ANSWER);
        assert_eq!(out, expected);
    }

    /// Written in pieces, which is how they actually arrive: the introducer and
    /// the terminator come from separate writes.
    #[test]
    fn a_query_split_across_reads_is_still_answered() {
        let mut answerer = Answerer::default();
        let mut out = Vec::new();
        for piece in [&b"\x1b]11"[..], b";?", b"\x07"] {
            answerer.answer(piece, &host(), &parser(), &mut out);
        }
        assert_eq!(out, b"\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\");
    }

    /// The cursor report is about this screen, so it comes from this screen.
    #[test]
    fn the_cursor_report_says_where_the_cursor_is() {
        let mut parser = parser();
        parser.process(b"\x1b[5;9H");
        let mut out = Vec::new();
        Answerer::default().answer(b"\x1b[6n", &host(), &parser, &mut out);
        // One-based, where the screen counts from zero.
        assert_eq!(out, b"\x1b[5;9R");
        assert_eq!(answered(b"\x1b[5n"), STATUS_ANSWER);
    }

    /// Ordinary output asks nothing, and must not be mistaken for a question or
    /// left to accumulate.
    #[test]
    fn output_that_asks_nothing_is_left_alone() {
        let mut answerer = Answerer::default();
        let mut out = Vec::new();
        for _ in 0..100u32 {
            // Colours, a cursor move, a window title: sequences, none of them
            // questions.
            answerer.answer(
                b"\x1b[1;32mhello\x1b[0m\r\n\x1b[2J\x1b]0;a title\x07",
                &host(),
                &parser(),
                &mut out,
            );
        }
        assert!(out.is_empty(), "{out:?}");
        assert!(answerer.pending.is_empty(), "{:?}", answerer.pending);
    }

    /// A program printing binary must not be able to grow the buffer for ever
    /// by starting a sequence it never finishes.
    #[test]
    fn an_endless_sequence_is_given_up_on() {
        let mut answerer = Answerer::default();
        let mut out = Vec::new();
        answerer.answer(b"\x1b]0;", &host(), &parser(), &mut out);
        for _ in 0..100u32 {
            answerer.answer(&[b'x'; 100], &host(), &parser(), &mut out);
        }
        assert!(
            answerer.pending.len() <= MAX_SEQUENCE,
            "{}",
            answerer.pending.len()
        );
        // And it recovers: a question after the noise is still answered.
        answerer.answer(b"\x1b[c", &host(), &parser(), &mut out);
        assert_eq!(out, DA1_ANSWER);
    }

    /// A question buried in ordinary output is still a question.
    #[test]
    fn a_query_among_other_output_is_found() {
        assert_eq!(answered(b"text \x1b[1m bold \x1b[c more"), DA1_ANSWER);
    }

    /// What the host sends back is taken apart by the same scanner, so the two
    /// cannot drift.
    #[test]
    fn the_hosts_answers_are_recognised() {
        assert_eq!(answered_colour(b"]11;rgb:00/00/00\x1b\\"), Some(11));
        assert_eq!(answered_colour(b"]0;a title\x07"), None);
        assert!(fence_answered(b"\x1b[?62;1;c"));
        assert!(!fence_answered(b"\x1b]11;rgb:00/00/00\x1b\\"));
    }
}
