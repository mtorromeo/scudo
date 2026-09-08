//! The terminal UI, driven through a terminal.
//!
//! There is no way to test this honestly without a pty: everything the mode
//! does — taking the screen, drawing, reading keys — is refused or meaningless
//! without one. So the tests give scudo a real terminal, of the same kind it
//! gives the command it runs, and read back what appeared on it.

#![cfg(all(target_os = "linux", feature = "tui"))]
#![expect(
    clippy::tests_outside_test_module,
    clippy::panic,
    clippy::default_numeric_fallback,
    clippy::let_underscore_untyped,
    clippy::let_underscore_must_use,
    clippy::zombie_processes,
    reason = "an integration test file is a test module, and reads worse dressed as one"
)]

use std::{
    io::{Read as _, Write as _},
    process::Command,
    time::{Duration, Instant},
};

use scudo::tui::pty;

/// Long enough for a debug build to start, draw and exit on a loaded machine;
/// short enough that a hang is a failed test rather than a stuck suite.
const PATIENCE: Duration = Duration::from_secs(20);

/// A scratch `$XDG_CONFIG_HOME`, so a test that makes scudo remember something
/// does not reach into the real one — nor into another test's.
fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("scudo-tui-{name}-{}", std::process::id()));
    drop(std::fs::remove_dir_all(&dir));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

fn scudo() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scudo"));
    // A stray config would change which profile matched, and with it whether
    // the command is run under `systemd-run` at all. The working directory
    // matters as much as the environment: scudo reads `$PWD/.scudo.toml`, and
    // this repository has one, which would stop for a trust prompt nobody is
    // there to answer.
    cmd.current_dir(std::env::temp_dir())
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .env("HOME", "/nonexistent")
        .env("TERM", "xterm-256color");
    cmd
}

/// Run scudo on a terminal of our own and return everything it drew.
///
/// `steps` are followed in order: each waits for its text to appear on screen
/// and then types its bytes. Waiting for what was drawn rather than for a fixed
/// delay is what keeps this from depending on how fast the machine is.
fn drive(cmd: &mut Command, steps: &[(&str, &[u8])]) -> (String, i32) {
    drive_on(cmd, 40, 120, steps)
}

/// As [`drive`], on a terminal of a given size.
fn drive_on(cmd: &mut Command, rows: u16, cols: u16, steps: &[(&str, &[u8])]) -> (String, i32) {
    let mut pty = pty::open(rows, cols).expect("a terminal");
    let mut child = pty.spawn(cmd).expect("scudo starts");
    let mut reader = pty.reader().expect("a reader");
    let mut writer = pty.writer().expect("a writer");

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 || tx.send(buf.get(..n).unwrap_or_default().to_vec()).is_err() {
                break;
            }
        }
    });

    let mut screen = String::new();
    let mut step = 0usize;
    let deadline = Instant::now()
        .checked_add(PATIENCE)
        .unwrap_or_else(Instant::now);
    while Instant::now() < deadline {
        if let Ok(chunk) = rx.recv_timeout(Duration::from_millis(100)) {
            screen.push_str(&String::from_utf8_lossy(&chunk));
        }
        if let Some((wait_for, keys)) = steps.get(step)
            && screen.contains(wait_for)
        {
            // A moment for the frame that follows the one we were waiting for:
            // the footer is drawn after the command's own output.
            std::thread::sleep(Duration::from_millis(300));
            let _ = writer.write_all(keys);
            let _ = writer.flush();
            step = step.saturating_add(1);
        }
        if let Ok(Some(status)) = child.try_wait() {
            // Drain whatever was drawn between the last read and the exit.
            while let Ok(chunk) = rx.recv_timeout(Duration::from_millis(200)) {
                screen.push_str(&String::from_utf8_lossy(&chunk));
            }
            return (screen, status.code().unwrap_or(-1));
        }
    }

    let _ = child.kill();
    panic!("scudo never finished. What it drew:\n{screen}");
}

/// The whole point of the mode: the command runs, on a real terminal, and what
/// it printed is on the screen.
#[test]
fn the_command_runs_and_its_output_is_on_the_screen() {
    let mut cmd = scudo();
    cmd.args(["--tui", "--", "/bin/echo", "marker-one-two-three"]);
    let (screen, code) = drive(&mut cmd, &[("marker-one-two-three", b"q")]);
    assert!(screen.contains("marker-one-two-three"), "{screen}");
    assert_eq!(code, 0);
}

/// The UI stays up after the command is over, and says so, until a key is hit.
#[test]
fn a_finished_command_waits_for_a_key_and_says_what_it_exited_with() {
    let mut cmd = scudo();
    cmd.args(["--tui", "--", "/bin/sh", "-c", "exit 3"]);
    let (screen, code) = drive(&mut cmd, &[("exited with 3", b"q")]);
    assert!(screen.contains("press q, Esc"), "{screen}");
    // scudo stands in for the command, so its code is the command's.
    assert_eq!(code, 3);
}

/// The whole point of keeping the UI up: everything it can do, it can still
/// do. The prefix reaches the UI's own keys, and the help they open is the one
/// written for a command that is over.
#[test]
fn a_finished_command_leaves_the_prefix_and_its_help_working() {
    let mut cmd = scudo();
    cmd.args(["--tui", "--", "/bin/sh", "-c", "exit 0"]);
    let (screen, _) = drive(
        &mut cmd,
        &[
            // `^A ?`, after the command is over rather than while it runs.
            ("press q, Esc", b"\x01?"),
            // A single word, because the drawing puts cursor moves between
            // them: what is on screen is not what is in the buffer.
            ("scrollback", b" "),
            ("press q, Esc", b"q"),
        ],
    );
    assert!(screen.contains("scrollback"), "{screen}");
}

/// The panel can still be set up after the fact, which is when the person has
/// actually seen how much of it they needed.
#[test]
fn a_finished_command_can_still_have_its_panel_resized_and_hidden() {
    let mut cmd = scudo();
    cmd.args(["--tui", "--", "/bin/echo", "marker-done"]);
    let (screen, _) = drive(
        &mut cmd,
        &[
            // 120 columns wide, so it starts at the 34-column floor; four leaps
            // of five widen it to 54.
            ("press q, Esc", b"\x01rhhhh"),
            // Out of the resize mode, then hide the panel.
            ("panel 54 columns", b"q\x01w"),
            // Bring it back and widen it once more. That the resize mode opens
            // at all is the proof the panel returned: it is refused while the
            // panel is hidden.
            ("press q, Esc", b"\x01w\x01rh"),
            ("panel 59 columns", b"q"),
            ("press q, Esc", b"q"),
        ],
    );
    assert!(screen.contains("panel 59 columns"), "{screen}");
}

/// Reading back what a command printed is the reason to stay, and the plain
/// keys do it: with nothing left to type at, asking for a mode first would be a
/// step for nothing.
#[test]
fn a_finished_command_can_still_have_its_scrollback_read() {
    let mut cmd = scudo();
    // Five times the height, so the first line is long gone off the top by the
    // time the command is over.
    cmd.args([
        "--tui",
        "--",
        "/bin/sh",
        "-c",
        "echo marker-topmost; seq 1 200",
    ]);
    let (screen, _) = drive(
        &mut cmd,
        &[
            // Home, with no prefix and no scroll mode asked for.
            ("press q, Esc", b"\x1b[H"),
            ("press q, Esc", b"q"),
        ],
    );
    // Counted rather than looked for: it was printed once on the way past, and
    // drawn a second time when the view went back up to it. The footer would
    // have said so too, but the drawing rewrites only the cells that changed
    // and puts cursor moves through the middle of its words.
    assert!(
        screen.matches("marker-topmost").count() >= 2,
        "the top of the scrollback should have been drawn again: {screen}"
    );
}

/// The panel is drawn even with no policy to report on, and says why it is
/// empty rather than looking like reporting that failed to start.
#[test]
fn the_panel_says_why_it_has_nothing_in_it() {
    let mut cmd = scudo();
    cmd.args(["--tui", "--", "/bin/echo", "marker-panel"]);
    let (screen, _) = drive(&mut cmd, &[("marker-panel", b"q")]);
    // The heading is a filled bar with the count right-aligned against the
    // panel's edge, so the two are not next to each other on the screen.
    assert!(screen.contains("BLOCKED"), "{screen}");
    // Nothing restricts this command, so there is nothing that could have been
    // taken from it — not on the network and not on disk.
    assert!(screen.contains("no policy applies"), "{screen}");
}

/// A terminal that could not be typed into would be a picture of one. This is
/// the round trip: a key pressed here reaches the command, and what the command
/// makes of it comes back to the screen.
#[test]
fn what_is_typed_reaches_the_command_and_its_answer_comes_back() {
    let mut cmd = scudo();
    cmd.args([
        "--tui",
        "--",
        "/bin/sh",
        "-c",
        "echo marker-ready; read line; echo marker-got:$line",
    ]);
    let (screen, _) = drive(
        &mut cmd,
        &[
            // Enter is carriage return on a terminal, not a newline.
            (
                "marker-ready",
                b"typed-this
",
            ),
            ("marker-got:typed-this", b"q"),
        ],
    );
    assert!(screen.contains("marker-got:typed-this"), "{screen}");
}

/// The prefix opens the UI's own keys instead of reaching the command, and the
/// help it puts up says so.
#[test]
fn the_prefix_opens_the_ui_rather_than_reaching_the_command() {
    let mut cmd = scudo();
    cmd.args([
        "--tui",
        "--",
        "/bin/sh",
        "-c",
        "echo marker-ready; read line; echo marker-got:$line",
    ]);
    let (screen, _) = drive(
        &mut cmd,
        &[
            // Ctrl-A then `?`: the list of commands, not an `?` in the shell.
            ("marker-ready", b"\x01?"),
            // A single word, because the drawing puts cursor moves between
            // them: what is on screen is not what is in the buffer.
            ("scrollback", b" "),
            // Dismissed, the terminal has the keys back.
            ("marker-ready", b"after-help\r"),
            ("marker-got:after-help", b"q"),
        ],
    );
    assert!(screen.contains("marker-got:after-help"), "{screen}");
}

/// The whole path, with a transient unit in it: `systemd-run --pty` allocates
/// a terminal of its own inside the unit and forwards to the one scudo drew.
#[test]
#[ignore = "needs a working systemd --user session"]
fn the_command_runs_under_systemd_and_still_reaches_the_screen() {
    let mut cmd = scudo();
    // Any property will do; it is there to make the run go through
    // `systemd-run` rather than take the direct path.
    cmd.args([
        "--tui",
        "-P",
        "MemoryMax=512M",
        "--",
        "/bin/sh",
        "-c",
        // Joined up, because the drawing only rewrites the cells that changed
        // and would leave the space between the two numbers untouched.
        "echo marker-in-a-unit; stty size | tr ' ' x",
    ]);
    let (screen, code) = drive(&mut cmd, &[("marker-in-a-unit", b"q")]);
    assert!(screen.contains("marker-in-a-unit"), "{screen}");
    // The terminal panel's size, not the window's: 40 rows less the footer,
    // and 120 columns less the panel. The command is told about the room it was
    // actually given, which is the point of resizing through the unit at all.
    assert!(
        screen.contains("39x86"),
        "the size inside the unit: {screen}"
    );
    assert_eq!(code, 0);
}

/// The width is not just drawn differently: the command inside is told about it,
/// which is the only version of this that matters. `stty size` before and after
/// has to change.
#[test]
fn resizing_the_panel_resizes_the_command_s_terminal() {
    let mut cmd = scudo();
    cmd.args([
        "--tui",
        "--",
        "/bin/sh",
        "-c",
        // Joined up: the drawing only rewrites the cells that changed, and would
        // leave the space between the two numbers untouched.
        "stty size | tr ' ' x; read line; stty size | tr ' ' x",
    ]);
    // 120 columns wide, so the automatic width is the 34-column floor and the
    // terminal starts with 86.
    let (screen, _) = drive(
        &mut cmd,
        &[
            // `^A r`, then four leaps of five columns: `h` moves the edge left,
            // so the panel grows by 20 and the terminal loses them.
            ("39x86", b"\x01rhhhh"),
            // `q` leaves the mode and Enter releases the `read`. Not Esc: sent
            // in the same breath as another key it is read back as Alt-that-key,
            // which is what a terminal does and not something to work around.
            ("panel 54 columns", b"q\r"),
            // The UI stays up after the command is over; this lets it go.
            ("press q, Esc", b"q"),
        ],
    );
    assert!(
        screen.contains("39x66"),
        "the size after resizing: {screen}"
    );
}

/// The complaint this was built for: 34 columns is right on a 120-column window
/// and mean on a 240-column one. The panel takes a share of the screen instead,
/// and the terminal gets everything else.
#[test]
fn the_panel_takes_a_share_of_a_wide_screen_rather_than_a_fixed_34() {
    let command = ["/bin/sh", "-c", "stty size | tr ' ' x"];

    let mut narrow = scudo();
    narrow.args(["--tui", "--"]).args(command);
    let (screen, _) = drive_on(&mut narrow, 40, 120, &[("39x86", b"q")]);
    // 120 wide: a quarter is 30, under the floor, so the floor of 34 applies.
    assert!(screen.contains("39x86"), "on a narrow screen: {screen}");

    let mut wide = scudo();
    wide.args(["--tui", "--"]).args(command);
    let (screen, _) = drive_on(&mut wide, 40, 200, &[("39x150", b"q")]);
    // 200 wide: a quarter is 50, and the terminal keeps the other 150.
    assert!(screen.contains("39x150"), "on a wide screen: {screen}");
}

/// A width set once should not have to be set again on every run.
#[test]
fn the_width_is_remembered_for_the_next_run() {
    let home = scratch("remembered");
    let run = |keys: &[(&str, &[u8])]| {
        let mut cmd = scudo();
        cmd.env("XDG_CONFIG_HOME", &home).args([
            "--tui",
            "--",
            "/bin/sh",
            "-c",
            // Twice, so a resize between the two shows up as a difference.
            "stty size | tr ' ' x; read line; stty size | tr ' ' x",
        ]);
        drive(&mut cmd, keys).0
    };

    // First run: widen the panel by 20 columns and leave.
    let first = run(&[
        ("39x86", b"\x01rhhhh"),
        ("panel 54 columns", b"q\r"),
        ("press q, Esc", b"q"),
    ]);
    assert!(first.contains("39x66"), "the size after resizing: {first}");
    assert!(
        home.join("scudo/state.toml").is_file(),
        "the width should have been written down"
    );

    // Second run: the same width is in force from the first frame.
    let second = run(&[("39x66", b"\r"), ("press q, Esc", b"q")]);
    assert!(
        !second.contains("39x86"),
        "the remembered width should have applied straight away: {second}"
    );

    drop(std::fs::remove_dir_all(&home));
}

/// Going back to automatic has to be possible, and has to be remembered as such.
#[test]
fn going_back_to_automatic_is_remembered_too() {
    let home = scratch("automatic");
    let run = |keys: &[(&str, &[u8])]| {
        let mut cmd = scudo();
        cmd.env("XDG_CONFIG_HOME", &home).args([
            "--tui",
            "--",
            "/bin/sh",
            "-c",
            "stty size | tr ' ' x; read line; stty size | tr ' ' x",
        ]);
        drive(&mut cmd, keys).0
    };

    run(&[
        ("39x86", b"\x01rhhhh"),
        ("panel 54 columns", b"q\r"),
        ("press q, Esc", b"q"),
    ]);
    // `=` in the resize mode puts it back to following the screen.
    let back = run(&[
        ("39x66", b"\x01r="),
        ("(automatic)", b"q\r"),
        ("press q, Esc", b"q"),
    ]);
    assert!(back.contains("39x86"), "back to automatic: {back}");

    let third = run(&[("39x86", b"\r"), ("press q, Esc", b"q")]);
    assert!(third.contains("39x86"), "still automatic: {third}");

    drop(std::fs::remove_dir_all(&home));
}

/// Without a terminal there is nothing to draw on, and saying so beats taking
/// over a pipe and producing nonsense.
#[test]
fn asking_for_the_ui_without_a_terminal_is_refused_plainly() {
    let output = scudo()
        .args(["--tui", "--", "/bin/echo", "hello"])
        .output()
        .expect("scudo runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("needs a terminal"), "{stderr}");
    assert!(!output.status.success());
}

/// The mode is reachable only when scudo is called by its own name: a symlink
/// dispatch rewrites the argv so that every flag belongs to the command.
#[test]
fn a_symlinked_name_cannot_ask_for_the_ui() {
    let dir = std::env::temp_dir().join(format!("scudo-tui-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    let link = dir.join("echo");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_scudo"), &link).expect("a symlink");

    let output = Command::new(&link)
        .current_dir(std::env::temp_dir())
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .env("HOME", "/nonexistent")
        .args(["--tui", "marker"])
        .output()
        .expect("the symlink runs");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // `--tui` was passed straight through to echo, which printed it.
    assert!(stdout.contains("--tui marker"), "{stdout}");
    drop(std::fs::remove_dir_all(&dir));
}

/// The size has to reach the command through `systemd-run --pty`, which puts a
/// second terminal between ours and it.
///
/// Setting the size on our master raises `SIGWINCH` on `systemd-run`, whose
/// forwarder resizes the inner pty in turn. Nothing in scudo can make that
/// happen if systemd does not do it, so it is worth a test of its own: without
/// it, every full-screen program run under a profile would be laid out for the
/// wrong terminal.
#[test]
#[ignore = "needs a working systemd --user session"]
fn the_size_reaches_the_command_through_systemd_run() {
    let mut pty = pty::open(24, 80).expect("a terminal");
    let mut cmd = Command::new("systemd-run");
    cmd.args(["--user", "--wait", "-Pdtq", "--"]).args([
        "/bin/sh",
        "-c",
        "stty size; sleep 2; stty size",
    ]);
    let mut child = pty.spawn(&mut cmd).expect("systemd-run starts");
    let mut reader = pty.reader().expect("a reader");

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 || tx.send(buf.get(..n).unwrap_or_default().to_vec()).is_err() {
                break;
            }
        }
    });

    let mut out = String::new();
    let deadline = Instant::now()
        .checked_add(PATIENCE)
        .unwrap_or_else(Instant::now);
    let mut resized = false;
    while Instant::now() < deadline {
        if let Ok(chunk) = rx.recv_timeout(Duration::from_millis(100)) {
            out.push_str(&String::from_utf8_lossy(&chunk));
        }
        if !resized && out.contains("24 80") {
            pty.resize(40, 120).expect("the terminal resizes");
            resized = true;
        }
        if child.try_wait().ok().flatten().is_some() {
            while let Ok(chunk) = rx.recv_timeout(Duration::from_millis(200)) {
                out.push_str(&String::from_utf8_lossy(&chunk));
            }
            break;
        }
    }
    let _ = child.kill();

    assert!(out.contains("24 80"), "the size it started with: {out:?}");
    assert!(
        out.contains("40 120"),
        "the size it was resized to: {out:?}"
    );
}
