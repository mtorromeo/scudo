//! The pseudo-terminal the command runs on.
//!
//! Written against `libc` rather than pulled from a crate: scudo is Linux-only
//! and already depends on `libc`, and the alternative brings a second unix
//! abstraction layer along with it for the sake of four ioctls.
//!
//! What runs on this terminal is normally `systemd-run --pty`, which allocates a
//! second pty inside the unit and forwards between the two. That is why
//! [`Pty::resize`] matters as much as it does: setting the size on our master
//! makes the kernel raise `SIGWINCH` on the process group of our slave, which is
//! `systemd-run`, whose forwarder then resizes the inner pty. Without it the
//! command would keep whatever size the window had when it started.

use std::{
    ffi::CStr,
    fs::File,
    io,
    os::{
        fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd},
        unix::process::CommandExt as _,
    },
    process::{Child, Command, Stdio},
};

use anyhow::{Context as _, Result};

/// A pty pair, held open from the master end.
#[derive(Debug)]
pub struct Pty {
    master: OwnedFd,
    /// Given up as soon as a command is started on it — see [`Pty::spawn`].
    slave: Option<OwnedFd>,
}

/// `ptsname_r` writes into a buffer we size; slave names are far shorter.
const PTSNAME_MAX: usize = 128;

/// Where the command reads from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// The terminal itself, which is what an interactive command reads.
    Terminal,
    /// Whatever the caller already put on the `Command` — scudo's own standard
    /// input, unless something else was set. It is what makes
    /// `cat file | scudo --tui -- less` mean inside the UI what it means
    /// outside it: the pipe has to reach the command, and a terminal in its
    /// place is not the same thing wearing a different hat.
    Given,
}

pub fn open(rows: u16, cols: u16) -> Result<Pty> {
    // SAFETY: a plain syscall wrapper taking no memory of ours. O_NOCTTY keeps
    // the master from becoming this process's controlling terminal, which would
    // put scudo's own signals on the wrong terminal.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0i32 {
        return Err(io::Error::last_os_error()).context("opening a pseudo-terminal");
    }
    // SAFETY: `master` is a fresh, valid fd this function owns from here on, so
    // wrapping it hands ownership over rather than duplicating it.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    set_cloexec(master.as_raw_fd()).context("setting close-on-exec on the pty master")?;

    // SAFETY: both take the master fd and nothing else; `grantpt` fixes the
    // slave's ownership and mode, `unlockpt` is what makes it openable.
    if unsafe { libc::grantpt(master.as_raw_fd()) } < 0i32 {
        return Err(io::Error::last_os_error()).context("granting the pty slave");
    }
    // SAFETY: as above.
    if unsafe { libc::unlockpt(master.as_raw_fd()) } < 0i32 {
        return Err(io::Error::last_os_error()).context("unlocking the pty slave");
    }

    let mut buf = [0i8; PTSNAME_MAX];
    // SAFETY: `buf` is ours, live for the call, and its length is passed
    // alongside it, so the write cannot run past the end.
    let rc = unsafe { libc::ptsname_r(master.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
    if rc != 0i32 {
        return Err(io::Error::from_raw_os_error(rc)).context("naming the pty slave");
    }
    // SAFETY: on success `ptsname_r` has written a NUL-terminated name into the
    // buffer, which outlives the borrow taken here.
    let name = unsafe { CStr::from_ptr(buf.as_ptr()) };

    // SAFETY: `name` points at a NUL-terminated string that lives across the
    // call. O_NOCTTY again: the child claims the terminal deliberately, in
    // `spawn`, and never as a side effect of opening it here.
    let slave = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave < 0i32 {
        return Err(io::Error::last_os_error()).context("opening the pty slave");
    }
    // SAFETY: a fresh, valid fd, owned from here on.
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    set_cloexec(slave.as_raw_fd()).context("setting close-on-exec on the pty slave")?;

    let pty = Pty {
        master,
        slave: Some(slave),
    };
    pty.resize(rows, cols)?;
    Ok(pty)
}

impl Pty {
    /// Tell the terminal how big it is. See the module note on why this reaches
    /// all the way into the unit.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ reads one `winsize` through the pointer, which
        // points at a live local of exactly that type.
        let rc = unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &raw const size) };
        if rc < 0i32 {
            return Err(io::Error::last_os_error()).context("resizing the pseudo-terminal");
        }
        Ok(())
    }

    /// Start `cmd` on the slave end, as leader of its own session with this
    /// terminal as its controlling terminal.
    ///
    /// The session is what makes the terminal work at all: without it there is
    /// no foreground process group for the kernel to deliver `SIGINT` or
    /// `SIGWINCH` to, and a shell started this way would report `no job control`.
    /// The parent keeps no copy of the slave afterwards, and that is not
    /// tidiness: a terminal is at its end when the last writer closes it, so
    /// one forgotten copy here would mean the reader never saw the command's
    /// output finish, and would wait for an end that could no longer come.
    ///
    /// `input` decides only where the command reads: what it writes always goes
    /// to this terminal, so it is drawn wherever the caller draws it.
    pub fn spawn(&mut self, cmd: &mut Command, input: Input) -> Result<Child> {
        let slave = self
            .slave
            .take()
            .context("this pty has already started a command")?;
        if input == Input::Terminal {
            cmd.stdin(stdio(&slave)?);
        }
        cmd.stdout(stdio(&slave)?).stderr(stdio(&slave)?);

        // SAFETY: the closure runs in the forked child, between fork and
        // exec, where only async-signal-safe calls are allowed; `claim_terminal`
        // makes two, both on that list.
        let cmd = unsafe { cmd.pre_exec(claim_terminal) };

        let child = cmd.spawn().context("starting the command");

        // The three the `Command` is holding go back here; ours goes out of
        // scope on return. The child dup'd its own before exec, so it keeps the
        // only copies that matter.
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        drop(slave);
        child
    }

    /// The read end, as an owned `File` so a thread can block on it alone.
    pub fn reader(&self) -> Result<File> {
        self.dup_master().context("opening the pty for reading")
    }

    /// The write end. Separate from [`Pty::reader`] so that reading and writing
    /// need no lock between them: the kernel serialises them for us.
    pub fn writer(&self) -> Result<File> {
        self.dup_master().context("opening the pty for writing")
    }

    fn dup_master(&self) -> Result<File> {
        let fd = self.master.try_clone()?;
        Ok(File::from(fd))
    }
}

fn stdio(slave: &OwnedFd) -> Result<Stdio> {
    let fd = slave.try_clone().context("duplicating the pty slave")?;
    // SAFETY: a valid fd whose ownership is handed to the `Stdio`, which closes
    // it once the child has it.
    Ok(unsafe { Stdio::from_raw_fd(fd.into_raw_fd()) })
}

/// Become the leader of a new session with this terminal as its controlling
/// terminal. Runs in the child, between fork and exec.
fn claim_terminal() -> io::Result<()> {
    // SAFETY: a new session for the calling process; nothing of ours is read
    // through a pointer, and it is async-signal-safe.
    if unsafe { libc::setsid() } < 0i32 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd 1 is the slave — `stdout` in `spawn` put it there, whichever
    // way `stdin` went — and TIOCSCTTY takes its argument by value, not through
    // a pointer.
    if unsafe { libc::ioctl(1i32, libc::TIOCSCTTY, 0i32) } < 0i32 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_cloexec(fd: RawFd) -> Result<()> {
    // SAFETY: both calls take the fd and a flag word; nothing of ours is read
    // through a pointer.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0i32 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0i32 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the module in one line: something written by a command
    /// on the slave has to come back out of the master.
    /// Reads until the command's terminal ends, which is what `spawn` giving up
    /// the slave is for: with a copy left behind this would never return.
    fn run(rows: u16, cols: u16, cmd: &mut Command) -> String {
        let mut pty = open(rows, cols).expect("a pty");
        let mut child = pty.spawn(cmd, Input::Terminal).expect("the command starts");
        let mut reader = pty.reader().expect("a reader");
        child.wait().expect("the command finishes");

        let mut out = String::new();
        // Linux reports the last close of the slave as EIO rather than as end
        // of file, so the error here is the end of the stream, not a failure.
        drop(std::io::Read::read_to_string(&mut reader, &mut out));
        out
    }

    #[test]
    fn what_the_command_prints_comes_back_out_of_the_master() {
        let mut cmd = Command::new("/bin/echo");
        cmd.arg("hello from the sandbox");
        let out = run(24, 80, &mut cmd);
        assert!(out.contains("hello from the sandbox"), "{out:?}");
    }

    /// The command has to be told its size, or everything it draws is laid out
    /// for a terminal that is not the one it is on.
    #[test]
    fn the_command_is_told_how_big_its_terminal_is() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("stty size");
        let out = run(30, 100, &mut cmd);
        assert!(out.contains("30 100"), "{out:?}");
    }

    /// A second command on the same pty would be handed a slave that is gone.
    #[test]
    fn a_pty_starts_one_command_and_says_so_if_asked_for_another() {
        let mut pty = open(24, 80).expect("a pty");
        let mut first = Command::new("/bin/true");
        let mut child = pty
            .spawn(&mut first, Input::Terminal)
            .expect("the command starts");
        child.wait().expect("the command finishes");

        let mut second = Command::new("/bin/true");
        let err = pty
            .spawn(&mut second, Input::Terminal)
            .expect_err("a second start is refused");
        assert!(err.to_string().contains("already started"), "{err}");
    }

    /// The other half of [`Input`]: what the caller put on the command is left
    /// where it was, so a pipe reaches the command rather than being replaced
    /// by a terminal that has nothing in it.
    #[test]
    fn a_command_given_its_own_input_reads_that_and_not_the_terminal() {
        use std::io::Write as _;

        let mut pty = open(24, 80).expect("a pty");
        let mut cmd = Command::new("/bin/cat");
        cmd.stdin(Stdio::piped());
        let mut child = pty
            .spawn(&mut cmd, Input::Given)
            .expect("the command starts");

        // Closed, or `cat` would sit on a pipe nobody is going to write to
        // again and the read below would never end.
        let mut stdin = child.stdin.take().expect("the pipe we asked for");
        stdin
            .write_all(b"down the pipe\n")
            .expect("the write lands");
        drop(stdin);

        let mut reader = pty.reader().expect("a reader");
        child.wait().expect("the command finishes");
        let mut out = String::new();
        drop(std::io::Read::read_to_string(&mut reader, &mut out));
        assert!(out.contains("down the pipe"), "{out:?}");
    }
}
