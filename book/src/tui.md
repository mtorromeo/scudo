# Terminal UI

`--tui` runs the command inside scudo rather than in place of it: a full terminal on the left,
and on the right a live list of what the sandbox turned away. That list comes from
`scudo-bpfd`, so it stays empty unless `scudo-bpfd.socket` is enabled and active in
`systemctl --user` (see [Installation](installation.md#enabling-scudo-bpfd)).

```console
$ scudo --tui -- curl https://example.com/
$ scudo --tui -- bash
```

```
                                     │▌ BLOCKED               3 │
 $ curl https://ads.example/         │ ● ads.example      2x    │
 curl: (6) Could not resolve host    │ ● 1.1.1.1:443      1x    │
 $                                   │ □ /usr/lib/libz.so 9x    │
                                     │                          │
                                     │  RECENT                  │
                                     │   1s ● blocked DNS for a…│
                                     │   4s ■ blocked open of /…│
 ^A  ? for help                        terminal │ blocked 3
```

The command's terminal is the only part of the screen left unpainted, so what shows through
it is the host terminal's own background; everything else — the panel, its two headings, the
status bar — carries scudo's own dark theme.

Every line carries a mark, and the mark answers two questions at once. Its **shape** says
which half of the sandbox the line came from — a round `●` for the network, a square `■` for
the filesystem — and its **colour** says whether the sandbox is the reason: the warm tint for
something it refused, the dim one for a path that was not there outside it either, which is
hidden until `^A m` asks for it. Both the glyphs and the two tints are part of the theme, so
they hold their meaning on a 256-colour terminal and on a sixteen-colour one.

The headings sit above their lists rather than in them, so they stay put while the lists
scroll, and each list has a scrollbar down its right edge once there is more of it than there
is room.

The left panel is a terminal in full: colours, resizing, scrollback, the mouse, and job
control. A shell runs in it as it would anywhere, `Ctrl-C` and `Ctrl-Z` included — in this
mode they are bytes for the command, not signals for scudo.

Piping works, and means what it means everywhere else:

```console
$ cat Cargo.toml | scudo --tui -- less
```

When scudo's own standard input is not a terminal it belongs to the command, which reads it
instead of the panel's terminal — a pipe is meant for the command, and handing it an empty
terminal in its place would make the same command line mean two different things inside and
outside the UI. Only what the command *writes* is drawn in the panel.

Two consequences, both of them the ones the mode already has outside the UI. `systemd-run`
falls back from `--pty` to `--pipe` when it is not given a terminal on all three descriptors,
so a command with something piped into it has no controlling terminal of its own: it is not
told when the panel is resized, and the keys pressed in the UI reach it only if it opens a
terminal for itself, as `less` does. And a command given nothing to read gets nothing:
`scudo --tui -- bash < /dev/null` ends at once rather than opening a shell.

Asking for the UI also turns denial reporting on for the run, the same way `--verbose` does;
without it the right panel would have nothing to show. When there is nothing to report the
panel says which of the reasons applies — no network policy, a policy that took the network
away entirely, or a sandbox that could not be watched — rather than sitting empty.

The mode is only available when scudo is invoked by its own name. Called through a symlink or
the FUSE shim, everything after the command name belongs to the command, so `--tui` is passed
straight through to it.

## Keys

Every key goes to the command except the prefix, `Ctrl-A` by default, which introduces one of
scudo's own:

| Key | Effect |
|-----|--------|
| `^A q` | leave, stopping the command if it is still running |
| `^A ^A` | send `Ctrl-A` to the command |
| `^A Tab` | move between the terminal and the panel's two lists |
| `^A PgUp` | read the scrollback — arrows, `PgUp`/`PgDn`, `Home`/`End`, `Esc` to return |
| `^A r` | set how wide the panel is — arrows by one, `h`/`l` by five, `=` back to automatic, `Esc` to return |
| `^A w` | show or hide the panel |
| `^A s` | show or hide what scudo decided: the profiles that matched and the command line it built |
| `^A m` | show or hide paths that were missing outside the sandbox too — see [file access reporting](filesystem.md#seeing-what-the-filesystem-restrictions-hid) |
| `^A /` | keep only the lines matching a pattern |
| `^A \` | the same, keeping out what matches instead |
| `^A n` | the network only, or everything again |
| `^A f` | the filesystem only, or everything again |
| `^A ?` | the list above |

With one of the panel's lists focused, the arrows, `PgUp`/`PgDn` and `Home`/`End` move that
list instead of reaching the command; every other key still reaches it, so the focus never
swallows what was typed. The tally is read from the top down and the running list from its
newest line back, and each stops at its own last line.

## Narrowing the panel

A build or a package manager names thousands of paths, and the handful worth looking at go
under. Two ways of cutting the panel down, which can be used together:

`^A /` opens a field for a **regular expression** — the same engine the profile matchers use —
and keeps only the lines that match it; `^A \` opens the same field on the other side, keeping
out what matches instead. The pattern applies as it is typed: `Tab` turns it round without
retyping it, `Ctrl-U` clears it, `Enter` keeps it and gives the keyboard back, and `Esc`
leaves the field putting back whatever was in force before it was opened. Case is ignored
unless the pattern says otherwise with `(?-i)`. A pattern is unfinished for most of the time
it is being written, so while it does not compile nothing is narrowed by it and the status bar
says why, in red, rather than emptying the lists at every intermediate keystroke.

`^A n` and `^A f` cut the panel to the network or to the filesystem alone; the same key again
puts everything back. The heading of each list shows what is in force — `[net] /usr` — so a
panel that is narrow because it was asked to be never looks like a panel with nothing in it.

Both are **views and only views**. What is on screen has no bearing on the line printed when
the UI closes, or on the `blocked N` count in the status bar: those are statements about the
run, and a run does not change because of what was being looked at while it happened.

Change the prefix with `tui.prefix` in `[scudo]` or with `--tui-prefix`; it is written as
`C-a`, `M-x` or `F12`, and must carry a modifier, since a bare character would be taken away
from the command with no way to type it.

Programs that ask the terminal about itself get an answer. scudo is the terminal here, so it
answers what it can: what kind of terminal it is, whether it is working, where the cursor is,
and — from the terminal it is itself drawing on, asked once when the UI starts — what colour
the foreground, background and cursor are. Anything else goes unanswered, as on any terminal
that does not implement it; the device-attributes reply is what tells a program to stop waiting
for the rest. Without this a program like `bat`, which asks about the background colour to
choose a light or dark theme, waits out its own timeout — a full second — on every run.

The mouse is handed to the program in the terminal only while that program asks for it, so
selecting and copying with the mouse keeps working everywhere else — at the cost of taking
whole screen rows, panel included, since scudo is drawing one screen.

When the command exits the UI stays up, and stays usable: the scrollback still scrolls, the
lists still scroll, the panel can still be shown, hidden and resized, and `^A ?` still opens
the help. Only the keys that were bytes for the command change hands — with nothing left to
type at, the plain arrows, `PgUp`/`PgDn` and `Home`/`End` read the scrollback without a mode
being asked for first, `Tab` moves between the terminal and the panel's lists, and `q`, `Esc`
or `^d` close. scudo exits with the command's own code, and the closing summary of what was
blocked is printed to stderr once the terminal has been given back, so it lands in the
scrollback you keep.

## How wide the panel is

By default the panel takes a quarter of the screen, never narrower than 34 columns and never
wider than 60 — past that it has all the room its contents can use, and the rest would be
taken from the terminal for nothing. On a 120-column window that is the same 34 columns it
always was; on a 240-column one it is 60.

| screen | panel |
|--------|-------|
| 100 | 34 |
| 160 | 40 |
| 200 | 50 |
| 240 and wider | 60 |

`^A r` sets it by hand. The keys move the **edge** between the two panels, not the panel's
width, so `←` and `h` widen the panel that sits to the right of that edge and `→` and `l`
narrow it; the arrows move it a column at a time and the letters five at a time. The command
inside is told about its new size as it happens, so a full-screen program redraws itself while
you are still moving the edge.

A width set this way is **remembered**, in `$XDG_CONFIG_HOME/scudo/state.toml`, and applies to
the next run. It also stops following the screen: resizing the window no longer moves it.
`=` in the resize mode puts it back to automatic, and that too is remembered.

That file is state, not configuration — scudo writes it, and nothing in it was typed by hand.
There is deliberately no `panel_width` in `[scudo.tui]`: two sources for one width could only
ever differ in order to disagree, and a config that still names it will say so rather than be
quietly ignored.

The panel is dropped altogether when the window is too narrow to leave the terminal 40
columns: a shell wrapping into nonsense costs more than the panel shows.

## Settings

```toml
[scudo]
tui.prefix = "C-b"          # default "C-a"
tui.scrollback = 20000      # default 10000 lines
```
