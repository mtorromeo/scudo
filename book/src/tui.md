# Terminal UI

With `--tui`, scudo stays running instead of executing into the command. The screen splits in
two. The left side is a full terminal running the command, and the right side is a panel that
lists what the sandbox blocked. The list comes from `scudo-bpfd`, so it stays empty unless
`scudo-bpfd.socket` is enabled and active in `systemctl --user`. See
[Installation](installation.md#enabling-scudo-bpfd).

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

scudo paints the panel, its headings and the status bar with its own dark theme. It leaves the
command's terminal unpainted, so that area shows the host terminal's background.

A shell works as it does anywhere else. `Ctrl-C` and `Ctrl-Z` go to the command as bytes.
scudo does not treat them as signals for itself.

Piping works the same as without the UI:

```console
$ cat Cargo.toml | scudo --tui -- less
```

If scudo's standard input is not a terminal, scudo passes it to the command. The command reads
the pipe, not the panel's terminal, so a command line does the same thing with and without
`--tui`. The panel shows only what the command writes.

This has two consequences, and both also apply without the UI. First, `systemd-run` switches
from `--pty` to `--pipe` unless all three standard descriptors are terminals. A command that
reads from a pipe therefore has no controlling terminal. It gets no resize notifications, and
it receives keys from the UI only if it opens a terminal itself, as `less` does. Second, a
command with empty input reads nothing: `scudo --tui -- bash < /dev/null` exits at once.

`--tui` turns on denial reporting for the run, as `--verbose` does, because the panel has
nothing to show without it. When there is nothing to report, the panel gives the reason. The
profile may have no network policy, the policy may remove the network entirely, or scudo may
have failed to watch the sandbox.

`--tui` works only when you call scudo by its own name. Through a symlink or the FUSE shim,
every argument after the command name belongs to the command, so scudo passes `--tui` on to it.

## Keys

Every key goes to the command except the prefix, `Ctrl-A` by default. The key after the prefix
is a scudo command:

| Key | Effect |
|-----|--------|
| `^A q` | quit, stopping the command if it is still running |
| `^A ^A` | send `Ctrl-A` to the command |
| `^A Tab` | move focus between the terminal and the panel's two lists |
| `^A PgUp` | read the scrollback with the arrows, `PgUp`/`PgDn` and `Home`/`End`; `Esc` returns |
| `^A r` | resize the panel with the arrows by one column and `h`/`l` by five; `=` restores automatic width, `Esc` returns |
| `^A w` | show or hide the panel |
| `^A s` | show or hide the profiles that matched and the command line scudo built |
| `^A m` | show or hide paths that were missing outside the sandbox too; see [file access reporting](filesystem.md#seeing-what-the-filesystem-restrictions-hid) |
| `^A /` | show only lines that match a pattern |
| `^A \` | hide lines that match a pattern |
| `^A n` | toggle between network lines only and all lines |
| `^A f` | toggle between filesystem lines only and all lines |
| `^A ?` | show this table |

When one of the panel's lists has focus, the arrows, `PgUp`/`PgDn` and `Home`/`End` scroll that
list. Every other key still goes to the command. The tally scrolls from the top down, the recent
list from its newest line back, and each stops at its last line.

To change the prefix, set `tui.prefix` in `[scudo]` or pass `--tui-prefix`. Write it as `C-a`,
`M-x` or `F12`. The prefix must include a modifier, because a bare character would become
impossible to type in the command.

## Filtering the panel

A build or a package manager can produce thousands of paths. Two filters reduce the panel to
the lines you care about, and you can combine them.

`^A /` opens a field for a regular expression and shows only the lines that match it. scudo
uses the same regex engine as the profile matchers. `^A \` opens the same field but hides the
matching lines instead. In the field:

- the filter updates as you type;
- `Tab` switches between showing and hiding matches;
- `Ctrl-U` clears the pattern;
- `Enter` keeps the pattern and returns the keyboard to the command;
- `Esc` closes the field and restores the filter that was active before.

Matching ignores case unless the pattern starts with `(?-i)`. While the pattern does not
compile, scudo ignores it and shows the error in red in the status bar, so the lists do not
empty out on every keystroke.

`^A n` shows only network lines and `^A f` only filesystem lines. Pressing the same key again
shows everything. The heading of each list names the active filters, for example
`[net] /usr`, so you can tell a filtered list from an empty one.

Filters change only what the panel displays. The `blocked N` count in the status bar and the
summary printed when the UI closes always cover the whole run.

## After the command exits

The UI stays open when the command exits. You can still scroll the scrollback and the lists,
show, hide and resize the panel, and open the help with `^A ?`. Keys that went to the command
now work without the prefix:

- the arrows, `PgUp`/`PgDn` and `Home`/`End` scroll the scrollback;
- `Tab` moves focus between the terminal and the lists;
- `q`, `Esc` or `Ctrl-D` close the UI.

scudo exits with the command's exit code. After it restores the terminal, it prints the summary
of what the sandbox blocked to stderr, so the summary stays in your scrollback.

## Panel width

By default the panel takes a quarter of the screen width, with a minimum of 34 columns and a
maximum of 60. The panel's contents never need more than 60 columns.

| screen | panel |
|--------|-------|
| 100 | 34 |
| 160 | 40 |
| 200 | 50 |
| 240 and wider | 60 |

`^A r` sets the width by hand. The keys move the border between the terminal and the panel.
`←` and `h` move it left and widen the panel, `→` and `l` move it right and narrow it. The
arrows move it by one column, the letters by five. scudo sends the new size to the command as
the border moves, so a full-screen program redraws while you resize.

## Settings

```toml
[scudo]
tui.prefix = "C-b"          # default "C-a"
tui.scrollback = 20000      # default 10000 lines
```
