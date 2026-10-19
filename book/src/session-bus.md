# Session bus

A command that can reach `systemd --user` can leave its sandbox: it only has to ask for a
process to be started in a sibling unit, or for its own to be moved into one. Chromium and
Electron do the latter on their own, to give themselves an `app-*.scope`. Out of the
sandbox's cgroup nothing bound to it applies any more — resource limits, IP filters, the
[network policy](network.md#network-filtering) — and the unit around it ends while the command is still
running, taking its `PrivateTmp=` with it.

So every sandboxed command, unless its profile says otherwise, gets:

| Property | Why |
|----------|-----|
| `InaccessiblePaths=-$XDG_RUNTIME_DIR/systemd` | the service manager's private socket |
| `InaccessiblePaths=-$XDG_RUNTIME_DIR/bus` | the session bus, which leads there too |
| `ProtectControlGroups=yes` | moving by hand, through `cgroup.procs` |

A property the profile sets itself is left alone: `systemd.ProtectControlGroups = false` stays
`no`, with a warning that the sandbox can now be left. `private` and `strict` get no warning:
they give the unit a cgroup namespace rooted at its own cgroup, and the kernel refuses every
migration across that root. Lists such as `InaccessiblePaths=` are
only ever added to, so a profile's own entries never stop these from being hidden.

Plenty of programs want a session bus, for the keyring, notifications or portals. The `dbus`
table gives them a filtered one instead:

```toml
[code.dbus]
session = "filter"    # "deny" (default), "filter" or "allow"
talk = ["org.freedesktop.secrets", "org.freedesktop.Notifications", "org.freedesktop.portal.*"]
see = []              # names that may be seen, but not called
own = ["com.visualstudio.code.*"]
call = []             # "NAME=RULE": calls allowed on a name not talked to
broadcast = []        # "NAME=RULE": broadcasts received from a name not talked to
log = false           # log every message, to the proxy unit's journal
```

The lists are an allow-list: whatever they do not name, the command cannot see on the bus, so
it cannot reach `org.freedesktop.systemd1` unless it is named. Naming anything implies
`session = "filter"`. Names may end in `.*`, which also matches the name itself; that is the
only wildcard there is. The options and their rules are
[`xdg-dbus-proxy`'s](https://man.archlinux.org/man/xdg-dbus-proxy.1), which does the
filtering. `session = "allow"` takes none of the three properties above away and leaves the
bus as it is, and with it the way out.

A name let through is let through entirely, whatever it can do on the command's behalf. Some
services start processes outside the sandbox when asked, `org.freedesktop.portal.*` included
(opening a link launches the browser, for instance), so name what the command needs and
nothing more.

## How the filter works

The proxy runs as a unit of its own, `scudo-dbus@<id>.service`, so that it can reach the real
bus that the sandbox cannot. The sandbox `Wants=` it and starts `After=` it is listening; its
socket is bind-mounted over `$XDG_RUNTIME_DIR/bus`, where every client already looks, and the
directory holding the other sandboxes' proxies is made inaccessible. Nothing needs the proxy
once the sandbox is gone (`StopWhenUnneeded=yes`), so systemd stops it. A proxy that fails to
start fails the sandbox as well: the bind mount has nothing to mount.

It needs `xdg-dbus-proxy`, and the `scudo-dbus@.service` template installed as a user unit:

```bash
sudo install -Dm644 scudo-dbus@.service -t /usr/lib/systemd/user
systemctl --user daemon-reload
```

Without either, a profile that asked for a filter gets no bus at all, and a warning.

A bus listening on an abstract socket (`unix:abstract=`) is not a file, and no mount can hide
it: scudo warns when it finds one, and only `PrivateNetwork=yes` keeps the command from it.

## Programs that detach

Some launchers, VS Code's included, start the real program in the background and exit. The
unit ends with its main process, and systemd kills what is left in it. Now that the program
cannot move itself to a unit of its own, add `systemd.ExitType = "cgroup"`: the unit then
lasts until the last process in it is gone, and `scudo` waits that long too.

## Nested calls

A sandboxed command that runs another one scudo wraps — `make` running `cargo` through a
shim, say — starts scudo again, inside the sandbox. When that sandbox cannot reach
`systemd --user` (the bus denied, or filtered without anything that lets
`org.freedesktop.systemd1` through), no new sandbox can be started from it, so the inner
scudo runs the command directly instead, without reading any config: it stays in the
sandbox it was started from, under that sandbox's restrictions and not the inner profile's.

This grants nothing the command did not already have: the outer sandbox could have run the
binary itself. What matters is that a scudo running *outside* any sandbox can never be made
to do the same, so the sign it looks for is not something the environment or a config file
could set, but its cgroup: the units of such sandboxes are named
`scudo-sealed-<id>.service`, and only a process already free to run `systemd-run` or write
to `cgroup.procs` could put itself in one.

A profile that sets `systemd.ProtectControlGroups = "private"` (or `"strict"`), as rootless
podman wants, hides that name: the unit gets a cgroup namespace of its own, in which its
cgroup reads as `/`. So such sandboxes also have `/dev/null` mounted on
`/run/user/<uid>/scudo/sealed`, and scudo takes a mount point there as the same sign. A file
at that path proves nothing — only a mount does, and making one takes a mount namespace,
which is as much freedom as writing to `cgroup.procs`.

- In a sandbox that can reach the manager (`session = "allow"`, a filter that names it, or
  a bus on an abstract socket), scudo starts a sandbox of its own as before, and the inner
  profile applies.
- A sealed sandbox whose profile delegates the command's profile (`delegate`, and the target
  `delegable`) hands the command to a broker outside, which runs it in a sandbox of its own: see
  [Delegating commands](delegation.md#delegating-commands).
- Restrictions asked for on the command line (`--profile`, `-P`, `--allow-dest`,
  `--deny-dest`, `--allow-port`, `--deny-port`, `--fs-hide`, `--fs-read`, `--fs-write`), `--delegate`, `--no-delegate` and `--tui` cannot be had
  inside, so they fail the command rather than being dropped. `--confirm` still asks.
