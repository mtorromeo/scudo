# scudo

scudo wraps commands with [`systemd-run`](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html), applying resource limits and sandboxing constraints defined in per-command profiles. It requires Linux with systemd.

## Usage

```
Usage: scudo [OPTIONS] <COMMAND> [COMMAND_ARGS]...

Arguments:
  <COMMAND>          
  [COMMAND_ARGS]...  

Options:
  -v, --verbose                         Enable verbose output. A shorthand for `--log-level debug`
      --log-level <LEVEL>               How much to report: off, error, warn, info, debug or trace [env: SCUDO_LOG_LEVEL]
      --log-target <TARGET>             Where to report it: stderr, file, syslog or journald (repeatable) [env: SCUDO_LOG_TARGET]
      --log-file <PATH>                 Write the log to this file. Implies `--log-target file` [env: SCUDO_LOG_FILE]
      --log-syslog-facility <FACILITY>  The syslog facility to log under. Only used by `--log-target syslog` [env: SCUDO_LOG_SYSLOG_FACILITY]
      --confirm                         Confirm before running the command
  -P, --property <PROPERTY=VALUE>       Set a property for the systemd-run command
  -p, --profile <NAME>                  Apply the named profile, ignoring its match rules (repeatable, comma-separated)
      --no-match                        Skip profile matching; apply only the profiles given with --profile
      --allow-dest <DEST>               Allow a destination (address, CIDR, host or glob), even one a profile denies (repeatable, comma-separated)
      --deny-dest <DEST>                Deny a destination, even one a profile allows (repeatable, comma-separated)
      --allow-port <PORT[/PROTO]>       Allow a port or range, optionally `/tcp` or `/udp`, even one a profile denies (repeatable, comma-separated)
      --deny-port <PORT[/PROTO]>        Deny a port or range, optionally `/tcp` or `/udp`, even one a profile allows (repeatable, comma-separated)
      --tui                             Run the command in scudo's terminal UI, beside a live list of blocks
      --tui-prefix <KEY>                The UI's prefix key, as `C-a`, `M-x` or `F12`. Overrides `[scudo]`
  -h, --help                            Print help
  -V, --version                         Print version
```

**Via symlink** — scudo detects it is being called through a symlink and selects the matching profile automatically:

```
ln -s /usr/bin/scudo /usr/local/bin/curl
curl https://example.com   # runs through scudo with the "curl" profile
```

**Via shell alias** — a lighter alternative that requires no changes to the filesystem:

```bash
alias curl='scudo curl'
alias wget='scudo wget'
```

**Via FUSE shim** — a virtual filesystem that intercepts every command automatically, with no per-command setup:

```bash
scudo-fuse ~/.scudo/shims /usr/bin/scudo
export PATH="$HOME/.scudo/shims:$PATH"
```

`scudo-fuse` mounts a read-only virtual directory. Every executable found in `PATH` appears there as a symlink pointing to the target binary (`/usr/bin/scudo`). Commands not present in the real `PATH` remain invisible, so tab-completion and `ls` only show entries that actually exist. Placing the shims directory first in `PATH` causes any command with a matching profile to be dispatched through scudo automatically, with no aliases or individual symlinks needed.

The shims directory itself is excluded from the PATH search used for the existence check, which prevents FUSE re-entrancy deadlocks when the shims directory is already in `PATH`.

> **Warning:** When using the FUSE shim, avoid broad globs (`*`, `code*`) that match large numbers of commands in combination with `confirm = true` or `verbose = true`. Because the shim intercepts every command in your session — including those run by scripts, your shell itself, and every subprocess — an overly wide profile with interactive options will trigger a confirmation prompt or dump debug output for each of them, making the environment unusable. Reserve `confirm` and `verbose` for profiles that match a few commands by name, and validate broad profiles without those options first.

By default the command search path is read from the `PATH` environment variable; pass `--path` / `-p` to override it:

```bash
scudo-fuse ~/.scudo/shims /usr/bin/scudo --path /usr/local/bin:/usr/bin:/bin
```

**Autostart with systemd (user service)**

A ready-made unit file is included in the repository as `scudo-fuse.service`. It uses `RuntimeDirectory=scudo` so the shims directory is created automatically under `$XDG_RUNTIME_DIR` (e.g. `/run/user/1000/scudo/shims`).

```bash
cp scudo-fuse.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now scudo-fuse
```

Add the `PATH` export to your shell's init file (`.bashrc`, `.zshrc`, …):

```bash
export PATH="${XDG_RUNTIME_DIR}/scudo/shims:$PATH"
```

## Configuration

Profiles are loaded from the following paths in order, with later files taking precedence over earlier ones:

| Path | Scope |
|------|-------|
| `/etc/scudo/config.toml` | system-wide |
| `$XDG_CONFIG_HOME/scudo/config.toml` | per-user |
| `/.scudo.toml` … `$PWD/.scudo.toml` | per-directory |

For the per-directory tier, scudo walks every ancestor of `$PWD` from the filesystem root down to the current directory, loading each `.scudo.toml` it finds. This lets a project directory override settings defined higher up the tree. For example, with `$PWD` set to `/home/user/projects/myapp`, the lookup order is `/.scudo.toml`, `/home/.scudo.toml`, `/home/user/.scudo.toml`, `/home/user/projects/.scudo.toml`, `/home/user/projects/myapp/.scudo.toml`.

Every top-level section is a profile, with one exception: `[scudo]` holds settings that are
about scudo itself rather than about a command — the [logging](#logging) defaults, the
[terminal UI](#terminal-ui) and the [lookup variables](#lookup-variables) every profile can
use. It is merged key by key across the files above like everything else, and `scudo` is
therefore not available as a profile name.

```toml
[scudo]
log.level = "info"
tui.prefix = "C-b"
tui.scrollback = 20000
vars.PROJECT_DIR = { lookup = ".git", fallback = "cwd" }
```

### Trust confirmation for per-directory configs

Because `.scudo.toml` files can be committed to a repository and may arrive from external sources, scudo requires explicit user approval before loading them. On first encounter scudo prints the full file contents and asks for confirmation. When a previously approved file changes, scudo shows a unified diff against the trusted version and asks again.

```
New config file: /home/user/projects/myapp/.scudo.toml

  [curl]
  PrivateNetwork = true
  MemoryMax = "256M"

Trust this config file? [y/N]
```

Approved files are recorded in `$XDG_CONFIG_HOME/scudo/trusted.toml`. Matching is done on the canonical absolute path and the exact file contents. If the user declines, scudo exits with an error rather than running the command without the intended sandboxing constraints.

### Profiles

Each TOML section defines a profile. The section name identifies the profile for `extend` and `--profile`; it is not a match pattern.

| Field | Type | Description |
|-------|------|-------------|
| `match` | string or array of strings | Glob(s) matched against the command name; any one is enough. See [Match patterns](#match-patterns). Absent = the profile never matches a command on its own and is reachable only through `extend` or `--profile`. |
| `extend` | string or array of strings | Profile(s) applied before this one, left to right; see [Combining profiles](#combining-profiles) |
| `inherit` | bool | Whether this profile adds to a same-named profile from a lower-priority config file (`true`, the default) or replaces it (`false`); see [Same-named profiles across files](#same-named-profiles-across-files) |
| `exec` | string | Absolute path of the binary to execute, bypassing PATH resolution |
| `verbose` | bool | Shorthand for `log.level = "debug"`, which among other things prints the full `systemd-run` command before executing (default: `false`) |
| `confirm` | bool | Prompt for confirmation before executing (default: `false`); silently skipped in non-interactive shells |
| `args` | table | Maps `$arg_*` variable names to the flag(s) that fill them; see [Command argument variables](#command-argument-variables) |
| `vars` | table | Variables naming a directory found by looking up the tree; see [Lookup variables](#lookup-variables) |
| `filesystem` | table | Which paths the command may write, read, not see or not touch; see [Filesystem access](#filesystem-access) |
| `network` | table | Network policy; see [Network filtering](#network-filtering) |
| `dbus` | table | What the command gets of the session bus; see [Session bus](#session-bus) |
| `log` | table | Level and destination for scudo's own output; see [Logging](#logging) |
| `systemd` | table | Unit properties passed to `systemd-run`; see below |

Every key of the `systemd` table is passed directly to `systemd-run` as `-p Key=value`. Use the exact systemd unit property names (PascalCase). Values can be strings, booleans (`true`/`false` → `yes`/`no`), integers, or arrays. Write it either as a sub-table header (`[curl.systemd]`) or with dotted keys (`systemd.MemoryMax = "256M"`).

The command starts in the current directory, unless `WorkingDirectory` is set (in the table or with `-P`): then `systemd-run` is not given `-d` and the property decides.

Any other key is a typo and scudo says so instead of ignoring it.

### Example

```toml
# The project a command runs in: the closest directory holding a `.git`
[scudo]
vars.PROJECT_DIR = { lookup = ".git", fallback = "cwd" }

# Base profile — no `match`, so it is never matched directly, only used via extend
[sandboxed]
filesystem.read = ["/"]
filesystem.write = ["/tmp", "$XDG_RUNTIME_DIR"]
systemd.PrivateTmp = true

[sandboxed-home]
extend = "sandboxed"
filesystem.hide = ["$HOME"]
filesystem.write = ["$HOME/.cache"]

# curl: extends the base sandbox
[curl]
match = "curl"
extend = "sandboxed"
systemd.MemoryMax = "256M"

# claude: works on the project it is started in, plus any --add-dir
[claude]
match = "claude"
extend = "sandboxed-home"
args.add_dir = { flags = "--add-dir", greedy = true }
filesystem.read = ["$HOME/.gitconfig", "$arg_add_dir"]
filesystem.write = ["$PROJECT_DIR", "$HOME/.claude", "$HOME/.claude.json"]
network.dest.allow = ["*.anthropic.com"]

# code: VS Code and its variants
[code]
match = ["code", "code-oss", "codium", "vscode"]
extend = "sandboxed-home"
filesystem.write = [
  "/proc",
  "/dev/shm",
  "/dev/dri",
  "$HOME/.vscode",
  "$HOME/.vscode-oss",
  "$HOME/.config/Code",
  "$HOME/.config/Code - OSS",
  "$PROJECT_DIR",
]
# The launcher leaves the editor running and exits: keep the unit until it is gone.
systemd.ExitType = "cgroup"
dbus.talk = [
  "org.freedesktop.secrets",
  "org.freedesktop.Notifications",
  "org.freedesktop.portal.*",
]
dbus.own = ["com.visualstudio.code.*"]

# npm: the npm cache and config, and the project
[npm]
match = "npm"
extend = "sandboxed-home"
filesystem.write = ["$HOME/.npm", "$PROJECT_DIR"]
filesystem.read = ["$HOME/.npmrc"]

[pnpm]
match = "pnpm"
extend = "npm"
filesystem.write = ["$HOME/.pnpm-store"]
```

Every list adds to the ones it inherits: `pnpm` can write `~/.npm`, the project and `~/.pnpm-store`, and read everything `sandboxed` lets it read.

### Filesystem access

The `filesystem` table says what the command may do with a path, in four lists:

| List | Meaning | Becomes |
|------|---------|---------|
| `write` | read and write | `ReadWritePaths=`, or `BindPaths=` inside a hidden directory |
| `read` | read only | `ReadOnlyPaths=`, or `BindReadOnlyPaths=` inside a hidden directory |
| `hide` | replaced by an empty, throwaway directory | `TemporaryFileSystem=` |
| `deny` | no access at all | `InaccessiblePaths=` |

```toml
[claude.filesystem]
hide = ["$HOME"]
deny = ["/etc/shadow"]
read = ["/", "$HOME/.gitconfig"]
write = ["$PROJECT_DIR", "$HOME/.claude"]
```

Writing the lists rather than the systemd properties is what lets profiles written without knowing about each other be combined:

- **A path named more than once gets the most permissive access** among them: `write` beats `read`, which beats `hide`, which beats `deny`. Which profile came first does not matter, so a profile that only reads a directory cannot take writing away from one that writes it.
- **What is granted inside a hidden directory is mounted back in.** A path under a `TemporaryFileSystem=` is not there to be made read-only, so `read` and `write` turn into bind mounts there — even when the `hide` comes from a different profile than the grant.

Every entry is made absolute against the current directory, and an entry that expands to nothing (an absent `$arg_*`) is dropped. Paths that do not exist are skipped rather than failing the command (they are passed with systemd's `-` prefix): a tool's config directory often does not exist yet.

Properties written by hand in the `systemd` table are passed as they are, next to the ones generated here.

### Session bus

A command that can reach `systemd --user` can leave its sandbox: it only has to ask for a
process to be started in a sibling unit, or for its own to be moved into one. Chromium and
Electron do the latter on their own, to give themselves an `app-*.scope`. Out of the
sandbox's cgroup nothing bound to it applies any more — resource limits, IP filters, the
[network policy](#network-filtering) — and the unit around it ends while the command is still
running, taking its `PrivateTmp=` with it.

So every sandboxed command, unless its profile says otherwise, gets:

| Property | Why |
|----------|-----|
| `InaccessiblePaths=-$XDG_RUNTIME_DIR/systemd` | the service manager's private socket |
| `InaccessiblePaths=-$XDG_RUNTIME_DIR/bus` | the session bus, which leads there too |
| `ProtectControlGroups=yes` | moving by hand, through `cgroup.procs` |

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

#### How the filter works

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

#### Programs that detach

Some launchers, VS Code's included, start the real program in the background and exit. The
unit ends with its main process, and systemd kills what is left in it. Now that the program
cannot move itself to a unit of its own, add `systemd.ExitType = "cgroup"`: the unit then
lasts until the last process in it is gone, and `scudo` waits that long too.

#### Nested calls

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

- In a sandbox that can reach the manager (`session = "allow"`, a filter that names it, or
  a bus on an abstract socket), scudo starts a sandbox of its own as before, and the inner
  profile applies.
- Restrictions asked for on the command line (`--profile`, `-P`, `--allow-dest`,
  `--deny-dest`, `--allow-port`, `--deny-port`) and `--tui` cannot be had
  inside, so they fail the command rather than being dropped. `--confirm` still asks.

### Network filtering

`PrivateNetwork = true` is all-or-nothing. The `[profile.network]` table asks for something
finer: deny everything by default and allow only what the command actually needs.

```toml
[cargo]
match = "cargo"
extend = "sandboxed-home"

[cargo.network]
default = "deny"            # "deny" (default) or "allow"
inbound = "deny"            # "deny" (default) or "allow"
on_unavailable = "fail"     # "fail" (default), "no-network", or "warn"
log = "off"                 # "off" (default) or "denied"; "denied" is watchable
                            # even when the policy denies everything

dest = { allow = ["10.0.0.0/8", "*.crates.io"], deny = ["10.1.2.0/24"] }
ports = { allow = [443, "53/udp"], deny = [22] }
```

#### The two dimensions

**`dest` and `ports` are independent sources of permission, not filters that narrow one
another.** A packet is judged by:

```text
if the destination is denied  or the port is denied   ->  deny
if the destination is allowed or the port is allowed  ->  allow
otherwise                                             ->  the default
```

Three things follow, and the second one is the one to read twice:

- **An empty `allow` list grants nothing, not everything.** A dimension with nothing in it
  abstains and the other one decides.
- **`ports.allow` opens those ports at *every* address**, including ones `dest` never mentions.
  It widens; it does not narrow. There is no way to say "port 443, but only on this host" —
  that is the price of dropping the per-rule port, and it is what lets the whole policy be two
  map lookups instead of a scan.
- **`ports.deny` is what narrows**, and it revokes everywhere — including at an address
  `dest.allow` names.

Traffic with no port of its own — ICMP, raw sockets — needs no special case: the port dimension
abstains on both sides and the destination decides alone.

#### Destinations

A `dest` entry is a bare string:

| Form | Example |
|------|---------|
| CIDR | `"10.0.0.0/8"`, `"2606:4700::/32"` |
| Address | `"1.1.1.1"`, `"2606:4700::1"` |
| Host or glob | `"api.github.com"`, `"*.crates.io"` |
| Symbolic name | `"any"`, `"localhost"`, `"link-local"`, `"multicast"` |

IPv6 addresses are written plainly — there is no port to tell them apart from, so they need no
brackets. Hosts accept `*` and `?` globs, and `*` crosses dots: `*.crates.io` covers
`a.b.crates.io` but not the bare `crates.io`. A symbolic name is systemd's, and expands to its
IPv4 *and* IPv6 networks.

#### Ports

A `ports` entry is a number, or a string holding a range, either of them optionally narrowed to
one protocol with a `/tcp` or `/udp` suffix:

| Form | Example |
|------|---------|
| Port | `443` |
| Range | `"8000-8100"` |
| Port and protocol | `"53/udp"` |
| Range and protocol | `"8000-8100/tcp"` |

A port written without a protocol covers TCP and UDP both.

#### Order does not matter

Every entry of a list carries the same verdict, so which one matches cannot change the outcome,
and `deny` beating `allow` is a property of how the two are consulted rather than of where
rules sit. That makes merging two profiles' lists a plain union: commutative, idempotent, and
impossible to get wrong by reordering. Entries take `$VAR` and `$arg_*` expansions like any
other profile value, and each of the four lists adds to the one it inherits.

#### From the command line

`--allow-dest`, `--deny-dest`, `--allow-port` and `--deny-port` change the rules for one run,
without touching the config. They take the same values as `dest` and `ports`, are repeatable
and accept comma-separated lists:

```
scudo --allow-dest api.github.com,10.0.0.0/8 --allow-port 53/udp --deny-port 22 cargo build
```

They are applied after every profile, those selected with `--profile` included, and they
**move** an entry rather than only adding it: `--allow-dest X` takes `X` out of `dest.deny` and
puts it in `dest.allow`, and `--deny-dest X` does the opposite. Without that, allowing something a
profile denied would change nothing, since a deny always wins. Entries are compared once
normalised — `localhost` stands for both of its networks, host names ignore case — and a port
is only the same rule with the same range and protocol, so `--deny-port 443` leaves an allowed
`443/tcp` alone. Allowing and denying the same entry at once is an error.

When no profile has a `network` table, the flags make a policy of their own. If any of them
allows something, it denies everything else, as `network = { ... }` would; if they only deny,
everything else stays allowed. Either way the other settings keep their defaults — the service
manager stays out of reach and `on_unavailable` is `"fail"`. When a profile does have a policy,
its `default` and `inbound` are left as they are.

Denying everything (`network = {}`) is realised with `PrivateNetwork=yes` and needs nothing
else — unless it also asks to be told what it turned away, which attaches an observer beside it;
see [Seeing what was blocked](#seeing-what-was-blocked). Anything finer needs the `scudo-bpfd` helper, which attaches eBPF programs to the
command's cgroup; systemd's own `IPAddressAllow=` and `SocketBindAllow=` are silently ignored
in user units, since `systemd --user` may not load BPF programs.

#### Names

**Naming a host in `dest` is what allows that domain to be resolved**, and the DNS allowlist is
nothing more than the set of names the destination lists mention. `scudo-bpfd` answers the
sandbox's DNS itself: the eBPF programs redirect every query to a resolver bound to loopback for
that one sandbox, which refuses names no rule mentions, forwards the rest to the system's
nameservers, and records the `A` and `AAAA` addresses it hands back. From that moment those
addresses are covered by the list that named the host, as `/32` and `/128` prefixes like any
other. Both UDP and TCP queries are served, and a truncated answer is retried over TCP.

The redirect happens before any check, so a policy whose port lists never mention 53 still
resolves names — and, for the same reason, `ports.deny = [53]` does not take that away: the
query never reaches the port rules, because it never reaches port 53. What decides which names
may be looked up is the set of names the destination rules mention, and nothing else. A policy
that names no host gets no resolver at all, and then port 53 is judged like any other port.

Three things follow from this design, and all three are deliberate:

- **The rule is matched against the question, not the CNAME chain**, so a rule for
  `api.github.com` covers whatever that name ends up resolving to.
- **A name in `dest.deny` still resolves.** That is how its addresses become known, so the rule
  keeps them out of reach even for a program that had the address hardcoded. Since the deny
  side is consulted first, the connection fails either way.
- **A name no rule mentions is refused — unless refusing it would buy nothing.** With
  `default = "allow"`, with a destination covering the whole address space (`any`,
  `0.0.0.0/0`), or with any `ports.allow` at all — each of these already lets the command reach
  an address it never named, so refusing the lookup would only break it.

Addresses learnt this way expire with the record's TTL, clamped to between 30 seconds and an
hour — a zero TTL would otherwise expire the address before the program managed to connect.
Expiry is a *removal*: the resolver takes the prefix back out, and the programs carry no expiry
check of their own. That is not an oversight. A prefix that had expired but was still present
would keep covering the shorter prefixes underneath it, with no way to fall back to the
next-longest match — so a stale `/32` in the deny trie would read as "no match" and let traffic
through. With removal alone, a sweep that runs late merely leaves an entry doing what it was
already doing for another half second, which errs the safe way in both directions.

A DNS-over-HTTPS or DNS-over-TLS resolver bypasses this entirely, but not the address rules:
its server has to be in the allowlist like anything else.

#### How it is enforced

`scudo-bpfd` attaches four `cgroup/sock_addr` programs (`connect4`, `connect6`, `sendmsg4`,
`sendmsg6`) so a blocked destination fails with a clean `EPERM` at `connect()` rather than
timing out, plus a `cgroup_skb` egress program as a backstop — the only layer that also covers
raw sockets, ICMP and anything that is neither TCP nor UDP. With `inbound = "deny"` an ingress
program matches the *source* address, and the source port, against the same two lists, the way
`IPAddressAllow=` does, so replies from an allowed peer still arrive. `recvmsg4` and `recvmsg6`
put the source of a redirected DNS reply back to the nameserver the query was sent to — the
address is remembered per socket, keyed by its cookie, when the query is redirected — so a stub
resolver on an unconnected socket, which checks that the answer came from the server it asked,
does not throw it away.

Programs are attached as BPF links, which stack: the kernel combines the verdicts of every
program on a cgroup with a logical AND, so a second policy on the same cgroup can only ever
narrow what is permitted, never widen it.

Profiles with an enforced policy also get `ProtectControlGroups=yes`, which keeps the command
from migrating out of the cgroup the programs are attached to, and one that needs the resolver
loses systemd-resolved's varlink sockets, since a lookup made through `nss-resolve` would
neither obey the allowlist nor teach the policy the address it resolved to.

None of this holds if the command can leave its cgroup — by asking `systemd --user` for a
sibling unit, for one, which has a network and no program of ours attached. Every sandbox is
kept in its cgroup whether it has a network policy or not; see [Session bus](#session-bus).

#### Installing the helper

```bash
sudo install -m755 target/release/scudo-bpfd /usr/bin/scudo-bpfd
sudo setcap cap_bpf,cap_net_admin,cap_perfmon=ep /usr/bin/scudo-bpfd
systemctl --user enable --now scudo-bpfd.socket
```

The daemon holds `CAP_BPF` and `CAP_NET_ADMIN` as file capabilities, so anyone on the system
can execute it. `CAP_PERFMON` is a third it can do without: it is needed only to load the
tracepoint programs behind [file access reporting](#seeing-what-the-filesystem-restrictions-hid),
and a daemon started without it does everything else and says so when that one thing is asked
for. What keeps that harmless is that it offers exactly one operation — *add*
restrictions to a cgroup the caller already owns — and no way to remove them: policies are
detached only when the cgroup itself disappears. It refuses any cgroup outside the calling
user's own systemd subtree, which it establishes from `SO_PEERCRED` rather than from anything
the caller says.

Registration happens in two steps for a reason. `scudo` registers the policy and gets a
single-use token; the command is then started as `scudo --bpf-shim <token> -- <command>`, and
that shim — running inside the unit, in the final cgroup — claims the token and only then
execs the real command. The cgroup does not exist before the unit starts, so registering
earlier is impossible, and attaching afterwards would leave a window in which the command runs
unfiltered.

**When the policy cannot be enforced** — the helper is not installed, lacks its capabilities,
or the kernel does not support it — `on_unavailable` decides what happens:

| Value | Behaviour |
|-------|-----------|
| `fail` (default) | The command does not run. |
| `no-network` | The command runs with no network at all. |
| `warn` | A warning is printed and the command runs unfiltered. |

The default is fail-closed: a profile that asks for a network policy never silently runs
without one.

#### Seeing what was blocked

A denied connection reaches the command as a bare `EPERM`, and a denied packet as nothing at
all, so a policy that is one rule too tight looks like a program that is simply broken.
`--verbose`, or `log = "denied"` on the profile, turns every refusal into a line on stderr:

```console
$ scudo --verbose -- curl -sS https://example.com/
scudo: warning: blocked DNS lookup of example.com (no rule names it)
scudo: warning: blocked connect to 1.1.1.1:443/tcp
scudo: curl: blocked example.com (2x), 1.1.1.1:443 (7x) [5 repeats suppressed]
```

Mixed into the command's own output, those lines are easy to lose; the
[terminal UI](#terminal-ui) puts them in a panel of their own instead:

```console
$ scudo --tui -- curl -sS https://example.com/
```

Each refusal is a `warn` event and the closing summary an `info` one, so they follow whatever
[logging](#logging) is configured. On journald they carry the address, port, stage and
transport as fields of their own, which is what makes them filterable there:

```console
$ journalctl -t scudo F_STAGE=connect -o json | jq -r '.F_ADDR + ":" + .F_PORT'
```

Refused DNS lookups are on the same stream, and usually come first: naming a host in a rule is
also what permits resolving it, so a missing rule shows up as a name that will not resolve long
before any address is reached.

Reporting is off unless asked for. It costs a ring buffer per sandbox and a small process to
read it, and with it off the emit sites are folded out of the eBPF programs entirely, so a
sandbox nobody is watching pays nothing. Repeats of the same refusal within a few seconds are
collapsed into one line — a denied connection is retried, and one `curl` would otherwise fill
the screen — and the closing summary counts every attempt, including the ones that were never
printed.

A policy that denies everything is realised by taking the network away rather than by attaching
anything, so on its own it has nothing to report from. Asking to be told is what changes that:
an *observer* is attached beside the empty namespace, allowing `localhost` and denying the rest
— which is exactly what that namespace already permits, so nothing is enforced that was not
enforced before and loopback keeps working without reporting itself. The cgroup hooks are not
scoped to a network namespace, which is what lets them see refusals inside one.

The observer is reporting and nothing else, so losing it costs only the reporting: if
`scudo-bpfd` cannot be reached, `on_unavailable` does **not** apply — the command runs, with the
network still taken away, and a warning says the refusals will not be named. `scudo-bpfd` is
needed to *watch* a deny-all policy; it is never needed to *enforce* one.

### Seeing what the filesystem restrictions hid

`ReadOnlyPaths=`, `TemporaryFileSystem=`, `InaccessiblePaths=`, `ProtectHome=` and `PrivateTmp=`
are applied by systemd, by rearranging the unit's mount namespace. scudo has no part in the
verdict and no hook that sees it: the command is handed an `ENOENT`, `EACCES` or `EROFS` with
no way to say which path it was about, and a profile that is one `BindPaths=` short looks
exactly like a program that is broken.

`filesystem.log = "denied"` on the profile — or `--verbose`, or `--tui` — asks `scudo-bpfd` to
watch the syscalls that name a path and report the ones that come back with an error a sandbox
could have caused:

```console
$ scudo --verbose --profile sandboxed-home -- bash -lc 'git status'
scudo: warning: blocked open of /home/me/.bashrc (hidden by the sandbox)
scudo: warning: blocked open of /home/me/.gitconfig (hidden by the sandbox)
scudo: warning: blocked open of /etc/shadow (permission denied)
```

```toml
[code]
match = ["code"]
filesystem.log = "denied"          # off (the default) | denied
filesystem.hide = ["$HOME"]
filesystem.write = ["$HOME/.config/Code"]
```

**Not every `ENOENT` is a refusal, and telling them apart is the point.** A shell walking
`$PATH`, a linker searching for a library, `node` resolving a module — all of them ask for
dozens of files that were never anywhere, and the kernel answers them exactly as it answers a
file the sandbox hid. So the daemon, which lives outside the unit's mount namespace, simply
goes and looks:

| What happened | How it reads |
|---|---|
| The path is there outside the sandbox | `blocked open of … (hidden by the sandbox)`, a `warn` |
| `EACCES`/`EPERM`, whatever is outside | `blocked open of … (permission denied)`, a `warn` |
| `EROFS`, whatever is outside | `blocked mkdir of … (read-only)`, a `warn` |
| It was not there outside either | `open of … failed: not there outside the sandbox either`, a `debug` |
| Could not be established | `… cannot tell whether it exists outside`, an `info` |

Nothing is thrown away — the level is what keeps a linker's search out of an ordinary run. Raise
the level to `debug` to see all of it, or in the [terminal UI](#terminal-ui) press `^A m`, which
shows the missing paths greyed beside the ones that were really taken away. On journald the
path, operation, error and outside verdict are fields of their own:

```console
$ journalctl -t scudo F_OUTSIDE=present -o json | jq -r .F_PATH
```

Only calls that name a path are watched: `open`, `openat`, `openat2`, `creat`, `stat`, `lstat`,
`newfstatat`, `statx`, `access`, `faccessat`, `faccessat2`, `readlink`, `readlinkat`, `execve`,
`execveat`, `unlink`, `unlinkat`, `rmdir`, `mkdir`, `mkdirat`, `rename`, `renameat`,
`renameat2`, `truncate` and `chdir`. One working on a file descriptor has already got past the
sandbox: the open that produced the descriptor is the call that would have been refused.

Unlike the network programs, which are loaded once per sandbox and attached to its cgroup,
these sit on the machine's `sys_enter` and `sys_exit` tracepoints, so one object is loaded for
the whole daemon — on the first sandbox that asks, and unloaded with the last. The cgroups
being watched live in a map the programs consult first, which is also what keeps a path
belonging to any other process on the machine from ever leaving the kernel.

They are *raw* tracepoints, attached by name through `bpf(2)`. A classic tracepoint per syscall
would be the obvious shape, but attaching one means reading its id out of
`<tracefs>/events/…/id`, and tracefs is `drwx------ root` on an ordinary system — no capability
opens it. Only x86-64 is implemented, since the syscall numbers are per-architecture and a
table guessed for another one would report the wrong calls rather than fail.

Reporting is off unless asked for, and asking for it costs the command a registration with the
daemon and a `ProtectControlGroups=yes` it would not otherwise have — the events are matched on
the cgroup they came from, and a command that can move itself out of that cgroup stops being
reported. A daemon without `CAP_PERFMON` says so and the command runs anyway: not being able to
watch something is never a reason not to run it.

### Logging

Everything scudo says about itself — warnings, the resolution trace, what a sandbox refused —
goes through one leveled logger. Both the level and the destination come from a `log` table on
the profile:

```toml
[curl]
match = "curl"
log.level = "debug"                  # off, error, warn, info, debug, trace
log.target = "file"                  # stderr, file, syslog, journald
log.path = "$SCUDO_CONFIG_DIR/scudo.log"
log.syslog_facility = "user"         # only read by target = "syslog"
```

`log.target` takes one target or a list of them, and a message goes to all of them. Naming a
`log.path` and no target selects the file, since there is nothing else the path could be for.
The default is `warn` on stderr — exactly the set of messages scudo printed before it had
levels at all.

Defaults for every command go in the reserved `[scudo]` section:

```toml
[scudo]
log.level = "info"
log.target = "journald"
```

It sits **under** the profiles rather than over them, which is what makes it a default: a
profile can be quieter than it as well as louder — unlike `verbose`, which only ever adds. A
profile matching everything says the same thing and is still perfectly good:

```toml
[default]
match = "*"
log.level = "info"
```

Between two profiles the ordinary order applies (the one written later wins, and `--profile`
above all; see [Combining profiles](#combining-profiles)), so write the catch-all first. `verbose = true` is still accepted and means `log.level = "debug"`; a level
written out next to it wins, being the more specific of the two.

The command line overrides the profiles:

```console
$ scudo --log-level debug -- curl https://example.com/
$ scudo --log-file /tmp/scudo.log -- npm install
$ scudo --log-target syslog,stderr -- rsync -a src/ dst/
```

`-v`/`--verbose` raises the floor to `debug` rather than setting it, so it cannot quieten a
`--log-level trace` written beside it. Each flag also reads an environment variable
(`SCUDO_LOG_LEVEL`, `SCUDO_LOG_TARGET`, `SCUDO_LOG_FILE`, `SCUDO_LOG_SYSLOG_FACILITY`).

Anything scudo emits while it is still reading the config obeys the command line and the
environment, not the config — the setting is not known yet. Use `--log-level` or
`SCUDO_LOG_LEVEL` to see that part of a run.

Stderr keeps the shape it always had (`scudo: warning: …`), with the event's fields appended
only at `debug` and below; a file adds a timestamp and the level; syslog and journald receive
the fields as fields. The confirmation prompt and the trust diff are **not** logs: they are
interactive output and always go to stderr, whatever the destination.

### Terminal UI

`--tui` runs the command inside scudo rather than in place of it: a full terminal on the left,
and on the right a live list of what the sandbox turned away.

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

#### Keys

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
| `^A m` | show or hide paths that were missing outside the sandbox too — see [file access reporting](#seeing-what-the-filesystem-restrictions-hid) |
| `^A /` | keep only the lines matching a pattern |
| `^A \` | the same, keeping out what matches instead |
| `^A n` | the network only, or everything again |
| `^A f` | the filesystem only, or everything again |
| `^A ?` | the list above |

With one of the panel's lists focused, the arrows, `PgUp`/`PgDn` and `Home`/`End` move that
list instead of reaching the command; every other key still reaches it, so the focus never
swallows what was typed. The tally is read from the top down and the running list from its
newest line back, and each stops at its own last line.

#### Narrowing the panel

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

#### How wide the panel is

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

#### Settings

```toml
[scudo]
tui.prefix = "C-b"          # default "C-a"
tui.scrollback = 20000      # default 10000 lines
```

### Match patterns

`match` holds one glob, or an array of them, compared against the name of the command — its last path component, so `/usr/bin/curl` is `curl`. Any one of them matching is enough.

| Form | Meaning |
|------|---------|
| absent | never match — base profile usable only via `extend` or `--profile` |
| `match = "curl"` | `curl` |
| `match = ["zed", "zeditor"]` | either `zed` or `zeditor` |
| `match = "code*"` | `code`, `code-oss`, `code-insiders`, … |
| `match = "*"` | every command: a catch-all default |

Every profile that matches is applied, in the order the profiles were written (see [Combining profiles](#combining-profiles)).

### Selecting profiles explicitly

`--profile <NAME>` applies a profile by name, whatever its `match` field says — including base profiles that declare no `match` at all. It is repeatable and also accepts a comma-separated list. Named profiles are applied *after* the ones that matched, so they take precedence; among themselves they are applied in the order given on the command line, with the last one winning.

`--no-match` skips pattern matching altogether. Combined with `--profile` it means "use exactly these profiles and nothing else"; on its own it runs the command with no profile at all.

| Invocation | Profiles applied |
|------------|------------------|
| `scudo --profile netblock -- curl https://example.com` | everything matching `curl`, then `netblock` |
| `scudo --profile a,b -- curl https://example.com` | matches for `curl`, then `a`, then `b` |
| `scudo --profile claude,npm,cargo -- zsh` | a shell with everything those three profiles allow, and their restrictions |
| `scudo --no-match --profile netblock -- curl https://example.com` | only `netblock` |
| `scudo --no-match -- curl https://example.com` | none — the command is executed directly, without `systemd-run` |
| `scudo --no-match -p MemoryMax=1G -- curl https://example.com` | none, but `systemd-run` still runs with the explicit property |

A profile that both matches and is named explicitly is applied only once, in its explicit position. An unknown profile name is a fatal error: scudo exits with status 1 without running the command, rather than running it with less sandboxing than was asked for.

```
$ scudo --profile snadboxed -- curl https://example.com
scudo: profile 'snadboxed' not found
```

Both flags belong to scudo itself, so they are only available through the explicit `scudo <command>` form. When scudo is invoked through a symlink or the FUSE shim, every argument belongs to the wrapped command.

### Combining profiles

Profiles come together in four ways — `extend`, matching the same command, `--profile`, and sharing a name across config files — and all four combine them the same way:

- **Lists accumulate.** Every array — in `match`, `extend`, `filesystem`, `network`, `dbus` and `systemd` — adds the entries it has to the ones already there, skipping duplicates. No profile can take away what another one added; for paths, see also [Filesystem access](#filesystem-access).
- **Everything else is taken from the profile applied last**, when it says anything: `exec`, `confirm`, `log.level`, `network.default`, `dbus.session`, a scalar systemd property such as `MemoryMax`.
- **`args` declarations are merged by name**, the last one applied winning.

The order profiles are applied in:

1. every profile that matches the command, in the order they were written: config files from the lowest priority to the highest, then by position in the file;
2. the profiles named with `--profile`, in the order given.

Each one is preceded by the profiles it `extend`s, left to right, recursively. A profile is applied once even when several others extend it, so a base shared by two profiles does not undo what the first one added on top of it.

```toml
[base]
systemd.BindPaths = ["/base"]

[cargo]
extend = "base"
systemd.BindPaths = ["$HOME/.cargo"]

[composer]
extend = "base"
systemd.BindPaths = ["$HOME/.composer"]

[dev]
match = "dev"
extend = ["cargo", "composer"]
systemd.BindPaths = ["$PWD"]         # → /base, ~/.cargo, ~/.composer, $PWD
```

### Same-named profiles across files

A profile defined again in a higher-priority config file **adds to** the one below it, by the rules above: its lists extend the inherited ones and its scalars win. A project's `.scudo.toml` can therefore give the system-wide `cargo` profile one more directory without restating it:

```toml
# /home/user/projects/myapp/.scudo.toml
[cargo]
filesystem.write = ["$SCUDO_CONFIG_DIR/target"]
```

To replace the lower-priority profile instead, set `inherit = false`:

```toml
[cargo]
inherit = false
match = "cargo"
filesystem.read = ["/"]
filesystem.write = ["$PROJECT_DIR"]
```

### Environment variables

String values (including array elements) support `$VAR` and `${VAR}` expansion using the environment of the calling process. A reference to an undefined variable is an error.

#### `$SCUDO_CONFIG_DIR`

Inside a profile, `$SCUDO_CONFIG_DIR` (also `${SCUDO_CONFIG_DIR}`) expands to the absolute path of the directory containing the config file that profile was defined in. This is resolved per file, so a profile in `/etc/scudo/config.toml` sees `/etc/scudo`, while one in a project's `.scudo.toml` sees that project directory. It is handy for referencing files that live next to the config:

```toml
[myapp]
exec = "$SCUDO_CONFIG_DIR/wrapper.sh"
systemd.BindReadOnlyPaths = ["$SCUDO_CONFIG_DIR/allowlist.txt"]
```

The value is substituted when the config is loaded, before `$arg_*` and other `$VAR` expansion. When a profile inherits values via `extend` or from a same-named profile, each inherited value keeps the config dir of the file it was written in.

#### Lookup variables

The `vars` table defines variables that name a directory, found by looking for a file or directory from the current directory up to `/`: the first directory holding it is the value. A command run anywhere inside a repository can thus be given the whole repository, or the package it is in:

```toml
[scudo]
vars.PROJECT_DIR = { lookup = ".git", fallback = "cwd" }

[npm]
match = "npm"
vars.PACKAGE_DIR = { lookup = "package.json" }
filesystem.write = ["$PACKAGE_DIR/node_modules", "$PROJECT_DIR/.git"]
```

| Key | Type | Description |
|-----|------|-------------|
| `lookup` | string or array of strings | Name(s), relative to each directory, to look for; a file and a directory count alike (a worktree has a `.git` file). With several, the closest directory holding any of them wins. |
| `fallback` | `"skip"`, `"cwd"` or `"error"` | What the variable is when no directory holds any of them (default `"skip"`) |

- `skip`: the value that references the variable is dropped as if it was never written — a list loses that entry, a property or a key is left out. `"$PACKAGE_DIR/node_modules"` outside a package is gone, not `/node_modules`.
- `cwd`: the current directory.
- `error`: the command does not run. Only a variable some value actually references is looked up, so an unused one never fails.

Variables in `[scudo]` are available to every profile; a profile's own `vars` add to them and win over a same-named one, and among profiles combined together the one applied last wins, as for `args`. A lookup variable takes precedence over an environment variable of the same name. Names follow the environment variable rules, and cannot start with `arg_` or be `SCUDO_CONFIG_DIR`.

### Command argument variables

Profile values can also reference the arguments of the command being run. These variables all start with `$arg_` and are silently empty if the corresponding argument was not passed (unlike environment variables, which are an error when undefined). Empty strings produced by absent argument variables are filtered out from arrays.

#### Flag variables

The `args` table names a variable and the flag(s) that fill it:

```toml
[myagent]
match = "myagent"
args.add_dir = "--add-dir"                     # one flag
args.target = ["-t", "--target-directory"]     # several spellings of it
filesystem.read = ["$arg_add_dir"]
filesystem.write = ["$arg_target"]
```

The value can be passed as `--add-dir value` or `--add-dir=value`, and every occurrence adds to the same variable: `myagent --add-dir a --add-dir b --add-dir=c` gives `$arg_add_dir` three values, which in a list become three entries.

For a flag that takes every argument after it, up to the next one starting with `-`, use the table form with `greedy = true`:

```toml
[claude]
match = "claude"
args.add_dir = { flags = "--add-dir", greedy = true }
filesystem.read = ["$arg_add_dir"]
# claude --add-dir a b c  →  $arg_add_dir = ["a", "b", "c"]
```

A greedy flag cannot tell a value from an argument that happens to follow it: in `claude --add-dir a "fix the bug"` the prompt is taken as a directory too. Paths that do not exist are skipped, so the harm is limited to that.

#### Positional variables

Arguments that are neither flags nor the value of a declared flag are positional. Flags not declared in `args` never take a value, so declare every flag whose value could otherwise be mistaken for a positional:

```toml
[install]
match = "install"
args.target = ["-t", "--target-directory"]
filesystem.write = ["$arg_1"]   # first positional argument
```

| Variable | Value |
|----------|-------|
| `$arg_1` | first positional argument |
| `$arg_2` | second positional argument |
| `$arg_N` | Nth positional argument |
| `$arg_rest` | all positionals space-joined (like `$*`) |

`--` terminates option parsing; all subsequent arguments are treated as positional.

#### Array expansion in string templates

When a named flag variable holds multiple values and appears inside a string template, the template is replicated once per value:

```toml
[rsync]
args.include = ["-I", "--include"]
systemd.BindReadOnlyPaths = ["/prefix/$arg_include"]
# -I a -I b  →  ["/prefix/a", "/prefix/b"]
```

Using more than one multi-value argument variable inside the same string template is an error; use separate array entries instead.

### Default values

`${NAME:-DEFAULT}` stands for `DEFAULT` when `NAME` is unset or empty, as in the shell. It works
with every kind of variable, so a profile can give an optional argument a sensible fallback:

```toml
[ls]
match = "ls"
filesystem.read = ["${arg_1:-$PWD}"]                          # ls → $PWD, ls dir → dir

[build]
match = "build"
args.out = "--out"
filesystem.write = ["${arg_out:-${PROJECT_DIR:-$PWD}/out}"]   # the argument, else the project, else the current directory
```

`DEFAULT` is itself a template — literal text, `$VAR`, or another `${…:-…}` to chain more
fallbacks — and is expanded only when it is used: a `$VAR` that is undefined in an unused default
is not an error. What counts as unset:

| Variable | Unset when |
|----------|------------|
| `$arg_*` | the argument was not passed (or only with empty values) |
| `$VAR` from the environment | it is not defined, or is empty |
| [lookup variable](#lookup-variables) | nothing is found; its own `fallback` is then not consulted |

`${arg_1:-}` is the same as `$arg_1`.

### Path canonicalization

Entries of the `filesystem` lists are always made absolute. When a variable (`$arg_*` or `$VAR`) is used inside a systemd property that expects filesystem paths (such as `BindPaths`, `ReadWritePaths`, `WorkingDirectory`, etc.), its expanded value is automatically made absolute relative to `$PWD`. This handles the common case where the user passes a relative path on the command line:

```toml
[rsync]
args.include = ["-I", "--include"]
systemd.BindReadOnlyPaths = ["$arg_include"]
# rsync -I ./src  →  BindReadOnlyPaths=/abs/cwd/src
```

Only the **expanded variable value** is canonicalized — literal text in the template is left untouched. This means systemd special prefix characters (`-`, `+`, `!`, `!!`) can be used freely in the literal part:

```toml
[app]
systemd.ReadWritePaths = ["-$arg_1"]
# ./relative  →  -/abs/cwd/relative   ('-' is literal, path is made absolute)
```

A [default value](#default-values) taking a variable's place counts as the variable's value, literal text included: `${arg_1:-out}` becomes `/abs/cwd/out` when no argument is given.

Absolute paths are passed through unchanged. Canonicalization is purely lexical (it does not require the path to exist).

## Building

```
cargo build --release
```

The stable toolchain is enough. The eBPF programs additionally need its `rust-src` component, since
`core` is built from source for their tier 3 target, and `bpf-linker`:

```
rustup component add rust-src --toolchain stable
cargo install bpf-linker
```

Two features are on by default and can be dropped:

| Feature | Drops |
|---------|-------|
| `bpf` | `scudo-bpfd` and the eBPF programs, along with the `rust-src` component and `bpf-linker` needed to build them. scudo still talks to a daemon that is installed. |
| `tui` | `--tui` and the terminal UI. A config naming `[scudo.tui]` still parses, so one shared with a full build is not rejected. |

```
cargo build --release --no-default-features --features bpf
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.
