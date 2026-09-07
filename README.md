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

> **Warning:** When using the FUSE shim, avoid broad matchers (`glob`, `regex`) that match large numbers of commands in combination with `confirm = true` or `verbose = true`. Because the shim intercepts every command in your session — including those run by scripts, your shell itself, and every subprocess — an overly wide profile with interactive options will trigger a confirmation prompt or dump debug output for each of them, making the environment unusable. Reserve `confirm` and `verbose` for profiles with narrow, exact-match patterns, and validate broad profiles without those options first.

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
| `match` | see [Match patterns](#match-patterns) | Pattern(s) to match against the command name. Absent = the profile never matches a command on its own and is reachable only through `extend` or `--profile`. |
| `extend` | string or array of strings | Profile(s) to inherit properties from, in left-to-right order (later entries take precedence). Including this profile's own name extends from the same-named profile in lower-priority config files; see [Cross-file profile inheritance](#cross-file-profile-inheritance). |
| `final` | bool | When `true`, this profile cannot be used as a base by a same-named profile in a higher-priority config file that self-extends. Higher-priority files can still replace it outright. (default: `false`) |
| `exec` | string | Absolute path of the binary to execute, bypassing PATH resolution |
| `verbose` | bool | Shorthand for `log.level = "debug"`, which among other things prints the full `systemd-run` command before executing (default: `false`) |
| `confirm` | bool | Prompt for confirmation before executing (default: `false`); silently skipped in non-interactive shells |
| `arg_aliases` | table | Maps variable names to the flag(s) that populate them; see [Command argument variables](#command-argument-variables) |
| `arg_flags` | array of strings | Flags that take no value (boolean flags); needed for correct positional detection |
| `network` | table | Network policy; see [Network filtering](#network-filtering) |
| `log` | table | Level and destination for scudo's own output; see [Logging](#logging) |
| `systemd` | table | Unit properties passed to `systemd-run`; see below |

Every key of the `systemd` table is passed directly to `systemd-run` as `-p Key=value`. Use the exact systemd unit property names (PascalCase). Values can be strings, booleans (`true`/`false` → `yes`/`no`), integers, or arrays. Write it either as a sub-table header (`[curl.systemd]`) or with dotted keys (`systemd.MemoryMax = "256M"`).

Any other key is a typo and scudo says so instead of ignoring it.

### Example

```toml
# Base profile — no `match`, so it is never matched directly, only used via extend
[sandboxed]

[sandboxed.systemd]
ReadOnlyPaths = ["/"]
ReadWritePaths = ["/tmp", "$XDG_RUNTIME_DIR"]
PrivateTmp = true

[sandboxed-home]
extend = "sandboxed"

[sandboxed-home.systemd]
TemporaryFileSystem = "$HOME"
BindPaths = ["$HOME/.cache"]

# curl: exact match, extends the base sandbox
[curl]
match = "curl"
extend = "sandboxed"

[curl.systemd]
PrivateNetwork = false
MemoryMax = "256M"

# code: match VS Code and variants via regex, extend the sandboxed profile with code-specific paths
[code]
match = { pattern = "^(vs)?cod(e|e-oss|ium)?$", type = "regex" }
extend = "sandboxed-home"

[code.systemd]
ReadWritePaths = ["...", "/proc", "/dev/shm", "/dev/dri"]
BindPaths = [
  "...",
  "$HOME/.vscode",
  "$HOME/.vscode-insiders",
  "$HOME/.vscode-insiders-shared",
  "$HOME/.vscode-oss",
  "$HOME/.vscode-oss-shared",
  "$HOME/.vscode-remote-workspace",
  "$HOME/.config/Code",
  "$HOME/.config/code-oss",
  "$HOME/.config/Code - OSS",
  "$HOME/.config/Code - Insiders",
  "$PWD",
]

# npm: extend the sandboxed-home profile with npm-specific paths, including $HOME/.npm and $HOME/.npmrc and the current working directory
[npm]
match = "npm"
extend = "sandboxed-home"

[npm.systemd]
BindPaths = ["...", "$HOME/.npm", "$PWD"]
BindReadOnlyPaths = ["$HOME/.npmrc"]

[pnpm]
match = "pnpm"
extend = "npm"

[pnpm.systemd]
BindPaths = ["...", "$HOME/.pnpm-store"]
```

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
service_manager = "deny"    # "deny" (default) or "allow"
on_unavailable = "fail"     # "fail" (default), "no-network", or "warn"
log = "off"                 # "off" (default) or "denied"

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
other profile value, and `"..."` splices in the list inherited from an extended profile —
each of the four lists inheriting on its own.

Denying everything (`network = {}`) is realised with `PrivateNetwork=yes` and needs nothing
else. Anything finer needs the `scudo-bpfd` helper, which attaches eBPF programs to the
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

Unless `service_manager` says otherwise, a profile with a policy also loses access to
`systemd --user`, via `InaccessiblePaths` on `$XDG_RUNTIME_DIR/systemd` and
`$XDG_RUNTIME_DIR/bus`. Without that the policy is trivially bypassed: a sandboxed command can
ask the service manager to start a process in a sibling cgroup, where no program of ours is
attached. That holds however the policy is realised — `network = {}` and a policy degraded to
`no-network` included, since `PrivateNetwork=yes` is worth nothing while the command can ask
for a unit that has a network.

That does mean the session bus goes away, which some programs need. Set
`service_manager = "allow"` to keep it — and be aware that anything able to reach the bus can
step outside the policy.

#### Installing the helper

```bash
sudo install -m755 target/release/scudo-bpfd /usr/bin/scudo-bpfd
sudo setcap cap_bpf,cap_net_admin=ep /usr/bin/scudo-bpfd
systemctl --user enable --now scudo-bpfd.socket
```

The daemon holds `CAP_BPF` and `CAP_NET_ADMIN` as file capabilities, so anyone on the system
can execute it. What keeps that harmless is that it offers exactly one operation — *add*
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
printed. A policy realised as `PrivateNetwork=yes` has no programs attached and therefore
nothing to report; `--verbose` says so rather than leaving the silence to be misread.

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

There is no reserved section for a global default; a profile that matches everything is one:

```toml
[default]
match = { type = "glob", pattern = "*" }
log.level = "info"
log.target = "journald"
```

Because this is an ordinary profile, the ordinary precedence applies (glob < regex < exact,
and `--profile` above all), so a command can be made **quieter** than the default as well as
louder — unlike `verbose`, which only ever adds. `verbose = true` is still accepted and means
`log.level = "debug"`; a level written out next to it wins, being the more specific of the two.

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

### Match patterns

The `match` field controls which commands a profile applies to:

| Form | Meaning |
|------|---------|
| absent | never match — base profile usable only via `extend` or `--profile` |
| `match = "curl"` | exact match for `curl` |
| `match = { pattern = "curl" }` | same, explicit table form |
| `match = { pattern = "curl*", type = "glob" }` | glob match |
| `match = { pattern = "^curl", type = "regex" }` | regex match |
| `match = { pattern = "git commit*", type = "glob", target = "full_command" }` | glob match against full command line |
| `match = [...]` | array of any of the above forms |

In the table form `pattern` is required. The `type` field accepts `exact` (default), `glob`, or `regex`. The `target` field accepts `command` (default, matches against the command name only) or `full_command` (matches against the command name and all arguments joined with spaces). `target` is only available in the table form; the simple string form always targets the command name. When the `match` field is an array, `"..."` splices the first parent profile's patterns at that position — the same sentinel used for systemd property arrays (see [Array extension](#array-extension)).

When multiple profiles match the same command, they are merged in order of increasing specificity: glob < regex < exact. Within each tier, the last match wins for scalar values.

> **Tip — matching a subcommand precisely.** `{ pattern = "git commit*", type = "glob", target = "full_command" }` looks right but breaks whenever git options precede the subcommand — `git -c user.name=x commit -m "msg"` produces a full command of `git -c user.name=x commit -m msg`, which does not start with `git commit`. A more robust alternative splits the command-name check from the subcommand check using an array:
>
> ```toml
> match = ["git", { pattern = "\\bcommit\\b", type = "regex", target = "full_command" }]
> ```
>
> The `"git"` entry matches exactly the `git` binary (command name only). The regex entry then checks whether the word `commit` appears anywhere in the full command line, regardless of any flags that precede it. `\bcommit\b` uses word boundaries so it does not accidentally match similar words like `commitlint` or `committed`. Of course this can still erroneously match when the word `commit` appears in other contexts but security-wise it is better to err on the side of caution and assume the word `commit` is a command name.

### Selecting profiles explicitly

`--profile <NAME>` applies a profile by name, whatever its `match` field says — including base profiles that declare no `match` at all. It is repeatable and also accepts a comma-separated list. Named profiles are applied *after* the ones that matched, so they take precedence; among themselves they are applied in the order given on the command line, with the last one winning.

`--no-match` skips pattern matching altogether. Combined with `--profile` it means "use exactly these profiles and nothing else"; on its own it runs the command with no profile at all.

| Invocation | Profiles applied |
|------------|------------------|
| `scudo --profile netblock -- curl https://example.com` | everything matching `curl`, then `netblock` |
| `scudo --profile a,b -- curl https://example.com` | matches for `curl`, then `a`, then `b` |
| `scudo --no-match --profile netblock -- curl https://example.com` | only `netblock` |
| `scudo --no-match -- curl https://example.com` | none — the command is executed directly, without `systemd-run` |
| `scudo --no-match -p MemoryMax=1G -- curl https://example.com` | none, but `systemd-run` still runs with the explicit property |

A profile that both matches and is named explicitly is applied only once, in its explicit position. An unknown profile name is a fatal error: scudo exits with status 1 without running the command, rather than running it with less sandboxing than was asked for.

```
$ scudo --profile snadboxed -- curl https://example.com
scudo: profile 'snadboxed' not found
```

Both flags belong to scudo itself, so they are only available through the explicit `scudo <command>` form. When scudo is invoked through a symlink or the FUSE shim, every argument belongs to the wrapped command.

### Array extension

By default an array value replaces the one defined in the extended profile. Place `"..."` anywhere in an array to splice in the base profile's list at that position:

```toml
[my-curl]
extend = "curl"
exec = "/usr/bin/curl"
systemd.ReadWritePaths = ["/home/user/downloads", "...", "/extra"]
#                         ^ prepend               ^ base  ^ append
```

`"..."` may appear at most once per array.

### Cross-file profile inheritance

By default a profile in a higher-priority config file completely replaces any same-named profile in lower-priority files. To layer on top of it instead, include the profile's own name in `extend`:

```toml
# ~/.config/scudo/config.toml
[curl]
extend = ["curl", "sandboxed"]    # inherit system curl, then also apply sandboxed
systemd.MemoryMax = "512M"        # override or add properties on top
```

When scudo loads this file and finds an existing `[curl]` from `/etc/scudo/config.toml`, it renames the system profile to an internal key and rewrites the self-reference, so the resolution chain becomes: system curl → sandboxed → user curl. Without the self-reference, the system `[curl]` would be silently discarded.

If the lower-priority profile has `final = true`, it cannot be used as a base. The self-reference is silently dropped and the higher-priority profile stands on its own, but it still replaces the lower-priority profile.

### Environment variables

String values (including array elements) support `$VAR` and `${VAR}` expansion using the environment of the calling process. A reference to an undefined variable is an error.

#### `$SCUDO_CONFIG_DIR`

Inside a profile, `$SCUDO_CONFIG_DIR` (also `${SCUDO_CONFIG_DIR}`) expands to the absolute path of the directory containing the config file that profile was defined in. This is resolved per file, so a profile in `/etc/scudo/config.toml` sees `/etc/scudo`, while one in a project's `.scudo.toml` sees that project directory. It is handy for referencing files that live next to the config:

```toml
[myapp]
exec = "$SCUDO_CONFIG_DIR/wrapper.sh"
systemd.BindReadOnlyPaths = ["$SCUDO_CONFIG_DIR/allowlist.txt"]
```

The value is substituted when the config is loaded, before `$arg_*` and other `$VAR` expansion. When a profile inherits values via `extend`, each inherited value keeps the config dir of the file it was written in.

### Command argument variables

Profile values can also reference the arguments of the command being run. These variables all start with `$arg_` and are silently empty if the corresponding argument was not passed (unlike environment variables, which are an error when undefined). Empty strings produced by absent argument variables are filtered out from arrays.

#### Named flag variables

Long options are detected automatically: `--foo-bar` becomes `$arg_foo_bar` (dashes converted to underscores). The value can be passed as `--foo-bar value` (space-separated) or `--foo-bar=value` (equals form).

Short options and custom variable names require an `arg_aliases` declaration:

```toml
[install]
arg_aliases = { target_directory = ["-t", "--target-directory"] }
systemd.BindPaths = ["$HOME/.cache", "$arg_target_directory"]
```

Named flag variables **accumulate** across multiple occurrences — `--flag a --flag b` produces a two-element array that, when used in a `BindPaths` array, expands to two separate entries.

If an `arg_aliases` entry should consume all consecutive non-flag arguments after the flag (instead of just one), use the extended form with `nargs = "+"`:

```toml
[rsync]
arg_aliases = { include = { flags = ["-I", "--include"], nargs = "+" } }
# --include a b c  →  $arg_include = ["a", "b", "c"]
```

#### Boolean flags and positional variables

Flags listed in `arg_flags` are treated as boolean (they never consume the next argument). This is necessary to correctly identify positional arguments when boolean short options are present:

```toml
[mkdir]
arg_flags = ["-p", "--parents", "-v", "--verbose"]
systemd.BindPaths = ["$arg_1"]   # first positional argument
```

With this profile, `mkdir -p /my/dir` correctly sets `$arg_1 = /my/dir`.

Positional variables:

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
arg_aliases = { include = ["-I", "--include"] }
systemd.BindReadOnlyPaths = ["/prefix/$arg_include"]
# -I a -I b  →  ["/prefix/a", "/prefix/b"]
```

Using more than one multi-value argument variable inside the same string template is an error; use separate array entries instead.

### Path canonicalization

When a variable (`$arg_*` or `$VAR`) is used inside a systemd property that expects filesystem paths (such as `BindPaths`, `ReadWritePaths`, `WorkingDirectory`, etc.), its expanded value is automatically made absolute relative to `$PWD`. This handles the common case where the user passes a relative path on the command line:

```toml
[rsync]
arg_aliases = { include = ["-I", "--include"] }
systemd.BindReadOnlyPaths = ["$arg_include"]
# rsync -I ./src  →  BindReadOnlyPaths=/abs/cwd/src
```

Only the **expanded variable value** is canonicalized — literal text in the template is left untouched. This means systemd special prefix characters (`-`, `+`, `!`, `!!`) can be used freely in the literal part:

```toml
[app]
systemd.ReadWritePaths = ["-$arg_1"]
# ./relative  →  -/abs/cwd/relative   ('-' is literal, path is made absolute)
```

Absolute paths are passed through unchanged. Canonicalization is purely lexical (it does not require the path to exist).

## Building

```
cargo build --release
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.
