# Filesystem access

The `filesystem` table says what the command may do with a path, in four lists:

| List | Meaning | Becomes |
|------|---------|---------|
| `write` | read and write | `ReadWritePaths=`, or `BindPaths=` inside a hidden or replaced directory |
| `read` | read only | `ReadOnlyPaths=`, or `BindReadOnlyPaths=` inside a hidden or replaced directory |
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
- **So is what is granted inside a directory the unit replaces.** The `systemd` table can hide directories too: `PrivateTmp=` gives the unit its own `/tmp` and `/var/tmp`, `PrivateDevices=` its own `/dev`, `ProtectHome=tmpfs` empties `/home`, `/root` and `/run/user`, and a `TemporaryFileSystem=` written by hand counts like a `hide`. With `PrivateTmp = true`, `write = ["/tmp/claude-1000"]` becomes `BindPaths=-/tmp/claude-1000`. Read-only settings (`ProtectSystem=`, `ProtectHome=read-only`) are not replacements: a nested `ReadWritePaths=` lifts them.
- **Nothing can be granted inside an inaccessible directory.** systemd mounts nothing under an `InaccessiblePaths=`, not even a bind mount, so a `read` or `write` under a `deny`, under `systemd.InaccessiblePaths` or under `ProtectHome=yes` has no effect, and scudo warns about it. Use `hide` instead: it is what lets paths inside be given back.

Every entry is made absolute against the current directory, and an entry that expands to nothing (an absent `$arg_*`) is dropped. Paths that do not exist are skipped rather than failing the command (they are passed with systemd's `-` prefix): a tool's config directory often does not exist yet.

Properties written by hand in the `systemd` table are passed as they are, next to the ones generated here.

## From the command line

`--fs-hide`, `--fs-read` and `--fs-write` change the access to a path for one run, without
touching the config. Each takes one path and is repeatable; there is no comma-separated form,
since a comma is a valid character in a path:

```
scudo --fs-hide ~/.ssh --fs-write ~/.cache/pip --fs-read /srv/data pip install .
```

They are applied after every profile, those selected with `--profile` included, and they have
**the last word** on the paths they name: whatever the profiles listed for that same path is
replaced, not merged. Without that, hiding a directory a profile reads would change nothing,
since the most permissive access wins. Only the path itself is replaced: what the profiles grant
below it stays, and is bind-mounted back in if the flag hid the directory, as with `hide`. So
`--fs-hide $HOME` next to a profile that writes `$HOME/.claude` still leaves `.claude` writable.

The paths are taken as written — the shell has already expanded them — and made absolute
against the current directory. Giving the same path two accesses at once is an error. With no
profile matched, the flags alone are enough to run the command in a sandbox.

## Seeing what the filesystem restrictions hid

`ReadOnlyPaths=`, `TemporaryFileSystem=`, `InaccessiblePaths=`, `ProtectHome=` and `PrivateTmp=`
are applied by systemd, by rearranging the unit's mount namespace. scudo has no part in the
verdict and no hook that sees it: the command is handed an `ENOENT`, `EACCES` or `EROFS` with
no way to say which path it was about, and a profile that is one `BindPaths=` short looks
exactly like a program that is broken.

`filesystem.log = "denied"` on the profile — or `--verbose`, or `--tui` — asks `scudo-bpfd` to
watch the syscalls that name a path and report the ones that come back with an error a sandbox
could have caused. That needs the daemon reachable, with `scudo-bpfd.socket` enabled and active
in `systemctl --user` (see [Installation](installation.md#enabling-scudo-bpfd)); without it the
restrictions still apply, and only the report is lost. With `sandbox` from the
[recommended configuration](configuration/recommended.md#recommended-configuration):

```console
$ scudo --verbose --profile sandbox -- bash -lc 'git status'
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
the level to `debug` to see all of it, or in the [terminal UI](tui.md#terminal-ui) press `^A m`, which
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

<svg class="diagram" viewBox="0 0 820 470" role="img" aria-labelledby="dg-fs-title">
<title id="dg-fs-title">How refused file accesses are reported: two raw tracepoints see every syscall on the machine, keep only path syscalls from watched cgroups, and hand the failures to scudo-bpfd, which checks whether the path exists outside and reports it to the sandbox's watchers</title>
<defs><marker id="dg-fs-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="head" d="M0 0 10 5 0 10z"/></marker></defs>
<rect class="zone" x="16" y="16" width="380" height="438" rx="10"/>
<text class="title" x="32" y="42">kernel</text>
<text class="muted" x="32" y="60">one object for the whole daemon, every syscall on the machine</text>
<rect class="box key" x="40" y="80" width="332" height="44" rx="6"/>
<text class="mono" x="206" y="107" text-anchor="middle">raw tracepoints sys_enter, sys_exit</text>
<rect class="box" x="40" y="160" width="332" height="56" rx="6"/>
<text x="206" y="184" text-anchor="middle">does the syscall name a path?</text>
<text class="muted" x="206" y="203" text-anchor="middle">no: done, without touching a map</text>
<rect class="box" x="40" y="252" width="332" height="56" rx="6"/>
<text x="206" y="276" text-anchor="middle">is its cgroup in WATCHED?</text>
<text class="muted" x="206" y="295" text-anchor="middle">no: nothing leaves the kernel</text>
<rect class="box" x="40" y="344" width="332" height="86" rx="6"/>
<text x="206" y="368" text-anchor="middle">enter: keep the path in PENDING</text>
<text x="206" y="388" text-anchor="middle">exit: an error goes to the ring buffer</text>
<text class="muted" x="206" y="410" text-anchor="middle">success only drops the PENDING entry</text>
<path class="flow" d="M206 124V158" marker-end="url(#dg-fs-arrow)"/>
<path class="flow" d="M206 216V250" marker-end="url(#dg-fs-arrow)"/>
<path class="flow" d="M206 308V342" marker-end="url(#dg-fs-arrow)"/>
<rect class="zone" x="440" y="16" width="364" height="438" rx="10"/>
<text class="title" x="456" y="42">scudo-bpfd</text>
<text class="muted" x="456" y="60">outside every sandbox's mount namespace</text>
<rect class="box" x="464" y="344" width="316" height="56" rx="6"/>
<text x="622" y="368" text-anchor="middle">routes each event by its cgroup id</text>
<text class="muted mono" x="622" y="387" text-anchor="middle">fsmon</text>
<path class="flow" d="M372 380H462" marker-end="url(#dg-fs-arrow)"/>
<rect class="box key" x="464" y="252" width="316" height="56" rx="6"/>
<text x="622" y="276" text-anchor="middle">is the path there outside the sandbox?</text>
<text class="muted" x="622" y="295" text-anchor="middle">hidden: warn · never there: debug</text>
<path class="flow" d="M622 344V310" marker-end="url(#dg-fs-arrow)"/>
<rect class="box" x="464" y="160" width="316" height="56" rx="6"/>
<text x="622" y="184" text-anchor="middle">the sandbox's notification bus</text>
<text class="muted" x="622" y="203" text-anchor="middle">shared with the network refusals</text>
<path class="flow" d="M622 252V218" marker-end="url(#dg-fs-arrow)"/>
<rect class="box" x="464" y="80" width="150" height="44" rx="6"/>
<text x="539" y="107" text-anchor="middle">watcher, stderr</text>
<rect class="box" x="630" y="80" width="150" height="44" rx="6"/>
<text x="705" y="107" text-anchor="middle">--tui panel</text>
<path class="flow" d="M580 160V126" marker-end="url(#dg-fs-arrow)"/>
<path class="flow" d="M664 160V126" marker-end="url(#dg-fs-arrow)"/>
</svg>

They are *raw* tracepoints, attached by name through `bpf(2)`. A classic tracepoint per syscall
would be the obvious shape, but attaching one means reading its id out of
`<tracefs>/events/…/id`, and tracefs is `drwx------ root` on an ordinary system — no capability
opens it. Only x86-64 is implemented, since the syscall numbers are per-architecture and a
table guessed for another one would report the wrong calls rather than fail.

Reporting is off unless asked for, and asking for it costs the command a registration with the
daemon and a `ProtectControlGroups=yes` it would not otherwise have (unless the profile sets
that property itself, which is then kept and warned about) — the events are matched on
the cgroup they came from, and a command that can move itself out of that cgroup stops being
reported. A daemon without `CAP_PERFMON` says so and the command runs anyway: not being able to
watch something is never a reason not to run it.
