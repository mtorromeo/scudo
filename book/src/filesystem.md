# Filesystem access

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

## Seeing what the filesystem restrictions hid

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
