# scudo

scudo wraps commands with [`systemd-run`](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html), applying resource limits and sandboxing constraints defined in per-command profiles. It requires Linux with systemd.

## Usage

```
Usage: scudo [OPTIONS] <COMMAND> [COMMAND_ARGS]...

Arguments:
  <COMMAND>          
  [COMMAND_ARGS]...  

Options:
      --debug    Enable debug output
      --confirm  Confirm before running the command
  -h, --help     Print help
  -V, --version  Print version
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

> **Warning:** When using the FUSE shim, avoid broad matchers (`glob`, `regex`) that match large numbers of commands in combination with `confirm = true` or `debug = true`. Because the shim intercepts every command in your session — including those run by scripts, your shell itself, and every subprocess — an overly wide profile with interactive options will trigger a confirmation prompt or dump debug output for each of them, making the environment unusable. Reserve `confirm` and `debug` for profiles with narrow, exact-match patterns, and validate broad profiles without those options first.

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

Each TOML section defines a profile. The section name is also the default match pattern.

| Field | Type | Description |
|-------|------|-------------|
| `match` | see [Match patterns](#match-patterns) | Pattern(s) to match against the command name. Absent = use section name (exact). `null` or `[]` = never match directly (base profile only). |
| `extend` | string or array of strings | Profile(s) to inherit properties from, in left-to-right order (later entries take precedence). Including this profile's own name extends from the same-named profile in lower-priority config files; see [Cross-file profile inheritance](#cross-file-profile-inheritance). |
| `final` | bool | When `true`, this profile cannot be used as a base by a same-named profile in a higher-priority config file that self-extends. Higher-priority files can still replace it outright. (default: `false`) |
| `exec` | string | Absolute path of the binary to execute, bypassing PATH resolution |
| `debug` | bool | Print the full `systemd-run` command to stderr before executing (default: `false`) |
| `confirm` | bool | Prompt for confirmation before executing (default: `false`); silently skipped in non-interactive shells |
| `arg_aliases` | table | Maps variable names to the flag(s) that populate them; see [Command argument variables](#command-argument-variables) |
| `arg_flags` | array of strings | Flags that take no value (boolean flags); needed for correct positional detection |

All other keys are passed directly to `systemd-run` as `-p Key=value` properties. Use the exact systemd unit property names (PascalCase). Values can be strings, booleans (`true`/`false` → `yes`/`no`), integers, or arrays.

### Example

```toml
# Base profile — never matched directly, only used via extend
[sandboxed]
match = []
ReadOnlyPaths = ["/"]
ReadWritePaths = ["/tmp", "$XDG_RUNTIME_DIR"]
PrivateTmp = true

[sandboxed-home]
match = []
extend = "sandboxed"
TemporaryFileSystem = "$HOME"
BindPaths = ["$HOME/.cache"]

# curl: exact match, extends the base sandbox
[curl]
extend = "sandboxed"
PrivateNetwork = false
MemoryMax = "256M"

# code: match VS Code and variants via regex, extend the sandboxed profile with code-specific paths
[code]
match = { pattern = "^(vs)?cod(e|e-oss|ium)?$", type = "regex" }
extend = "sandboxed-home"
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
extend = "sandboxed-home"
BindPaths = ["...", "$HOME/.npm", "$PWD"]
BindReadOnlyPaths = ["$HOME/.npmrc"]

[pnpm]
extend = "npm"
BindPaths = ["...", "$HOME/.pnpm-store"]
```

### Match patterns

The `match` field controls which commands a profile applies to:

| Form | Meaning |
|------|---------|
| absent | section name, exact match |
| `match = []` | never match — base profile usable only via `extend` |
| `match = "curl"` | exact match for `curl` |
| `match = { pattern = "curl" }` | same, explicit table form |
| `match = { pattern = "curl*", type = "glob" }` | glob match |
| `match = { pattern = "^curl", type = "regex" }` | regex match |
| `match = { pattern = "git commit*", type = "glob", target = "full_command" }` | glob match against full command line |
| `match = [...]` | array of any of the above forms |

The `type` field accepts `exact` (default), `glob`, or `regex`. The `target` field accepts `command` (default, matches against the command name only) or `full_command` (matches against the command name and all arguments joined with spaces). `target` is only available in the table form; the simple string form always targets the command name. When the `match` field is an array, `"..."` splices the first parent profile's patterns at that position — the same sentinel used for systemd property arrays (see [Array extension](#array-extension)).

When multiple profiles match the same command, they are merged in order of increasing specificity: glob < regex < exact. Within each tier, the last match wins for scalar values.

> **Tip — matching a subcommand precisely.** `{ pattern = "git commit*", type = "glob", target = "full_command" }` looks right but breaks whenever git options precede the subcommand — `git -c user.name=x commit -m "msg"` produces a full command of `git -c user.name=x commit -m msg`, which does not start with `git commit`. A more robust alternative splits the command-name check from the subcommand check using an array:
>
> ```toml
> match = ["git", { pattern = "\\bcommit\\b", type = "regex", target = "full_command" }]
> ```
>
> The `"git"` entry matches exactly the `git` binary (command name only). The regex entry then checks whether the word `commit` appears anywhere in the full command line, regardless of any flags that precede it. `\bcommit\b` uses word boundaries so it does not accidentally match similar words like `commitlint` or `committed`. Of course this can still erroneously match when the word `commit` appears in other contexts but security-wise it is better to err on the side of caution and assume the word `commit` is a command name.

### Array extension

By default an array value replaces the one defined in the extended profile. Place `"..."` anywhere in an array to splice in the base profile's list at that position:

```toml
[my-curl]
extend = "curl"
exec = "/usr/bin/curl"
ReadWritePaths = ["/home/user/downloads", "...", "/extra"]
#                 ^ prepend               ^ base  ^ append
```

`"..."` may appear at most once per array.

### Cross-file profile inheritance

By default a profile in a higher-priority config file completely replaces any same-named profile in lower-priority files. To layer on top of it instead, include the profile's own name in `extend`:

```toml
# ~/.config/scudo/config.toml
[curl]
extend = ["curl", "sandboxed"]   # inherit system curl, then also apply sandboxed
MemoryMax = "512M"               # override or add properties on top
```

When scudo loads this file and finds an existing `[curl]` from `/etc/scudo/config.toml`, it renames the system profile to an internal key and rewrites the self-reference, so the resolution chain becomes: system curl → sandboxed → user curl. Without the self-reference, the system `[curl]` would be silently discarded.

If the lower-priority profile has `final = true`, it cannot be used as a base. The self-reference is silently dropped and the higher-priority profile stands on its own, but it still replaces the lower-priority profile.

### Environment variables

String values (including array elements) support `$VAR` and `${VAR}` expansion using the environment of the calling process. A reference to an undefined variable is an error.

### Command argument variables

Profile values can also reference the arguments of the command being run. These variables all start with `$arg_` and are silently empty if the corresponding argument was not passed (unlike environment variables, which are an error when undefined). Empty strings produced by absent argument variables are filtered out from arrays.

#### Named flag variables

Long options are detected automatically: `--foo-bar` becomes `$arg_foo_bar` (dashes converted to underscores). The value can be passed as `--foo-bar value` (space-separated) or `--foo-bar=value` (equals form).

Short options and custom variable names require an `arg_aliases` declaration:

```toml
[install]
arg_aliases = { target_directory = ["-t", "--target-directory"] }
BindPaths = ["$HOME/.cache", "$arg_target_directory"]
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
BindPaths = ["$arg_1"]   # first positional argument
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
BindReadOnlyPaths = ["/prefix/$arg_include"]
# -I a -I b  →  ["/prefix/a", "/prefix/b"]
```

Using more than one multi-value argument variable inside the same string template is an error; use separate array entries instead.

### Path canonicalization

When a variable (`$arg_*` or `$VAR`) is used inside a systemd property that expects filesystem paths (such as `BindPaths`, `ReadWritePaths`, `WorkingDirectory`, etc.), its expanded value is automatically made absolute relative to `$PWD`. This handles the common case where the user passes a relative path on the command line:

```toml
[rsync]
arg_aliases = { include = ["-I", "--include"] }
BindReadOnlyPaths = ["$arg_include"]
# rsync -I ./src  →  BindReadOnlyPaths=/abs/cwd/src
```

Only the **expanded variable value** is canonicalized — literal text in the template is left untouched. This means systemd special prefix characters (`-`, `+`, `!`, `!!`) can be used freely in the literal part:

```toml
[app]
ReadWritePaths = ["-$arg_1"]
# ./relative  →  -/abs/cwd/relative   ('-' is literal, path is made absolute)
```

Absolute paths are passed through unchanged. Canonicalization is purely lexical (it does not require the path to exist).

## Building

```
cargo build --release
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.
