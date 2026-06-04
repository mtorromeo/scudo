# scudo

scudo wraps commands with [`systemd-run`](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html), applying resource limits and sandboxing constraints defined in per-command profiles. It requires Linux with systemd.

## Usage

```
scudo <command> [args...]
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
| `pattern` | string | Pattern to match against the command name (default: section name) |
| `match` | `exact` \| `glob` \| `regex` \| `never` | Matching strategy (default: `exact`) |
| `extend` | string | Name of another profile to inherit properties from |
| `exec` | string | Absolute path of the binary to execute, bypassing PATH resolution |
| `debug` | bool | Print the full `systemd-run` command to stderr before executing (default: `false`) |
| `confirm` | bool | Prompt for confirmation before executing (default: `false`) |

All other keys are passed directly to `systemd-run` as `-p Key=value` properties. Use the exact systemd unit property names (PascalCase). Values can be strings, booleans (`true`/`false` → `yes`/`no`), integers, or arrays.

When multiple profiles match the same command, they are merged in order of increasing specificity: glob < regex < exact. Within each tier, the last match wins for scalar values.

### Example

```toml
# Base profile — never matched directly, only used via extend
[sandboxed]
match = "never"
ReadOnlyPaths = ["/"]
ReadWritePaths = ["/tmp", "/run/user/$UID"]
PrivateTmp = true

# curl: exact match, extends the base sandbox
[curl]
extend = "sandboxed"
PrivateNetwork = false
MemoryMax = "256M"

# All *-browser commands: add GPU and display access on top of sandboxed
[browsers]
pattern = "*-browser"
match = "glob"
extend = "sandboxed"
ReadWritePaths = ["...", "/dev/dri", "$XDG_RUNTIME_DIR"]

# npm: extend the sandboxed profile with npm-specific paths, including $HOME/.npm and $HOME/.npmrc and the current working directory
[npm]
extend = "sandboxed"
ReadWritePaths = ["...", "$XDG_RUNTIME_DIR"]
TemporaryFileSystem = "$HOME"
BindPaths = ["$HOME/.npm", "$PWD"]
BindReadOnlyPaths = ["$HOME/.npmrc"]

[pnpm]
extend = "npm"
BindPaths = ["...", "$HOME/.pnpm-store"]
```

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

### Environment variables

String values (including array elements) support `$VAR` and `${VAR}` expansion using the environment of the calling process. A reference to an undefined variable is an error.

## Building

```
cargo build --release
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.
