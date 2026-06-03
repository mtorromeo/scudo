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
| `$PWD/.scudo.toml` | per-directory |

Each TOML section defines a profile. The section name is also the default match pattern.

### Profile fields

| Field | Type | Description |
|-------|------|-------------|
| `pattern` | string | Pattern to match against the command name (default: section name) |
| `match` | `exact` \| `glob` \| `regex` \| `never` | Matching strategy (default: `exact`) |
| `extend` | string | Name of another profile to inherit properties from |
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
