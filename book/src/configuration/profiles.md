# Profiles

Each TOML section defines a profile. The section name identifies the profile for `extend` and `--profile`; it is not a match pattern.

| Field | Type | Description |
|-------|------|-------------|
| `match` | string or array of strings | Glob(s) or `/regex/flags` matched against the command name, or against the whole command line when the pattern holds a space; any one is enough. See [Match patterns](matching.md#match-patterns). Absent = the profile never matches a command on its own and is reachable only through `extend` or `--profile`. |
| `extend` | string or array of strings | Profile(s) applied before this one, left to right; see [Combining profiles](matching.md#combining-profiles) |
| `delegate` | `true`, string or array of strings | Profiles whose commands, started from inside this sandbox, run in a sandbox of their own: `true` for every `delegable` one, or their names. See [Delegating commands](../delegation.md#delegating-commands) |
| `delegable` | bool | Whether a sandbox may have this profile's commands run under it on its request; inherited through `extend` (default: `false`). See [Delegating commands](../delegation.md#delegating-commands) |
| `replace` | array of strings | Fields that replace, instead of adding to, what a same-named profile from a lower-priority config file says; only `"match"` for now. See [Same-named profiles across files](matching.md#same-named-profiles-across-files) |
| `inherit` | bool | Whether this profile adds to a same-named profile from a lower-priority config file (`true`, the default) or replaces it (`false`); see [Same-named profiles across files](matching.md#same-named-profiles-across-files) |
| `exec` | string | Absolute path of the binary to execute, bypassing PATH resolution |
| `verbose` | bool | Shorthand for `log.level = "debug"`, which among other things prints the full `systemd-run` command before executing (default: `false`) |
| `confirm` | bool | Prompt for confirmation before executing (default: `false`); silently skipped in non-interactive shells |
| `args` | table | Maps `$arg_*` variable names to the flag(s) that fill them; see [Command argument variables](variables.md#command-argument-variables) |
| `vars` | table | Variables naming a directory found by looking up the tree; see [Lookup variables](variables.md#lookup-variables) |
| `filesystem` | table | Which paths the command may write, read, not see or not touch; see [Filesystem access](../filesystem.md#filesystem-access) |
| `network` | table | Network policy; see [Network filtering](../network.md#network-filtering) |
| `dbus` | table | What the command gets of the session bus; see [Session bus](../session-bus.md#session-bus) |
| `log` | table | Level and destination for scudo's own output; see [Logging](../logging.md#logging) |
| `systemd` | table | Unit properties passed to `systemd-run`; see below |

Every key of the `systemd` table is passed directly to `systemd-run` as `-p Key=value`. Use the exact systemd unit property names (PascalCase). Values can be strings, booleans (`true`/`false` → `yes`/`no`), integers, or arrays. Write it either as a sub-table header (`[curl.systemd]`) or with dotted keys (`systemd.MemoryMax = "256M"`).

The command starts in the current directory, unless `WorkingDirectory` is set (in the table or with `-P`): then `systemd-run` is not given `-d` and the property decides.

Any other key is a typo and scudo says so instead of ignoring it.

## Example

The bases here are those of the [recommended configuration](recommended.md#recommended-configuration),
cut down to what the example needs.

```toml
# The project a command runs in: the closest directory holding a `.git`
[scudo]
vars.PROJECT_DIR = { lookup = ".git", fallback = "cwd" }

# Base profiles — no `match`, so they are never matched directly, only used via extend
[sandbox]
filesystem.read = ["/", "$XDG_RUNTIME_DIR/scudo/shims"]
filesystem.hide = ["$HOME", "$XDG_RUNTIME_DIR"]
filesystem.write = ["/tmp", "$HOME/.cache"]
systemd.PrivateTmp = true

[git-project]
extend = "sandbox"
filesystem.write = ["$PROJECT_DIR"]

# curl: extends the base sandbox
[curl]
match = "curl"
extend = "sandbox"
systemd.MemoryMax = "256M"

# claude: works on the project it is started in, plus any --add-dir
[claude]
match = "claude"
extend = "git-project"
args.add_dir = { flags = "--add-dir", greedy = true }
filesystem.read = ["$HOME/.gitconfig", "$arg_add_dir"]
filesystem.write = ["$HOME/.claude", "$HOME/.claude.json"]
network.dest.allow = ["*.anthropic.com"]

# code: VS Code and its variants
[code]
match = ["code", "code-oss", "codium", "vscode"]
extend = "git-project"
filesystem.write = [
  "/proc",
  "/dev/shm",
  "/dev/dri",
  "$HOME/.vscode",
  "$HOME/.vscode-oss",
  "$HOME/.config/Code",
  "$HOME/.config/Code - OSS",
]
# The display: the one socket of the session's an editor needs, given back alone.
filesystem.read = ["$XDG_RUNTIME_DIR/${WAYLAND_DISPLAY:-wayland-0}"]
# The launcher leaves the editor running and exits: keep the unit until it is gone.
systemd.ExitType = "cgroup"
dbus.talk = [
  "org.freedesktop.secrets",
  "org.freedesktop.Notifications",
  "org.freedesktop.portal.*",
]
dbus.own = ["com.visualstudio.code.*"]

# npm: the npm cache, and the project
[npm]
match = "npm"
extend = "git-project"
filesystem.write = ["$HOME/.npm"]

[pnpm]
match = "pnpm"
extend = "npm"
filesystem.write = ["$HOME/.pnpm-store"]
```

Every list adds to the ones it inherits: `pnpm` can write `~/.npm`, the project and `~/.pnpm-store`, and read everything `sandbox` lets it read.
