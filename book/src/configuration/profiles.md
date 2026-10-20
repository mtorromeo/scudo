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
| `deny_env` | string or array of strings | Environment variables, by name or glob, kept out of the sandbox; see [Environment](#environment) |
| `allow_env` | string or array of strings | Environment variables, by name or glob, passed on even though `deny_env` matches them; see [Environment](#environment) |
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

## Environment

The command gets the environment scudo is started with, as it would without scudo. `systemd-run` starts the unit from the service manager's environment (`systemctl --user show-environment`), so scudo changes that one into its own: a variable the manager has with a different value, or not at all, is passed on with `systemd-run --setenv=NAME`, and one the manager has but scudo's environment does not is removed with `UnsetEnvironment=`.

`deny_env` keeps variables out, wherever they come from: what it matches is neither passed on nor left in from the manager's environment. `allow_env` lets back in some of what `deny_env` keeps out. Both take names or globs (`*`, `?`, `[A-Z]`), and a variable `allow_env` matches is passed on whatever `deny_env` says:

```toml
# Credentials stay outside, as in the recommended configuration's `sandbox`.
[sandbox]
deny_env = ["*_SECRET", "*_TOKEN", "*_KEY"]

# A profile that extends it lets back in the one it needs.
[sentry-wizard]
match = "npx @sentry/wizard*"
extend = "sandbox"
allow_env = "SENTRY_ACCESS_TOKEN"
```

The alternative is to keep out everything but what is named, which leaves nothing to a naming convention:

```toml
[supply-chain]
deny_env = "*"
allow_env = [
  "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "COLORTERM",
  "LANG", "LANGUAGE", "LC_*", "TZ", "XDG_*",
]
```

`--deny-env` and `--allow-env` (`-E`) do the same for one run, adding to what the profiles say:

```sh
scudo --deny-env '*' -E PATH,HOME,TERM,SENTRY_ACCESS_TOKEN npx @sentry/wizard
```

The lists add up across combined profiles like any other list, so any profile can deny a variable and any profile can allow it back.

Some variables are never passed on:

- those a profile or scudo sets in the unit with `Environment=`: `systemd.Environment = ["NAME=value"]` sets a fixed value that the caller's environment does not replace, and `$NAME` expands there as in any other value;
- those systemd sets for the unit scudo itself runs in (`NOTIFY_SOCKET`, `LISTEN_*`, `INVOCATION_ID`, `JOURNAL_STREAM`, `MANAGERPID`, …), which describe that unit and not the sandbox, and those scudo uses between a [broker](../delegation.md#delegating-commands) and the run it starts;
- names that are not valid variable names, such as the `BASH_FUNC_name%%` bash exports functions with.

Some variables are never taken away, since the command would get them in any unit: those a profile or scudo sets with `Environment=`, and those systemd sets for every unit it starts (`INVOCATION_ID`, `SYSTEMD_EXEC_PID`, `MEMORY_PRESSURE_WATCH`, and `HOME`, `USER`, `PATH` when the manager's environment lacks them), even with `deny_env = "*"`. `systemd.UnsetEnvironment` removes them by name.

To read the manager's environment scudo runs `busctl --user`. When that fails, every variable is passed on with `--setenv` and none is removed, unless `deny_env` or `--deny-env` names any, which makes it an error: what is denied could not be taken out.

Only the names appear on the `systemd-run` command line that scudo prints, but the values become properties of the unit: while the command runs, `systemctl --user show` on the unit shows them to your own user.

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
