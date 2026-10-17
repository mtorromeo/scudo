# Matching and combining profiles

## Match patterns

`match` holds one pattern, or an array of them. Any one of them matching is enough.

- A pattern written `/…/` is a regular expression ([`regex` syntax](https://docs.rs/regex/latest/regex/#syntax)), optionally followed by flags as in sed: `i` (case-insensitive), `m` (multi-line), `s` (`.` matches newlines), `x` (verbose), `U` (swap greedy and lazy). It is not anchored: it matches anywhere unless it says `^…$`. The last `/` closes it, so a `/` inside needs no escaping, and an unknown flag is an error. Write regexes in single quotes, as TOML literal strings, so that backslashes reach the regex as written (`"\S"` is not a valid TOML string).
- Any other pattern is a glob, which has to match the whole text.
- A pattern holding a space is compared with the **command line**: the command's name, then its arguments, joined by single spaces (no quoting). Any other pattern is compared with the **name** alone.

The name is the command's last path component, so `/usr/bin/curl` is `curl`, also at the start of the command line.

| Form | Meaning |
|------|---------|
| absent | never match — base profile usable only via `extend` or `--profile` |
| `match = "curl"` | `curl` |
| `match = ["zed", "zeditor"]` | either `zed` or `zeditor` |
| `match = "code*"` | `code`, `code-oss`, `code-insiders`, … |
| `match = "*"` | every command: a catch-all default |
| `match = "git push*"` | `git push`, `git push origin main`, … but not `git status` |
| `match = '/^python3?$/'` | `python` or `python3`, not `python3.12` |
| `match = '/^npm( \S+)* (-g\|--global)( \|$)/'` | `npm` run with `-g` or `--global` anywhere among its arguments |

Every profile that matches is applied, in the order the profiles were written (see [Combining profiles](#combining-profiles)).

## Selecting profiles explicitly

`--profile <NAME>` applies a profile by name, whatever its `match` field says — including base profiles that declare no `match` at all. It is repeatable and also accepts a comma-separated list. Named profiles are applied *after* the ones that matched, so they take precedence; among themselves they are applied in the order given on the command line, with the last one winning.

`--no-match` skips pattern matching altogether. Combined with `--profile` it means "use exactly these profiles and nothing else"; on its own it runs the command with no profile at all.

| Invocation | Profiles applied |
|------------|------------------|
| `scudo --profile no-net -- curl https://example.com` | everything matching `curl`, then `no-net` |
| `scudo --profile a,b -- curl https://example.com` | matches for `curl`, then `a`, then `b` |
| `scudo --profile agents,npm,cargo -- zsh` | a shell with everything those three profiles allow, and their restrictions |
| `scudo --no-match --profile no-net -- curl https://example.com` | only `no-net` |
| `scudo --no-match -- curl https://example.com` | none — the command is executed directly, without `systemd-run` |
| `scudo --no-match -p MemoryMax=1G -- curl https://example.com` | none, but `systemd-run` still runs with the explicit property |

A profile that both matches and is named explicitly is applied only once, in its explicit position. An unknown profile name is a fatal error: scudo exits with status 1 without running the command, rather than running it with less sandboxing than was asked for.

```
$ scudo --profile sandbx -- curl https://example.com
scudo: profile 'sandbx' not found
```

Both flags belong to scudo itself, so they are only available through the explicit `scudo <command>` form. When scudo is invoked through a symlink or the FUSE shim, every argument belongs to the wrapped command.

## Combining profiles

Profiles come together in four ways — `extend`, matching the same command, `--profile`, and sharing a name across config files — and all four combine them the same way:

- **Lists accumulate.** Every array — in `match`, `extend`, `filesystem`, `network`, `dbus` and `systemd` — adds the entries it has to the ones already there, skipping duplicates. No profile can take away what another one added; for paths, see also [Filesystem access](../filesystem.md#filesystem-access).
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

## Same-named profiles across files

A profile defined again in a higher-priority config file **adds to** the one below it, by the rules above: its lists extend the inherited ones and its scalars win. A project's `.scudo.toml` can therefore give the system-wide `cargo` profile one more directory without restating it:

```toml
# /home/user/projects/myapp/.scudo.toml
[cargo]
filesystem.write = ["$SCUDO_CONFIG_DIR/target"]
```

To replace only its `match` patterns and keep adding to the rest, list `match` in `replace`. With `replace = ["match"]` and no `match`, the profile no longer matches anything and becomes a base:

```toml
# the system-wide profile matches "cargo" and "rustc"
[cargo]
replace = ["match"]
match = "cargo"
filesystem.write = ["$SCUDO_CONFIG_DIR/target"]
```

To replace the lower-priority profile as a whole, set `inherit = false`:

```toml
[cargo]
inherit = false
match = "cargo"
filesystem.read = ["/"]
filesystem.write = ["$PROJECT_DIR"]
```
