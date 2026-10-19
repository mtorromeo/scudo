# Recommended configuration

scudo ships a configuration meant to be copied and adapted:
[`examples/config.toml`](https://github.com/mtorromeo/scudo/blob/main/examples/config.toml),
also installed with the documentation by the packages and included in the release
archives. It is reproduced in full [below](#the-file).

> **It is a starting point, not a guarantee.** You are responsible for the configuration you
> choose to use, and for judging whether it protects what you need it to protect in your own
> case. scudo enforces exactly what the profiles say, and a profile that grants too much
> protects nothing ([What it is not](../introduction.md#what-it-is-not)). Read it, adapt it to
> the tools and the paths you actually have, and check what a command can still reach before
> relying on it — `scudo --tui -- <command>`, or a shell under one of its profiles:
> `scudo --no-match --profile supply-chain -- sh`.

Copy it to your own configuration, whole or only the profiles you want:

```bash
mkdir -p ~/.config/scudo
curl -fsSLo ~/.config/scudo/config.toml \
    https://raw.githubusercontent.com/mtorromeo/scudo/main/examples/config.toml
```

scudo itself has to be installed outside `$HOME`, as the packages do, or in `~/.local/bin`.
It runs inside every sandbox that reports refusals, filters the network or delegates
commands, and these profiles hide the rest of `$HOME`. For the same reason the
[FUSE shim](../dispatch.md#symlinks-aliases-and-the-fuse-shim) has to be mounted under
`$XDG_RUNTIME_DIR/scudo/shims`, the one place these profiles give back, for commands started
inside a sandbox to be wrapped too.

Beware if you install it as `/etc/scudo/config.toml`. Profiles there are merged into every user's
profiles of the same name ([Same-named profiles across
files](matching.md#same-named-profiles-across-files)), and its `match` rules would sandbox
every user's package managers.

## What is in it

| Profile | Matches | What it is |
|---------|---------|------------|
| `sandbox` | — | Everything read-only, `$HOME` and `$XDG_RUNTIME_DIR` replaced by empty directories, a private `/tmp`; `~/.cache`, `~/.local/bin` (read-only) and scudo's own daemon socket and FUSE shim (read-only) given back |
| `git-project` | — | `sandbox`, plus the [project](variables.md#lookup-variables) writable and `/var` denied |
| `no-net` | — | No network beyond `localhost`; for `--profile` |
| `supply-chain` | — | `git-project`, with the project's `.git` read-only; `delegable` |
| `npm`, `pnpm`, `yarn`, `bun`, `deno` | their commands | `supply-chain` and the tool's cache; `~/.npmrc` stays hidden |
| `pip`, `uv`, `poetry` | their commands | `supply-chain`, the tool's config read-only |
| `cargo` | `cargo` | `supply-chain`, `~/.cargo` and `~/.rustup` read-only except the registry, credentials denied |
| `composer`, `go`, `ruby` | their commands | `supply-chain` and the tool's cache |
| `cargo-install` | `cargo install`, `cargo binstall`, `cargo install-update`, `cargo-binstall`, `cargo-install-update` | `cargo`, with all of `~/.cargo` writable except the credentials; not `delegable` |
| `npm-auth` | `npm publish`, `npm login` | `~/.npmrc` writable on top of `npm`; not `delegable` |
| `agents` | `claude`, `opencode` | `git-project`, writing `.git` and the agent's own state; [delegates](../delegation.md#delegating-commands) every `delegable` profile |

Several pages of this documentation build their examples on these profiles.

## Why it is written this way

- **`$HOME` is hidden, not made read-only.** A read-only `$HOME` still hands out SSH keys,
  tokens and browser profiles to anyone who reads them. Each profile gives back what its tool
  needs, which is usually its cache and its configuration.
- **The session's sockets are hidden with it, in the base every profile extends.** `ssh-agent`, `gpg-agent`, the keyring and the
  container sockets let a program act as you without reading a single secret, and connecting to
  a socket needs no write access, so a read-only runtime directory is not enough. Only one
  entry of scudo's own comes back, read-only: `shims`, so that a command started inside is
  still wrapped. The sockets scudo needs in there — `scudo-bpfd`'s when a policy needs the
  daemon, the broker's when the sandbox [delegates](../delegation.md#delegating-commands) — it
  mounts by itself, read-only. Do not give back the whole `$XDG_RUNTIME_DIR/scudo`: it also
  holds the session bus proxies and the brokers of other sandboxes.
- **`.git` is read-only for build and install tools.** Hooks, `core.hooksPath` and
  `core.fsmonitor` are run by git outside any sandbox, so a writable `.git` is a way out. The
  agent, which commits, gets it back.
- **Directories on `PATH` stay read-only**: `~/.local/bin`, `~/.cargo/bin`, Composer's
  `vendor/bin`. A build script that could write there would replace `npm` or `git` with
  something that runs unsandboxed the next time. Installing into them is what the
  `cargo-install` profile is for: it matches `cargo install` on its arguments, and says
  `delegable = false` so that a sandbox delegating `cargo` cannot install through it.
- **`$XDG_RUNTIME_DIR` is never written by a base profile.** The most permissive access to a
  path wins ([Filesystem access](../filesystem.md#filesystem-access)), so a base that wrote it
  would undo the hiding in every profile built on it. A profile that needs one socket, an
  editor talking to the display say, gives back that socket alone.
- **What the agent can use as you is opt-in.** The display (to paste images), `gpg-agent` (to
  sign commits) and the keyring's SSH agent (to push) are listed in comments at the end of
  `[agents]`: each one is something a prompt injection could use too.

## The file

```toml
{{#include ../../../examples/config.toml}}
```
