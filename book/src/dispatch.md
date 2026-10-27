# Symlinks, aliases and the FUSE shim

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

> **Warning:** When using the FUSE shim, avoid broad globs (`*`, `code*`) that match large numbers of commands in combination with `confirm = true` or `verbose = true`. Because the shim intercepts every command in your session — including those run by scripts, your shell itself, and every subprocess — an overly wide profile with interactive options will trigger a confirmation prompt or dump debug output for each of them, making the environment unusable. Reserve `confirm` and `verbose` for profiles that match a few commands by name, and validate broad profiles without those options first.

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

**Alongside other shims**

Another wrapper installed under the same name, such as a build cache in front of `cargo`, needs no configuration. scudo skips itself in `PATH`, and most such wrappers skip themselves too, so each would keep finding the other. scudo notices a call that comes straight back with the same name, arguments and directory it just dispatched. It skips what it chose last time and runs the next match in `PATH`, so the chain ends at the real command: `cargo` → scudo → wrapper → scudo → `cargo`. When every match in `PATH` leads back to scudo, it fails with an error instead of looping.
