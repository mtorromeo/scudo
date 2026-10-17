# scudo

**Sandbox any command, without thinking about it.**

scudo wraps commands with [`systemd-run`](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html),
applying resource limits, filesystem, session bus and network restrictions defined in
per-command profiles. Symlink it under a command's name, or let its FUSE shim do it for every
command on your `PATH`, and the command runs sandboxed without you having to remember to ask.

📖 **Documentation: https://mtorromeo.github.io/scudo/docs/**

## Why

Package managers, build scripts, editors with extensions, AI coding agents: a lot of what runs
on a developer's machine executes code nobody has read, with full access to `$HOME`, your SSH
keys and the whole network. Containers fix that at the cost of a different filesystem, a
different toolchain and a lot of friction. scudo takes the other route: the command runs on
your system as it is, inside a transient systemd unit that is told what it may see and reach.

## Use cases

- **Keep `npm install`, `pip` and `cargo build` away from your secrets** — hide `$HOME`, give
  back only the project and the tool's cache, and let it reach its registry and nothing else.
- **Fence an AI coding agent into the project it was started in** — writable project
  directory, read-only everything else, network limited to its API.
- **Cap a hungry program** — `MemoryMax=`, `CPUQuota=`, `IOWeight=` and anything else a
  systemd unit can say, per command.
- **Run an editor or an Electron app without letting it escape** — scudo filters the session
  bus so the program cannot ask `systemd --user` to move it out of its own sandbox.
- **Find out what a program actually touches** — refused connections, DNS lookups and hidden
  files are reported as they happen, or live beside the command in the terminal UI (`--tui`).

## Features

- Profiles in TOML, matched by exact name, glob or regex, composable with `extend`.
- Configuration layered from `/etc/scudo/config.toml`, `$XDG_CONFIG_HOME/scudo/config.toml`
  and per-directory `.scudo.toml` files, which you are asked to trust before they apply.
- Filesystem access as four lists — `write`, `read`, `hide`, `deny` — that merge sensibly
  across profiles.
- Network filtering by destination (addresses, networks, host globs) and port, enforced by
  eBPF programs attached to the command's cgroup. No root needed at run time.
- Variables from the environment, from the command's own arguments and from lookups such as
  "the closest directory holding a `.git`".
- Three ways in: `scudo <command>`, a symlink named after the command, or the FUSE shim.

## Quick start

Build and install (the [documentation](https://mtorromeo.github.io/scudo/docs/building.html)
lists the toolchain requirements and optional features):

```bash
cargo build --release
sudo install -m755 target/release/scudo target/release/scudo-fuse target/release/scudo-bpfd /usr/bin/
# Only needed for network filtering
sudo setcap cap_bpf,cap_net_admin,cap_perfmon=ep /usr/bin/scudo-bpfd
systemctl --user enable --now scudo-bpfd.socket
```

Start from the recommended configuration in [`examples/config.toml`](examples/config.toml):
base profiles that hide `$HOME` and the session's sockets, profiles for the common package
managers, and one for AI coding agents that runs those in sandboxes of their own.

```bash
mkdir -p ~/.config/scudo
cp examples/config.toml ~/.config/scudo/config.toml
```

It is a starting point, not a guarantee: you are responsible for the configuration you choose
to use, and for judging whether it protects what you need it to in your own case. Read it,
adapt it, and check what a command can still reach before relying on it.

A project can add to its profiles in a `.scudo.toml` of its own (you are asked to trust it
first). Here cargo also gets a memory limit, and no network beyond its registry:

```toml
# .scudo.toml in the project
[cargo]
systemd.MemoryMax = "4G"
network.dest.allow = ["*.crates.io"]
```

And run the command through scudo:

```bash
scudo cargo build                    # explicitly
scudo --tui -- cargo build           # beside a live list of what was blocked
ln -s /usr/bin/scudo ~/.local/bin/cargo && cargo build   # transparently
```

Everything else — the full profile reference, the session bus filter, network policies,
logging, the terminal UI and the FUSE shim — is in the
**[documentation](https://mtorromeo.github.io/scudo/docs/)**.

## Requirements

- Linux with systemd (user session).
- `fuse3` for the FUSE shim; `xdg-dbus-proxy` and the `scudo-dbus@.service` user unit for the
  session bus filter.
- For network filtering, a kernel with cgroup eBPF support and `scudo-bpfd` installed with its
  file capabilities.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT), at your option.
