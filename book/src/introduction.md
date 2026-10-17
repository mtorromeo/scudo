# scudo

scudo wraps commands with [`systemd-run`](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html), applying resource limits and sandboxing constraints defined in per-command profiles. It requires Linux with systemd.

## What it is

Much of what runs on a developer's machine executes code that nobody has read:

- package managers running install scripts;
- build systems running `build.rs`, `setup.py` and Makefiles;
- editors loading extensions;
- AI coding agents running whatever they decide to.

All of it runs as you, with the same access you have: your `$HOME`, your SSH keys and tokens,
your session bus, the whole network.

scudo narrows that access, one command at a time. The command still runs on your system,
with your toolchain and your files, but inside a transient systemd unit that is told what it
may see, write and reach. A **profile** says what that is, and is matched by the command's
name. Once scudo is symlinked under a command's name, or its FUSE shim is on your `PATH`, the
command is sandboxed every time it runs, without anyone having to remember to ask
([Symlinks, aliases and the FUSE shim](dispatch.md#symlinks-aliases-and-the-fuse-shim)).

What a profile can say:

- **Files**: which paths are writable, read-only, replaced by an empty directory, or
  inaccessible. Typically: the project and the tool's own cache, and nothing else of `$HOME`
  ([Filesystem access](filesystem.md#filesystem-access)).
- **Network**: which addresses, hosts and ports may be reached, enforced by eBPF programs on
  the command's cgroup, with DNS answered only for the names the rules mention
  ([Network filtering](network.md#network-filtering)).
- **Session bus**: none of it by default, or a filtered view, so that the command cannot ask
  `systemd --user` to start something outside the sandbox
  ([Session bus](session-bus.md#session-bus)).
- **Resources and everything else a systemd unit can say**: `MemoryMax=`, `CPUQuota=`,
  `IOWeight=`, capabilities, private `/tmp` and so on.

It also tells you what it took away. A sandboxed command that fails because a file was hidden
or a connection refused looks exactly like a broken program, so scudo can report every
refusal, as it happens or in a [terminal UI](tui.md#terminal-ui) beside the command.

## What it is not

- **Not an antivirus.** scudo does not scan, detect or recognise anything. It has no idea
  whether the code it runs is malicious, and it never will. It limits what *any* code run
  under a profile can do, whatever that code turns out to be. A malicious package is still
  installed, still runs, and can still do whatever its profile allows. What changes is what
  that amounts to.
- **Not a container or a virtual machine.** The command runs on your kernel, as your user,
  against your real filesystem, seen through mount restrictions. A kernel vulnerability, or a
  privileged program it is allowed to talk to, is outside what scudo can contain.
- **Not stronger than its profile.** Whatever a profile grants is granted:
  - a project directory left writable can be damaged;
  - a token left readable can be read;
  - a network left open can carry it away.

  A profile that hides nothing protects nothing.
- **Not something that cannot be avoided.** Commands that are not run through scudo are not
  sandboxed: a script that calls `/usr/bin/npm` by its full path skips the symlink. scudo
  confines the commands you route through it, not everything on the machine.
- **Not a replacement for reviewing what you install.** It limits the damage of a bad
  dependency, it does not tell you that you have one.

## Use cases

- **Keep `npm install`, `pip` and `cargo build` away from your secrets.** Hide `$HOME`, give
  back only the project and the tool's cache, and let the tool reach its registry and nothing
  else.
- **Fence an AI coding agent into the project it was started in.** The project is writable,
  everything else is read-only or hidden, and the network is limited to the agent's API. The
  tools the agent runs can be [delegated](delegation.md#delegating-commands) to sandboxes of
  their own, so that an install script run by the agent does not inherit the agent's access.
- **Run an editor or an Electron app without letting it escape.** The session bus is filtered,
  so the program cannot ask `systemd --user` to move it out of its sandbox.
- **Cap a hungry program** with memory, CPU and I/O limits, per command.
- **Find out what a program actually touches.** Refused connections, DNS lookups and hidden
  files are reported as they happen.

## What it protects against

A typical case is code from a compromised dependency, run by a tool you trusted. Without
scudo it has everything you have. Under a profile that hides `$HOME` and restricts the
network, it is kept from:

- **Reading your secrets**: SSH keys, cloud credentials, registry tokens, browser profiles,
  password stores and anything else under `$HOME` that the profile does not give back.
- **Using your agents**: the ssh-agent and gpg-agent sockets let a program push or sign as you
  without ever reading a key. Hiding `$XDG_RUNTIME_DIR` takes them away with every other
  socket of your session.
- **Sending what it found somewhere**: with a network policy, the command can only reach the
  hosts its rules name, and can only resolve those names.
- **Staying behind**: no writing to shell startup files, to directories on your `PATH`, to
  `.git/hooks`, or to anything else that would run its code again later, outside the sandbox.
- **Leaving the sandbox**: no session bus and no way to the service manager, so it cannot
  start a process in a unit of its own, nor move itself out of its cgroup.
- **Taking the machine down**: memory, CPU and process limits, if the profile sets them.

Each of these holds only as far as the profile says so: scudo enforces the profile, and the
profile decides how much protection there is.

## How it differs from other sandboxes

Flatpak, bubblewrap and Firejail all confine programs on Linux, and all three are good at what
they were made for. scudo was made for a different job: putting the tools you already have,
installed the way they already are, under a policy that follows the command wherever it is
run from.

| | scudo | Flatpak | bubblewrap | Firejail |
|---|---|---|---|---|
| What it confines | the commands already on your system | applications packaged as Flatpaks | whatever command line you write for it | the commands already on your system |
| Configured by | per-command profiles, matched by name | the app's manifest, plus overrides | flags on each invocation | per-program profiles |
| Privileges | none; an optional helper with file capabilities for network filtering | none (it uses bubblewrap) | none | a setuid-root binary |
| Network | per host, address and port, DNS answered only for named hosts | all or nothing | all or nothing | all or nothing, or a firewall inside a network namespace of its own |
| Resource limits | anything a systemd unit can set | none of its own | none | rlimits |
| Reporting | every refused connection, lookup and file, live | — | — | blacklisted files, to syslog |

**Flatpak** is a way to distribute desktop applications. An application is built against a
runtime, ships with a description of what it needs, and talks to the desktop through portals.
That is the right shape for a GUI app you install from Flathub, but not for the `npm`, `cargo`
or `make` on your `PATH`: those are not Flatpaks, they work on your files and your toolchain,
and repackaging them would mean replacing the environment you build in. scudo confines those
binaries as they are.

**bubblewrap** is the low-level tool Flatpak is built on: it sets up namespaces and bind
mounts from its command line and runs the command. It has no notion of a profile, of which
command is being run, or of a policy beyond the flags it was given, so using it day to day
means writing a wrapper script for each command. It also stops at namespaces: there are no
cgroup limits and no network rules finer than having a network or not. scudo gets its
namespaces from systemd instead, and adds what a wrapper script would otherwise have to
reinvent:
- profiles chosen by the command's name;
- variables from the project and the command's arguments;
- limits, network filtering and refusal reports.

**Firejail** is the closest in spirit. It also confines the programs you already have,
symlinked under their own names, and ships a large collection of profiles for desktop
software. The differences are in how it gets there and what it aims at:
- **Privileges.** Firejail is setuid root, so every sandbox starts from a root process that
  parses user input. scudo runs entirely as you. Its one privileged part, the network helper,
  holds two file capabilities and can only ever add restrictions to a cgroup you already own.
- **The network.** Filtering by host name, with DNS refused for every name the rules do not
  mention, works on the command's own cgroup. It needs no network namespace, bridge or
  firewall setup.
- **Developer tools and agents.** Profiles can follow the project the command was started in,
  or a directory named in its arguments. An agent's sandbox can
  [delegate](delegation.md#delegating-commands) the tools it runs to sandboxes of their own.
  Neither of these is something a desktop application needs, which is what Firejail's profiles
  are written for.

What scudo gives up in return:
- it needs Linux with systemd, and `systemd --user` running;
- reporting refused file accesses is implemented on x86-64 only;
- it has no answer for desktop integration beyond filtering the session bus: an app that lives
  on portals is better served by Flatpak.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/mtorromeo/scudo/blob/main/LICENSE-APACHE) or [MIT License](https://github.com/mtorromeo/scudo/blob/main/LICENSE-MIT), at your option.
