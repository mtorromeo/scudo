# Installation

scudo needs Linux with systemd and a user session (`systemd --user`). Some features need a
little more:

- `fuse3` for the [FUSE shim](dispatch.md#symlinks-aliases-and-the-fuse-shim);
- `xdg-dbus-proxy` for the [session bus](session-bus.md#session-bus) filter;
- a kernel with cgroup eBPF support, and `scudo-bpfd` with its file capabilities, for
  [network filtering](network.md#network-filtering) and for reporting refused file accesses.

## Prebuilt binaries

Each [release](https://github.com/mtorromeo/scudo/releases) has an archive for x86-64,
`scudo-<version>-x86_64-linux.tar.xz`. Its binaries are statically linked, glibc included, so
they depend on no library of the host. They are built against glibc 2.28 and run on RHEL 8,
Ubuntu 22.04 and anything newer.

The archive holds `scudo`, `scudo-fuse` and `scudo-bpfd`, the systemd user units under
`systemd/`, the licenses and the README. The units expect the binaries in `/usr/bin`:

```bash
tar -xJf scudo-<version>-x86_64-linux.tar.xz
cd scudo-<version>-x86_64-linux
sudo install -m755 scudo scudo-fuse scudo-bpfd /usr/bin/
sudo install -m644 systemd/* /usr/lib/systemd/user/
```

A tar archive does not carry file capabilities, so they have to be given back to
`scudo-bpfd`. Without `cap_bpf` and `cap_net_admin` it can do nothing; `cap_perfmon` is only
for reporting refused file accesses:

```bash
sudo setcap cap_bpf,cap_net_admin,cap_perfmon=ep /usr/bin/scudo-bpfd
systemctl --user enable --now scudo-bpfd.socket
```

Every release also has a `.sha256` file beside the archive, to check it with
`sha256sum -c`.

## Building

```
cargo build --release
```

The stable toolchain is enough. The eBPF programs additionally need its `rust-src` component, since
`core` is built from source for their tier 3 target, and `bpf-linker`:

```
rustup component add rust-src --toolchain stable
cargo install bpf-linker
```

Two features are on by default and can be dropped:

| Feature | Drops |
|---------|-------|
| `bpf` | `scudo-bpfd` and the eBPF programs, along with the `rust-src` component and `bpf-linker` needed to build them. scudo still talks to a daemon that is installed. |
| `tui` | `--tui` and the terminal UI. A config naming `[scudo.tui]` still parses, so one shared with a full build is not rejected. |

```
cargo build --release --no-default-features --features bpf
```

The binaries go in `target/release`, and are installed as above:

```bash
sudo install -m755 target/release/scudo target/release/scudo-fuse target/release/scudo-bpfd /usr/bin/
sudo install -m644 scudo-bpfd.service scudo-bpfd.socket scudo-fuse.service scudo-dbus@.service \
    /usr/lib/systemd/user/
sudo setcap cap_bpf,cap_net_admin,cap_perfmon=ep /usr/bin/scudo-bpfd
```

### Static binaries

The release archives are built by `packaging/build-static.sh`, in an AlmaLinux 8 container.
The same build can be run locally with podman or docker:

```bash
podman run --rm -v "$PWD:/src:Z" -w /src almalinux:8 packaging/build-static.sh
```

The archive ends up in `dist/`.
