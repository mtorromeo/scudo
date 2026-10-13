# Building

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
