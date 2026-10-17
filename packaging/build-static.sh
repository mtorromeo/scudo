#!/bin/sh
# Builds statically linked x86_64 binaries of scudo, scudo-fuse and scudo-bpfd
# and packs them into dist/.
#
# Meant to run as root inside an `almalinux:8` container, which is what the
# release workflow does: glibc is linked statically, and linking it from the
# oldest supported distribution (glibc 2.28) keeps the few things a static glibc
# still looks up at run time compatible with RHEL 8, Ubuntu 22.04 and anything
# newer. To try it locally:
#
#     podman run --rm -v "$PWD:/src:Z" -w /src almalinux:8 packaging/build-static.sh
set -eu

target=x86_64-unknown-linux-gnu
bpf_linker_version=v0.12.0

# glibc-static lives in the powertools repository.
dnf install -y --setopt=install_weak_deps=False dnf-plugins-core
dnf config-manager --set-enabled powertools
dnf install -y --setopt=install_weak_deps=False \
    gcc glibc-static file tar zstd xz

if ! command -v rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
        sh -s -- -y --profile minimal --default-toolchain stable
fi
export PATH="$HOME/.cargo/bin:$PATH"
# The eBPF programs target bpfel-unknown-none, which ships no prebuilt core:
# build.rs builds it from rust-src with the stable toolchain.
rustup component add rust-src --toolchain stable

# The musl build of bpf-linker is static and bundles its own LLVM, so it runs
# here whatever glibc and LLVM the container has. EL8's tar predates --zstd.
if ! command -v bpf-linker >/dev/null 2>&1; then
    curl -sSfL "https://github.com/aya-rs/bpf-linker/releases/download/$bpf_linker_version/bpf-linker-x86_64-unknown-linux-musl.tar.zst" |
        zstd -dc | tar -x -C "$HOME/.cargo/bin" bpf-linker
fi

# Scoped to the target, so that build scripts, proc macros and the eBPF build
# that build.rs starts are not linked statically too.
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS='-C target-feature=+crt-static'
cargo build --locked --release --target "$target"

out="target/$target/release"
for bin in scudo scudo-fuse scudo-bpfd; do
    if ! file "$out/$bin" | grep -Eq 'statically linked|static-pie linked'; then
        echo "error: $bin is not statically linked" >&2
        file "$out/$bin" >&2
        exit 1
    fi
done

# The release workflow passes the tag, `v1.2.3`.
version=${SCUDO_VERSION:-$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)}
version=${version#v}
name="scudo-$version-x86_64-linux"
stage="dist/$name"
rm -rf "$stage"
mkdir -p "$stage/systemd" "$stage/examples"
install -m0755 "$out/scudo" "$out/scudo-fuse" "$out/scudo-bpfd" "$stage/"
install -m0644 scudo-bpfd.service scudo-bpfd.socket scudo-fuse.service \
    scudo-dbus@.service "$stage/systemd/"
install -m0644 README.md LICENSE-MIT LICENSE-APACHE "$stage/"
install -m0644 examples/config.toml "$stage/examples/"
tar -C dist -cJf "dist/$name.tar.xz" "$name"
(cd dist && sha256sum "$name.tar.xz" >"$name.tar.xz.sha256")
echo "built dist/$name.tar.xz"
