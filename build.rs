//! Builds the eBPF programs `scudo-bpfd` loads.
//!
//! They live in their own crate because they target `bpfel-unknown-none`, which
//! needs the stable toolchain's `rust-src` component and `bpf-linker`. Without
//! the `bpf` feature none of that is required.

// A build script reports failure by panicking: cargo turns that into the error
// the user sees, and there is nothing above us to hand a Result to.
#[expect(clippy::panic)]
fn main() {
    #[cfg(feature = "bpf")]
    {
        use aya_build::{Package, Toolchain, build_ebpf};

        // bpfel-unknown-none is a tier 3 target: rustup ships no prebuilt core
        // for it, so aya-build has to add `-Z build-std=core`, which stable only
        // accepts under RUSTC_BOOTSTRAP. aya-build adds the flag when this is "1"
        // and hands our environment to the cargo it runs. A value already set is
        // left alone, so `RUSTC_BOOTSTRAP=-1` skips build-std on a toolchain that
        // ships the BPF targets prebuilt.
        println!("cargo:rerun-if-env-changed=RUSTC_BOOTSTRAP");
        if std::env::var_os("RUSTC_BOOTSTRAP").is_none() {
            // SAFETY: a build script is single-threaded, so nothing else can be
            // reading the environment while it changes.
            unsafe {
                std::env::set_var("RUSTC_BOOTSTRAP", "1");
            }
        }

        if let Err(err) = build_ebpf(
            [Package {
                name: "scudo-bpf-ebpf",
                root_dir: "ebpf/scudo-bpf-ebpf",
                ..Package::default()
            }],
            Toolchain::Custom("stable"),
        ) {
            panic!("failed to build eBPF programs: {err:#}");
        }
    }
}
