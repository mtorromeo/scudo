//! Builds the eBPF programs `scudo-bpfd` loads.
//!
//! They live in their own crate because they target `bpfel-unknown-none`, which
//! needs a nightly toolchain and `bpf-linker`. Without the `bpf` feature none of
//! that is required.

// A build script reports failure by panicking: cargo turns that into the error
// the user sees, and there is nothing above us to hand a Result to.
#[expect(clippy::panic)]
fn main() {
    #[cfg(feature = "bpf")]
    {
        use aya_build::{Package, Toolchain, build_ebpf};

        if let Err(err) = build_ebpf(
            [Package {
                name: "scudo-bpf-ebpf",
                root_dir: "ebpf/scudo-bpf-ebpf",
                ..Package::default()
            }],
            Toolchain::default(),
        ) {
            panic!("failed to build eBPF programs: {err:#}");
        }
    }
}
