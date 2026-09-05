//! The privileged helper that enforces scudo policies with eBPF.
//!
//! It needs `CAP_BPF` and `CAP_NET_ADMIN` — cgroup BPF programs cannot be loaded
//! without them, and a user service manager has neither, which is why systemd's
//! own `IPAddressAllow=` does nothing in user units.
//!
//! Install it with:
//!
//! ```sh
//! setcap cap_bpf,cap_net_admin=ep /usr/bin/scudo-bpfd
//! ```

#![cfg(target_os = "linux")]

use std::process::exit;

fn main() {
    if let Err(err) = scudo::bpfd::server::run() {
        eprintln!("scudo-bpfd: {err:#}");
        exit(1);
    }
}
