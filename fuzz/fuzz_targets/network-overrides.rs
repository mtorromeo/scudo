//! `--allow-dest`, `--deny-dest`, `--allow-port` and `--deny-port`. Whatever
//! parses has to be something the daemon can load as it stands.
#![no_main]

use core::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use scudo::policy::network::{Destination, NetworkOverrides};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    // Four lists separated by NUL, entries by newline.
    let mut lists = text.split('\0').map(|list| {
        list.split('\n')
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    });
    let mut next = || lists.next().unwrap_or_default();
    let (allow_dest, deny_dest, allow_port, deny_port) = (next(), next(), next(), next());

    let Ok(overrides) =
        NetworkOverrides::parse(&allow_dest, &deny_dest, &allow_port, &deny_port)
    else {
        return;
    };

    for dest in overrides.dest.allow.iter().chain(&overrides.dest.deny) {
        if let Destination::Net { addr, prefix_len } = dest {
            let width = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            assert!(*prefix_len <= width, "{dest:?} has a prefix past the address");
        }
    }
    for rule in overrides.ports.allow.iter().chain(&overrides.ports.deny) {
        assert!(rule.ports.start != 0, "{rule:?} names port 0");
        assert!(rule.ports.start <= rule.ports.end, "{rule:?} is backwards");
    }

    drop(overrides.describe());
    drop(overrides.apply(None));
});
