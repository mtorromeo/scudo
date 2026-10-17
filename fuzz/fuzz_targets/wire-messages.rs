//! The JSON lines spoken to `scudo-bpfd` and to the broker. The daemon takes
//! requests from any local user, and the broker from inside a sandbox.
//!
//! Beyond not panicking, whatever is read has to write back out as something
//! that reads the same, or the two ends of a socket could disagree on it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scudo::{
    bpfd::protocol,
    broker,
};
use serde::{Serialize, de::DeserializeOwned};

fn round_trip<T: Serialize + DeserializeOwned>(data: &[u8]) {
    let Ok(message) = serde_json::from_slice::<T>(data) else {
        return;
    };
    let first = serde_json::to_vec(&message).expect("a message that was read can be written");
    let again: T = serde_json::from_slice(&first).expect("a message that was written can be read");
    let second = serde_json::to_vec(&again).expect("a message that was read can be written");
    assert_eq!(first, second, "a message changed on its way through");
}

fuzz_target!(|data: &[u8]| {
    round_trip::<protocol::Request>(data);
    round_trip::<protocol::Response>(data);
    round_trip::<protocol::Notification>(data);
    round_trip::<broker::Request>(data);
    round_trip::<broker::Reply>(data);
    round_trip::<broker::Spec>(data);
    round_trip::<broker::Limits>(data);
});
