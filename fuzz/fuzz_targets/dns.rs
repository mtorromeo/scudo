//! The resolver's DNS parsing. Queries come from the sandboxed command and
//! answers from whoever got a packet to the upstream socket first, so neither
//! side is trusted — and what `answers` returns goes into the destination tries.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scudo::bpfd::dns;

fuzz_target!(|msg: &[u8]| {
    let refused = dns::refuse(msg);
    assert_eq!(refused.len(), msg.len(), "a refusal echoes the query whole");

    if let Ok(asked) = dns::question(msg) {
        // The refusal has to be one the client accepts as the answer to what it
        // asked, or it waits out its timeout instead of hearing no.
        assert_eq!(
            dns::question(&refused).ok(),
            Some(asked),
            "a refusal echoes the question"
        );
        assert!(dns::is_answer_to(msg, &refused));
    }

    // A query reflected back is not an answer to itself.
    if msg.get(2).is_some_and(|flags| flags & 0x80 == 0) {
        assert!(!dns::is_answer_to(msg, msg));
    }

    if let Ok(found) = dns::answers(msg) {
        let ancount = usize::from(u16::from_be_bytes([msg[6], msg[7]]));
        assert!(found.len() <= ancount, "more addresses than answer records");
    }

    core::hint::black_box(dns::is_truncated(msg));
});
