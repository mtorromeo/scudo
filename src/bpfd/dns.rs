//! Just enough DNS to run an allowlisting resolver.
//!
//! We need three things from a message: the name being asked about, the
//! addresses in an answer, and a way to say no. Everything else is skipped.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};

/// Fixed part of every DNS message.
const HEADER_LEN: usize = 12;

/// Record types we care about.
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

/// The two high bits of a label length mark a compression pointer.
const POINTER_MASK: u8 = 0xc0;

/// A name may not be followed forever: cap the pointer chain.
const MAX_JUMPS: usize = 16;

/// Response code 5, "refused", is the honest answer for a name the policy does
/// not allow: not "this does not exist", but "I will not look it up".
const RCODE_REFUSED: u8 = 5;

/// The question a query is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Lowercased, dot-separated, without the trailing root dot.
    pub name: String,
    pub qtype: u16,
}

/// An address from an answer section, with the TTL it came with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    pub addr: IpAddr,
    pub ttl: u32,
}

fn u16_at(msg: &[u8], at: usize) -> Result<u16> {
    let hi = *msg.get(at).ok_or_else(short)?;
    let lo = *msg.get(at.saturating_add(1)).ok_or_else(short)?;
    Ok(u16::from_be_bytes([hi, lo]))
}

fn u32_at(msg: &[u8], at: usize) -> Result<u32> {
    let hi = u16_at(msg, at)?;
    let lo = u16_at(msg, at.saturating_add(2))?;
    Ok((u32::from(hi) << 16) | u32::from(lo))
}

fn short() -> anyhow::Error {
    anyhow::anyhow!("truncated DNS message")
}

/// Read a name, following compression pointers, and return it with the offset
/// just past the name *as encoded here* (a pointer is two bytes, whatever it
/// points at).
fn read_name(msg: &[u8], start: usize) -> Result<(String, usize)> {
    let mut name = String::new();
    let mut at = start;
    let mut after: Option<usize> = None;
    let mut jumps = 0usize;

    loop {
        let len = *msg.get(at).ok_or_else(short)?;
        if len & POINTER_MASK == POINTER_MASK {
            let target = usize::from(u16_at(msg, at)? & 0x3fff);
            // The end of this name is right after the pointer, wherever it leads.
            after.get_or_insert(at.saturating_add(2));
            jumps = jumps.saturating_add(1);
            if jumps > MAX_JUMPS {
                bail!("DNS name has a compression loop");
            }
            if target >= at {
                // Pointers must go backwards; anything else is a loop waiting to
                // happen.
                bail!("DNS name has a forward compression pointer");
            }
            if target < HEADER_LEN {
                // Nothing in a real message lives there, and the header is
                // what `refuse` rewrites: a name read out of it would not be
                // the name echoed back.
                bail!("DNS name points into the header");
            }
            at = target;
            continue;
        }
        if len == 0 {
            let end = after.unwrap_or_else(|| at.saturating_add(1));
            return Ok((name, end));
        }
        if len & POINTER_MASK != 0 {
            bail!("DNS name uses a reserved label type");
        }

        let from = at.saturating_add(1);
        let to = from.saturating_add(usize::from(len));
        let label = msg.get(from..to).ok_or_else(short)?;
        if !name.is_empty() {
            name.push('.');
        }
        for byte in label {
            name.push(byte.to_ascii_lowercase() as char);
        }
        at = to;
    }
}

/// Skip over a name without building it.
fn skip_name(msg: &[u8], start: usize) -> Result<usize> {
    let (_, end) = read_name(msg, start)?;
    Ok(end)
}

/// Read the question a query is asking.
///
/// A message with no question, or with more than one, is rejected: every real
/// resolver sends exactly one, and refusing the unusual case keeps the
/// allowlist from being talked around with a crafted packet.
pub fn question(msg: &[u8]) -> Result<Question> {
    if msg.len() < HEADER_LEN {
        bail!("DNS message is shorter than its header");
    }
    let qdcount = u16_at(msg, 4)?;
    if qdcount != 1 {
        bail!("DNS query carries {qdcount} questions; expected exactly one");
    }
    let (name, after) = read_name(msg, HEADER_LEN)?;
    let qtype = u16_at(msg, after)?;
    Ok(Question { name, qtype })
}

/// Collect the addresses from a response's answer section.
pub fn answers(msg: &[u8]) -> Result<Vec<Answer>> {
    if msg.len() < HEADER_LEN {
        bail!("DNS message is shorter than its header");
    }
    let qdcount = u16_at(msg, 4)?;
    let ancount = u16_at(msg, 6)?;

    let mut at = HEADER_LEN;
    for _ in 0..qdcount {
        at = skip_name(msg, at)?;
        // qtype and qclass
        at = at.saturating_add(4);
    }

    let mut found = Vec::new();
    for _ in 0..ancount {
        at = skip_name(msg, at)?;
        let rtype = u16_at(msg, at)?;
        let ttl = u32_at(msg, at.saturating_add(4))?;
        let rdlength = usize::from(u16_at(msg, at.saturating_add(8))?);
        let rdata_at = at.saturating_add(10);
        let rdata = msg
            .get(rdata_at..rdata_at.saturating_add(rdlength))
            .ok_or_else(short)?;

        match (rtype, rdata.len()) {
            (TYPE_A, 4) => {
                let mut octets = [0u8; 4];
                octets.copy_from_slice(rdata);
                found.push(Answer {
                    addr: IpAddr::V4(Ipv4Addr::from(octets)),
                    ttl,
                });
            }
            (TYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                found.push(Answer {
                    addr: IpAddr::V6(Ipv6Addr::from(octets)),
                    ttl,
                });
            }
            // CNAMEs and everything else are passed through to the caller
            // untouched; only addresses need to reach the dynamic map.
            _ => {}
        }

        at = rdata_at.saturating_add(rdlength);
    }

    Ok(found)
}

/// Build a "refused" response to `query`, echoing its header and question.
#[must_use]
pub fn refuse(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();
    if let Some(flags_hi) = response.get_mut(2) {
        // QR = 1 (this is a response), keep the opcode, RD as the client set it.
        *flags_hi |= 0x80;
        // Clear AA (0x04) and TC (0x02): we are nobody's authority, and there is
        // nothing here that could have been truncated.
        *flags_hi &= 0xf9;
    }
    if let Some(flags_lo) = response.get_mut(3) {
        *flags_lo = RCODE_REFUSED;
    }
    // No answers, authorities or additionals of our own.
    for at in [6usize, 8, 10] {
        if let Some(slot) = response.get_mut(at..at.saturating_add(2)) {
            slot.fill(0);
        }
    }
    response
}

/// `true` when `response` really is the answer to `query`: same id, the QR bit
/// set, and the same question echoed back.
///
/// This matters more here than in an ordinary resolver. A query goes out on an
/// unconnected UDP socket, so anyone who guesses the ephemeral port and forges
/// the nameserver's address can get an answer in first — and the addresses in an
/// answer go straight into the policy's destination tries. An answer nobody
/// asked for would not merely poison a cache: it would widen what the sandbox is
/// allowed to reach, or keep a real address out of a deny trie.
#[must_use]
pub fn is_answer_to(query: &[u8], response: &[u8]) -> bool {
    let (Some(asked), Some(answered)) = (query.get(..2), response.get(..2)) else {
        return false;
    };
    if asked != answered {
        return false;
    }
    // A copy of our own query reflected back is not an answer.
    if response.get(2).is_none_or(|flags| flags & 0x80 == 0) {
        return false;
    }
    match (question(query), question(response)) {
        (Ok(asked), Ok(answered)) => asked == answered,
        _ => false,
    }
}

/// `true` when the response's TC bit is set, meaning the answer did not fit and
/// the client is expected to retry over TCP.
#[must_use]
pub fn is_truncated(msg: &[u8]) -> bool {
    msg.get(2).is_some_and(|flags| flags & 0x02 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query for `api.github.com`, A record.
    fn query() -> Vec<u8> {
        let mut msg = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: standard query, recursion desired
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
        for label in ["api", "github", "com"] {
            msg.push(u8::try_from(label.len()).unwrap());
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes()); // class IN
        msg
    }

    #[test]
    fn reads_the_question() {
        let q = question(&query()).unwrap();
        assert_eq!(q.name, "api.github.com");
        assert_eq!(q.qtype, TYPE_A);
    }

    #[test]
    fn names_are_lowercased() {
        let mut msg = query();
        // Uppercase the first label in place.
        if let Some(byte) = msg.get_mut(13) {
            *byte = b'A';
        }
        assert_eq!(question(&msg).unwrap().name, "api.github.com");
    }

    #[test]
    fn rejects_a_query_without_exactly_one_question() {
        let mut msg = query();
        if let Some(slot) = msg.get_mut(5) {
            *slot = 2;
        }
        question(&msg).unwrap_err();

        let mut msg = query();
        if let Some(slot) = msg.get_mut(5) {
            *slot = 0;
        }
        question(&msg).unwrap_err();
    }

    #[test]
    fn rejects_a_truncated_message() {
        let msg = query();
        for len in [0usize, 4, 11, 13] {
            let truncated: Vec<u8> = msg.iter().copied().take(len).collect();
            question(&truncated).unwrap_err();
        }
    }

    /// Build a response with one A and one AAAA answer, using a compression
    /// pointer for the names the way a real server does.
    fn response() -> Vec<u8> {
        let mut msg = query();
        if let Some(slot) = msg.get_mut(2..4) {
            slot.copy_from_slice(&[0x81, 0x80]); // response, no error
        }
        if let Some(slot) = msg.get_mut(6..8) {
            slot.copy_from_slice(&2u16.to_be_bytes()); // ancount
        }
        // Answer 1: A 140.82.121.6, TTL 60, name as a pointer to offset 12.
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[140, 82, 121, 6]);
        // Answer 2: AAAA 2606:50c0::1, TTL 30.
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&TYPE_AAAA.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&30u32.to_be_bytes());
        msg.extend_from_slice(&16u16.to_be_bytes());
        let v6: Ipv6Addr = "2606:50c0::1".parse().unwrap();
        msg.extend_from_slice(&v6.octets());
        msg
    }

    #[test]
    fn collects_addresses_from_the_answer() {
        let found = answers(&response()).unwrap();
        assert_eq!(
            found,
            vec![
                Answer {
                    addr: IpAddr::V4(Ipv4Addr::new(140, 82, 121, 6)),
                    ttl: 60,
                },
                Answer {
                    addr: IpAddr::V6("2606:50c0::1".parse().unwrap()),
                    ttl: 30,
                },
            ]
        );
    }

    /// A record we do not understand must be skipped, not fatal, or one odd
    /// answer would take out every address beside it.
    #[test]
    fn unknown_record_types_are_skipped() {
        let mut msg = response();
        if let Some(slot) = msg.get_mut(6..8) {
            slot.copy_from_slice(&3u16.to_be_bytes());
        }
        // A TXT record between the two we know about would shift everything, so
        // append it instead.
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&16u16.to_be_bytes()); // TXT
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(b"\x03abc");
        assert_eq!(answers(&msg).unwrap().len(), 2);
    }

    #[test]
    fn refuses_a_compression_loop() {
        let mut msg = query();
        // Point the name at itself.
        if let Some(slot) = msg.get_mut(12..14) {
            slot.copy_from_slice(&[0xc0, 0x0c]);
        }
        question(&msg).unwrap_err();
    }

    /// Found by the `dns` fuzz target: a name spelt out of the answer count,
    /// which the refusal zeroes, so the refusal asked a different question.
    #[test]
    fn refuses_a_name_read_out_of_the_header() {
        let msg = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0xff, 0xff, 0x00, 0x42, 0xc0, 0x07,
            0x1c, 0x01, 0x0f,
        ];
        question(&msg).unwrap_err();
        answers(&msg).unwrap_err();
    }

    #[test]
    fn a_refusal_answers_the_query_it_was_given() {
        let refusal = refuse(&query());
        assert_eq!(refusal.get(..2), query().get(..2), "id must be echoed");
        assert_eq!(refusal.get(2).map(|f| f & 0x80), Some(0x80), "QR bit");
        assert_eq!(refusal.get(3).map(|f| f & 0x0f), Some(RCODE_REFUSED));
        assert_eq!(u16_at(&refusal, 6).unwrap(), 0, "no answers");
        // The question is still there, as the RFC requires.
        assert_eq!(question(&refusal).unwrap().name, "api.github.com");
    }

    /// A refusal is not authoritative, and nothing in it was truncated.
    #[test]
    fn a_refusal_claims_neither_authority_nor_truncation() {
        let mut query = query();
        if let Some(flags) = query.get_mut(2) {
            *flags |= 0x06; // AA and TC, as a server would never send them here
        }
        let refusal = refuse(&query);
        assert_eq!(
            refusal.get(2).map(|f| f & 0x04),
            Some(0),
            "AA must be clear"
        );
        assert_eq!(
            refusal.get(2).map(|f| f & 0x02),
            Some(0),
            "TC must be clear"
        );
        // RD, which the client set, survives.
        assert_eq!(refusal.get(2).map(|f| f & 0x01), Some(0x01));
    }

    /// Only an answer to the question we asked, carrying the id we chose, may be
    /// believed: its addresses go straight into the policy's tries.
    #[test]
    fn only_a_real_answer_is_accepted() {
        let query = query();
        assert!(is_answer_to(&query, &response()));

        // A different transaction id.
        let mut forged = response();
        if let Some(slot) = forged.get_mut(..2) {
            slot.copy_from_slice(&[0xff, 0xff]);
        }
        assert!(!is_answer_to(&query, &forged));

        // The right id, a different question.
        let mut forged = response();
        if let Some(byte) = forged.get_mut(13) {
            *byte = b'x'; // "xpi.github.com"
        }
        assert!(!is_answer_to(&query, &forged));

        // Our own query, reflected back with the QR bit still clear.
        assert!(!is_answer_to(&query, &query));

        // Nothing at all.
        assert!(!is_answer_to(&query, &[]));
    }

    #[test]
    fn spots_a_truncated_response() {
        assert!(!is_truncated(&response()));
        let mut msg = response();
        if let Some(flags) = msg.get_mut(2) {
            *flags |= 0x02;
        }
        assert!(is_truncated(&msg));
    }
}
