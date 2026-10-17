//! Recognising the terminal queries a command writes under `--tui`. The bytes
//! are the command's output, and a sequence may arrive split across any number
//! of reads: the answers must not depend on where the reads fell.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scudo::tui::query::{Answerer, Host};

/// Below `MAX_SEQUENCE` in `query.rs`. Past it an overlong sequence is thrown
/// away, and *what* is thrown away legitimately depends on how it was split.
const MAX_INPUT: usize = 4000;

fn replies(chunks: &[&[u8]]) -> Vec<u8> {
    // Never fed: the cursor report then has the same answer in both runs.
    let parser = vt100::Parser::new(24, 80, 0);
    let host = Host::default();
    let mut answerer = Answerer::default();
    let mut out = Vec::new();
    for chunk in chunks {
        answerer.answer(chunk, &host, &parser, &mut out);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // The first byte says how many split points follow, each a byte long.
    let Some((&count, rest)) = data.split_first() else {
        return;
    };
    let count = usize::from(count % 8).min(rest.len());
    let (cuts, output) = rest.split_at(count);
    if output.len() > MAX_INPUT {
        return;
    }

    let mut points: Vec<usize> = cuts
        .iter()
        .map(|&cut| usize::from(cut) * output.len() / 256)
        .collect();
    points.sort_unstable();
    let mut chunks = Vec::new();
    let mut from = 0;
    for point in points {
        chunks.push(&output[from..point]);
        from = point;
    }
    chunks.push(&output[from..]);

    assert_eq!(
        replies(&[output]),
        replies(&chunks),
        "answers depend on how the output was split"
    );
});
