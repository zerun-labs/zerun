//! Stage timing (aligns with the T0 latency budget in the design doc).
//!
//! When `ZERUN_TRACE` is set, nanosecond offsets from process start are printed to
//! stderr for each stage (clone / pivot / pseudo-fs / security / exec). The bench
//! harness parses these lines.
use std::sync::OnceLock;
use std::time::Instant;

static START: OnceLock<Instant> = OnceLock::new();

pub fn init() {
    START.get_or_init(Instant::now);
}

pub fn mark(stage: &str) {
    if std::env::var_os("ZERUN_TRACE").is_some() {
        let ns = START.get().map(|i| i.elapsed().as_nanos()).unwrap_or(0);
        eprintln!("[trace] {:>10} ns  {stage}", ns);
    }
}
