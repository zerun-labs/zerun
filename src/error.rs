//! Unified error type.
//!
//! Errors raised inside the container child are reported to the parent over the
//! error pipe (see `namespace.rs`).
use std::io;

#[derive(Debug)]
pub struct ZError(pub String);

impl std::fmt::Display for ZError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ZError {}

impl From<io::Error> for ZError {
    fn from(e: io::Error) -> Self {
        ZError(format!(
            "{} (os error {})",
            e,
            e.raw_os_error().unwrap_or(-1)
        ))
    }
}

impl From<String> for ZError {
    fn from(s: String) -> Self {
        ZError(s)
    }
}

#[macro_export]
macro_rules! zerr {
    ($($t:tt)*) => { $crate::error::ZError(format!($($t)*)) };
}

pub type ZResult<T> = Result<T, ZError>;

/// Build an error from the current errno, annotated with `ctx`.
pub fn last_err(ctx: &str) -> ZError {
    ZError(format!("{ctx}: {}", io::Error::last_os_error()))
}
