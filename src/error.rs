//! Error type for this crate.
#![forbid(unsafe_code)]

use std::ffi::CString;
use std::fmt;

/// Convenience alias for results produced by this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong while talking to libmodsecurity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// `msc_init()` or `msc_create_rules_set()` returned `NULL`.
    ///
    /// The payload names the C function that failed.
    NullHandle(&'static str),

    /// Rule loading or merging failed. The payload is libmodsecurity's own
    /// parser diagnostic.
    Rules(String),

    /// A string argument that must cross the FFI boundary as a C string
    /// contained an interior NUL byte. The payload names the argument.
    ///
    /// Header names and values are *not* subject to this: they are passed with
    /// explicit lengths and may contain arbitrary bytes.
    InteriorNul(&'static str),

    /// A filesystem path could not be represented as a C string.
    InvalidPath,

    /// A libmodsecurity call reported failure (returned `0`) without raising an
    /// intervention. The payload names the C function.
    Failed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullHandle(func) => write!(f, "{func}() returned NULL"),
            Self::Rules(msg) => write!(f, "rule error: {msg}"),
            Self::InteriorNul(arg) => {
                write!(f, "argument `{arg}` contains an interior NUL byte")
            }
            Self::InvalidPath => f.write_str("path is not representable as a C string"),
            Self::Failed(func) => write!(f, "{func}() failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Converts a Rust string into a `CString`, reporting interior NULs against a
/// named argument instead of panicking.
pub(crate) fn cstring(value: &str, argument: &'static str) -> Result<CString> {
    CString::new(value).map_err(|_| Error::InteriorNul(argument))
}

/// Converts a path into a `CString`.
pub(crate) fn cpath(path: &std::path::Path) -> Result<CString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::InvalidPath)
    }
    #[cfg(not(unix))]
    {
        let s = path.to_str().ok_or(Error::InvalidPath)?;
        CString::new(s).map_err(|_| Error::InvalidPath)
    }
}
