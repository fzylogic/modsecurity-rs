//! Rule sets: parsing and holding SecLang configuration.

use std::ffi::{CStr, c_char};
use std::fmt;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::{Mutex, MutexGuard};

use crate::error::{Error, Result, cpath, cstring};
use crate::ffi;

/// Serialises every call into libmodsecurity's rule-set API.
///
/// The SecLang parser keeps global state: parsing two rule sets at once
/// interleaves their diagnostics and corrupts the heap. Rule sets are built
/// during start-up and configuration reload, never per request, so a single
/// process-wide lock costs nothing that matters.
///
/// The lock covers parsing, construction and destruction only. Evaluating
/// transactions against an already-parsed rule set is lock-free, which is what
/// libmodsecurity's own connectors rely on.
static PARSER: Mutex<()> = Mutex::new(());

/// Takes the parser lock, ignoring poisoning.
///
/// Nothing between acquiring and releasing it can panic: the guarded sections
/// only call C functions, so a poisoned lock never indicates damaged state.
fn parser_lock() -> MutexGuard<'static, ()> {
    PARSER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A parsed set of SecLang rules.
///
/// Build one by loading rule files or inline rule text, then share it across
/// transactions. Loading takes `&mut self`, so a rules set cannot be modified
/// while transactions are evaluating against it.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use modsecurity::Rules;
///
/// let mut rules = Rules::new()?;
/// rules.add_file("/etc/modsecurity.d/modsecurity.conf")?;
/// rules.add_plain(r#"SecRule ARGS "@contains attack" "id:1,phase:2,deny,status:403""#)?;
/// # Ok(()) }
/// ```
pub struct Rules {
    raw: NonNull<ffi::RulesSet>,
}

// SAFETY: `Rules` owns its `RulesSet` exclusively, and every method that
// mutates it takes `&mut self`. Concurrent *evaluation* against a shared rules
// set is the model libmodsecurity's own connectors use.
unsafe impl Send for Rules {}
// SAFETY: see above.
unsafe impl Sync for Rules {}

impl Rules {
    /// Creates an empty rules set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NullHandle`] if `msc_create_rules_set()` fails.
    pub fn new() -> Result<Self> {
        let _guard = parser_lock();
        // SAFETY: no preconditions; serialised against every other rule-set
        // call by `_guard`.
        let raw = unsafe { ffi::msc_create_rules_set() };
        let raw = NonNull::new(raw).ok_or(Error::NullHandle("msc_create_rules_set"))?;
        Ok(Self { raw })
    }

    /// Loads rules from a file, returning the number of rules added.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rules`] with libmodsecurity's parser diagnostic if the
    /// file cannot be read or parsed, or [`Error::InvalidPath`] if the path is
    /// not representable as a C string.
    pub fn add_file(&mut self, path: impl AsRef<Path>) -> Result<u32> {
        let c = cpath(path.as_ref())?;
        let mut error: *const c_char = std::ptr::null();
        let _guard = parser_lock();
        // SAFETY: valid rules set, NUL-terminated path, and `error` is a valid
        // out-parameter that the callee only writes on failure. The global
        // parser state is serialised by `_guard`.
        let ret = unsafe { ffi::msc_rules_add_file(self.raw.as_ptr(), c.as_ptr(), &mut error) };
        finish(ret, error)
    }

    /// Parses inline SecLang rule text, returning the number of rules added.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rules`] with the parser diagnostic, or
    /// [`Error::InteriorNul`] if `rules` contains a NUL byte.
    pub fn add_plain(&mut self, rules: &str) -> Result<u32> {
        let c = cstring(rules, "rules")?;
        let mut error: *const c_char = std::ptr::null();
        let _guard = parser_lock();
        // SAFETY: as `add_file`.
        let ret = unsafe { ffi::msc_rules_add(self.raw.as_ptr(), c.as_ptr(), &mut error) };
        finish(ret, error)
    }

    /// Downloads and loads a remote rules file (`SecRemoteRules`), returning the
    /// number of rules added.
    ///
    /// This performs network I/O and blocks until it completes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rules`] if the download or parse fails, or
    /// [`Error::InteriorNul`] if an argument contains a NUL byte.
    pub fn add_remote(&mut self, key: &str, uri: &str) -> Result<u32> {
        let key = cstring(key, "key")?;
        let uri = cstring(uri, "uri")?;
        let mut error: *const c_char = std::ptr::null();
        let _guard = parser_lock();
        // SAFETY: as `add_file`; both strings outlive the call.
        let ret = unsafe {
            ffi::msc_rules_add_remote(self.raw.as_ptr(), key.as_ptr(), uri.as_ptr(), &mut error)
        };
        finish(ret, error)
    }

    /// Merges another rules set into this one, returning the number of rules
    /// added.
    ///
    /// `other` is only read; it remains usable afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rules`] if the merge fails.
    pub fn merge(&mut self, other: &Rules) -> Result<u32> {
        let mut error: *const c_char = std::ptr::null();
        let _guard = parser_lock();
        // SAFETY: both pointers are valid rules sets. `msc_rules_merge` only
        // reads from the source; the `*mut` is a signature artefact, and no
        // Rust `&mut` to `other` is created, so the shared borrow is honoured.
        let ret =
            unsafe { ffi::msc_rules_merge(self.raw.as_ptr(), other.raw.as_ptr(), &mut error) };
        finish(ret, error)
    }

    /// Prints the parsed rules to standard output. Debugging aid.
    pub fn dump(&self) {
        let _guard = parser_lock();
        // SAFETY: valid rules set; the call only reads and writes to stdout.
        unsafe { ffi::msc_rules_dump(self.raw.as_ptr()) };
    }

    /// Raw rules-set pointer, for [`Transaction`](crate::Transaction).
    pub(crate) fn as_ptr(&self) -> *mut ffi::RulesSet {
        self.raw.as_ptr()
    }
}

impl fmt::Debug for Rules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rules").finish_non_exhaustive()
    }
}

impl Drop for Rules {
    fn drop(&mut self) {
        let _guard = parser_lock();
        // SAFETY: created by `msc_create_rules_set` and released exactly once.
        // Lifetimes guarantee no live transaction refers to it.
        unsafe { ffi::msc_rules_cleanup(self.raw.as_ptr()) };
    }
}

/// Interprets a rules-API return value, taking ownership of the error string.
///
/// libmodsecurity returns `-1` on failure and sets `*error` to a `strdup`ed
/// diagnostic; on success it returns the number of rules added.
fn finish(ret: i32, error: *const c_char) -> Result<u32> {
    if ret < 0 {
        return Err(Error::Rules(take_error(error)));
    }
    debug_assert!(error.is_null(), "error set on a successful rules call");
    Ok(ret.unsigned_abs())
}

/// Copies a `strdup`ed diagnostic into a `String` and frees the original.
fn take_error(error: *const c_char) -> String {
    if error.is_null() {
        return "unknown error (libmodsecurity reported no diagnostic)".to_string();
    }
    // SAFETY: non-NULL and NUL-terminated; libmodsecurity produced it with
    // `strdup` and hands ownership to the caller.
    let msg = unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: `error` came from the C allocator and is not aliased; this is the
    // single owner releasing it.
    unsafe { ffi::free(error.cast_mut().cast()) };
    msg
}
