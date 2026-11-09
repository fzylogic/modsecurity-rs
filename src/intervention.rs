//! The action libmodsecurity wants the host server to take.

use std::fmt;

use crate::ffi;

/// A disruptive action requested by the rule engine.
///
/// An `Intervention` is produced after a processing phase when a rule with a
/// disruptive action (`deny`, `drop`, `redirect`, `pause`, ...) matched. The
/// host server is responsible for carrying it out: libmodsecurity itself never
/// touches the connection.
///
/// All strings are copied out of the C struct on construction, so an
/// `Intervention` borrows nothing and outlives its transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Intervention {
    /// HTTP status code to return, e.g. `403`.
    pub status: i32,
    /// Milliseconds the server should stall before responding (`pause` action).
    pub pause: i32,
    /// Redirect target set by the `redirect` action, if any.
    pub url: Option<String>,
    /// Log line describing the rule that fired, if any.
    pub log: Option<String>,
    /// Whether the request must actually be disrupted.
    ///
    /// Only interventions with this set are returned by this crate, so it is
    /// always `true` in practice; it is kept for fidelity with the C struct.
    pub disruptive: bool,
}

impl Intervention {
    /// Takes ownership of the contents of a raw intervention struct.
    ///
    /// The `url` and `log` strings are copied into Rust `String`s (lossily, as
    /// libmodsecurity makes no encoding guarantee) and the originals are freed,
    /// leaving `raw` with NULL pointers.
    ///
    /// # Safety
    ///
    /// `raw` must have been filled in by a successful `msc_intervention` call:
    /// its `url` and `log` fields must each be either NULL or a pointer
    /// returned by `strdup` that nothing else will free.
    pub(crate) unsafe fn from_raw(raw: &mut ffi::ModSecurityIntervention) -> Self {
        // SAFETY: upheld by the caller; `take_cstring` nulls the field so no
        // pointer can be freed twice.
        let url = unsafe { take_cstring(&mut raw.url) };
        // SAFETY: as above.
        let log = unsafe { take_cstring(&mut raw.log) };
        Self {
            status: raw.status,
            pause: raw.pause,
            url,
            log,
            disruptive: raw.disruptive != 0,
        }
    }

    /// Returns the redirect target, if this intervention is a redirect.
    #[must_use]
    pub fn redirect_url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Returns libmodsecurity's log line for the rule that fired.
    #[must_use]
    pub fn log_message(&self) -> Option<&str> {
        self.log.as_deref()
    }
}

impl fmt::Display for Intervention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "intervention: status={}", self.status)?;
        if self.pause != 0 {
            write!(f, " pause={}ms", self.pause)?;
        }
        if let Some(url) = &self.url {
            write!(f, " redirect={url}")?;
        }
        if let Some(log) = &self.log {
            write!(f, " log={log}")?;
        }
        Ok(())
    }
}

/// Copies a `strdup`-allocated C string into a `String` and frees the original,
/// leaving `*slot` NULL.
///
/// # Safety
///
/// `*slot` must be NULL or a pointer owned by the C allocator that is not
/// aliased elsewhere.
unsafe fn take_cstring(slot: &mut *mut std::ffi::c_char) -> Option<String> {
    let ptr = std::mem::replace(slot, std::ptr::null_mut());
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non-NULL and NUL-terminated by `strdup`; borrowed only for the
    // duration of this copy.
    let owned = unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: `ptr` came from `strdup` (the C allocator) and the slot has been
    // cleared, so this is the single owner releasing it.
    unsafe { ffi::free(ptr.cast()) };
    Some(owned)
}
