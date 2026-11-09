//! The ModSecurity engine handle.

use std::ffi::{CStr, c_void};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::NonNull;
use std::sync::OnceLock;

use crate::error::{Error, Result, cstring};
use crate::ffi;

/// A callback invoked for every log line libmodsecurity emits.
///
/// The slice is the raw log text, without a trailing newline or NUL, and is
/// only valid for the duration of the call.
pub type LogCallback = dyn Fn(&[u8]) + Send + Sync + 'static;

/// Stable, heap-pinned home for one handle's log callback.
///
/// Its address is handed to C as the per-transaction `logCbData`, so it must
/// not move while any transaction is alive. Boxing it keeps the address fixed
/// even if the owning [`ModSecurity`] handle is moved.
struct LogCallbackCell {
    callback: Option<Box<LogCallback>>,
}

/// The one `modsecurity::ModSecurity` object this process will ever have.
///
/// `NonNull` is not `Send`/`Sync`, so it is wrapped. Writing to the engine
/// happens only under `&mut ModSecurity`; everything else reads.
struct SharedEngine(NonNull<ffi::ModSecurity>);

// SAFETY: the pointer is created once, never freed, and libmodsecurity's own
// connectors share a single engine across every worker thread.
unsafe impl Send for SharedEngine {}
// SAFETY: see above.
unsafe impl Sync for SharedEngine {}

static ENGINE: OnceLock<Option<SharedEngine>> = OnceLock::new();

/// Returns the process-wide engine, creating it on first use.
fn shared_engine() -> Result<NonNull<ffi::ModSecurity>> {
    let engine = ENGINE.get_or_init(|| {
        // SAFETY: takes no arguments and has no preconditions. `OnceLock`
        // guarantees this runs exactly once, which matters because
        // `ModSecurity`'s constructor initialises process-global libxml2 state.
        let raw = unsafe { ffi::msc_init() };
        let raw = NonNull::new(raw)?;

        // Install the trampoline once, for the life of the process. It is a
        // no-op until a handle registers a callback, so the C-side state never
        // changes again.
        //
        // SAFETY: `raw` is a freshly created engine, and `log_trampoline` has
        // the signature `ModSecLogCb` requires.
        unsafe { ffi::msc_set_log_cb(raw.as_ptr(), Some(log_trampoline)) };

        Some(SharedEngine(raw))
    });

    engine
        .as_ref()
        .map(|e| e.0)
        .ok_or(Error::NullHandle("msc_init"))
}

/// A handle to the ModSecurity engine.
///
/// # One engine per process
///
/// libmodsecurity's `ModSecurity` destructor calls libxml2's
/// `xmlCleanupParser()`, which tears down state shared by the whole process.
/// Running it while another thread — or another engine, or any other libxml2
/// user linked into the program — is working is a use-after-free, and nothing
/// in the C API lets a caller prevent that.
///
/// So this crate creates exactly one engine, lazily, and never destroys it. A
/// `ModSecurity` value is a cheap handle to it: constructing one is cheap after
/// the first, and dropping one frees only the handle's own callback. The object
/// is reclaimed by the operating system at exit; if you need the destructor to
/// run anyway, see [`shutdown`](Self::shutdown).
///
/// Two consequences follow, both of which only matter if you hold more than one
/// handle at a time:
///
/// * [`set_connector_info`](Self::set_connector_info) writes to shared state,
///   so the most recent call wins.
/// * [`set_log_callback`](Self::set_log_callback) is *per handle*: transactions
///   report to the callback of the handle that created them.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use modsecurity::ModSecurity;
///
/// let mut ms = ModSecurity::new()?;
/// ms.set_connector_info("my-proxy/1.0")?;
/// ms.set_log_callback(|msg: &[u8]| {
///     eprintln!("[modsec] {}", String::from_utf8_lossy(msg));
/// });
/// println!("{}", ms.who_am_i());
/// # Ok(()) }
/// ```
pub struct ModSecurity {
    raw: NonNull<ffi::ModSecurity>,
    log: Box<LogCallbackCell>,
}

// SAFETY: the engine behind `raw` is shared and immutable after initialisation;
// every call that writes to it takes `&mut self`, and the callback cell is
// owned solely by this handle.
unsafe impl Send for ModSecurity {}
// SAFETY: see above.
unsafe impl Sync for ModSecurity {}

impl ModSecurity {
    /// Returns a handle to the engine, initialising it on first use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NullHandle`] if `msc_init()` failed. The failure is
    /// recorded, so later calls report it too rather than retrying.
    pub fn new() -> Result<Self> {
        Ok(Self {
            raw: shared_engine()?,
            log: Box::new(LogCallbackCell { callback: None }),
        })
    }

    /// Identifies the host connector to ModSecurity, e.g. `"my-proxy/1.0"`.
    ///
    /// Recommended by upstream; it appears in audit logs. This writes to
    /// process-wide state shared by every handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InteriorNul`] if `connector` contains a NUL byte.
    pub fn set_connector_info(&mut self, connector: &str) -> Result<()> {
        let c = cstring(connector, "connector")?;
        // SAFETY: `self.raw` is the live engine, `c` outlives the call, and the
        // callee copies the string into a `std::string`. `&mut self` keeps this
        // write exclusive with respect to every transaction, which borrows the
        // handle.
        unsafe { ffi::msc_set_connector_info(self.raw.as_ptr(), c.as_ptr()) };
        Ok(())
    }

    /// Builder form of [`set_connector_info`](Self::set_connector_info).
    ///
    /// # Errors
    ///
    /// As [`set_connector_info`](Self::set_connector_info).
    pub fn with_connector_info(mut self, connector: &str) -> Result<Self> {
        self.set_connector_info(connector)?;
        Ok(self)
    }

    /// Returns libmodsecurity's self-description, e.g.
    /// `"ModSecurity v3.0.12 (Linux)"`.
    #[must_use]
    pub fn who_am_i(&self) -> String {
        // SAFETY: `self.raw` is the live engine. The returned pointer belongs
        // to its `m_whoami` member, which is only written during construction;
        // the bytes are copied out before returning.
        let ptr = unsafe { ffi::msc_who_am_i(self.raw.as_ptr()) };
        if ptr.is_null() {
            return String::new();
        }
        // SAFETY: non-NULL and NUL-terminated, and not mutated during the copy.
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }

    /// Registers a callback for libmodsecurity's log output.
    ///
    /// It applies to transactions created from *this* handle, including ones
    /// created before the call — but the borrow checker makes that impossible,
    /// since outstanding transactions borrow the handle.
    ///
    /// The callback runs on whichever thread is evaluating a transaction, so it
    /// must be `Send + Sync`. A panic inside it is caught at the FFI boundary
    /// and discarded rather than unwinding into C++.
    ///
    /// # What arrives here
    ///
    /// Only **non-disruptive** matches — a rule with `log` that does not deny,
    /// drop or redirect. A disruptive match is delivered as an
    /// [`Intervention`](crate::Intervention) returned by the phase method, with
    /// its message in [`Intervention::log`](crate::Intervention::log), and
    /// never reaches this callback. Handle both to see every match.
    pub fn set_log_callback<F>(&mut self, callback: F)
    where
        F: Fn(&[u8]) + Send + Sync + 'static,
    {
        self.log.callback = Some(Box::new(callback));
    }

    /// Removes a previously registered log callback.
    pub fn clear_log_callback(&mut self) {
        self.log.callback = None;
    }

    /// Destroys the process-wide engine.
    ///
    /// You almost certainly do not want this: the engine is meant to live for
    /// the life of the process, and the operating system reclaims it at exit.
    /// It exists for programs that must satisfy a leak checker.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that, for the rest of the process's life:
    ///
    /// * no [`ModSecurity`], [`Rules`](crate::Rules) or
    ///   [`Transaction`](crate::Transaction) value exists or will be created;
    /// * no other thread is running, or any that are use neither this crate nor
    ///   libxml2 — libmodsecurity's destructor calls `xmlCleanupParser()`,
    ///   which frees state shared by every libxml2 user in the process.
    ///
    /// Calling it more than once is a double free.
    pub unsafe fn shutdown() {
        if let Some(Some(engine)) = ENGINE.get() {
            // SAFETY: the caller guarantees nothing else refers to the engine
            // or to libxml2, and that this runs once.
            unsafe { ffi::msc_cleanup(engine.0.as_ptr()) };
        }
    }

    /// Raw engine pointer, for [`Transaction`](crate::Transaction).
    pub(crate) fn as_ptr(&self) -> *mut ffi::ModSecurity {
        self.raw.as_ptr()
    }

    /// Address of this handle's pinned callback cell, passed to C as
    /// `logCbData`.
    ///
    /// Valid for as long as `&self` is borrowed: the cell lives in a `Box`, and
    /// replacing the callback requires `&mut self`.
    pub(crate) fn log_data(&self) -> *mut c_void {
        (&*self.log as *const LogCallbackCell).cast_mut().cast()
    }
}

impl fmt::Debug for ModSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModSecurity")
            .field("who_am_i", &self.who_am_i())
            .field("log_callback", &self.log.callback.is_some())
            .finish()
    }
}

/// `ModSecLogCb` trampoline: turns a C callback into a Rust closure call.
///
/// # Safety
///
/// Called only by libmodsecurity, with the `logCbData` this crate supplied in
/// `msc_new_transaction` (the address of a live `LogCallbackCell`) and a
/// NUL-terminated `const char *` message.
unsafe extern "C" fn log_trampoline(data: *mut c_void, msg: *const c_void) {
    if data.is_null() || msg.is_null() {
        return;
    }
    // Never let a panic cross back into C++.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `data` is the address of a `LogCallbackCell` owned by a
        // `ModSecurity` handle that is borrowed for the whole life of the
        // transaction that produced this message. Only shared access is taken,
        // and replacing the callback requires `&mut ModSecurity`, which cannot
        // overlap with that borrow.
        let cell = unsafe { &*data.cast::<LogCallbackCell>() };
        let Some(callback) = cell.callback.as_ref() else {
            return;
        };
        // SAFETY: with the default log properties libmodsecurity passes a
        // NUL-terminated C string that stays valid for the duration of the call.
        let bytes = unsafe { CStr::from_ptr(msg.cast::<std::ffi::c_char>()) }.to_bytes();
        callback(bytes);
    }));
}
