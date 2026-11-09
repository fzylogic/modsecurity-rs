//! Per-request transactions: the inspection state machine.

use std::ffi::c_int;
use std::fmt;
use std::marker::PhantomData;
use std::path::Path;
use std::ptr::NonNull;

use crate::error::{Error, Result, cpath, cstring};
use crate::ffi;
use crate::intervention::Intervention;
use crate::modsecurity::ModSecurity;
use crate::rules::Rules;

/// A single HTTP transaction under inspection.
///
/// A transaction borrows the [`ModSecurity`] engine and the [`Rules`] set, so
/// the compiler guarantees both outlive it — which is exactly the ordering
/// libmodsecurity requires for cleanup.
///
/// # Phases
///
/// Feed the request and response through in order. Each phase method returns
/// `Ok(Some(intervention))` when a rule asked for a disruptive action; stop
/// processing and apply it. Calling phases out of order is not unsafe, but
/// libmodsecurity will not have the variables a rule expects.
///
/// 1. [`process_connection`](Self::process_connection)
/// 2. [`process_uri`](Self::process_uri)
/// 3. [`add_request_header`](Self::add_request_header) …,
///    [`process_request_headers`](Self::process_request_headers)
/// 4. [`append_request_body`](Self::append_request_body) …,
///    [`process_request_body`](Self::process_request_body)
/// 5. [`add_response_header`](Self::add_response_header) …,
///    [`process_response_headers`](Self::process_response_headers)
/// 6. [`append_response_body`](Self::append_response_body) …,
///    [`process_response_body`](Self::process_response_body)
/// 7. [`process_logging`](Self::process_logging)
///
/// Call [`process_logging`](Self::process_logging) before dropping the
/// transaction, even when an earlier phase intervened: it is what flushes the
/// audit log. Dropping does not do it for you, because it can write to disk.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use modsecurity::{ModSecurity, Rules, Transaction};
///
/// let ms = ModSecurity::new()?;
/// let mut rules = Rules::new()?;
/// rules.add_plain(
///     "SecRuleEngine On\n\
///      SecRule ARGS:q \"@contains <script>\" \"id:1,phase:1,deny,status:403\"",
/// )?;
///
/// let mut tx = Transaction::new(&ms, &rules)?;
/// tx.process_connection("203.0.113.9", 51234, "198.51.100.1", 443)?;
/// tx.process_uri("/search?q=%3Cscript%3E", "GET", "1.1")?;
/// tx.add_request_header(b"Host", b"example.com")?;
///
/// if let Some(action) = tx.process_request_headers()? {
///     eprintln!("blocked with {}", action.status);
/// }
/// tx.process_logging()?;
/// # Ok(()) }
/// ```
pub struct Transaction<'a> {
    raw: NonNull<ffi::Transaction>,
    /// Ties the transaction's life to the engine and rules it points at, and
    /// to the log-callback cell whose address was handed to C.
    _borrows: PhantomData<(&'a ModSecurity, &'a Rules)>,
}

// SAFETY: a transaction owns a distinct C++ object and holds no thread-local
// state, so it may be moved between threads. It is deliberately *not* `Sync`:
// every libmodsecurity call on it mutates transaction state, and `&mut self` on
// every such method keeps those calls exclusive. This mirrors how upstream
// connectors hand a transaction between worker threads.
unsafe impl Send for Transaction<'_> {}

impl<'a> Transaction<'a> {
    /// Starts a transaction with a ModSecurity-generated id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NullHandle`] if `msc_new_transaction()` fails.
    pub fn new(ms: &'a ModSecurity, rules: &'a Rules) -> Result<Self> {
        // SAFETY: both pointers are valid and, by the `'a` borrows recorded in
        // `_borrows`, outlive the transaction. `ms.log_data()` points at the
        // engine's boxed callback cell, which is pinned for the same reason.
        let raw = unsafe { ffi::msc_new_transaction(ms.as_ptr(), rules.as_ptr(), ms.log_data()) };
        Self::from_raw(raw, "msc_new_transaction")
    }

    /// Starts a transaction with a caller-supplied id, which appears in the
    /// audit log and lets you correlate it with your own request id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InteriorNul`] if `id` contains a NUL byte, or
    /// [`Error::NullHandle`] if `msc_new_transaction_with_id()` fails.
    pub fn with_id(ms: &'a ModSecurity, rules: &'a Rules, id: &str) -> Result<Self> {
        let mut id = cstring(id, "id")?.into_bytes_with_nul();
        // SAFETY: as `new`. The `*mut c_char` is a signature artefact:
        // libmodsecurity copies the id into a `std::string` during the call and
        // never writes through the pointer, and `id` outlives the call.
        let raw = unsafe {
            ffi::msc_new_transaction_with_id(
                ms.as_ptr(),
                rules.as_ptr(),
                id.as_mut_ptr().cast(),
                ms.log_data(),
            )
        };
        Self::from_raw(raw, "msc_new_transaction_with_id")
    }

    fn from_raw(raw: *mut ffi::Transaction, func: &'static str) -> Result<Self> {
        let raw = NonNull::new(raw).ok_or(Error::NullHandle(func))?;
        Ok(Self {
            raw,
            _borrows: PhantomData,
        })
    }

    // --- phase 0: connection ------------------------------------------------

    /// Records the connection's endpoints (phase 0 variables: `REMOTE_ADDR`,
    /// `REMOTE_PORT`, `SERVER_ADDR`, `SERVER_PORT`).
    ///
    /// # Errors
    ///
    /// [`Error::InteriorNul`] for addresses containing NUL, or
    /// [`Error::Failed`] if libmodsecurity rejects the call.
    pub fn process_connection(
        &mut self,
        client_ip: &str,
        client_port: u16,
        server_ip: &str,
        server_port: u16,
    ) -> Result<Option<Intervention>> {
        let client = cstring(client_ip, "client_ip")?;
        let server = cstring(server_ip, "server_ip")?;
        // SAFETY: valid transaction; both strings are NUL-terminated and
        // outlive the call, which copies them.
        let ret = unsafe {
            ffi::msc_process_connection(
                self.raw.as_ptr(),
                client.as_ptr(),
                c_int::from(client_port),
                server.as_ptr(),
                c_int::from(server_port),
            )
        };
        self.outcome("msc_process_connection", ret)
    }

    /// Records the request line and parses the query string into `ARGS`.
    ///
    /// `method` is the HTTP method (`"GET"`, `"POST"`, …) — the C header calls
    /// this parameter `protocol`, but libmodsecurity assigns it to
    /// `REQUEST_METHOD`. `http_version` is the bare version, e.g. `"1.1"`.
    ///
    /// # Errors
    ///
    /// [`Error::InteriorNul`] or [`Error::Failed`].
    pub fn process_uri(
        &mut self,
        uri: &str,
        method: &str,
        http_version: &str,
    ) -> Result<Option<Intervention>> {
        let uri = cstring(uri, "uri")?;
        let method = cstring(method, "method")?;
        let version = cstring(http_version, "http_version")?;
        // SAFETY: valid transaction and three NUL-terminated strings that
        // outlive the call.
        let ret = unsafe {
            ffi::msc_process_uri(
                self.raw.as_ptr(),
                uri.as_ptr(),
                method.as_ptr(),
                version.as_ptr(),
            )
        };
        self.outcome("msc_process_uri", ret)
    }

    // --- phase 1: request headers -------------------------------------------

    /// Adds a request header.
    ///
    /// Takes bytes with explicit lengths, so header names and values may
    /// contain anything, including NUL.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if libmodsecurity rejects the header.
    pub fn add_request_header(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        // SAFETY: valid transaction; pointer/length pairs come from live
        // slices, and libmodsecurity copies the bytes during the call.
        let ret = unsafe {
            ffi::msc_add_n_request_header(
                self.raw.as_ptr(),
                name.as_ptr(),
                name.len(),
                value.as_ptr(),
                value.len(),
            )
        };
        check(ret, "msc_add_n_request_header")
    }

    /// Runs phase 1 (`REQUEST_HEADERS`).
    ///
    /// # Errors
    ///
    /// [`Error::Failed`].
    pub fn process_request_headers(&mut self) -> Result<Option<Intervention>> {
        // SAFETY: valid, exclusively borrowed transaction.
        let ret = unsafe { ffi::msc_process_request_headers(self.raw.as_ptr()) };
        self.outcome("msc_process_request_headers", ret)
    }

    // --- phase 2: request body ----------------------------------------------

    /// Appends a chunk of the request body.
    ///
    /// Returns an intervention if the body exceeded `SecRequestBodyLimit` and
    /// the configured limit action is `Reject`.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`].
    pub fn append_request_body(&mut self, chunk: &[u8]) -> Result<Option<Intervention>> {
        // SAFETY: valid transaction; the pointer/length pair comes from a live
        // slice whose bytes are copied during the call.
        let ret =
            unsafe { ffi::msc_append_request_body(self.raw.as_ptr(), chunk.as_ptr(), chunk.len()) };
        self.outcome("msc_append_request_body", ret)
    }

    /// Uses a file's contents as the request body.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPath`] or [`Error::Failed`] (for example if the file
    /// cannot be read).
    pub fn request_body_from_file(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = cpath(path.as_ref())?;
        // SAFETY: valid transaction and a NUL-terminated path that outlives the
        // call.
        let ret = unsafe { ffi::msc_request_body_from_file(self.raw.as_ptr(), path.as_ptr()) };
        check(ret, "msc_request_body_from_file")
    }

    /// Runs phase 2 (`REQUEST_BODY`).
    ///
    /// # Errors
    ///
    /// [`Error::Failed`].
    pub fn process_request_body(&mut self) -> Result<Option<Intervention>> {
        // SAFETY: valid, exclusively borrowed transaction.
        let ret = unsafe { ffi::msc_process_request_body(self.raw.as_ptr()) };
        self.outcome("msc_process_request_body", ret)
    }

    /// Number of request body bytes buffered so far.
    #[must_use]
    pub fn request_body_length(&mut self) -> usize {
        // SAFETY: valid transaction; the call only reads a stream position.
        unsafe { ffi::msc_get_request_body_length(self.raw.as_ptr()) }
    }

    // --- phase 3: response headers ------------------------------------------

    /// Adds a response header. As [`add_request_header`](Self::add_request_header).
    ///
    /// # Errors
    ///
    /// [`Error::Failed`].
    pub fn add_response_header(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        // SAFETY: as `add_request_header`.
        let ret = unsafe {
            ffi::msc_add_n_response_header(
                self.raw.as_ptr(),
                name.as_ptr(),
                name.len(),
                value.as_ptr(),
                value.len(),
            )
        };
        check(ret, "msc_add_n_response_header")
    }

    /// Runs phase 3 (`RESPONSE_HEADERS`) with the status code and protocol
    /// string, e.g. `(200, "HTTP/1.1")`.
    ///
    /// # Errors
    ///
    /// [`Error::InteriorNul`] or [`Error::Failed`].
    pub fn process_response_headers(
        &mut self,
        status: i32,
        protocol: &str,
    ) -> Result<Option<Intervention>> {
        let protocol = cstring(protocol, "protocol")?;
        // SAFETY: valid transaction and a NUL-terminated string that outlives
        // the call.
        let ret = unsafe {
            ffi::msc_process_response_headers(self.raw.as_ptr(), status, protocol.as_ptr())
        };
        self.outcome("msc_process_response_headers", ret)
    }

    // --- phase 4: response body ---------------------------------------------

    /// Appends a chunk of the response body.
    ///
    /// Returns an intervention if the body exceeded `SecResponseBodyLimit` and
    /// the configured limit action is `Reject`.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`].
    pub fn append_response_body(&mut self, chunk: &[u8]) -> Result<Option<Intervention>> {
        // SAFETY: as `append_request_body`.
        let ret = unsafe {
            ffi::msc_append_response_body(self.raw.as_ptr(), chunk.as_ptr(), chunk.len())
        };
        self.outcome("msc_append_response_body", ret)
    }

    /// Runs phase 4 (`RESPONSE_BODY`).
    ///
    /// # Errors
    ///
    /// [`Error::Failed`].
    pub fn process_response_body(&mut self) -> Result<Option<Intervention>> {
        // SAFETY: valid, exclusively borrowed transaction.
        let ret = unsafe { ffi::msc_process_response_body(self.raw.as_ptr()) };
        self.outcome("msc_process_response_body", ret)
    }

    /// Number of response body bytes buffered so far.
    ///
    /// There is deliberately no accessor for the body *contents*: upstream's
    /// `msc_get_response_body` returns a pointer into a destroyed `std::string`
    /// temporary, so it cannot be wrapped soundly. libmodsecurity v3 never
    /// rewrites the body, so the caller already has the bytes it fed in.
    #[must_use]
    pub fn response_body_length(&mut self) -> usize {
        // SAFETY: valid transaction; the call only reads a stream position.
        unsafe { ffi::msc_get_response_body_length(self.raw.as_ptr()) }
    }

    // --- phase 5: logging ----------------------------------------------------

    /// Runs phase 5 (`LOGGING`) and flushes the audit log.
    ///
    /// Call this exactly once, at the end of every transaction, including ones
    /// that were blocked earlier.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`].
    pub fn process_logging(&mut self) -> Result<()> {
        // SAFETY: valid, exclusively borrowed transaction.
        let ret = unsafe { ffi::msc_process_logging(self.raw.as_ptr()) };
        check(ret, "msc_process_logging")
    }

    // --- misc ----------------------------------------------------------------

    /// Tells ModSecurity the status code the server actually produced, so that
    /// phase 5 rules can inspect it.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`].
    pub fn update_status_code(&mut self, status: i32) -> Result<()> {
        // SAFETY: valid, exclusively borrowed transaction.
        let ret = unsafe { ffi::msc_update_status_code(self.raw.as_ptr(), status) };
        check(ret, "msc_update_status_code")
    }

    /// Takes the pending disruptive action, if any.
    ///
    /// The phase methods call this for you and hand back the result, so you
    /// only need it when driving the raw phases yourself. Each intervention is
    /// reported once: taking it clears the transaction's pending action.
    pub fn intervention(&mut self) -> Option<Intervention> {
        let mut raw = ffi::ModSecurityIntervention::zeroed();
        // SAFETY: valid, exclusively borrowed transaction, and `raw` is a fully
        // initialised out-parameter that lives across the call.
        let ret = unsafe { ffi::msc_intervention(self.raw.as_ptr(), &mut raw) };
        if ret == 0 {
            // Nothing was written, so there is nothing to free.
            debug_assert!(raw.url.is_null() && raw.log.is_null());
            return None;
        }
        // SAFETY: `msc_intervention` reported a disruptive action, so `url` and
        // `log` are each NULL or a `strdup`ed string now owned by us.
        Some(unsafe { Intervention::from_raw(&mut raw) })
    }

    /// Maps a phase return value plus any pending intervention onto a result.
    ///
    /// libmodsecurity signals "rule asked to disrupt" through the intervention
    /// out-parameter rather than the return value, and a `0` return with a
    /// pending intervention (body limit exceeded, for instance) is an expected
    /// outcome rather than a failure.
    fn outcome(&mut self, func: &'static str, ret: c_int) -> Result<Option<Intervention>> {
        let intervention = self.intervention();
        if ret == 0 && intervention.is_none() {
            return Err(Error::Failed(func));
        }
        Ok(intervention)
    }
}

impl fmt::Debug for Transaction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction").finish_non_exhaustive()
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        // SAFETY: created by `msc_new_transaction*` and released exactly once,
        // before the engine and rules set it borrows.
        unsafe { ffi::msc_transaction_cleanup(self.raw.as_ptr()) };
    }
}

/// Maps a boolean-ish C return value onto a result.
fn check(ret: c_int, func: &'static str) -> Result<()> {
    if ret == 0 {
        return Err(Error::Failed(func));
    }
    Ok(())
}
